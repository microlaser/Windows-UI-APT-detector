/*
 * ui_tamper_monitor.c
 *
 * UI Manipulation Detection Tool
 * For forensic use: detects signs of APT-level Windows UI tampering.
 *
 * Monitors for:
 *   1. Overlay windows (WS_EX_LAYERED | WS_EX_TRANSPARENT over other windows)
 *   2. Injected DLLs in running processes (unsigned / unsigned-path DLLs)
 *   3. Global Windows hooks registered via SetWindowsHookEx
 *   4. UI Automation COM server registrations (out-of-process UIA clients)
 *   5. Suspicious cross-process memory regions (RWX pages injected into processes)
 *
 * Build (MinGW):
 *   gcc -o ui_tamper_monitor.exe ui_tamper_monitor.c \
 *       -lpsapi -lole32 -loleaut32 -luiautomationcore \
 *       -lntdll -lshlwapi -ladvapi32 -luser32 -lgdi32 \
 *       -mwindows -Wall -O2
 *
 * Build (MSVC Developer Command Prompt):
 *   cl ui_tamper_monitor.c /Fe:ui_tamper_monitor.exe \
 *      psapi.lib ole32.lib oleaut32.lib shlwapi.lib \
 *      advapi32.lib user32.lib gdi32.lib ntdll.lib
 *
 * Run:
 *   ui_tamper_monitor.exe
 *   (Logs written to ui_tamper_log.txt in the same directory)
 *   (Press Ctrl+C to stop)
 *
 * NOTE: Run as Administrator for full process access.
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601   /* Windows 7+ */

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

/* ── Configuration ─────────────────────────────────────────────────────────── */
#define POLL_INTERVAL_MS       3000    /* scan every 3 seconds                 */
#define LOG_FILE               L"ui_tamper_log.txt"

/* Heuristic: DLLs loaded from these path prefixes are suspicious             */
static const wchar_t *SUSPICIOUS_PATH_PREFIXES[] = {
    L"%TEMP%",
    L"%APPDATA%",
    L"%LOCALAPPDATA%",
    L"\\Users\\",          /* any user-writable path                          */
    L"\\ProgramData\\",
    NULL
};

/* Known-good system DLL paths (only flag DLLs NOT under these)               */
static const wchar_t *KNOWN_GOOD_PATH_PREFIXES[] = {
    L"C:\\Windows\\System32\\",
    L"C:\\Windows\\SysWOW64\\",
    L"C:\\Windows\\WinSxS\\",
    L"C:\\Program Files\\",
    L"C:\\Program Files (x86)\\",
    NULL
};

/* ── Globals ────────────────────────────────────────────────────────────────── */
static FILE  *g_log        = NULL;
static BOOL   g_running    = TRUE;

/* ── Logging ────────────────────────────────────────────────────────────────── */
static void log_write(const wchar_t *fmt, ...)
{
    wchar_t  buf[2048];
    va_list  args;
    time_t   t  = time(NULL);
    struct tm *tm = localtime(&t);
    char     ts[32];

    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    va_start(args, fmt);
    vswprintf(buf, 2048, fmt, args);
    va_end(args);

    /* stdout */
    wprintf(L"[%hs] %ls\n", ts, buf);
    fflush(stdout);

    /* file */
    if (g_log) {
        fprintf(g_log, "[%s] %ls\n", ts, buf);
        fflush(g_log);
    }
}

static void log_separator(void)
{
    log_write(L"─────────────────────────────────────────────────────────────");
}

/* ── Helper: expand environment strings ─────────────────────────────────────── */
static void expand_path(const wchar_t *src, wchar_t *dst, DWORD dst_len)
{
    ExpandEnvironmentStringsW(src, dst, dst_len);
}

/* ── Helper: check if a path starts with a prefix (case-insensitive) ─────────── */
static BOOL path_starts_with(const wchar_t *path, const wchar_t *prefix)
{
    return (_wcsnicmp(path, prefix, wcslen(prefix)) == 0);
}

/* ── Helper: check if DLL path looks suspicious ─────────────────────────────── */
static BOOL dll_path_is_suspicious(const wchar_t *dll_path)
{
    /* If NOT under a known-good path, flag it */
    int i;
    for (i = 0; KNOWN_GOOD_PATH_PREFIXES[i] != NULL; i++) {
        if (path_starts_with(dll_path, KNOWN_GOOD_PATH_PREFIXES[i]))
            return FALSE;
    }
    return TRUE;   /* not in any known-good location */
}

/* ── Helper: verify Authenticode signature ───────────────────────────────────── */
static BOOL file_is_signed(const wchar_t *path)
{
    WINTRUST_FILE_INFO fi  = { 0 };
    WINTRUST_DATA      wd  = { 0 };
    GUID               pol = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG               res;

    fi.cbStruct       = sizeof(fi);
    fi.pcwszFilePath  = path;

    wd.cbStruct            = sizeof(wd);
    wd.dwUIChoice          = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;   /* offline-friendly */
    wd.dwUnionChoice       = WTD_CHOICE_FILE;
    wd.pFile               = &fi;
    wd.dwStateAction       = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags         = WTD_SAFER_FLAG;

    res = WinVerifyTrust(NULL, &pol, &wd);

    /* Close the action */
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &pol, &wd);

    return (res == ERROR_SUCCESS);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * CHECK 1 — Overlay / layered transparent windows
 * An attacker may place a WS_EX_LAYERED | WS_EX_TRANSPARENT window on top of
 * legitimate UI controls to render fake values while passing all input through.
 * ══════════════════════════════════════════════════════════════════════════════ */

typedef struct {
    int   found;
    HWND  topmost_under[64];
    int   topmost_count;
} OverlayCtx;

static BOOL CALLBACK enum_overlay_cb(HWND hwnd, LPARAM lp)
{
    OverlayCtx *ctx = (OverlayCtx *)lp;
    DWORD       ex_style;
    RECT        r;
    wchar_t     cls[256], title[256];
    DWORD       pid;

    ex_style = (DWORD)GetWindowLongPtrW(hwnd, GWL_EXSTYLE);

    /* Look for layered + transparent windows that are visible */
    if ((ex_style & WS_EX_LAYERED) && (ex_style & WS_EX_TRANSPARENT) &&
        IsWindowVisible(hwnd))
    {
        GetClassNameW(hwnd, cls,   255);
        GetWindowTextW(hwnd, title, 255);
        GetWindowRect(hwnd, &r);
        GetWindowThreadProcessId(hwnd, &pid);

        log_write(L"[OVERLAY] Suspicious layered+transparent window detected:");
        log_write(L"  HWND       : 0x%08X",  (unsigned)hwnd);
        log_write(L"  PID        : %lu",      pid);
        log_write(L"  Class      : %ls",      cls);
        log_write(L"  Title      : \"%ls\"",  title);
        log_write(L"  Rect       : (%d,%d)-(%d,%d)",
                  r.left, r.top, r.right, r.bottom);
        log_write(L"  ExStyle    : 0x%08X",   ex_style);

        /* Extra suspicion: no caption, no taskbar button, on top */
        if ((ex_style & WS_EX_TOOLWINDOW) || (ex_style & WS_EX_TOPMOST))
            log_write(L"  ** Also TOOLWINDOW or TOPMOST — elevated suspicion **");

        ctx->found++;
    }
    return TRUE;
}

static void check_overlay_windows(void)
{
    OverlayCtx ctx = { 0 };
    EnumWindows(enum_overlay_cb, (LPARAM)&ctx);
    if (ctx.found == 0)
        log_write(L"[OVERLAY] No suspicious overlay windows found.");
    else
        log_write(L"[OVERLAY] Total suspicious overlay windows: %d", ctx.found);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * CHECK 2 — Injected / unsigned DLLs in running processes
 * ══════════════════════════════════════════════════════════════════════════════ */

static void check_injected_dlls(void)
{
    HANDLE          snap;
    PROCESSENTRY32W pe  = { sizeof(pe) };
    int             total_suspicious = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        log_write(L"[DLL-INJECT] CreateToolhelp32Snapshot failed: %lu", GetLastError());
        return;
    }

    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        return;
    }

    do {
        HANDLE hproc;
        HMODULE mods[1024];
        DWORD   needed;
        DWORD   i, cnt;
        wchar_t mod_path[MAX_PATH];

        /* Skip System / Idle */
        if (pe.th32ProcessID <= 4)
            continue;

        hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                            FALSE, pe.th32ProcessID);
        if (!hproc)
            continue;

        if (!EnumProcessModulesEx(hproc, mods, sizeof(mods), &needed,
                                  LIST_MODULES_ALL)) {
            CloseHandle(hproc);
            continue;
        }

        cnt = needed / sizeof(HMODULE);
        for (i = 0; i < cnt; i++) {
            if (!GetModuleFileNameExW(hproc, mods[i], mod_path, MAX_PATH))
                continue;

            if (!dll_path_is_suspicious(mod_path))
                continue;

            /* It's in a suspicious path — check if also unsigned */
            BOOL signed_ok = file_is_signed(mod_path);

            log_write(L"[DLL-INJECT] Suspicious DLL in PID %lu (%ls):",
                      pe.th32ProcessID, pe.szExeFile);
            log_write(L"  Module     : %ls", mod_path);
            log_write(L"  Signed     : %ls", signed_ok ? L"YES" : L"NO ← unsigned");
            if (!signed_ok)
                log_write(L"  ** Unsigned DLL in user-writable path — high suspicion **");

            total_suspicious++;
        }

        CloseHandle(hproc);
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);

    if (total_suspicious == 0)
        log_write(L"[DLL-INJECT] No suspicious DLLs found in running processes.");
    else
        log_write(L"[DLL-INJECT] Total suspicious DLL instances: %d", total_suspicious);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * CHECK 3 — Global Windows hooks (SetWindowsHookEx)
 * Hooks installed with a non-NULL hMod across all threads are visible via
 * the undocumented NtQuerySystemInformation class 38 (SystemHandleInformation)
 * but a simpler proxy is to look for WH_* hook DLLs loaded into explorer.exe
 * and other shell processes, which is where global hooks are injected.
 *
 * We enumerate DLLs in explorer.exe and flag anything non-system.
 * ══════════════════════════════════════════════════════════════════════════════ */

static DWORD get_pid_by_name(const wchar_t *name)
{
    HANDLE          snap;
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD           pid = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static void check_global_hooks(void)
{
    /* Global hooks are injected into every GUI process — check explorer.exe
       and also dwm.exe (Desktop Window Manager, graphics pipeline target)    */
    static const wchar_t *HOOK_TARGETS[] = {
        L"explorer.exe",
        L"dwm.exe",
        L"winlogon.exe",
        NULL
    };
    int i, total_suspicious = 0;

    for (i = 0; HOOK_TARGETS[i] != NULL; i++) {
        DWORD   pid;
        HANDLE  hproc;
        HMODULE mods[1024];
        DWORD   needed, cnt, j;
        wchar_t mod_path[MAX_PATH];

        pid = get_pid_by_name(HOOK_TARGETS[i]);
        if (!pid) continue;

        hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                            FALSE, pid);
        if (!hproc) continue;

        if (!EnumProcessModulesEx(hproc, mods, sizeof(mods), &needed,
                                  LIST_MODULES_ALL)) {
            CloseHandle(hproc);
            continue;
        }

        cnt = needed / sizeof(HMODULE);
        for (j = 0; j < cnt; j++) {
            if (!GetModuleFileNameExW(hproc, mods[j], mod_path, MAX_PATH))
                continue;
            if (!dll_path_is_suspicious(mod_path))
                continue;

            BOOL signed_ok = file_is_signed(mod_path);
            log_write(L"[HOOK] Non-system DLL in %ls (PID %lu):",
                      HOOK_TARGETS[i], pid);
            log_write(L"  Module     : %ls", mod_path);
            log_write(L"  Signed     : %ls", signed_ok ? L"YES" : L"NO ← unsigned");
            log_write(L"  ** Possible global hook injection vector **");
            total_suspicious++;
        }
        CloseHandle(hproc);
    }

    if (total_suspicious == 0)
        log_write(L"[HOOK] No non-system DLLs found in hook-target processes.");
    else
        log_write(L"[HOOK] Total suspicious entries in hook-target processes: %d",
                  total_suspicious);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * CHECK 4 — Executable (RWX) memory regions in GUI processes
 * Shellcode injection and reflective DLL loading leave RWX (or RX after write)
 * private memory regions in the target process — not backed by any file on disk.
 * ══════════════════════════════════════════════════════════════════════════════ */

static void check_rwx_memory(void)
{
    HANDLE          snap;
    PROCESSENTRY32W pe  = { sizeof(pe) };
    int             total = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        return;
    }

    do {
        HANDLE               hproc;
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T               addr = 0;
        BOOL                 is_gui_proc = FALSE;
        HWND                 dummy;

        if (pe.th32ProcessID <= 4) continue;

        /* Quick check: does this process own any windows? (GUI process) */
        /* We use a rough heuristic — check if user32.dll is loaded      */
        hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                            FALSE, pe.th32ProcessID);
        if (!hproc) continue;

        /* Walk the process address space */
        while (VirtualQueryEx(hproc, (LPCVOID)addr, &mbi, sizeof(mbi)) ==
               sizeof(mbi))
        {
            addr += mbi.RegionSize;

            /* We want: committed, private (not mapped/image), executable */
            if (mbi.State   != MEM_COMMIT)             continue;
            if (mbi.Type    != MEM_PRIVATE)            continue;
            if (!(mbi.Protect & (PAGE_EXECUTE |
                                 PAGE_EXECUTE_READ |
                                 PAGE_EXECUTE_READWRITE |
                                 PAGE_EXECUTE_WRITECOPY))) continue;

            /* RWX or just RX-private is already interesting;
               RWX (simultaneous write+execute) is most suspicious         */
            BOOL is_rwx = (mbi.Protect == PAGE_EXECUTE_READWRITE ||
                           mbi.Protect == PAGE_EXECUTE_WRITECOPY);

            log_write(L"[RWX-MEM] Private executable region in PID %lu (%ls):",
                      pe.th32ProcessID, pe.szExeFile);
            log_write(L"  Base       : 0x%p",  mbi.BaseAddress);
            log_write(L"  Size       : %zu bytes", mbi.RegionSize);
            log_write(L"  Protect    : 0x%08X %ls",
                      mbi.Protect,
                      is_rwx ? L"← RWX (read+write+exec simultaneously) HIGH RISK"
                              : L"");
            total++;

            if (total > 64) {
                /* Safety valve — don't flood the log                     */
                log_write(L"[RWX-MEM] Hit 64-entry cap, stopping for this cycle.");
                goto done_rwx;
            }
        }

        CloseHandle(hproc);
        continue;

    done_rwx:
        CloseHandle(hproc);
        break;

    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);

    if (total == 0)
        log_write(L"[RWX-MEM] No suspicious private executable memory regions found.");
    else
        log_write(L"[RWX-MEM] Total suspicious regions: %d", total);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * CHECK 5 — UI Automation: enumerate out-of-process UIA clients
 * A hostile process using IUIAutomation to read/write UI elements in other
 * processes will appear as a COM server calling into UIAutomationCore.dll.
 * We detect processes that have UIAutomationCore.dll loaded but are NOT
 * known accessibility tools.
 * ══════════════════════════════════════════════════════════════════════════════ */

/* Known-legitimate processes that may use UIA */
static const wchar_t *UIA_WHITELIST[] = {
    L"narrator.exe",
    L"magnify.exe",
    L"osk.exe",            /* on-screen keyboard */
    L"nvda.exe",           /* NVDA screen reader */
    L"jaws.exe",
    L"zoomtext.exe",
    L"inspect.exe",        /* Microsoft Inspect tool */
    L"accexplorer.exe",
    L"uispy.exe",
    L"msedge.exe",         /* Chromium-based accessibility */
    L"chrome.exe",
    L"firefox.exe",
    NULL
};

static BOOL proc_in_uia_whitelist(const wchar_t *name)
{
    int i;
    for (i = 0; UIA_WHITELIST[i] != NULL; i++)
        if (_wcsicmp(name, UIA_WHITELIST[i]) == 0)
            return TRUE;
    return FALSE;
}

static void check_uia_clients(void)
{
    HANDLE          snap;
    PROCESSENTRY32W pe  = { sizeof(pe) };
    int             total = 0;
    wchar_t         uia_path[MAX_PATH];

    /* Resolve UIAutomationCore.dll path once */
    GetSystemDirectoryW(uia_path, MAX_PATH);
    PathAppendW(uia_path, L"UIAutomationCore.dll");
    _wcslwr(uia_path);  /* normalise for comparison */

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        return;
    }

    do {
        HANDLE  hproc;
        HMODULE mods[1024];
        DWORD   needed, cnt, j;
        wchar_t mod_path[MAX_PATH];
        BOOL    has_uia = FALSE;

        if (pe.th32ProcessID <= 4) continue;
        if (proc_in_uia_whitelist(pe.szExeFile)) continue;

        hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                            FALSE, pe.th32ProcessID);
        if (!hproc) continue;

        if (!EnumProcessModulesEx(hproc, mods, sizeof(mods), &needed,
                                  LIST_MODULES_ALL)) {
            CloseHandle(hproc);
            continue;
        }

        cnt = needed / sizeof(HMODULE);
        for (j = 0; j < cnt; j++) {
            wchar_t lower[MAX_PATH];
            if (!GetModuleFileNameExW(hproc, mods[j], mod_path, MAX_PATH))
                continue;
            wcsncpy(lower, mod_path, MAX_PATH);
            _wcslwr(lower);
            if (wcsstr(lower, L"uiautomationcore.dll")) {
                has_uia = TRUE;
                break;
            }
        }
        CloseHandle(hproc);

        if (has_uia) {
            log_write(L"[UIA] Non-whitelisted process has UIAutomationCore loaded:");
            log_write(L"  Process    : %ls (PID %lu)",
                      pe.szExeFile, pe.th32ProcessID);
            log_write(L"  ** Could be reading or writing UI elements cross-process **");
            total++;
        }
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);

    if (total == 0)
        log_write(L"[UIA] No unexpected UIA clients found.");
    else
        log_write(L"[UIA] Total unexpected UIA clients: %d", total);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * MAIN LOOP
 * ══════════════════════════════════════════════════════════════════════════════ */

static BOOL WINAPI ctrl_handler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) {
        log_write(L"Received stop signal — shutting down.");
        g_running = FALSE;
        return TRUE;
    }
    return FALSE;
}

int wmain(void)
{
    DWORD cycle = 0;

    /* Open log file */
    _wfopen_s(&g_log, LOG_FILE, L"a, ccs=UTF-8");
    if (!g_log) {
        fwprintf(stderr, L"Could not open log file %ls\n", LOG_FILE);
        return 1;
    }

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    log_write(L"");
    log_write(L"╔══════════════════════════════════════════════════════════╗");
    log_write(L"║        UI Tamper Monitor — Starting                     ║");
    log_write(L"║  Poll interval : %d ms                                  ║",
              POLL_INTERVAL_MS);
    log_write(L"║  Log file      : %-37ls║", LOG_FILE);
    log_write(L"╚══════════════════════════════════════════════════════════╝");
    log_write(L"NOTE: Run as Administrator for full process access.");
    log_write(L"NOTE: Some false positives are normal — look for REPEATED "
              L"entries across cycles.");
    log_write(L"");

    while (g_running) {
        cycle++;
        log_separator();
        log_write(L"SCAN CYCLE #%lu", cycle);
        log_separator();

        log_write(L"--- Check 1: Overlay Windows ---");
        check_overlay_windows();

        log_write(L"--- Check 2: Injected / Unsigned DLLs ---");
        check_injected_dlls();

        log_write(L"--- Check 3: Global Hook Injection (explorer/dwm/winlogon) ---");
        check_global_hooks();

        log_write(L"--- Check 4: Private Executable Memory Regions (shellcode) ---");
        check_rwx_memory();

        log_write(L"--- Check 5: Unexpected UI Automation Clients ---");
        check_uia_clients();

        log_separator();
        log_write(L"Cycle #%lu complete. Waiting %d ms...", cycle, POLL_INTERVAL_MS);
        log_separator();
        log_write(L"");

        Sleep(POLL_INTERVAL_MS);
    }

    if (g_log) fclose(g_log);
    return 0;
}
