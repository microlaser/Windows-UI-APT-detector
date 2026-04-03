UI Tamper Monitor (Windows) — v1.0 [PRE-RELEASE / UNTESTED]
⚠️ NOTICE: This code is currently UNTESTED.
This source was developed to detect specific state-level UI interference and parallel construction artifacts. During the initial deployment phase on a Windows VM, the host macOS system was remotely compromised and forced into a full reinstall to prevent the execution of this monitor. It is being released "as-is" for the research community to audit and verify.

🛡️ Overview
ui_tamper_monitor.c is a native C forensic tool designed to identify Advanced Persistent Threat (APT) activity targeting the Windows User Interface. Unlike traditional EDR, which focuses on kernel-level exploits, this tool monitors the Syntax of UI Trust—detecting the subtle "glass" layers and programmatic hooks used to manipulate user consent and intercept sensitive data.

Key Detection Vectors:
Layered Window Audit: Identifies WS_EX_LAYERED and WS_EX_TRANSPARENT windows used for clickjacking and UI redlining.

Reflective DLL Injection: Scans GUI processes for Private Executable (RWX) memory regions—a primary indicator of fileless, memory-resident surveillance tools.

UI Automation (UIA) Monitoring: Detects non-whitelisted processes utilizing the IUIAutomation interface to programmatically "read" or "click" UI elements.

Global Hook Detection: Audits explorer.exe and dwm.exe (Desktop Window Manager) for unauthorized third-party DLLs used to intercept system-wide input.

Signature Verification: Automatically checks the Authenticode status of DLLs loaded from suspicious or user-writable paths (e.g., %TEMP%, Appdata).

🚀 Build Instructions
This tool is written in Win32 C and has zero external dependencies beyond standard Windows system libraries.

Option 1: MinGW (cross-platform or native)
Bash
gcc -o ui_tamper_monitor.exe ui_tamper_monitor.c \
    -lpsapi -lole32 -loleaut32 -luiautomationcore \
    -lntdll -lshlwapi -ladvapi32 -luser32 -lgdi32 \
    -mwindows -Wall -O2
Option 2: MSVC (Visual Studio Developer Command Prompt)
DOS
cl ui_tamper_monitor.c /Fe:ui_tamper_monitor.exe \
   psapi.lib ole32.lib oleaut32.lib shlwapi.lib \
   advapi32.lib user32.lib gdi32.lib ntdll.lib
📋 Usage
Run as Administrator: Full process memory access and TCC/UIA auditing require elevated privileges.

Log Output: The tool creates a ui_tamper_log.txt in the execution directory.

Forensic Analysis: Look for REPEATED entries across scan cycles. Modern APT tools often attempt to re-inject or re-hook if a connection is dropped.

⚖️ Disclaimer
This tool is a forensic artifact released for educational and research purposes. Given the circumstances of its development, users should audit the source code before execution in a production environment.

Author: Michael Lazin

Status: Alpha / Forensic Release

License: MIT
