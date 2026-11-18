# windows-security-check

A small **read-only** PowerShell script that reviews the basic security of a Windows computer and gives a clear report, on screen and as an HTML file.

I built it to practise what a security team looks at first on a Windows endpoint: is Microsoft Defender working, is the firewall on, is the system patched, who has admin rights, and what the event logs say about failed sign-ins and critical errors.

## What it checks

| # | Check | How | WARN when |
|---|-------|-----|-----------|
| 1 | Microsoft Defender | `Get-MpComputerStatus` | Antivirus or real-time protection is off, or signatures are older than 3 days |
| 2 | Windows Firewall | `Get-NetFirewallProfile` | Any profile (Domain, Private, Public) is off |
| 3 | Windows Update | `Get-HotFix` | Last update is older than 30 days |
| 4 | Local administrators | `Get-LocalGroupMember -SID S-1-5-32-544` | Built-in Administrator is enabled, or more than 2 admins |
| 5 | Guest account | `Get-LocalUser` (SID ending in `-501`) | Guest is enabled |
| 6 | Failed sign-ins | `Get-WinEvent`, Security log, **event 4625** | 10 or more failed sign-ins in the period |
| 7 | Critical and error events | `Get-WinEvent`, System + Application logs, **levels 1 and 2** | Any critical event (for example, Kernel-Power 41: unexpected shutdown) |

Each result is marked as `[OK]`, `[WARN]`, `[INFO]` or `[SKIP]`. If one check fails, the script carries on with the others.

Groups and accounts are found by their **SID**, not by name, so it works on any Windows language (for example, the Administrators group is called *Administradores* in Spanish).

## Usage

Open PowerShell **as administrator** (needed for check 6) and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\windows-security-check.ps1
```

Options:

```powershell
# Look at the last 3 days instead of 7
.\windows-security-check.ps1 -Days 3

# Choose where to save the HTML report
.\windows-security-check.ps1 -ReportPath C:\Temp\report.html
```

Without administrator rights it still works; check 6 is just marked as `[SKIP]`.

## Example output

Illustrative example (values will be different on your computer):

```text
Windows security check - DESKTOP-EXAMPLE - 2026-11-18 17:05

[OK  ] Microsoft Defender: Defender is on and up to date.
       - Antivirus enabled: True
       - Real-time protection: True
       - Signature age: 0 day(s) (version 1.441.212.0)
[OK  ] Windows Firewall: Firewall is on in all profiles.
       - Domain: True
       - Private: True
       - Public: True
[OK  ] Windows Update: Last update was installed 6 day(s) ago (KB5070001).
[INFO] Local administrators: 2 admin account(s).
       - DESKTOP-EXAMPLE\Administrator (User, Local)
       - DESKTOP-EXAMPLE\student (User, Local)
[OK  ] Guest account: The Guest account ('Guest') is disabled.
[WARN] Failed sign-ins: 14 failed sign-ins in 7 day(s). Someone may be guessing passwords.
       - 12 attempt(s) - user/IP: admin, 192.0.2.25
       - 2 attempt(s) - user/IP: student, -
[WARN] Critical and error events: 1 critical and 23 error event(s) in 7 day(s).
       - CRITICAL 2026-11-16 22:41 - Microsoft-Windows-Kernel-Power (ID 41) - The system has rebooted without cleanly shutting down first...
       - Most frequent: 9x System / Service Control Manager (ID 7000)

Summary: 4 OK, 2 warning(s), 7 checks.
HTML report saved to: C:\Users\student\security-report-DESKTOP-EXAMPLE-2026-11-18.html
```

## Requirements

- Windows 10 or 11
- Windows PowerShell 5.1 (included in Windows) or PowerShell 7
- No extra modules

## Design notes

- **Read-only:** it never changes a setting, so it is safe to run on any machine.
- **Clear limits:** the thresholds (3 days, 30 days, 2 admins, 10 failed sign-ins) are at the top of the script and easy to change.
- **Reports stay local:** the HTML report contains computer and user names, so `.gitignore` keeps it out of the repository.

## Ideas for next steps

- Send the results to **Microsoft Sentinel** (Log Analytics) to watch many computers from one place.
- Add checks for BitLocker, SMBv1 and the Windows Update service.
- Compare the results with the CIS Benchmark for Windows.

## License

[MIT](LICENSE)
