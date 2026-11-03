# Detecting Renamed System Binaries with Sysmon (MITRE ATT&CK T1036.003)

Detecting masquerading, where an attacker copies a trusted Windows binary and runs it under a different name, using Sysmon's `OriginalFileName` field. Individual project for a Seneca Polytechnic threat management course, June 2026.

## The technique

**T1036.003, Masquerading: Rename System Utilities.** Attackers copy legitimate tools such as `cmd.exe` or `powershell.exe` and rename them, either to look like a system process or to slip past rules that match on process name.

## Why `OriginalFileName` is the signal

Renaming a file changes its name on disk, but not the name compiled into the file's version information. Sysmon Event ID 1 (process creation) records both:

- **Image:** the path and name the process ran as
- **OriginalFileName:** the name stored inside the binary

When a known binary runs under a different name, the two disagree.

## Lab

- Windows 11 VM with Sysmon 15.21 and a custom configuration
- Atomic Red Team for repeatable attack simulation
- Event Viewer and PowerShell (`Get-WinEvent`) for analysis

## What I did

1. **Confirmed Sysmon logging.** Verified service start (Event 4), configuration load (Event 16) and process creation (Event 1). [Screenshot](screenshots/sysmon-logging.png)
2. **Simulated the attack by hand.** Copied `cmd.exe` to `C:\Windows\Temp\lsass.exe` and ran a harmless command through it. [Screenshot](screenshots/manual-simulation.png)
3. **Found the evidence.** Sysmon Event 1 recorded Image `C:\Windows\Temp\lsass.exe` with OriginalFileName `Cmd.Exe` and description "Windows Command Processor": a command shell posing as a critical system process. [Screenshot](screenshots/event1-evidence.png)
4. **Repeated it with Atomic Red Team.** Ran test T1036.003-1, "Masquerading as Windows LSASS process," which copied `cmd.exe` and launched it as `lsass.exe`. The test reached its 20-second timeout because the renamed shell waited for input. [Screenshot](screenshots/atomic-red-team-test.png)
5. **Cleaned up and verified.** Ran the Atomic cleanup, deleted leftover copies, removed the temporary Microsoft Defender exclusion and confirmed none remained. [Atomic cleanup](screenshots/atomic-cleanup.png) · [Verification](screenshots/cleanup-verified.png)

## Detection logic

Alert on Sysmon Event ID 1 when either condition is true:

| Condition | Example from this lab |
|---|---|
| A commonly abused binary runs under a different name: OriginalFileName is on a watchlist (`cmd.exe`, `powershell.exe`, `rundll32.exe`, `mshta.exe`, `wscript.exe`, `cscript.exe`, `certutil.exe`) and the Image file name does not match | OriginalFileName `Cmd.Exe`, Image `...\lsass.exe` |
| A critical system process name runs from the wrong location: Image file name is `lsass.exe` and the path is not `C:\Windows\System32` | `C:\Windows\Temp\lsass.exe` |

Compare names case-insensitively: Sysmon recorded `Cmd.Exe`, not `cmd.exe`.

## Tuning: why not alert on every mismatch

A simple "file name differs from OriginalFileName" rule is noisy, and this lab's own logs show why:

- **False positives:** the legitimate Windows process `unsecapp.exe` reports OriginalFileName `unsecapp.dll`. ([Screenshot](screenshots/sysmon-logging.png), first event)
- **Blind spots:** some binaries have no OriginalFileName at all. `Sysmon64.exe` shows `-`. A renamed executable without version information would never trigger a mismatch rule.

Scoping the first condition to a watchlist of commonly abused binaries keeps alerts meaningful. The location condition covers renamed executables that the watchlist misses.

## What I would add

- **Detect the setup step too.** To run the test, I added a Defender exclusion with `Add-MpPreference -ExclusionPath`. Attackers do the same (T1562.001, Impair Defenses), so in production that command deserves its own alert.
- **Measure coverage.** Run the other T1036.003 Atomic tests listed in the screenshot, such as PowerShell running as `taskhostw.exe` or a non-Windows executable named as a Windows one.
- **Move it to a SIEM.** Next step: implement this logic as a KQL analytics rule in Microsoft Sentinel (November 2026).

## Safety

All testing ran in an isolated lab VM with harmless commands only. Every test artifact was removed and the Defender setting restored afterward.
