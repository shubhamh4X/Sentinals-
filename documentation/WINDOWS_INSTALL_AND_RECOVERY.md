# Sentinel AC: Windows Installation, Startup & Disaster Recovery Guide

## 1. System Overview & Compatibility

Sentinel AC is a dedicated Windows Anti-Cheat monitoring platform designed specifically for **Free Fire** (`com.dts.freefireth` and `com.dts.freefiremax`) running inside Android emulators on Windows.

### Supported Operating Systems
- **Windows 11 (64-bit)**: Version 21H2, 22H2, 23H2, 24H2+ (All Editions)
- **Windows 10 (64-bit)**: Build 19041+ (Version 2004, 20H2, 21H1, 21H2, 22H2)
- **Architecture**: x86_64 / AMD64

### Supported Android Emulators
1. **BlueStacks 5**: Multi-instance Pie64, Android 11, Nougat 32/64 (`HD-Player.exe`)
2. **LDPlayer 9**: Android 9 64-bit kernel (`dnplayer.exe`, `LdVBoxHeadless.exe`)
3. **MEmu Play 9**: Android 9 64-bit (`MEmu.exe`, `MEmuHeadless.exe`)
4. **NoxPlayer 7**: Android 9/12 (`Nox.exe`, `NoxVMHandle.exe`)
5. **Google Play Games PC**: Google official virtualization platform (`crosvm.exe`)

---

## 2. Automatic Installation & Startup Configuration

### Step 1: Running the Installer
Open an elevated **Windows PowerShell** terminal (Run as Administrator) and navigate to the Sentinel AC folder, or run:
```powershell
powershell -ExecutionPolicy Bypass -File .\windows-agent\scripts\install.ps1 -ServerUrl "https://your-soc-dashboard.com"
```
Or simply double-click `launch.cmd`, which automatically requests UAC administrative elevation.

### What the Installer Configures:
1. **Directory Structure**: Installs all binaries and configs to `C:\Program Files\SentinelAC\` (or `%LOCALAPPDATA%\SentinelAC` if run without admin rights).
2. **Persistent Configuration**: Deploys `sentinel.config.json` recording server URLs, target game packages, and detection sensitivity.
3. **Automatic Startup (Windows Task Scheduler)**:
   - Task Name: `SentinelAC_Agent_AutoStart`
   - Trigger: At system logon for any active user.
   - Run Level: Highest Available Privileges (allows reading emulator handle tables and process tokens).
   - Resilience: Configured with `RestartCount 3` and `RestartInterval 1 min` in case of process termination.
4. **Watchdog Crash Recovery**: If the agent process encounters an unhandled exception, `start-agent.ps1` catches the fault, logs the stack trace, and safely recovers the agent in 4 seconds.

---

## 3. Recovery After a Clean Windows Reset

### What Happens During a Clean Windows Reset?
When a user performs a clean Windows reset (`Settings > System > Recovery > Reset this PC`), Windows reinstalls the OS and completely removes:
- `C:\Program Files\SentinelAC`
- Windows Task Scheduler registrations
- Windows Registry keys under `HKCU\Software` and `HKLM\Software`
- Non-default drivers and services

### The 60-Second Reinstallation Procedure:
Because Windows resets destroy local filesystem and registry state, no user-mode or kernel application can silently survive a full clean reset without hardware EFI persistence (which violates Windows security integrity).

To restore Sentinel AC immediately after resetting Windows:
1. Re-install your Android emulator of choice (e.g. BlueStacks 5 or LDPlayer 9) and download Free Fire.
2. Open Sentinel AC Dashboard in your web browser.
3. Navigate to **Connect My PC** or click **Setup Wizard**.
4. Click **Download Agent (.ps1)** or run the one-line setup command.
5. Sentinel AC will automatically reconstruct the configuration, register the startup task, and resume monitoring seamlessly.

---

## 4. Diagnostics & Troubleshooting

To inspect the agent status, emulator detection, and network latency at any time:
```powershell
powershell -ExecutionPolicy Bypass -File .\windows-agent\scripts\diagnostics.ps1
```
The script generates `sentinel-diagnostic-report.json` with comprehensive hardware, process, and network telemetry.

---

## 5. Security & Operational Boundaries

### Safe & Transparent Design:
- **No Windows Defender Tampering**: Sentinel AC never disables Windows Defender, modifies Secure Boot, or manipulates core OS protections.
- **Privacy Protection**: Sentinel AC monitors process integrity, module loading, and emulator memory. It never inspects personal files, passwords, browser history, or keystrokes.
- **Clean Uninstallation**: Running `uninstall.ps1` cleanly removes all tasks, registry entries, and agent files without leaving residual background services.
- **Architectural Boundary**: Sentinel AC operates user-mode telemetry and memory validation (`VirtualQueryEx`, Authenticode checks, handle verification). It clearly documents when low-level hypervisor or ring-0 cheats are beyond user-mode detection boundaries.
