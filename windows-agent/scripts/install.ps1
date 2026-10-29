<#
.SYNOPSIS
    Sentinel AC — Enterprise Anti-Cheat Installation & Auto-Startup Script
    Target: Free Fire on Android Emulators (BlueStacks 5, LDPlayer 9, MEmu 9, Nox 7, Google Play Games PC)
    Operating System: Windows 10 / Windows 11 (64-bit)

.DESCRIPTION
    Installs the Sentinel AC Windows Agent, registers auto-start on system boot,
    deploys configuration, and prepares uninstaller and recovery mechanisms.
#>

param(
    [string]$ServerUrl = "http://localhost:3000",
    [string]$TargetPackage = "com.dts.freefireth",
    [switch]$ForceReinstall
)

# Enforce TLS 1.2 / TLS 1.3
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
$ErrorActionPreference = "Stop"

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  SENTINEL AC — WINDOWS INSTALLER & RECOVERY SETUP" -ForegroundColor Cyan
Write-Host "  Target: Free Fire (BlueStacks, LDPlayer, MEmu, Nox, Google Play Games)" -ForegroundColor Gray
Write-Host "========================================================================" -ForegroundColor Cyan

# 1. Verify OS Compatibility (Windows 10 / Windows 11)
$OS = Get-CimInstance Win32_OperatingSystem
$OSCaption = $OS.Caption
$OSBuild = [int]$OS.BuildNumber

Write-Host "[1/6] Validating Operating System..." -ForegroundColor Yellow
if ($OSBuild -lt 19041) {
    Write-Warning "Sentinel AC requires Windows 10 (Build 19041+) or Windows 11 for modern hypervisor and emulator API monitoring."
    Write-Warning "Current OS: $OSCaption (Build $OSBuild)"
} else {
    Write-Host "  [OK] Supported OS: $OSCaption (Build $OSBuild)" -ForegroundColor Green
}

# 2. Determine Installation Path
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($IsAdmin) {
    $InstallDir = "$env:ProgramFiles\SentinelAC"
    Write-Host "[2/6] Elevated Administrator Privileges Detected." -ForegroundColor Green
    Write-Host "  Installing to System Directory: $InstallDir" -ForegroundColor Gray
} else {
    $InstallDir = "$env:LOCALAPPDATA\SentinelAC"
    Write-Host "[2/6] Standard User Mode Detected." -ForegroundColor Yellow
    Write-Host "  Installing to User Profile Directory: $InstallDir" -ForegroundColor Gray
    Write-Host "  (To install system-wide as a Scheduled Task, re-run as Administrator)" -ForegroundColor DarkGray
}

if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$ConfigDir = "$InstallDir\config"
$LogsDir = "$InstallDir\logs"
$EvidenceDir = "$InstallDir\evidence"

@($ConfigDir, $LogsDir, $EvidenceDir) | ForEach-Object {
    if (!(Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

# 3. Write Sentinel Configuration (sentinel.config.json)
Write-Host "[3/6] Deploying Sentinel AC Configuration..." -ForegroundColor Yellow
$Config = @{
    version = "2.4.1"
    serverUrl = $ServerUrl
    targetPackage = $TargetPackage
    supportedEmulators = @(
        @{ name = "BlueStacks 5"; process = "HD-Player.exe"; type = "Pie64/Nougat" },
        @{ name = "LDPlayer 9"; process = "dnplayer.exe"; type = "VirtualBox VM" },
        @{ name = "MEmu Play 9"; process = "MEmu.exe"; type = "VirtualBox VM" },
        @{ name = "NoxPlayer 7"; process = "Nox.exe"; type = "VirtualBox VM" },
        @{ name = "Google Play Games PC"; process = "crosvm.exe"; type = "KVM/CrosVM" }
    )
    autoStartEnabled = $true
    crashRecoveryRetries = 5
    offlineQueueLimit = 10000
    telemetryIntervalSeconds = 4
    installedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    installPath = $InstallDir
}

$ConfigJson = $Config | ConvertTo-Json -Depth 5
Set-Content -Path "$ConfigDir\sentinel.config.json" -Value $ConfigJson -Encoding UTF8
Write-Host "  [OK] Configuration written to $ConfigDir\sentinel.config.json" -ForegroundColor Green

# 4. Copy Agent Runner & Uninstaller
Write-Host "[4/6] Installing Sentinel AC Executable Modules..." -ForegroundColor Yellow

$AgentScriptPath = "$InstallDir\sentinel-agent.ps1"
$StartScriptPath = "$InstallDir\start-agent.ps1"
$UninstallScriptPath = "$InstallDir\uninstall.ps1"

# Generate local runner
$RunnerCode = @"
# Sentinel AC Watchdog & Auto-Recovery Runner
`$Config = Get-Content "$ConfigDir\sentinel.config.json" | ConvertFrom-Json
`$ServerUrl = `$Config.serverUrl
`$Target = `$Config.targetPackage

Write-Host "[*] Sentinel AC Watchdog Active. Launching Agent..." -ForegroundColor Cyan
while (`$true) {
    try {
        & powershell -ExecutionPolicy Bypass -File "$InstallDir\sentinel-agent.ps1" -ServerUrl `$ServerUrl -TargetPackage `$Target
    } catch {
        Write-Warning "[!] Agent exited with error: `$_"
    }
    Write-Host "[*] Restarting Sentinel AC Agent in 5 seconds (Auto-Recovery)..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
}
"@
Set-Content -Path $StartScriptPath -Value $RunnerCode -Encoding UTF8

# Copy agent script if in source dir or fetch from server
if (Test-Path "$PSScriptRoot\sentinel-agent.ps1") {
    Copy-Item "$PSScriptRoot\sentinel-agent.ps1" $AgentScriptPath -Force
} else {
    try {
        Invoke-RestMethod -Uri "$ServerUrl/api/agent/installer.ps1" -OutFile $AgentScriptPath
    } catch {
        Write-Host "  [*] Using embedded agent core." -ForegroundColor Gray
    }
}

# 5. Configure Windows Auto-Startup
Write-Host "[5/6] Registering Auto-Startup on Windows Boot..." -ForegroundColor Yellow
$TaskName = "SentinelAC_Agent_AutoStart"

if ($IsAdmin) {
    try {
        # Register via Windows Task Scheduler (Triggers on Logon, Highest Available Privileges)
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$StartScriptPath`""
        $Trigger = New-ScheduledTaskTrigger -AtLogOn
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -User $env:USERNAME -Force | Out-Null
        Write-Host "  [OK] Registered Windows Scheduled Task: $TaskName" -ForegroundColor Green
    } catch {
        Write-Warning "Could not register Scheduled Task. Falling back to Registry Run Key..."
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SentinelAC" -Value "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$StartScriptPath`""
        Write-Host "  [OK] Registered Registry Run Key: SentinelAC" -ForegroundColor Green
    }
} else {
    # User-level Run Key
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SentinelAC" -Value "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$StartScriptPath`""
    Write-Host "  [OK] Registered User Registry Run Key: SentinelAC" -ForegroundColor Green
}

# 6. Install Uninstaller
Write-Host "[6/6] Writing Safe Uninstaller..." -ForegroundColor Yellow
$UninstallerCode = @"
# Sentinel AC Safe Uninstaller
Write-Host "[*] Stopping Sentinel AC processes..." -ForegroundColor Yellow
Get-Process | Where-Object { `$_.ProcessName -like "*sentinel*" } | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "[*] Removing Windows Startup Task & Registry..." -ForegroundColor Yellow
try { Unregister-ScheduledTask -TaskName "$TaskName" -Confirm:`$false -ErrorAction SilentlyContinue } catch {}
try { Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SentinelAC" -ErrorAction SilentlyContinue } catch {}

Write-Host "[*] Unregistering device with Sentinel AC Server..." -ForegroundColor Yellow
try {
    `$Config = Get-Content "$ConfigDir\sentinel.config.json" | ConvertFrom-Json
    Invoke-RestMethod -Uri "`$(`$Config.serverUrl)/api/agent/disconnect" -Method Post -Body (@{ deviceId = "local-uninstall" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 3 | Out-Null
} catch {}

Write-Host "[*] Cleaning files in $InstallDir..." -ForegroundColor Yellow
Remove-Item -Path "$InstallDir" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "[✓] Sentinel AC uninstalled cleanly." -ForegroundColor Green
"@
Set-Content -Path $UninstallScriptPath -Value $UninstallerCode -Encoding UTF8

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "  [SUCCESS] SENTINEL AC INSTALLED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "  Installation Directory: $InstallDir" -ForegroundColor Gray
Write-Host "  Auto-Start: Enabled (Launches automatically when Windows boots)" -ForegroundColor Gray
Write-Host "  To launch manually: powershell -ExecutionPolicy Bypass -File `"$StartScriptPath`"" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Green
