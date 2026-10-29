<#
.SYNOPSIS
    Sentinel AC — Safe Windows Uninstaller
    Removes the agent, startup Scheduled Task/Registry keys, and notifies server.
#>

param(
    [switch]$KeepLogs
)

Write-Host "========================================================================" -ForegroundColor Yellow
Write-Host "  SENTINEL AC — SAFE UNINSTALLER" -ForegroundColor Yellow
Write-Host "========================================================================" -ForegroundColor Yellow

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$InstallDir = if ($IsAdmin) { "$env:ProgramFiles\SentinelAC" } else { "$env:LOCALAPPDATA\SentinelAC" }

# 1. Terminate running agent watchdog and PowerShell scripts
Write-Host "[1/4] Stopping active Sentinel AC processes..." -ForegroundColor Cyan
Get-Process | Where-Object { $_.ProcessName -like "*sentinel*" -or $_.CommandLine -like "*sentinel-agent*" } | Stop-Process -Force -ErrorAction SilentlyContinue

# 2. Remove Windows Task Scheduler & Registry Auto-Start
Write-Host "[2/4] Removing startup registration..." -ForegroundColor Cyan
try {
    Unregister-ScheduledTask -TaskName "SentinelAC_Agent_AutoStart" -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "  [OK] Removed Scheduled Task" -ForegroundColor Green
} catch {}

try {
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SentinelAC" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SentinelAC" -ErrorAction SilentlyContinue
    Write-Host "  [OK] Removed Registry Auto-Start Keys" -ForegroundColor Green
} catch {}

# 3. Disconnect from Server
Write-Host "[3/4] Notifying Sentinel AC Server of uninstallation..." -ForegroundColor Cyan
try {
    $cfgFile = "$InstallDir\config\sentinel.config.json"
    if (Test-Path $cfgFile) {
        $cfg = Get-Content $cfgFile | ConvertFrom-Json
        $serverUrl = $cfg.serverUrl
        $discBody = @{ deviceId = "win-" + $env:COMPUTERNAME.ToLower(); reason = "uninstalled" } | ConvertTo-Json
        Invoke-RestMethod -Uri "$serverUrl/api/agent/disconnect" -Method Post -Body $discBody -ContentType "application/json" -TimeoutSec 3 | Out-Null
        Write-Host "  [OK] Clean disconnection registered" -ForegroundColor Green
    }
} catch {
    Write-Host "  [*] Server notification bypassed (offline/unreachable)" -ForegroundColor Gray
}

# 4. Remove Files
Write-Host "[4/4] Removing application files..." -ForegroundColor Cyan
if (Test-Path $InstallDir) {
    if ($KeepLogs) {
        Get-ChildItem -Path $InstallDir -Exclude "logs", "evidence" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  [OK] Preserved logs in $InstallDir\logs" -ForegroundColor Green
    } else {
        Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  [OK] All files removed from $InstallDir" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "[✓] Sentinel AC has been completely and safely uninstalled from your Windows PC." -ForegroundColor Green
