<#
.SYNOPSIS
    Sentinel AC — Standalone Agent Runner & Watchdog
    Monitors Free Fire on BlueStacks 5, LDPlayer 9, MEmu 9, Nox 7, and Google Play Games PC.
#>

param(
    [string]$ServerUrl = "http://localhost:3000",
    [string]$TargetPackage = "com.dts.freefireth"
)

# Enforce TLS 1.2 / TLS 1.3
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
$ErrorActionPreference = "Continue"

$ConfigPath = "$PSScriptRoot\..\config\sentinel.config.json"
if (Test-Path $ConfigPath) {
    try {
        $cfg = Get-Content $ConfigPath | ConvertFrom-Json
        if ($cfg.serverUrl) { $ServerUrl = $cfg.serverUrl }
        if ($cfg.targetPackage) { $TargetPackage = $cfg.targetPackage }
    } catch {}
}

# Auto upgrade http to https for remote domains
if ($ServerUrl -match "^http://" -and $ServerUrl -notmatch "localhost|127\.0\.0\.1") {
    $ServerUrl = $ServerUrl -replace "^http://", "https://"
}

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  SENTINEL AC — AGENT LAUNCHER & WATCHDOG" -ForegroundColor Cyan
Write-Host "  Server: $ServerUrl | Target: $TargetPackage" -ForegroundColor Gray
Write-Host "========================================================================" -ForegroundColor Cyan

$AgentScript = "$PSScriptRoot\sentinel-agent.ps1"
if (!(Test-Path $AgentScript)) {
    $AgentScript = "$PSScriptRoot\..\sentinel-agent.ps1"
}

if (!(Test-Path $AgentScript)) {
    Write-Host "[*] Downloading latest signed agent script from SOC Server..." -ForegroundColor Yellow
    try {
        Invoke-RestMethod -Uri "$ServerUrl/api/agent/installer.ps1" -OutFile "$PSScriptRoot\sentinel-agent.ps1"
        $AgentScript = "$PSScriptRoot\sentinel-agent.ps1"
    } catch {
        Write-Error "Could not locate or download sentinel-agent.ps1"
        exit 1
    }
}

# Watchdog loop
$crashCount = 0
while ($true) {
    Write-Host "[*] Executing Sentinel AC Monitoring Core..." -ForegroundColor Cyan
    & powershell -ExecutionPolicy Bypass -File $AgentScript -ServerUrl $ServerUrl -TargetPackage $TargetPackage
    
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) {
        Write-Host "[*] Agent terminated normally." -ForegroundColor Gray
        break
    } else {
        $crashCount++
        Write-Warning "[!] Sentinel AC Agent stopped with exit code $exitCode (Crash Count: $crashCount)"
        Write-Host "[*] Recovering in 4 seconds..." -ForegroundColor Yellow
        Start-Sleep -Seconds 4
    }
}
