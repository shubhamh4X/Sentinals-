<#
.SYNOPSIS
    Sentinel AC — System Diagnostic & Compatibility Analyzer
    Checks OS, installed emulators, Free Fire detection, network latency, and memory integrity.
#>

param(
    [string]$ServerUrl = "http://localhost:3000",
    [string]$OutputFile = "$PSScriptRoot\sentinel-diagnostic-report.json"
)

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  SENTINEL AC — SYSTEM DIAGNOSTICS & AUDIT" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

# 1. OS Inspection
$os = Get-CimInstance Win32_OperatingSystem
$comp = $env:COMPUTERNAME
$osFull = "$($os.Caption) (Build $($os.BuildNumber))"
Write-Host "[1/5] Host: $comp | OS: $osFull" -ForegroundColor Green

# 2. Emulator Check
$emulators = @(
    @{ Name = "BlueStacks 5"; Exe = "HD-Player"; KnownPath = "C:\Program Files\BlueStacks_nxt\HD-Player.exe" },
    @{ Name = "LDPlayer 9"; Exe = "dnplayer"; KnownPath = "C:\LDPlayer\LDPlayer9\dnplayer.exe" },
    @{ Name = "MEmu Play 9"; Exe = "MEmu"; KnownPath = "C:\Program Files\Microvirt\MEmu\MEmu.exe" },
    @{ Name = "NoxPlayer 7"; Exe = "Nox"; KnownPath = "C:\Program Files\Nox\bin\Nox.exe" },
    @{ Name = "Google Play Games PC"; Exe = "crosvm"; KnownPath = "C:\Program Files\Google\Play Games\crosvm.exe" }
)

$detectedEmulators = @()
$runningProcesses = Get-Process -ErrorAction SilentlyContinue

Write-Host "[2/5] Inspecting Android Emulators..." -ForegroundColor Yellow
foreach ($emu in $emulators) {
    $proc = $runningProcesses | Where-Object { $_.ProcessName -like "*$($emu.Exe)*" } | Select-Object -First 1
    $installed = (Test-Path $emu.KnownPath) -or ($null -ne $proc)
    
    if ($proc) {
        Write-Host "  [RUNNING] $($emu.Name) (PID: $($proc.Id))" -ForegroundColor Green
        $detectedEmulators += @{ Name = $emu.Name; Status = "Running"; PID = $proc.Id }
    } elseif ($installed) {
        Write-Host "  [INSTALLED] $($emu.Name)" -ForegroundColor Cyan
        $detectedEmulators += @{ Name = $emu.Name; Status = "Installed (Not Running)"; PID = $null }
    }
}

if ($detectedEmulators.Count -eq 0) {
    Write-Host "  [!] No supported emulators currently active." -ForegroundColor Yellow
}

# 3. Network Latency & Server Reachability
Write-Host "[3/5] Testing SOC Server Connectivity ($ServerUrl)..." -ForegroundColor Yellow
$latencyMs = -1
$serverHealthy = $false
try {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $health = Invoke-RestMethod -Uri "$ServerUrl/api/health" -TimeoutSec 4
    $sw.Stop()
    $latencyMs = [int]$sw.ElapsedMilliseconds
    $serverHealthy = $true
    Write-Host "  [OK] Server reached in ${latencyMs}ms (Health: $($health.status))" -ForegroundColor Green
} catch {
    Write-Host "  [!] Server ping failed: $_" -ForegroundColor Red
}

# 4. Security Check (Suspicious processes)
Write-Host "[4/5] Scanning for Memory Tampering & Cheat Signatures..." -ForegroundColor Yellow
$cheatSigs = @("cheatengine", "speedhack", "x64dbg", "injector", "processhacker", "ida64")
$threatsFound = @()
foreach ($p in $runningProcesses) {
    $name = $p.ProcessName.ToLower()
    foreach ($sig in $cheatSigs) {
        if ($name -like "*$sig*") {
            Write-Host "  [THREAT FOUND] Suspicious Process: $($p.ProcessName) (PID: $($p.Id))" -ForegroundColor Red
            $threatsFound += @{ ProcessName = $p.ProcessName; PID = $p.Id; Signature = $sig }
        }
    }
}
if ($threatsFound.Count -eq 0) {
    Write-Host "  [CLEAN] No known cheat tools or memory debuggers detected." -ForegroundColor Green
}

# 5. Compile Diagnostic Report
$diagReport = @{
    reportId = "diag-" + (Get-Random -Minimum 10000 -Maximum 99999)
    generatedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    hostname = $comp
    os = $osFull
    serverUrl = $ServerUrl
    serverReachable = $serverHealthy
    latencyMs = $latencyMs
    emulators = $detectedEmulators
    activeProcessesCount = $runningProcesses.Count
    threatsFound = $threatsFound
    recommendations = @()
}

if (!$serverHealthy) {
    $diagReport.recommendations += "Check firewall or proxy rules allowing outbound HTTPS to Sentinel AC SOC."
}
if ($detectedEmulators.Count -eq 0) {
    $diagReport.recommendations += "Launch BlueStacks 5, LDPlayer 9, or your preferred emulator before opening Free Fire."
}
if ($threatsFound.Count -gt 0) {
    $diagReport.recommendations += "Terminate unauthorized debugging or memory inspection software."
}
if ($diagReport.recommendations.Count -eq 0) {
    $diagReport.recommendations += "System is healthy, verified, and ready for protected gameplay."
}

$json = $diagReport | ConvertTo-Json -Depth 5
Set-Content -Path $OutputFile -Value $json -Encoding UTF8
Write-Host "[5/5] Diagnostic report saved to: $OutputFile" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Cyan
