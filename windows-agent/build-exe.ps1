# ==============================================================================
# Sentinel AC — Reproducible Windows EXE Builder Script (build-exe.ps1)
# Compiles SentinelAgent.cs into a standalone SentinelAgent.exe on Windows 10/11
# Uses the built-in Windows .NET Framework 64-bit C# compiler (no SDK install needed)
# or .NET 8 SDK if installed.
# ==============================================================================

param(
    [string]$ServerUrl = "http://localhost:3000",
    [string]$EnrollmentToken = "enr_sentinel_default_multi_pc",
    [switch]$LaunchAfterBuild
)

$ErrorActionPreference = "Stop"
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  SENTINEL AC — WINDOWS .EXE AGENT COMPILER (v2.6.0-win64)" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

$OutDir = Join-Path $PSScriptRoot "dist-win64"
if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

$SourceFile = Join-Path $PSScriptRoot "SentinelAgent.cs"
$OutputExe = Join-Path $OutDir "SentinelAgent.exe"

# Locate built-in Windows 10/11 64-bit C# compiler (csc.exe)
$CscPaths = @(
    "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
)

$CscExe = $null
foreach ($p in $CscPaths) {
    if (Test-Path $p) {
        $CscExe = $p
        break
    }
}

if ($CscExe) {
    Write-Host "[*] Found built-in Windows C# compiler: $CscExe" -ForegroundColor Green
    Write-Host "[*] Compiling $SourceFile -> $OutputExe ..." -ForegroundColor Yellow
    & $CscExe /nologo /optimize+ /target:exe /out:$OutputExe /r:System.Security.dll $SourceFile
    if ($LASTEXITCODE -eq 0 -and (Test-Path $OutputExe)) {
        $fileHash = (Get-FileHash -Path $OutputExe -Algorithm SHA256).Hash.ToLower()
        Write-Host "[✓] Successfully compiled standalone executable: $OutputExe" -ForegroundColor Green
        Write-Host "[✓] Binary SHA-256: $fileHash" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Run on any authorized Windows 10/11 PC:" -ForegroundColor White
        Write-Host "  .\dist-win64\SentinelAgent.exe --server `"$ServerUrl`" --enrollment-token `"$EnrollmentToken`"" -ForegroundColor Green
        Write-Host "Optional Startup Opt-In:" -ForegroundColor White
        Write-Host "  .\dist-win64\SentinelAgent.exe --server `"$ServerUrl`" --install-startup" -ForegroundColor Yellow
        Write-Host "Clean Uninstall:" -ForegroundColor White
        Write-Host "  .\dist-win64\SentinelAgent.exe --uninstall" -ForegroundColor Gray
    } else {
        throw "Compilation failed with exit code $LASTEXITCODE"
    }
} else {
    Write-Host "[*] Built-in Framework csc.exe not found; checking for dotnet SDK..." -ForegroundColor Yellow
    & dotnet publish (Join-Path $PSScriptRoot "SentinelAgent.csproj") -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o $OutDir
}

if ($LaunchAfterBuild -and (Test-Path $OutputExe)) {
    Write-Host ""
    Write-Host "[*] Launching SentinelAgent.exe..." -ForegroundColor Cyan
    & $OutputExe --server $ServerUrl --enrollment-token $EnrollmentToken
}
