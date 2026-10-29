@echo off
:: ============================================================================
:: Sentinel AC — Windows Launcher (Batch Elevation & PowerShell Bootstrap)
:: ============================================================================
title Sentinel AC — Launcher
setlocal EnableDelayedExpansion

echo ========================================================================
echo   SENTINEL AC — WINDOWS ANTI-CHEAT LAUNCHER
echo ========================================================================
echo.

:: Check for administrative rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Requesting Administrator Elevation...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

echo [*] Elevated session confirmed.
echo [*] Launching Sentinel AC Watchdog...
echo.

if exist "start-agent.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "start-agent.ps1"
) else if exist "install.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "install.ps1"
) else (
    echo [!] Could not locate start-agent.ps1 or install.ps1.
    pause
)

endlocal
