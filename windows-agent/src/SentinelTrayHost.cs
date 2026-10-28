// ============================================================================
// Sentinel AC — Windows Service Controller & Tray Companion (C# / .NET 8)
// File: windows-agent/src/SentinelTrayHost.cs
//
// Responsibilities:
// - Manages Windows auto-start registration via HKCU\...\Run or SCM
// - Coordinates clean service startup/shutdown for SentinelACService
// - Displays transparent monitoring state to the local player (no stealth/rootkit)
// - Executes signed rule bundle verification before hot-reloading agent rules
// ============================================================================

using System;
using System.IO;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace SentinelAC.Host
{
    public sealed class StartupRegistrationManager
    {
        private const string RunRegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string AppRegistryValueName = "SentinelACMonitor";

        public static bool IsAutoStartEnabled()
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunRegistryPath, writable: false);
            return key?.GetValue(AppRegistryValueName) != null;
        }

        public static void SetAutoStart(bool enabled, string executablePath)
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunRegistryPath, writable: true);
            if (key == null) return;

            if (enabled)
            {
                key.SetValue(AppRegistryValueName, $"\"{executablePath}\" --background-monitor");
            }
            else if (key.GetValue(AppRegistryValueName) != null)
            {
                key.DeleteValue(AppRegistryValueName, throwOnMissingValue: false);
            }
        }
    }

    public sealed class AgentSelfIntegrityVerifier
    {
        public static string ComputeExecutableSha256(string filePath)
        {
            using FileStream stream = File.OpenRead(filePath);
            using SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
    }
}
