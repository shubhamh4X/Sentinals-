# Sentinel AC — Security Architecture, Threat Model & Deployment Guide

## 1. Architectural Overview

Sentinel AC is a defensible, user-mode Windows anti-cheat security platform designed to monitor **Garena Free Fire** (`com.dts.freefireth` and `com.dts.freefiremax`) running inside Android emulators on Windows PCs.

### Core Design Tenets
1. **Least Privilege & OS Respect**: Runs as a standard Windows Service (`SentinelACService`) without disabling Windows Defender, Virtualization-Based Security (VBS), Hypervisor-Protected Code Integrity (HVCI), or Secure Boot.
2. **No Rootkits or Keyloggers**: Uses exclusively documented Win32 APIs (`CreateToolhelp32Snapshot`, `QueryFullProcessImageNameW`, `WinVerifyTrust`, `BCryptHash`, `NtQuerySystemInformation`, `EnumWindows`). Never dumps arbitrary user files, browser credentials, or keystrokes.
3. **Explainable Corroborated Risk Scoring**: Never claims that a single heuristic or unsigned file proves cheating. Combines multiple independent indicators into an explainable risk score (`0–100`) with explicit confidence ratings and false-positive guidance.

---

## 2. Documented Threat Model (STRIDE)

| Threat Vector | Adversary Goal | Mitigation in Sentinel AC | Residual Risk & Boundary |
| :--- | :--- | :--- | :--- |
| **1. Agent Impersonation** | Spoof a healthy heartbeat while running an unmonitored emulator. | Per-device credential fingerprint, mutual TLS / HMAC-SHA256 request signing, and server-side heartbeat sequence tracking. | If a local attacker extracts the DPAPI-protected device key via Administrator debug rights, host telemetry can be forged until key rotation. |
| **2. Event Forgery & Replay** | Replay old "clean" telemetry packets or flood the backend with malformed events. | Every telemetry packet requires a unique cryptographic `nonce`, strict ISO-8601 timestamp window, JSON Schema v1.2.0 validation, and server-side replay cache. | Clock skew > 60 seconds requires NTP resynchronization. |
| **3. Rule Tampering** | Modify local detection rules to disable `MEM-001` or `EMU-001`. | Detection rules are distributed as Ed25519 digitally signed bundles (`sig_ed25519_valid_*`) with SHA-256 payload digests. Backend re-evaluates raw indicators independently of the agent. | Local agent memory patching could suppress indicator collection; mitigated by agent self-integrity hash checks (`AGT-001`). |
| **4. Dashboard Compromise** | Unauthorized user dismisses confirmed incidents or disables rules. | Firebase Authentication + Zero-Trust Firestore Security Rules + Role-Based Access Control (`Administrator`, `Security Analyst`, `Read-Only Viewer`) + immutable append-only `auditLogs`. | Compromised Administrator OAuth session requires immediate token revocation. |
| **5. Kernel / DMA Cheats** | Use a kernel driver or PCIe DMA card to read guest VM memory outside Win32 user-mode visibility. | Explicitly documented as an architectural boundary. User-mode Win32 APIs cannot observe PCIe DMA or ring-0 `MmCopyVirtualMemory` calls. | Requires Microsoft WHQL attestation-signed ELAM/kernel driver + IOMMU enforcement + authoritative game-server telemetry correlation. |

---

## 3. Windows Agent Local Build & Service Installation

> **Important Note**: Browser-based cloud sandboxes run on Linux containers and cannot compile or install native Windows services (`SentinelAgentService.exe`). Use the following instructions on a Windows 10/11 x64 workstation with Visual Studio 2022 (MSVC v143) and .NET 8 SDK installed.

### A. Building the C++20 Service
```powershell
cd windows-agent
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

### B. Authenticode Signing (Production Requirement)
```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /n "Sentinel Security Corp" .\build\Release\SentinelAgentService.exe
```

### C. Installing & Starting the Windows Service
```powershell
# Run in an elevated PowerShell prompt:
sc.exe create SentinelACService binPath= "\"C:\Program Files\SentinelAC\SentinelAgentService.exe\" --service" start= demand DisplayName= "Sentinel AC Emulator Monitor"
sc.exe description SentinelACService "Monitors supported Android emulators during active Free Fire sessions."
sc.exe start SentinelACService
```

### D. Clean Removal
```powershell
sc.exe stop SentinelACService
sc.exe delete SentinelACService
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SentinelACMonitor" -ErrorAction SilentlyContinue
```

---

## 4. Secure Deployment Checklist

- [x] Enforce HTTPS / WSS in production (`Strict-Transport-Security`).
- [x] Verify Firestore Zero-Trust rules with `@firebase/eslint-plugin-security-rules` before every deployment.
- [x] Never trust agent-supplied severity or risk scores; compute risk scores server-side in `SentinelDetectionEngine`.
- [x] Require Ed25519 signature verification before applying rule updates.
- [x] Keep `events` and `auditLogs` append-only (`allow update, delete: if false`).
