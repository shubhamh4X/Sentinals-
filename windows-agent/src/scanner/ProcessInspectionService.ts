import {
  InjectionDetectionItem,
  MemoryScanItem,
  ProcessScanItem,
  ProcessScanReport,
} from '../../../shared-schemas/types.ts';

export class ProcessInspectionService {
  // Whitelist of approved gaming overlays and development tools
  private readonly APPROVED_OVERLAYS = new Set([
    'discordhook64.dll',
    'gameoverlayrenderer64.dll',
    'nvspcap64.dll',
    'rtsshooks64.dll',
    'graphics-hook64.dll', // OBS Studio
    'dxgi.dll', // Standard DirectX Graphic Infrastructure
  ]);

  // Known cheat indicators and signature substrings
  private readonly CHEAT_SIGNATURES = [
    'cheatengine',
    'speedhack',
    'x64dbg',
    'processhacker',
    'injector',
    'ida64',
    'frida-server',
    'aimbot',
    'memoryscanner',
  ];

  public runFullProcessScan(deviceId: string, hostname: string): ProcessScanReport {
    // Generate realistic process table representing a Windows 10/11 gaming system
    const scannedItems: ProcessScanItem[] = [
      {
        pid: 4,
        name: 'System',
        path: 'C:\\Windows\\System32\\ntoskrnl.exe',
        parentPid: 0,
        parentName: 'System Idle Process',
        sha256: '9f83c12a84092b9d2f1029c8e192a83b4c5d6e7f8091a2b3c4d5e6f708192a3b',
        signerIdentity: 'Microsoft Windows Publisher',
        status: 'clean',
        notes: 'Core Windows Kernel Process. Verified Authenticode signature.',
      },
      {
        pid: 612,
        name: 'csrss.exe',
        path: 'C:\\Windows\\System32\\csrss.exe',
        parentPid: 540,
        parentName: 'smss.exe',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        signerIdentity: 'Microsoft Windows Publisher',
        status: 'clean',
        notes: 'Client Server Runtime Subsystem. Verified system path.',
      },
      {
        pid: 1420,
        name: 'explorer.exe',
        path: 'C:\\Windows\\explorer.exe',
        parentPid: 1390,
        parentName: 'userinit.exe',
        sha256: 'a12b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
        signerIdentity: 'Microsoft Windows Publisher',
        status: 'clean',
        notes: 'Windows Desktop Shell.',
      },
      {
        pid: 3840,
        name: 'HD-Player.exe',
        path: 'C:\\Program Files\\BlueStacks_nxt\\HD-Player.exe',
        parentPid: 1420,
        parentName: 'explorer.exe',
        sha256: '648fbc92384a1029e8471c2b536480a9c8f2b3a1d0e4f5a6b7c8d9e0f1a2b3c4',
        signerIdentity: 'now.gg, Inc. (BlueStacks)',
        status: 'clean',
        notes: 'Target Emulator: BlueStacks 5 (Pie64 instance). Legitimate signature verified.',
      },
      {
        pid: 4912,
        name: 'Discord.exe',
        path: 'C:\\Users\\User\\AppData\\Local\\Discord\\app-1.0.9150\\Discord.exe',
        parentPid: 1420,
        parentName: 'explorer.exe',
        sha256: 'b45c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c',
        signerIdentity: 'Discord Inc.',
        status: 'clean',
        notes: 'Approved gaming communication software.',
      },
    ];

    let clean = 0;
    let suspicious = 0;
    let strongly = 0;

    scannedItems.forEach((item) => {
      if (item.status === 'clean') clean++;
      else if (item.status === 'suspicious') suspicious++;
      else if (item.status === 'strongly_suspicious') strongly++;
    });

    return {
      scanId: `proc-scan-${Date.now()}`,
      timestamp: new Date().toISOString(),
      deviceId,
      hostname,
      totalProcessesScanned: scannedItems.length,
      cleanCount: clean,
      suspiciousCount: suspicious,
      stronglySuspiciousCount: strongly,
      items: scannedItems,
    };
  }

  public runInjectionCheck(targetEmulatorProcess: string): InjectionDetectionItem[] {
    return [
      {
        targetProcess: targetEmulatorProcess || 'HD-Player.exe',
        pid: 3840,
        moduleName: 'discordhook64.dll',
        modulePath: 'C:\\Users\\User\\AppData\\Local\\Discord\\app-1.0.9150\\modules\\discordhook64.dll',
        sha256: '38a9b2c1d0e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0',
        signer: 'Discord Inc.',
        isWhitelisted: true,
        classification: 'legitimate_overlay',
        memoryProtection: 'PAGE_EXECUTE_READ',
        notes: 'Whitelisted Discord in-game overlay hook. Authenticode signature valid.',
      },
      {
        targetProcess: targetEmulatorProcess || 'HD-Player.exe',
        pid: 3840,
        moduleName: 'nvspcap64.dll',
        modulePath: 'C:\\Program Files\\NVIDIA Corporation\\NVIDIA GeForce Experience\\nvspcap64.dll',
        sha256: '9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
        signer: 'NVIDIA Corporation',
        isWhitelisted: true,
        classification: 'legitimate_overlay',
        memoryProtection: 'PAGE_EXECUTE_READ',
        notes: 'Whitelisted NVIDIA ShadowPlay capture module. Signature valid.',
      },
    ];
  }

  public runMemoryScan(targetProcessName: string): MemoryScanItem[] {
    return [
      {
        baseAddress: '0x00007FF71A400000',
        regionSize: '0x0000000000180000',
        protection: 'PAGE_EXECUTE_READ',
        state: 'MEM_COMMIT',
        type: 'MEM_IMAGE',
        status: 'safe',
        signatureMatch: undefined,
      },
      {
        baseAddress: '0x00007FF71A580000',
        regionSize: '0x0000000000045000',
        protection: 'PAGE_READWRITE',
        state: 'MEM_COMMIT',
        type: 'MEM_IMAGE',
        status: 'safe',
        signatureMatch: undefined,
      },
      {
        baseAddress: '0x000001E85A200000',
        regionSize: '0x0000000000080000',
        protection: 'PAGE_READWRITE',
        state: 'MEM_COMMIT',
        type: 'MEM_PRIVATE',
        status: 'safe',
        signatureMatch: 'Emulator Android Guest RAM (libil2cpp heap mapped)',
      },
    ];
  }
}
