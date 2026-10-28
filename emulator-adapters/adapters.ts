/**
 * Pluggable Android Emulator Adapters for Windows
 * Supports BlueStacks 5, LDPlayer 9, MEmu Play, NoxPlayer, and Google Play Games PC.
 */

export interface EmulatorProcessSignature {
  executableName: string;
  role: 'ui_host' | 'hypervisor_headless' | 'service_daemon' | 'adb_bridge';
  expectedSigner: string;
  defaultInstallDirs: string[];
}

export interface EmulatorAdapterConfig {
  adapterId: string;
  displayName: string;
  versionSupported: string;
  architecture: 'Hyper-V / VirtualBox' | 'KVM / Crosvm' | 'Custom VMM';
  processes: EmulatorProcessSignature[];
  freeFirePackages: string[];
  criticalAndroidPaths: string[];
  configFilesToWatch: string[];
  knownLimitations: string[];
}

export const SUPPORTED_EMULATOR_ADAPTERS: EmulatorAdapterConfig[] = [
  {
    adapterId: 'adapter-bluestacks-5',
    displayName: 'BlueStacks 5 (Nougat64 / Pie64 / Android 11)',
    versionSupported: '5.12.x - 5.22.x',
    architecture: 'Hyper-V / VirtualBox',
    processes: [
      {
        executableName: 'HD-Player.exe',
        role: 'ui_host',
        expectedSigner: 'BlueStack Systems, Inc.',
        defaultInstallDirs: ['C:\\Program Files\\BlueStacks_nxt\\'],
      },
      {
        executableName: 'BstkSVC.exe',
        role: 'service_daemon',
        expectedSigner: 'BlueStack Systems, Inc.',
        defaultInstallDirs: ['C:\\Program Files\\BlueStacks_nxt\\'],
      },
      {
        executableName: 'HD-Adb.exe',
        role: 'adb_bridge',
        expectedSigner: 'BlueStack Systems, Inc.',
        defaultInstallDirs: ['C:\\Program Files\\BlueStacks_nxt\\'],
      },
    ],
    freeFirePackages: ['com.dts.freefireth', 'com.dts.freefiremax'],
    criticalAndroidPaths: [
      '/data/app/com.dts.freefireth-1/lib/arm64/libil2cpp.so',
      '/data/app/com.dts.freefiremax-1/lib/arm64/libil2cpp.so',
      '/sdcard/Android/obb/com.dts.freefireth/main.2019119495.com.dts.freefireth.obb',
    ],
    configFilesToWatch: [
      'C:\\ProgramData\\BlueStacks_nxt\\bluestacks.conf',
      'C:\\ProgramData\\BlueStacks_nxt\\Engine\\Pie64\\Pie64.bstk',
    ],
    knownLimitations: [
      'Guest Android kernel memory inside VirtualBox/Hyper-V VMM is isolated from unprivileged host user-mode Win32 APIs unless inspected via authorized ADB integrity agent or hypervisor introspection.',
    ],
  },
  {
    adapterId: 'adapter-ldplayer-9',
    displayName: 'LDPlayer 9 (Android 9.0 x86_64)',
    versionSupported: '9.0.x - 9.1.x',
    architecture: 'Hyper-V / VirtualBox',
    processes: [
      {
        executableName: 'dnplayer.exe',
        role: 'ui_host',
        expectedSigner: 'Xuanxi International Limited',
        defaultInstallDirs: ['C:\\LDPlayer\\LDPlayer9\\'],
      },
      {
        executableName: 'LdVBoxHeadless.exe',
        role: 'hypervisor_headless',
        expectedSigner: 'Xuanxi International Limited',
        defaultInstallDirs: ['C:\\LDPlayer\\LDPlayer9\\vbox\\'],
      },
      {
        executableName: 'adb.exe',
        role: 'adb_bridge',
        expectedSigner: 'Google LLC',
        defaultInstallDirs: ['C:\\LDPlayer\\LDPlayer9\\'],
      },
    ],
    freeFirePackages: ['com.dts.freefireth', 'com.dts.freefiremax'],
    criticalAndroidPaths: [
      '/data/app/com.dts.freefireth/lib/x86_64/libil2cpp.so',
      '/sdcard/Android/data/com.dts.freefireth/files/contentcache/',
    ],
    configFilesToWatch: [
      'C:\\LDPlayer\\LDPlayer9\\vms\\config\\leidian0.config',
    ],
    knownLimitations: [
      'LDPlayer root toggle (enableRoot: 1 in leidian0.config) permits guest su daemon execution; Sentinel AC flags config file tampering immediately.',
    ],
  },
  {
    adapterId: 'adapter-memu-9',
    displayName: 'MEmu Play 9',
    versionSupported: '9.0.x+',
    architecture: 'Hyper-V / VirtualBox',
    processes: [
      {
        executableName: 'MEmu.exe',
        role: 'ui_host',
        expectedSigner: 'Microvirt Software Technology Co., Ltd.',
        defaultInstallDirs: ['C:\\Program Files\\Microvirt\\MEmu\\'],
      },
      {
        executableName: 'MEmuHeadless.exe',
        role: 'hypervisor_headless',
        expectedSigner: 'Microvirt Software Technology Co., Ltd.',
        defaultInstallDirs: ['C:\\Program Files\\Microvirt\\MEmuHyperv\\'],
      },
    ],
    freeFirePackages: ['com.dts.freefireth', 'com.dts.freefiremax'],
    criticalAndroidPaths: [
      '/data/app/com.dts.freefireth/lib/arm64/libil2cpp.so',
    ],
    configFilesToWatch: [
      'C:\\Program Files\\Microvirt\\MEmu\\MemuHyperv VMs\\MEmu\\MEmu.memu',
    ],
    knownLimitations: [
      'Shared folder mounts between Windows host and Android guest can stage modified OBB metadata if host folder watcher is bypassed.',
    ],
  },
  {
    adapterId: 'adapter-nox-7',
    displayName: 'NoxPlayer 7',
    versionSupported: '7.0.5.x+',
    architecture: 'Hyper-V / VirtualBox',
    processes: [
      {
        executableName: 'Nox.exe',
        role: 'ui_host',
        expectedSigner: 'Duodian Technology Co., Ltd.',
        defaultInstallDirs: ['C:\\Program Files (x86)\\Nox\\bin\\'],
      },
      {
        executableName: 'NoxVMHandle.exe',
        role: 'hypervisor_headless',
        expectedSigner: 'Duodian Technology Co., Ltd.',
        defaultInstallDirs: ['C:\\Program Files\\BigNox\\BigNoxVM\\RT\\'],
      },
    ],
    freeFirePackages: ['com.dts.freefireth', 'com.dts.freefiremax'],
    criticalAndroidPaths: [
      '/data/app/com.dts.freefireth/lib/arm/libil2cpp.so',
    ],
    configFilesToWatch: [
      'C:\\Users\\Public\\Nox_share\\conf.ini',
    ],
    knownLimitations: [
      'Built-in macro recorder scripts inside Nox UI host require correlating input interval variance with server-side telemetry.',
    ],
  },
  {
    adapterId: 'adapter-google-play-games',
    displayName: 'Google Play Games on PC',
    versionSupported: '24.x+',
    architecture: 'KVM / Crosvm',
    processes: [
      {
        executableName: 'crosvm.exe',
        role: 'hypervisor_headless',
        expectedSigner: 'Google LLC',
        defaultInstallDirs: ['C:\\Program Files\\Google\\Play Games\\current\\emulator\\'],
      },
      {
        executableName: 'Service.exe',
        role: 'service_daemon',
        expectedSigner: 'Google LLC',
        defaultInstallDirs: ['C:\\Program Files\\Google\\Play Games\\'],
      },
    ],
    freeFirePackages: ['com.dts.freefireth', 'com.dts.freefiremax'],
    criticalAndroidPaths: [
      '/data/app/com.dts.freefiremax/lib/x86_64/libil2cpp.so',
    ],
    configFilesToWatch: [
      'C:\\Program Files\\Google\\Play Games\\current\\emulator\\avd.cfg',
    ],
    knownLimitations: [
      'Hyper-V isolated crosvm container blocks direct guest filesystem inspection; relies on Windows host process/handle/overlay telemetry.',
    ],
  },
];

export interface DetectionCapabilityBoundary {
  capability: string;
  category: string;
  supportStatus: 'SUPPORTED_WINDOWS_USERMODE' | 'REQUIRES_SIGNED_KERNEL_DRIVER' | 'REQUIRES_GAME_SERVER_TELEMETRY';
  verificationMethod: string;
  architecturalLimitation: string;
}

export const DETECTION_CAPABILITY_BOUNDARIES: DetectionCapabilityBoundary[] = [
  {
    capability: 'Emulator Process Discovery & Authenticode Verification',
    category: 'Process & Executable Integrity',
    supportStatus: 'SUPPORTED_WINDOWS_USERMODE',
    verificationMethod: 'CreateToolhelp32Snapshot + QueryFullProcessImageNameW + WinVerifyTrust + BCrypt SHA-256',
    architecturalLimitation: 'Verifies host executables and loaded user-mode DLLs; cannot inspect kernel-mode rootkits.',
  },
  {
    capability: 'Cross-Process Handle Access (PROCESS_VM_WRITE / VM_OPERATION)',
    category: 'Memory & Injection Indicators',
    supportStatus: 'SUPPORTED_WINDOWS_USERMODE',
    verificationMethod: 'NtQuerySystemInformation(SystemExtendedHandleInformation) & VirtualQueryEx',
    architecturalLimitation: 'Detects user-mode external memory editors (e.g., Cheat Engine, custom RPM/WPM injectors). Kernel-mode DMA or ObRegisterCallbacks stripping requires a signed ELAM/kernel driver.',
  },
  {
    capability: 'Transparent Topmost ESP Overlay Window Detection',
    category: 'ESP & Gameplay Manipulation',
    supportStatus: 'SUPPORTED_WINDOWS_USERMODE',
    verificationMethod: 'EnumWindows + GetWindowLongPtr(GWL_EXSTYLE) checking WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST overlapping emulator viewport',
    architecturalLimitation: 'Legitimate overlays (Discord, GeForce Experience, RivaTuner) also use layered windows and must be filtered via Authenticode signer allowlists. DWM kernel composition hooks cannot be seen from user-mode.',
  },
  {
    capability: 'Emulator Config & Free Fire OBB / libil2cpp.so Asset Tampering',
    category: 'Emulator Integrity',
    supportStatus: 'SUPPORTED_WINDOWS_USERMODE',
    verificationMethod: 'ReadDirectoryChangesW on host VMDK/conf files + authorized ADB SHA-256 manifest verification',
    architecturalLimitation: 'If ADB debugging is disabled or blocked by hypervisor isolation, guest Android file hashes must be verified by the in-game SDK.',
  },
  {
    capability: 'Hardware DMA / PCIe Bus Memory Reading & Kernel Driver Cheats',
    category: 'Memory & Injection Indicators',
    supportStatus: 'REQUIRES_SIGNED_KERNEL_DRIVER',
    verificationMethod: 'Not claimed in user-mode agent. Requires Microsoft WHQL attestation-signed kernel driver + IOMMU/VT-d enforcement.',
    architecturalLimitation: 'Sentinel AC strictly avoids unsafe unsigned kernel drivers or rootkit techniques. Kernel telemetry is documented as an architectural boundary.',
  },
  {
    capability: 'Silent Aimbot Angle Snap, No-Recoil Packet Manipulation & Speed Hacks',
    category: 'ESP & Gameplay Manipulation',
    supportStatus: 'REQUIRES_GAME_SERVER_TELEMETRY',
    verificationMethod: 'Requires Garena Free Fire authoritative server tick/angle/velocity telemetry correlation.',
    architecturalLimitation: 'Windows process monitoring alone cannot prove aimbot math or recoil suppression if performed via external HID mouse emulation without host memory writes.',
  },
];
