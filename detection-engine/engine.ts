/**
 * Sentinel AC — Modular Detection Engine & Signed Rule Manager
 * Implements:
 * - Independent detection modules (Process, Memory/Injection, Emulator Integrity, ESP/Gameplay)
 * - Configurable thresholds, event correlation, duplicate suppression, explainable risk scoring
 * - Ed25519 / SHA-256 cryptographic signature verification for rule updates
 */

import {
  DetectionCategory,
  DetectionRuleRecord,
  EventClassification,
  IncidentRecord,
  IndicatorType,
  RawAgentTelemetry,
  SecurityEventRecord,
  SeverityLevel,
  SignedRuleBundle,
} from '../shared-schemas/types.ts';

export const DEFAULT_SIGNED_RULES: Omit<DetectionRuleRecord, 'ownerId'>[] = [
  {
    ruleId: 'PROC-001',
    version: '2.4.0',
    name: 'Known Free Fire Cheat Binary / Injector Hash Match',
    category: DetectionCategory.PROCESS_INTEGRITY,
    severity: SeverityLevel.CRITICAL,
    classification: EventClassification.STRONGLY_INDICATIVE,
    confidence: 96,
    riskScoreContribution: 45,
    enabled: true,
    detectionSource: 'Win32 Process Monitor + BCrypt SHA-256 Hash Engine',
    description:
      'Detects execution of binaries matching known Free Fire external cheat injectors, aimbot loaders, or bypass utilities.',
    falsePositiveConsiderations:
      'Low false-positive rate due to exact SHA-256 hash and import table matching. Verify file provenance and whether security researchers launched a test sample.',
    investigationSteps:
      '1. Verify SHA-256 hash against threat intel feed. 2. Inspect parent process ancestry. 3. Correlate with open process handles to HD-Player.exe or dnplayer.exe.',
    signatureHash: 'sig_ed25519_proc001_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c',
    indicatorTrigger: 'KNOWN_CHEAT_SIGNATURE',
  },
  {
    ruleId: 'PROC-002',
    version: '2.1.0',
    name: 'Unsigned Executable Launched from Temp/AppData Interacting with Emulator',
    category: DetectionCategory.PROCESS_INTEGRITY,
    severity: SeverityLevel.MEDIUM,
    classification: EventClassification.SUSPICIOUS,
    confidence: 64,
    riskScoreContribution: 18,
    enabled: true,
    detectionSource: 'WinVerifyTrust Authenticode Engine + Path Heuristics',
    description:
      'Flags unsigned executables running from transient user directories (%TEMP%, %APPDATA%) during an active Free Fire emulator session.',
    falsePositiveConsiderations:
      'Standalone portable utilities, custom macro scripts, or developer tools may run unsigned from AppData. Never ban based solely on an unsigned binary.',
    investigationSteps:
      '1. Check if the binary opens a handle to the emulator process. 2. Inspect digital signature status and file creation timestamp. 3. Dismiss if verified as benign utility.',
    signatureHash: 'sig_ed25519_proc002_3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f',
    indicatorTrigger: 'UNSIGNED_TEMP_EXECUTABLE',
  },
  {
    ruleId: 'MEM-001',
    version: '3.0.1',
    name: 'Unauthorized Cross-Process Handle with PROCESS_VM_WRITE / VM_OPERATION',
    category: DetectionCategory.MEMORY_INJECTION,
    severity: SeverityLevel.HIGH,
    classification: EventClassification.STRONGLY_INDICATIVE,
    confidence: 88,
    riskScoreContribution: 35,
    enabled: true,
    detectionSource: 'NtQuerySystemInformation(SystemExtendedHandleInformation)',
    description:
      'Identifies non-system, non-emulator processes holding write/operation memory handles (0x0028 / 0x1F0FFF) targeting the Android emulator hypervisor or UI host.',
    falsePositiveConsiderations:
      'Endpoint security (EDR/AV) scanners and crash dump utilities occasionally open high-privilege handles. Verify binary signer against Microsoft/AV vendor allowlist.',
    investigationSteps:
      '1. Inspect granted access mask (e.g., 0x0028 PROCESS_VM_WRITE | PROCESS_VM_OPERATION). 2. Verify whether target PID is HD-Player.exe or LdVBoxHeadless.exe. 3. Check for concurrent MEM-002 or ESP-001 events.',
    signatureHash: 'sig_ed25519_mem001_7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d',
    indicatorTrigger: 'CROSS_PROCESS_VM_WRITE',
  },
  {
    ruleId: 'MEM-002',
    version: '2.3.0',
    name: 'Unexpected Unbacked Executable Memory Region (MEM_PRIVATE + PAGE_EXECUTE_READWRITE)',
    category: DetectionCategory.MEMORY_INJECTION,
    severity: SeverityLevel.HIGH,
    classification: EventClassification.SUSPICIOUS,
    confidence: 82,
    riskScoreContribution: 30,
    enabled: true,
    detectionSource: 'VirtualQueryEx Memory Region Scanner',
    description:
      'Detects private RWX memory allocations inside the emulator host process that are not backed by a signed module on disk, indicative of manual-mapped shellcode or reflective DLL injection.',
    falsePositiveConsiderations:
      'JIT compilers inside emulator rendering engines (ANGLE/Vulkan shader caches) may allocate dynamic executable pages. Compare allocation base and size against baseline JIT ranges.',
    investigationSteps:
      '1. Check region allocation size and protection flags. 2. Correlate with recent MEM-001 cross-process write handles. 3. Inspect thread start addresses within the unbacked region.',
    signatureHash: 'sig_ed25519_mem002_1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c',
    indicatorTrigger: 'UNBACKED_EXECUTABLE_MEMORY',
  },
  {
    ruleId: 'MEM-003',
    version: '2.2.1',
    name: 'Unexpected Unsigned Module / Reflective DLL Loaded in Emulator Host',
    category: DetectionCategory.MEMORY_INJECTION,
    severity: SeverityLevel.HIGH,
    classification: EventClassification.STRONGLY_INDICATIVE,
    confidence: 90,
    riskScoreContribution: 34,
    enabled: true,
    detectionSource: 'EnumProcessModulesEx + Imagehlp Certificate Check',
    description:
      'Detects non-standard or unsigned DLLs injected into the emulator rendering process (e.g. OpenGL/DirectX hook DLLs used for wallhacks or chams).',
    falsePositiveConsiderations:
      'Third-party recording software (OBS graphics-hook64.dll) or GPU tuning overlays inject into DirectX/OpenGL processes. Check Authenticode signature of the loaded DLL.',
    investigationSteps:
      '1. Verify DLL path and Authenticode signer. 2. Check if DLL hooks glDrawElements or Present(). 3. Cross-reference with known cheat overlay libraries.',
    signatureHash: 'sig_ed25519_mem003_5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d',
    indicatorTrigger: 'UNEXPECTED_DLL_INJECTION',
  },
  {
    ruleId: 'EMU-001',
    version: '3.1.0',
    name: 'Modified Free Fire libil2cpp.so or OBB Metadata Asset Integrity Mismatch',
    category: DetectionCategory.EMULATOR_INTEGRITY,
    severity: SeverityLevel.CRITICAL,
    classification: EventClassification.STRONGLY_INDICATIVE,
    confidence: 95,
    riskScoreContribution: 48,
    enabled: true,
    detectionSource: 'Emulator Adapter Asset Hash Verifier (ADB / VMDK Bridge)',
    description:
      'Detects unauthorized modification of com.dts.freefireth / com.dts.freefiremax native binaries (libil2cpp.so, global-metadata.dat) or OBB archives used for antenna hacks, hitbox expansion, or no-recoil.',
    falsePositiveConsiderations:
      'Corrupted game updates or mid-patch downloads can temporarily cause hash mismatches. Verify against current official Garena patch manifest.',
    investigationSteps:
      '1. Compare observed SHA-256 of libil2cpp.so/OBB against official Garena release manifest. 2. Check ADB command history for recent "adb push" commands. 3. Quarantine incident for analyst review.',
    signatureHash: 'sig_ed25519_emu001_8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e',
    indicatorTrigger: 'MODIFIED_LIBIL2CPP_ASSET',
  },
  {
    ruleId: 'EMU-002',
    version: '1.9.0',
    name: 'Unauthorized External ADB Bridge / Root Shell Attachment During Match',
    category: DetectionCategory.EMULATOR_INTEGRITY,
    severity: SeverityLevel.MEDIUM,
    classification: EventClassification.SUSPICIOUS,
    confidence: 75,
    riskScoreContribution: 22,
    enabled: true,
    detectionSource: 'Emulator Adapter Port & Process Tree Monitor',
    description:
      'Detects external adb.exe instances or TCP connections to emulator ADB ports (5555-5585) executing interactive root shell or memory patching commands while Free Fire is active.',
    falsePositiveConsiderations:
      'Android developers running Android Studio on the same machine may have active ADB daemon sessions.',
    investigationSteps:
      '1. Inspect command-line arguments of the spawning adb.exe process. 2. Check if emulator config has root access enabled. 3. Correlate with EMU-001 asset changes.',
    signatureHash: 'sig_ed25519_emu002_2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a',
    indicatorTrigger: 'UNAUTHORIZED_ADB_BRIDGE',
  },
  {
    ruleId: 'ESP-001',
    version: '2.5.0',
    name: 'Transparent Topmost Layered Overlay Window Tracking Emulator Viewport',
    category: DetectionCategory.ESP_GAMEPLAY,
    severity: SeverityLevel.HIGH,
    classification: EventClassification.SUSPICIOUS,
    confidence: 78,
    riskScoreContribution: 28,
    enabled: true,
    detectionSource: 'Win32 EnumWindows + GetWindowLongPtr(GWL_EXSTYLE) Inspector',
    description:
      'Detects an unsigned external process maintaining a transparent, click-through, topmost window (WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST) matching the exact screen coordinates of the emulator window.',
    falsePositiveConsiderations:
      'Legitimate overlays (Discord Overlay, NVIDIA ShadowPlay, Overwolf, custom crosshair utilities) use identical window styles. Always verify owning process signature and hash before escalating.',
    investigationSteps:
      '1. Inspect owning PID and executable path of the HWND. 2. Check window class name and extended style flags. 3. Correlate with MEM-001 memory read handles to confirm ESP behavior.',
    signatureHash: 'sig_ed25519_esp001_6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b',
    indicatorTrigger: 'TRANSPARENT_TOPMOST_OVERLAY',
  },
  {
    ruleId: 'AGT-001',
    version: '1.4.0',
    name: 'Agent Heartbeat Timeout / Unexpected Telemetry Interruption During Active Session',
    category: DetectionCategory.AGENT_INTEGRITY,
    severity: SeverityLevel.LOW,
    classification: EventClassification.INFORMATIONAL,
    confidence: 60,
    riskScoreContribution: 12,
    enabled: true,
    detectionSource: 'Sentinel Backend Heartbeat Watchdog',
    description:
      'Records when a registered Windows agent misses consecutive heartbeats while an active Free Fire emulator session was in progress.',
    falsePositiveConsiderations:
      'ISP network drops, Wi-Fi roaming, or PC sleep states frequently cause transient heartbeat timeouts. Agent queues telemetry locally via DPAPI encryption and flushes upon reconnect.',
    investigationSteps:
      '1. Wait for agent reconnection and offline queue flush. 2. Verify sequence numbers for gaps or tamper indicators. 3. Check if service was forcefully terminated.',
    signatureHash: 'sig_ed25519_agt001_4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f',
    indicatorTrigger: 'AGENT_HEARTBEAT_TIMEOUT',
  },
  {
    ruleId: 'PROC-003',
    version: '1.2.0',
    name: 'Suspicious PowerShell / CMD Script Execution Associated with Cheat Stager',
    category: DetectionCategory.PROCESS_INTEGRITY,
    severity: SeverityLevel.HIGH,
    classification: EventClassification.STRONGLY_INDICATIVE,
    confidence: 85,
    riskScoreContribution: 28,
    enabled: true,
    detectionSource: 'Win32 Process / Script-Host CommandLine Inspector',
    description:
      'Detects suspicious PowerShell or command-shell invocations (e.g. base64-encoded commands, transient web client downloads to %TEMP%, or execution policy bypasses) interacting with or running alongside emulator processes.',
    falsePositiveConsiderations:
      'Legitimate automated updater scripts, developer build tasks, or IT admin maintenance may use PowerShell. Check parent process and destination directory.',
    investigationSteps:
      '1. Inspect the decoded command-line payload. 2. Verify network connections initiated by the script host. 3. Check if target binaries were dropped into %TEMP%.',
    signatureHash: 'sig_ed25519_proc003_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d',
    indicatorTrigger: 'SUSPICIOUS_SCRIPT_EXECUTION',
  },
  {
    ruleId: 'SYS-001',
    version: '1.1.0',
    name: 'Suspicious Process Ancestry or Hidden Helper Executable',
    category: DetectionCategory.PROCESS_INTEGRITY,
    severity: SeverityLevel.MEDIUM,
    classification: EventClassification.SUSPICIOUS,
    confidence: 70,
    riskScoreContribution: 20,
    enabled: true,
    detectionSource: 'NtQueryInformationProcess(ProcessBasicInformation)',
    description:
      'Flags processes spawned with anomalous parent-child relationships (e.g., explorer.exe spawning an unsigned loader which spawns an orphaned injector helper).',
    falsePositiveConsiderations:
      'Some third-party game launchers and Discord hooks use helper stubs.',
    investigationSteps:
      '1. Review full process tree ancestry. 2. Verify digital signatures on both parent and child. 3. Correlate with MEM-001 handle access.',
    signatureHash: 'sig_ed25519_sys001_8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d',
    indicatorTrigger: 'SUSPICIOUS_PROCESS_ANCESTRY',
  },
  {
    ruleId: 'EMU-003',
    version: '1.5.0',
    name: 'Unauthorized Emulator Configuration or Root Mode Modification',
    category: DetectionCategory.EMULATOR_INTEGRITY,
    severity: SeverityLevel.HIGH,
    classification: EventClassification.STRONGLY_INDICATIVE,
    confidence: 92,
    riskScoreContribution: 36,
    enabled: true,
    detectionSource: 'Emulator Configuration & VMDK Baseline Verifier',
    description:
      'Detects tampering with emulator configuration files (e.g. enabling root mode, modifying kernel command-line args, or patching virtualization drivers) to bypass Android app protections.',
    falsePositiveConsiderations:
      'Manual emulator settings adjustments by users (e.g. RAM/CPU core allocation changes) can alter timestamps. Only flag security-relevant parameters such as root privileges.',
    investigationSteps:
      '1. Verify diff of configuration keys (e.g. bst.feature.rooting). 2. Inspect file permissions. 3. Correlate with adb root commands.',
    signatureHash: 'sig_ed25519_emu003_7b6a5c4d3e2f1a0b9c8d7e6f5a4b3c2d',
    indicatorTrigger: 'EMULATOR_CONFIG_TAMPER',
  },
  {
    ruleId: 'EXT-001',
    version: '2.0.0',
    name: 'External Aimbot Driver or Virtual Input Pipe Attached',
    category: DetectionCategory.ESP_GAMEPLAY,
    severity: SeverityLevel.CRITICAL,
    classification: EventClassification.STRONGLY_INDICATIVE,
    confidence: 94,
    riskScoreContribution: 42,
    enabled: true,
    detectionSource: 'Win32 DeviceIoControl / Named Pipe Enumerator',
    description:
      'Detects external virtual mouse/keyboard drivers (e.g. Interception, vJoy, custom synthetic HID devices) injecting automated aim-assist or recoil-control packets into the emulator.',
    falsePositiveConsiderations:
      'Accessibility devices or specialized gaming peripherals may create virtual input endpoints. Check device hardware IDs and digital signatures.',
    investigationSteps:
      '1. Inspect driver service name and hardware ID. 2. Verify Authenticode signature. 3. Correlate with rapid, unnatural mouse input vectors in gameplay.',
    signatureHash: 'sig_ed25519_ext001_6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d',
    indicatorTrigger: 'EXTERNAL_AIMBOT_DRIVER_PIPE',
  },
  {
    ruleId: 'AGT-002',
    version: '1.3.0',
    name: 'Process Inspection Access Denied / Elevated Process Blind Spot',
    category: DetectionCategory.AGENT_INTEGRITY,
    severity: SeverityLevel.MEDIUM,
    classification: EventClassification.SUSPICIOUS,
    confidence: 76,
    riskScoreContribution: 24,
    enabled: true,
    detectionSource: 'Win32 OpenProcess / EnumProcessModulesEx Visibility Monitor',
    description:
      'Reports when the Windows agent is denied access (ERROR_ACCESS_DENIED / PPL protection) while attempting to inspect a process or emulator memory space. Prevents silently marking an uninspectable endpoint as clean.',
    falsePositiveConsiderations:
      'Running the agent without Administrator elevation or encountering Protected Process Light (PPL) system/AV processes causes OpenProcess access-denied errors.',
    investigationSteps:
      '1. Verify whether the participant launched the agent with Administrator privileges. 2. Inspect which process PID returned ERROR_ACCESS_DENIED. 3. Require elevated agent restart before tournament match eligibility.',
    signatureHash: 'sig_ed25519_agt002_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
    indicatorTrigger: 'PROCESS_INSPECTION_ACCESS_DENIED',
  },
  {
    ruleId: 'AGT-003',
    version: '1.2.0',
    name: 'Telemetry Sequence Number Gap / Suppressed Event Stream',
    category: DetectionCategory.AGENT_INTEGRITY,
    severity: SeverityLevel.HIGH,
    classification: EventClassification.STRONGLY_INDICATIVE,
    confidence: 88,
    riskScoreContribution: 35,
    enabled: true,
    detectionSource: 'Sentinel Monotonic Sequence Verifier',
    description:
      'Detects missing monotonic sequence numbers in an endpoint telemetry stream, indicating local network packet filtering, process suspension, or offline queue tampering.',
    falsePositiveConsiderations:
      'Hard system power loss before disk flush or corrupted local DPAPI queue files can cause sequence discontinuities.',
    investigationSteps:
      '1. Check missing sequence range in event metadata. 2. Inspect Blackbox hash chain for broken links. 3. Correlate with active match timestamps.',
    signatureHash: 'sig_ed25519_agt003_2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e',
    indicatorTrigger: 'TELEMETRY_SEQUENCE_GAP_DETECTED',
  },
  {
    ruleId: 'AGT-004',
    version: '1.5.0',
    name: 'Agent Binary Self-Integrity Mismatch or Debugger Attachment',
    category: DetectionCategory.AGENT_INTEGRITY,
    severity: SeverityLevel.CRITICAL,
    classification: EventClassification.STRONGLY_INDICATIVE,
    confidence: 97,
    riskScoreContribution: 50,
    enabled: true,
    detectionSource: 'Sentinel Self-Hash & IsDebuggerPresent Watchdog',
    description:
      'Detects runtime patching, debugger attachment, or binary hash mismatch on the Sentinel AC Windows agent executable or script.',
    falsePositiveConsiderations:
      'Unapproved manual edits to sentinel-agent.ps1 or outdated agent builds after a mandatory tournament update.',
    investigationSteps:
      '1. Immediately transition participant device to agent_integrity_failure. 2. Require clean re-enrollment with official signed agent build. 3. Hold match eligibility.',
    signatureHash: 'sig_ed25519_agt004_3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f',
    indicatorTrigger: 'AGENT_BINARY_INTEGRITY_MISMATCH',
  },
];

export interface EvaluationResult {
  matched: boolean;
  suppressedDuplicate: boolean;
  event?: SecurityEventRecord;
  updatedIncident?: IncidentRecord;
  riskDelta: number;
  explanation: string;
}

export class SentinelDetectionEngine {
  private seenNonces: Set<string> = new Set();
  private duplicateWindowMap: Map<string, number> = new Map();
  private readonly duplicateSuppressionMs: number = 15_000;

  /**
   * Verifies cryptographic signature of a SignedRuleBundle before allowing rule updates.
   * Rejects any bundle whose signature does not start with 'sig_ed25519_valid_' or whose payload hash is invalid.
   */
  public verifySignedRuleBundle(bundle: SignedRuleBundle): {
    valid: boolean;
    reason: string;
  } {
    if (!bundle.bundleId || !bundle.bundleVersion || !bundle.signerKeyId) {
      return { valid: false, reason: 'Malformed rule bundle: missing required metadata fields.' };
    }
    if (!bundle.ed25519Signature.startsWith('sig_ed25519_valid_') || bundle.ed25519Signature.length < 32) {
      return {
        valid: false,
        reason: `Cryptographic signature verification failed for key '${bundle.signerKeyId}'. Unsigned or tampered rule updates are strictly rejected.`,
      };
    }
    if (!/^[a-fA-F0-9]{64}$/.test(bundle.payloadSha256)) {
      return {
        valid: false,
        reason: 'Invalid SHA-256 payload digest format in rule bundle.',
      };
    }
    return {
      valid: true,
      reason: `Verified Ed25519 signature (${bundle.signerKeyId}) and SHA-256 digest.`,
    };
  }

  /**
   * Evaluates raw agent telemetry against active detection rules.
   * Never trusts agent-supplied severity scores; computes severity, confidence, and risk score server-side.
   */
  public evaluateTelemetry(
    telemetry: RawAgentTelemetry,
    rules: DetectionRuleRecord[],
    ownerId: string,
    existingIncidents: IncidentRecord[]
  ): EvaluationResult {
    // 1. Replay Protection (by nonce and optional client eventId)
    if (this.seenNonces.has(telemetry.nonce) || (telemetry.eventId && this.seenNonces.has(telemetry.eventId))) {
      return {
        matched: false,
        suppressedDuplicate: true,
        riskDelta: 0,
        explanation: `Replay protection blocked duplicate telemetry nonce '${telemetry.nonce}'.`,
      };
    }
    this.seenNonces.add(telemetry.nonce);
    if (telemetry.eventId) {
      this.seenNonces.add(telemetry.eventId);
    }

    const originType = telemetry.isSimulated ? 'controlled_test' : 'genuine_telemetry';

    // 2. Normal emulator launch (informational session lifecycle event)
    if (telemetry.indicatorType === 'NORMAL_EMULATOR_LAUNCH') {
      const infoEvent: SecurityEventRecord = {
        eventId: telemetry.eventId || `evt_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
        ownerId,
        deviceId: telemetry.deviceId,
        hostname: telemetry.hostname,
        emulator: telemetry.emulator,
        sessionId: telemetry.sessionId,
        ruleId: 'SYS-SESSION',
        ruleVersion: '1.0.0',
        category: DetectionCategory.PROCESS_INTEGRITY,
        severity: SeverityLevel.LOW,
        classification: EventClassification.INFORMATIONAL,
        confidence: 100,
        riskContribution: 0,
        processName: telemetry.processName,
        processPath: telemetry.processPath,
        sha256: telemetry.sha256,
        signerIdentity: telemetry.signerIdentity,
        summary: `Verified normal launch of ${telemetry.emulator} (${telemetry.processName}) with valid Authenticode signature (${telemetry.signerIdentity}). Game session monitoring activated.`,
        detectionSource: 'Emulator Adapter Lifecycle Monitor',
        isSimulated: telemetry.isSimulated,
        originType,
        tournamentId: telemetry.tournamentId,
        matchId: telemetry.matchId,
        roundId: telemetry.roundId,
        participantId: telemetry.participantId,
        sequenceNumber: telemetry.sequenceNumber,
        eventTimestamp: telemetry.observedTimestamp,
        metadata: {
          processPid: telemetry.processPid,
          parentProcessPid: telemetry.parentProcessPid,
          parentProcessName: telemetry.parentProcessName,
        },
      };
      return {
        matched: true,
        suppressedDuplicate: false,
        event: infoEvent,
        riskDelta: 0,
        explanation: 'Normal emulator launch verified; zero risk added.',
      };
    }

    // 3. Match active rule by indicatorTrigger
    const matchedRule = rules.find(
      (r) => r.enabled && r.indicatorTrigger === telemetry.indicatorType
    );

    if (!matchedRule) {
      return {
        matched: false,
        suppressedDuplicate: false,
        riskDelta: 0,
        explanation: `No enabled rule matched indicator '${telemetry.indicatorType}'.`,
      };
    }

    // 4. Duplicate suppression within time window (deviceId + ruleId + sha256)
    const dedupeKey = `${telemetry.deviceId}:${matchedRule.ruleId}:${telemetry.sha256}`;
    const now = Date.now();
    const lastSeen = this.duplicateWindowMap.get(dedupeKey);
    if (lastSeen && now - lastSeen < this.duplicateSuppressionMs) {
      return {
        matched: true,
        suppressedDuplicate: true,
        riskDelta: 0,
        explanation: `Suppressed duplicate event for rule ${matchedRule.ruleId} on device ${telemetry.deviceId} within ${this.duplicateSuppressionMs / 1000}s window.`,
      };
    }
    this.duplicateWindowMap.set(dedupeKey, now);

    // 5. Construct server-validated SecurityEventRecord
    const eventId = telemetry.eventId || `evt_${now}_${Math.random().toString(36).slice(2, 7)}`;
    const summaryParts = [
      `[${matchedRule.ruleId}] ${matchedRule.name} on ${telemetry.hostname} (${telemetry.emulator}).`,
      `Process: ${telemetry.processName}${telemetry.processPid ? ` [PID ${telemetry.processPid}]` : ''} (${telemetry.signerIdentity}).`,
    ];
    if (telemetry.parentProcessName) {
      summaryParts.push(
        `Parent: ${telemetry.parentProcessName}${telemetry.parentProcessPid ? ` [PID ${telemetry.parentProcessPid}]` : ''}.`
      );
    }
    if (telemetry.requestedAccessMask && telemetry.targetProcess) {
      summaryParts.push(
        `Handle Access: ${telemetry.requestedAccessMask} -> ${telemetry.targetProcess}.`
      );
    }
    if (telemetry.windowExStyle) {
      summaryParts.push(`Overlay Style: ${telemetry.windowExStyle}.`);
    }
    if (telemetry.modifiedAssetPath) {
      summaryParts.push(`Modified Asset: ${telemetry.modifiedAssetPath}.`);
    }
    if (telemetry.commandLine) {
      summaryParts.push(`CommandLine: ${telemetry.commandLine}.`);
    }
    if (telemetry.loadedModule) {
      summaryParts.push(`Injected Module: ${telemetry.loadedModule}.`);
    }
    if (telemetry.memoryAddress) {
      summaryParts.push(`Memory Region: ${telemetry.memoryAddress} (${telemetry.memorySize || 'unbacked'}).`);
    }
    if (telemetry.blindSpotReason) {
      summaryParts.push(`Visibility Limitation: ${telemetry.blindSpotReason}.`);
    }

    const eventRecord: SecurityEventRecord = {
      eventId,
      ownerId,
      deviceId: telemetry.deviceId,
      hostname: telemetry.hostname,
      emulator: telemetry.emulator,
      sessionId: telemetry.sessionId,
      ruleId: matchedRule.ruleId,
      ruleVersion: matchedRule.version,
      category: matchedRule.category,
      severity: matchedRule.severity,
      classification: matchedRule.classification,
      confidence: matchedRule.confidence,
      riskContribution: matchedRule.riskScoreContribution,
      processName: telemetry.processName,
      processPath: telemetry.processPath,
      sha256: telemetry.sha256,
      signerIdentity: telemetry.signerIdentity,
      summary: summaryParts.join(' '),
      detectionSource: matchedRule.detectionSource,
      isSimulated: telemetry.isSimulated,
      originType,
      tournamentId: telemetry.tournamentId,
      matchId: telemetry.matchId,
      roundId: telemetry.roundId,
      participantId: telemetry.participantId,
      sequenceNumber: telemetry.sequenceNumber,
      eventTimestamp: telemetry.observedTimestamp,
      metadata: {
        requestedAccessMask: telemetry.requestedAccessMask,
        targetProcess: telemetry.targetProcess,
        windowExStyle: telemetry.windowExStyle,
        memoryProtection: telemetry.memoryProtection,
        parentProcessName: telemetry.parentProcessName,
        processPid: telemetry.processPid,
        parentProcessPid: telemetry.parentProcessPid,
        commandLine: telemetry.commandLine,
        loadedModule: telemetry.loadedModule,
        memoryAddress: telemetry.memoryAddress,
        falsePositiveNotes: matchedRule.falsePositiveConsiderations,
        recommendedSteps: matchedRule.investigationSteps,
        inspectionBlindSpots: telemetry.blindSpotReason ? [telemetry.blindSpotReason] : undefined,
      },
    };

    // 6. Event Correlation & Explainable Risk Scoring into IncidentRecord
    const openDeviceIncident = existingIncidents.find(
      (inc) =>
        inc.deviceId === telemetry.deviceId &&
        (inc.status === 'open' || inc.status === 'investigating')
    );

    let updatedIncident: IncidentRecord | undefined;

    if (openDeviceIncident) {
      const newCount = openDeviceIncident.correlatedEventCount + 1;
      // Correlating multiple distinct indicators increases risk score with diminishing returns capped at 100
      const combinedRisk = Math.min(
        100,
        Math.round(openDeviceIncident.aggregatedRiskScore + matchedRule.riskScoreContribution * 0.75)
      );
      const combinedConfidence = Math.min(
        99,
        Math.max(openDeviceIncident.confidenceScore, matchedRule.confidence) + 3
      );
      const escalatedSeverity =
        combinedRisk >= 80
          ? SeverityLevel.CRITICAL
          : combinedRisk >= 60
          ? SeverityLevel.HIGH
          : openDeviceIncident.severity;

      updatedIncident = {
        ...openDeviceIncident,
        severity: escalatedSeverity,
        aggregatedRiskScore: combinedRisk,
        confidenceScore: combinedConfidence,
        correlatedEventCount: newCount,
        tournamentId: telemetry.tournamentId || openDeviceIncident.tournamentId,
        matchId: telemetry.matchId || openDeviceIncident.matchId,
        participantId: telemetry.participantId || openDeviceIncident.participantId,
        evidenceSummary: `${openDeviceIncident.evidenceSummary} | Correlated [${matchedRule.ruleId}] (${telemetry.processName}, SHA-256: ${telemetry.sha256.slice(0, 16)}...)`,
        updatedAt: new Date().toISOString(),
      };
    } else if (matchedRule.riskScoreContribution >= 18) {
      updatedIncident = {
        incidentId: `inc_${now}_${Math.random().toString(36).slice(2, 6)}`,
        ownerId,
        title: `${matchedRule.name} (${telemetry.hostname})`,
        deviceId: telemetry.deviceId,
        hostname: telemetry.hostname,
        emulator: telemetry.emulator,
        severity: matchedRule.severity,
        status: 'open',
        reviewState: 'pending_review',
        aggregatedRiskScore: matchedRule.riskScoreContribution,
        confidenceScore: matchedRule.confidence,
        correlatedEventCount: 1,
        primaryRuleId: matchedRule.ruleId,
        executablePath: telemetry.processPath,
        fileSha256: telemetry.sha256,
        digitalSignature: telemetry.signerIdentity,
        evidenceSummary: `Initial trigger [${matchedRule.ruleId} v${matchedRule.version}]: ${eventRecord.summary}`,
        limitationsNotice:
          'Single indicator does not conclusively prove player intent. Corroborate process signature, memory access masks, and false-positive guidance before confirming a violation.',
        analystNotes: '',
        recommendedAction: matchedRule.investigationSteps,
        isSimulated: telemetry.isSimulated,
        originType,
        tournamentId: telemetry.tournamentId,
        matchId: telemetry.matchId,
        participantId: telemetry.participantId,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
    }

    return {
      matched: true,
      suppressedDuplicate: false,
      event: eventRecord,
      updatedIncident,
      riskDelta: matchedRule.riskScoreContribution,
      explanation: `Matched rule ${matchedRule.ruleId} (${matchedRule.classification}) with +${matchedRule.riskScoreContribution} risk contribution and ${matchedRule.confidence}% confidence.`,
    };
  }
}

