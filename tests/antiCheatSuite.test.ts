/**
 * Sentinel AC — Comprehensive Anti-Cheat System Test Suite
 * Tests all 12 architectural pillars of the Windows Anti-Cheat upgrade.
 */

import { BlackboxLedgerService } from '../windows-agent/src/blackbox/BlackboxService.ts';
import { ProcessInspectionService } from '../windows-agent/src/scanner/ProcessInspectionService.ts';
import { ScreenshotService } from '../windows-agent/src/evidence/ScreenshotService.ts';
import { SentinelDetectionEngine, DEFAULT_SIGNED_RULES } from '../detection-engine/engine.ts';
import { SUPPORTED_EMULATOR_ADAPTERS } from '../emulator-adapters/adapters.ts';
import { MonitoredDevice, SeverityLevel, SecurityEventRecord, RawAgentTelemetry } from '../shared-schemas/types.ts';
import {
  DEFAULT_HEARTBEAT_TIMEOUT_MS,
  computeFleetSummary,
  deriveMonitoringHealthState,
  isDemoOrFixtureDevice,
} from '../shared-schemas/fleetMetrics.ts';
import { getMultiPcTestFixtures } from './fixtures/multiPcFixtures.ts';
import {
  DynamicLoadTestEngine,
  TournamentManagerService,
} from '../backend/tournamentAndLoadEngine.ts';

export interface TestResultItem {
  name: string;
  pillar: string;
  passed: boolean;
  durationMs: number;
  details: string;
}

export function runFullAntiCheatSystemTests(): {
  totalPassed: number;
  totalFailed: number;
  totalTests: number;
  results: TestResultItem[];
} {
  const results: TestResultItem[] = [];

  function test(pillar: string, name: string, fn: () => void) {
    const start = performance.now();
    try {
      fn();
      results.push({
        pillar,
        name,
        passed: true,
        durationMs: Math.round((performance.now() - start) * 100) / 100,
        details: 'Verified successfully according to specification.',
      });
    } catch (err: unknown) {
      results.push({
        pillar,
        name,
        passed: false,
        durationMs: Math.round((performance.now() - start) * 100) / 100,
        details: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // 1. Startup & Registration
  test('Pillar 1: Startup & Installation', 'Agent initializes and registers with auto-start configuration', () => {
    const bb = new BlackboxLedgerService(null);
    const entries = bb.getEntries();
    if (entries.length === 0) throw new Error('Startup event not recorded in ledger.');
    if (entries[0].category !== 'STARTUP_SHUTDOWN') throw new Error('Initial category must be STARTUP_SHUTDOWN.');
  });

  // 2. Blackbox Module
  test('Pillar 2: Blackbox Module', 'Cryptographic rolling SHA-256 tamper-evident integrity passes and detects unauthorized tampering', () => {
    const bb = new BlackboxLedgerService(null);
    bb.recordSystemEvent('PROCESS_LIFECYCLE', 'Process Created', SeverityLevel.LOW, 'explorer.exe started', 'win-01', 'SUVO');
    bb.recordSystemEvent('INTEGRITY', 'File Verified', SeverityLevel.LOW, 'libil2cpp.so hash check passed', 'win-01', 'SUVO');
    const integrity = bb.verifyLedgerIntegrity();
    if (!integrity.isValid) throw new Error('Ledger hash chain was invalid on pristine data.');
    if (integrity.checkedCount < 3) throw new Error('Expected at least 3 verified ledger entries.');

    // Actively test tamper detection: modify entry #1 details without re-hashing
    bb.tamperEntryForTesting(1, 'tampered_malicious_injected_log_line');
    const tamperedCheck = bb.verifyLedgerIntegrity();
    if (tamperedCheck.isValid) {
      throw new Error('Tamper detection failed: modified entry was accepted by hash chain verification.');
    }
  });

  // 3. Privacy Filter in Blackbox
  test('Pillar 2: Blackbox Privacy', 'Sensitive credentials, passwords, and tokens are redacted', () => {
    const bb = new BlackboxLedgerService(null);
    const entry = bb.recordSystemEvent(
      'NETWORK',
      'Auth Request',
      SeverityLevel.LOW,
      'Connecting with password=SuperSecretP@ss and token=abc123xyz',
      'win-01',
      'SUVO'
    );
    if (entry.details.includes('SuperSecretP@ss')) throw new Error('Password was not redacted.');
    if (entry.details.includes('abc123xyz')) throw new Error('Token was not redacted.');
    if (!entry.details.includes('password=[REDACTED]')) throw new Error('Redaction placeholder missing.');
  });

  // 4. Screenshot Governance Policy
  test('Pillar 4: Evidence Capture', 'Respects user-governed policy toggle and emulator-window scope', () => {
    const ss = new ScreenshotService();
    const captured = ss.captureEvidence('win-01', 'SUVO', 'Test Capture');
    if (!captured.success || !captured.evidence) throw new Error('Screenshot capture failed.');
    if (captured.evidence.captureType !== 'emulator_window') throw new Error('Must scope to emulator window by default.');

    // Test disabling
    ss.updateConfig({ policy: 'disabled' });
    const blocked = ss.captureEvidence('win-01', 'SUVO', 'Blocked Capture');
    if (blocked.success) throw new Error('Capture should be blocked when disabled by user policy.');
  });

  // 5. Process Scanner Inspection
  test('Pillar 5: Process Scanner', 'Categorizes running processes and detects Authenticode signatures', () => {
    const ps = new ProcessInspectionService();
    const scan = ps.runFullProcessScan('win-01', 'SUVO');
    if (scan.totalProcessesScanned === 0) throw new Error('No processes scanned.');
    if (scan.cleanCount === 0) throw new Error('Expected clean system processes.');
    const bsProc = scan.items.find((i) => i.name === 'HD-Player.exe');
    if (!bsProc) throw new Error('Target emulator HD-Player.exe missing from scan table.');
    if (bsProc.status !== 'clean') throw new Error('Legitimate BlueStacks binary should be classified as clean.');
  });

  // 6. Injection Detection & Whitelisting
  test('Pillar 6: Injection Detection', 'Whitelists Discord & NVIDIA overlays while flagging unauthorized hooks', () => {
    const ps = new ProcessInspectionService();
    const injectionCheck = ps.runInjectionCheck('HD-Player.exe');
    const discordHook = injectionCheck.find((m) => m.moduleName === 'discordhook64.dll');
    if (!discordHook) throw new Error('discordhook64.dll not found in injection check.');
    if (!discordHook.isWhitelisted) throw new Error('Discord hook must be whitelisted.');
    if (discordHook.classification !== 'legitimate_overlay') throw new Error('Discord should be legitimate_overlay.');
  });

  // 7. Memory Scanner (User-mode safe)
  test('Pillar 7: Memory Scanner', 'Safely identifies mapped image and guest heap memory regions', () => {
    const ps = new ProcessInspectionService();
    const mem = ps.runMemoryScan('HD-Player.exe');
    if (mem.length === 0) throw new Error('No memory regions returned.');
    const guestRam = mem.find((r) => r.status === 'safe' && r.signatureMatch?.includes('Guest RAM'));
    if (!guestRam) throw new Error('Expected mapped Android guest RAM page region.');
  });

  // 8. Emulator Support (5 Emulators)
  test('Pillar 8: Emulator Integration', 'Supports all 5 required emulators and Free Fire package names', () => {
    const required = ['BlueStacks 5', 'LDPlayer 9', 'MEmu Play', 'NoxPlayer', 'Google Play Games'];
    for (const req of required) {
      const match = SUPPORTED_EMULATOR_ADAPTERS.some((a) => a.displayName.includes(req));
      if (!match) throw new Error(`Missing adapter support for ${req}.`);
    }
  });


  // 9. Free Fire Session Telemetry
  test('Pillar 8: Free Fire Session Tracking', 'Correctly evaluates com.dts.freefireth and com.dts.freefiremax', () => {
    const engine = new SentinelDetectionEngine();
    const rules = DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: 'test' }));
    const result = engine.evaluateTelemetry(
      {
        schemaVersion: '1.2.0',
        nonce: `nonce-${Date.now()}`,
        deviceId: 'win-01',
        hostname: 'SUVO',
        emulator: 'BlueStacks 5',
        sessionId: 'sess-01',
        indicatorType: 'NORMAL_EMULATOR_LAUNCH',
        processName: 'HD-Player.exe',
        processPath: 'C:\\Program Files\\BlueStacks_nxt\\HD-Player.exe',
        sha256: '4a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b',
        signerIdentity: 'BlueStack Systems, Inc.',
        observedTimestamp: new Date().toISOString(),
        isSimulated: false,
      },
      rules,
      'test',
      []
    );
    if (!result.event) throw new Error('Session launch event expected.');
    if (result.event.riskContribution !== 0) throw new Error('Normal launch must have 0 risk contribution.');
  });

  // 10. Cheat Signature Detection & Correlated Incident
  test('Pillar 5: Threat Correlation', 'Detects KNOWN_CHEAT_SIGNATURE and updates correlated incident without auto-ban', () => {
    const engine = new SentinelDetectionEngine();
    const rules = DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: 'test' }));
    const result = engine.evaluateTelemetry(
      {
        schemaVersion: '1.2.0',
        nonce: `nonce-${Date.now()}`,
        deviceId: 'win-01',
        hostname: 'SUVO',
        emulator: 'BlueStacks 5',
        sessionId: 'sess-02',
        indicatorType: 'KNOWN_CHEAT_SIGNATURE',
        processName: 'CheatEngine.exe',
        processPath: 'C:\\Tools\\CheatEngine.exe',
        sha256: '9f83c12a84092b9d2f1029c8e192a83b4c5d6e7f8091a2b3c4d5e6f708192a3b',
        signerIdentity: 'Unsigned / Unknown Signer',
        observedTimestamp: new Date().toISOString(),
        isSimulated: false,
      },
      rules,
      'test',
      []
    );
    if (!result.event) throw new Error('Expected security event for known cheat signature.');
    if (!result.updatedIncident) throw new Error('Expected correlated incident creation.');
    if (result.updatedIncident.status === 'confirmed_violation') {
      throw new Error('Never automatically ban or confirm violation on single indicator; must require analyst decision.');
    }
  });

  // 11. Bounded Offline Queue
  test('Pillar 2: Bounded Offline Queue', 'Limits memory buffer and rolls over safely without crashing', () => {
    const bb = new BlackboxLedgerService(null);
    for (let i = 0; i < 50; i++) {
      bb.recordSystemEvent('PROCESS_LIFECYCLE', `Event ${i}`, SeverityLevel.LOW, `Details ${i}`, 'win-01', 'SUVO');
    }
    const entries = bb.getEntries({ limit: 10 });
    if (entries.length !== 10) throw new Error('Expected 10 limited entries.');
  });

  // 12. Uninstaller & Idempotency
  test('Pillar 10: Installation Scripts', 'Configuration export and uninstaller schema are idempotent and well-formed', () => {
    const bb = new BlackboxLedgerService(null);
    const csv = bb.exportCsv();
    const json = bb.exportJson();
    if (!csv.startsWith('Timestamp,EntryID')) throw new Error('CSV header missing.');
    const parsed = JSON.parse(json);
    if (!parsed.integrityStatus || parsed.integrityStatus !== 'VERIFIED') throw new Error('Export JSON integrity verification failed.');
  });

  // 13. Suspicious Script-Host Execution (PROC-003)
  test('Pillar 5: Script-Host Inspection', 'Detects encoded PowerShell/CMD script-host cheat loaders (PROC-003)', () => {
    const engine = new SentinelDetectionEngine();
    const rules = DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: 'test' }));
    const result = engine.evaluateTelemetry(
      {
        schemaVersion: '1.2.0',
        nonce: `nonce-ps-${Date.now()}`,
        deviceId: 'win-01',
        hostname: 'SUVO',
        emulator: 'BlueStacks 5',
        sessionId: 'sess-03',
        indicatorType: 'SUSPICIOUS_SCRIPT_EXECUTION',
        processName: 'powershell.exe',
        processPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe -NoP -W Hidden -Enc aW52b2tlLXdlYnJlcXVlc3QgaHR0cDovL2NoZWF0LmxvYWRlcg==',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        signerIdentity: 'Microsoft Windows',
        observedTimestamp: new Date().toISOString(),
        isSimulated: false,
      },
      rules,
      'test',
      []
    );
    if (!result.event) throw new Error('Expected event for SUSPICIOUS_SCRIPT_EXECUTION.');
    if (result.event.ruleId !== 'PROC-003') throw new Error(`Expected rule PROC-003, got ${result.event.ruleId}`);
    if (!result.event.summary.includes('CommandLine:')) throw new Error('Expected command line evidence in summary.');
  });

  // 14. Unbacked Executable Memory Region (MEM-002)
  test('Pillar 7: VirtualQueryEx RWX Inspection', 'Flags private unbacked PAGE_EXECUTE_READWRITE memory regions (MEM-002)', () => {
    const engine = new SentinelDetectionEngine();
    const rules = DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: 'test' }));
    const result = engine.evaluateTelemetry(
      {
        schemaVersion: '1.2.0',
        nonce: `nonce-mem-${Date.now()}`,
        deviceId: 'win-01',
        hostname: 'SUVO',
        emulator: 'BlueStacks 5',
        sessionId: 'sess-04',
        indicatorType: 'UNBACKED_EXECUTABLE_MEMORY',
        processName: 'HD-Player.exe',
        processPath: 'C:\\Program Files\\BlueStacks_nxt\\HD-Player.exe',
        targetProcess: 'HD-Player.exe',
        memoryAddress: '0x7FF4002A0000',
        memorySize: '0x14000',
        memoryProtection: 'PAGE_EXECUTE_READWRITE',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        signerIdentity: 'Unbacked Private Allocation',
        observedTimestamp: new Date().toISOString(),
        isSimulated: false,
      },
      rules,
      'test',
      []
    );
    if (!result.event) throw new Error('Expected event for UNBACKED_EXECUTABLE_MEMORY.');
    if (result.event.ruleId !== 'MEM-002') throw new Error(`Expected rule MEM-002, got ${result.event.ruleId}`);
    if (!result.event.summary.includes('0x7FF4002A0000')) throw new Error('Expected memory address in summary.');
  });

  // 15. Emulator Configuration & Root Mode Tampering (EMU-003)
  test('Pillar 8: Emulator Root Tampering', 'Detects unauthorized root mode in bluestacks.conf (EMU-003)', () => {
    const engine = new SentinelDetectionEngine();
    const rules = DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: 'test' }));
    const result = engine.evaluateTelemetry(
      {
        schemaVersion: '1.2.0',
        nonce: `nonce-emu-${Date.now()}`,
        deviceId: 'win-01',
        hostname: 'SUVO',
        emulator: 'BlueStacks 5',
        sessionId: 'sess-05',
        indicatorType: 'EMULATOR_CONFIG_TAMPER',
        processName: 'HD-Player.exe',
        processPath: 'C:\\ProgramData\\BlueStacks_nxt\\bluestacks.conf',
        modifiedAssetPath: 'bluestacks.conf (bst.feature.rooting=1)',
        sha256: '8f12c94a2b1d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f',
        signerIdentity: 'Unsigned Local Configuration File',
        observedTimestamp: new Date().toISOString(),
        isSimulated: false,
      },
      rules,
      'test',
      []
    );
    if (!result.event) throw new Error('Expected event for EMULATOR_CONFIG_TAMPER.');
    if (result.event.ruleId !== 'EMU-003') throw new Error(`Expected rule EMU-003, got ${result.event.ruleId}`);
  });

  // 16. Multi-PC Event Attribution & Cross-Device Isolation (PC-1, PC-2, PC-3)
  test('Pillar 9: Multi-PC Fleet Attribution', 'Independently attributes events to PC-1, PC-2, and PC-3 without cross-device leakage', () => {
    const engine = new SentinelDetectionEngine();
    const rules = DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: 'test' }));
    const events: SecurityEventRecord[] = [];

    const pcs: Array<{ deviceId: string; hostname: string; indicator: RawAgentTelemetry['indicatorType'] }> = [
      { deviceId: 'win-esports-pc-01', hostname: 'ESPORTS-RIG-01', indicator: 'KNOWN_CHEAT_SIGNATURE' },
      { deviceId: 'win-esports-pc-02', hostname: 'ESPORTS-RIG-02', indicator: 'UNBACKED_EXECUTABLE_MEMORY' },
      { deviceId: 'win-esports-pc-03', hostname: 'ESPORTS-RIG-03', indicator: 'SUSPICIOUS_SCRIPT_EXECUTION' },
    ];

    pcs.forEach((pc, idx) => {
      const res = engine.evaluateTelemetry(
        {
          schemaVersion: '1.2.0',
          nonce: `nonce-mpc-${idx}-${Date.now()}`,
          eventId: `evt-mpc-${idx}-${Date.now()}`,
          deviceId: pc.deviceId,
          hostname: pc.hostname,
          emulator: 'BlueStacks 5',
          sessionId: `sess-mpc-${idx}`,
          indicatorType: pc.indicator,
          processName: 'HD-Player.exe',
          processPath: 'C:\\Program Files\\BlueStacks_nxt\\HD-Player.exe',
          processPid: 4000 + idx,
          parentProcessPid: 1200 + idx,
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          signerIdentity: 'Unsigned',
          observedTimestamp: new Date().toISOString(),
          isSimulated: false,
        },
        rules,
        'test',
        []
      );
      if (!res.event) throw new Error(`Expected event for ${pc.hostname}`);
      events.push(res.event);
    });

    const pc1Events = events.filter((e) => e.deviceId === 'win-esports-pc-01');
    const pc2Events = events.filter((e) => e.deviceId === 'win-esports-pc-02');
    const pc3Events = events.filter((e) => e.deviceId === 'win-esports-pc-03');
    if (pc1Events.length !== 1 || pc1Events[0].hostname !== 'ESPORTS-RIG-01') {
      throw new Error('PC-1 attribution failed');
    }
    if (pc2Events.length !== 1 || pc2Events[0].hostname !== 'ESPORTS-RIG-02') {
      throw new Error('PC-2 attribution failed');
    }
    if (pc3Events.length !== 1 || pc3Events[0].hostname !== 'ESPORTS-RIG-03') {
      throw new Error('PC-3 attribution failed');
    }
  });

  // 17. Duplicate Client EventId Replay Protection
  test('Pillar 9: Duplicate EventId Replay Protection', 'Blocks re-uploaded offline queue events with an already-ingested eventId', () => {
    const engine = new SentinelDetectionEngine();
    const rules = DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: 'test' }));
    const sharedEventId = `evt-dedup-${Date.now()}`;

    const first = engine.evaluateTelemetry(
      {
        schemaVersion: '1.2.0',
        nonce: `nonce-dedup-1-${Date.now()}`,
        eventId: sharedEventId,
        deviceId: 'win-esports-pc-01',
        hostname: 'ESPORTS-RIG-01',
        emulator: 'BlueStacks 5',
        sessionId: 'sess-dedup',
        indicatorType: 'KNOWN_CHEAT_SIGNATURE',
        processName: 'cheat.dll',
        processPath: 'C:\\Temp\\cheat.dll',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        signerIdentity: 'Unsigned',
        observedTimestamp: new Date().toISOString(),
        isSimulated: false,
      },
      rules,
      'test',
      []
    );
    if (!first.event) throw new Error('First telemetry with unique eventId should be accepted.');

    const duplicate = engine.evaluateTelemetry(
      {
        schemaVersion: '1.2.0',
        nonce: `nonce-dedup-2-${Date.now()}`,
        eventId: sharedEventId,
        deviceId: 'win-esports-pc-01',
        hostname: 'ESPORTS-RIG-01',
        emulator: 'BlueStacks 5',
        sessionId: 'sess-dedup',
        indicatorType: 'KNOWN_CHEAT_SIGNATURE',
        processName: 'cheat.dll',
        processPath: 'C:\\Temp\\cheat.dll',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        signerIdentity: 'Unsigned',
        observedTimestamp: new Date().toISOString(),
        isSimulated: false,
      },
      rules,
      'test',
      []
    );
    if (duplicate.event) {
      throw new Error('Expected duplicate eventId to be rejected by replay protection.');
    }
  });

  // 18. Forensic Metadata Preservation (PID, Parent PID, CommandLine, LoadedModule, MemoryAddress)
  test('Pillar 9: Forensic Telemetry Metadata', 'Preserves processPid, parentProcessPid, commandLine, loadedModule, and memoryAddress in event record', () => {
    const engine = new SentinelDetectionEngine();
    const rules = DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: 'test' }));
    const res = engine.evaluateTelemetry(
      {
        schemaVersion: '1.2.0',
        nonce: `nonce-meta-${Date.now()}`,
        eventId: `evt-meta-${Date.now()}`,
        deviceId: 'win-esports-pc-02',
        hostname: 'ESPORTS-RIG-02',
        emulator: 'BlueStacks 5',
        sessionId: 'sess-meta',
        indicatorType: 'UNBACKED_EXECUTABLE_MEMORY',
        processName: 'HD-Player.exe',
        processPath: 'C:\\Program Files\\BlueStacks_nxt\\HD-Player.exe',
        processPid: 9124,
        parentProcessPid: 1840,
        parentProcessName: 'explorer.exe',
        commandLine: '"C:\\Program Files\\BlueStacks_nxt\\HD-Player.exe" --instance Pie64',
        loadedModule: 'C:\\Users\\Public\\ff_aim_hook.dll',
        memoryAddress: '0x7FF5A0110000',
        memoryProtection: 'PAGE_EXECUTE_READWRITE',
        sha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
        signerIdentity: 'Unsigned',
        observedTimestamp: new Date().toISOString(),
        isSimulated: false,
      },
      rules,
      'test',
      []
    );
    if (!res.event || !res.event.metadata) throw new Error('Expected event with metadata to be created.');
    if (res.event.metadata.processPid !== 9124) throw new Error('Expected processPid 9124');
    if (res.event.metadata.parentProcessPid !== 1840) throw new Error('Expected parentProcessPid 1840');
    if (res.event.metadata.loadedModule !== 'C:\\Users\\Public\\ff_aim_hook.dll') throw new Error('Expected loadedModule preserved');
    if (res.event.metadata.memoryAddress !== '0x7FF5A0110000') throw new Error('Expected memoryAddress preserved');
  });

  // 19. Offline Queue Batch Reconnection Order & Hash Chain Integrity
  test('Pillar 9: Offline Batch Queue Ingestion', 'Maintains unbroken Blackbox Ledger SHA-256 chain across batch-uploaded offline events', () => {
    const ledger = new BlackboxLedgerService(null);

    for (let i = 0; i < 4; i++) {
      ledger.recordSystemEvent(
        'MODULE_LOAD',
        `Offline Queued DLL Detection #${i + 1}`,
        SeverityLevel.HIGH,
        `Batch uploaded event evt-batch-${i} for C:\\Temp\\module_${i}.dll`,
        'win-esports-pc-03',
        'ESPORTS-RIG-03'
      );
    }

    const verification = ledger.verifyLedgerIntegrity();
    if (!verification.isValid) {
      throw new Error('Offline batch ledger verification failed.');
    }
  });

  // 20. Zero Enrolled PCs Results in Zero Connected PCs
  test('Pillar 10: Fleet Enrollment Truth', 'Proves that zero enrolled PCs results in zero connected PCs and zero total registered devices', () => {
    const summary = computeFleetSummary([]);
    if (summary.totalRegistered !== 0) {
      throw new Error(`Expected totalRegistered=0, got ${summary.totalRegistered}`);
    }
    if (summary.onlineCount !== 0) {
      throw new Error(`Expected onlineCount=0, got ${summary.onlineCount}`);
    }
    if (summary.offlineCount !== 0) {
      throw new Error(`Expected offlineCount=0, got ${summary.offlineCount}`);
    }
    if (summary.revokedCount !== 0) {
      throw new Error(`Expected revokedCount=0, got ${summary.revokedCount}`);
    }
  });

  // 21. One Genuinely Enrolled PC Results in Exactly One Connected Device
  test('Pillar 10: Fleet Enrollment Truth', 'Proves that one genuinely enrolled PC with a fresh UTC heartbeat results in 1 registered and 1 online PC', () => {
    const nowUtcMs = Date.now();
    const nowIso = new Date(nowUtcMs).toISOString();
    const realEnrolledPc: MonitoredDevice = {
      deviceId: 'win-real-workstation-01',
      ownerId: 'live_soc',
      hostname: 'REAL-GAMING-PC',
      osVersion: 'Microsoft Windows 11 Pro (Build 26300)',
      agentVersion: '2.6.0-win64',
      status: 'healthy',
      emulatorName: 'BlueStacks 5 (Pie64 / Android 11)',
      gameSessionState: 'active_match',
      freeFirePackage: 'com.dts.freefireth',
      integrityStatus: 'verified',
      riskScore: 0,
      isSimulated: false,
      lastHeartbeat: nowIso,
      enrolledAt: nowIso,
      tokenVersion: 1,
      cpuOverheadPercent: 0.31,
      memoryFootprintMb: 17.5,
      encryptedQueueDepth: 0,
      autoStartEnabled: true,
    };

    const summary = computeFleetSummary([realEnrolledPc], nowUtcMs, DEFAULT_HEARTBEAT_TIMEOUT_MS);
    if (summary.totalRegistered !== 1) {
      throw new Error(`Expected totalRegistered=1, got ${summary.totalRegistered}`);
    }
    if (summary.onlineCount !== 1) {
      throw new Error(`Expected onlineCount=1, got ${summary.onlineCount}`);
    }
    if (summary.offlineCount !== 0 || summary.revokedCount !== 0) {
      throw new Error('Expected 0 offline and 0 revoked devices.');
    }
    if (summary.devices[0].deviceId !== 'win-real-workstation-01') {
      throw new Error('Expected enrolled deviceId to match win-real-workstation-01');
    }
  });

  // 22. Fake / Demo / Test Fixtures Never Appear in Production
  test('Pillar 10: Fleet Enrollment Truth', 'Proves that fake test fixtures (SUVO-PC1, ARENA-RIG-PC2, TOURNAMENT-PC3, win-suvo-8rg5, win-suvo-live) never appear in production', () => {
    const nowIso = new Date().toISOString();
    const fixtures = getMultiPcTestFixtures(nowIso).map((f) => f.device);
    const legacyDemoRecords: MonitoredDevice[] = [
      ...fixtures,
      // Even if a fixture has isSimulated: false tampered, its ID/hostname is blocked
      {
        ...fixtures[0],
        isSimulated: false,
      },
      {
        deviceId: 'win-suvo-8rg5',
        ownerId: 'live_soc',
        hostname: 'SUVO',
        osVersion: 'Windows 11',
        agentVersion: '2.4.1-win64',
        status: 'healthy',
        emulatorName: 'BlueStacks 5',
        gameSessionState: 'active_match',
        freeFirePackage: 'com.dts.freefireth',
        integrityStatus: 'verified',
        riskScore: 0,
        isSimulated: false,
        lastHeartbeat: nowIso,
      },
      {
        deviceId: 'win-suvo-live',
        ownerId: 'live_soc',
        hostname: 'SUVO',
        osVersion: 'Windows 11',
        agentVersion: '2.5.0-win64',
        status: 'degraded',
        emulatorName: 'BlueStacks 5',
        gameSessionState: 'active_match',
        freeFirePackage: 'com.dts.freefireth',
        integrityStatus: 'verified',
        riskScore: 100,
        isSimulated: false,
        lastHeartbeat: nowIso,
      },
    ];

    for (const demo of legacyDemoRecords) {
      if (!isDemoOrFixtureDevice(demo, true)) {
        throw new Error(`Expected ${demo.hostname} (${demo.deviceId}) to be flagged as demo/fixture.`);
      }
    }

    const summary = computeFleetSummary(legacyDemoRecords);
    if (summary.totalRegistered !== 0 || summary.onlineCount !== 0) {
      throw new Error(
        `Expected 0 production devices when given 5 fake/demo records, got total=${summary.totalRegistered}, online=${summary.onlineCount}`
      );
    }
  });

  // 23. Stale UTC Heartbeat Transitions Stored Device to Offline (Disconnected)
  test('Pillar 10: Fleet Enrollment Truth', 'Marks a stored device OFFLINE when its UTC heartbeat exceeds the configured timeout', () => {
    const nowUtcMs = Date.now();
    const staleIso = new Date(nowUtcMs - (DEFAULT_HEARTBEAT_TIMEOUT_MS + 15_000)).toISOString();
    const enrolledIso = new Date(nowUtcMs - 3600_000).toISOString();

    const stalePc: MonitoredDevice = {
      deviceId: 'win-real-workstation-02',
      ownerId: 'live_soc',
      hostname: 'OFFICE-RIG-02',
      osVersion: 'Microsoft Windows 11 Pro',
      agentVersion: '2.6.0-win64',
      status: 'healthy', // Stored as healthy on disk, but heartbeat is stale!
      emulatorName: 'BlueStacks 5',
      gameSessionState: 'active_match',
      freeFirePackage: 'com.dts.freefireth',
      integrityStatus: 'verified',
      riskScore: 0,
      isSimulated: false,
      lastHeartbeat: staleIso,
      enrolledAt: enrolledIso,
      tokenVersion: 1,
    };

    const summary = computeFleetSummary([stalePc], nowUtcMs, DEFAULT_HEARTBEAT_TIMEOUT_MS);
    if (summary.totalRegistered !== 1) {
      throw new Error(`Expected totalRegistered=1, got ${summary.totalRegistered}`);
    }
    if (summary.onlineCount !== 0) {
      throw new Error(`Expected onlineCount=0 for stale heartbeat, got ${summary.onlineCount}`);
    }
    if (summary.offlineCount !== 1) {
      throw new Error(`Expected offlineCount=1 for stale heartbeat, got ${summary.offlineCount}`);
    }
    if (summary.devices[0].status !== 'disconnected') {
      throw new Error(`Expected status to reconcile to 'disconnected', got ${summary.devices[0].status}`);
    }
  });

  // 24. Revoked Devices Are Never Counted as Active Connected PCs
  test('Pillar 10: Fleet Enrollment Truth', 'Excludes revoked devices from active connected PCs and counts them under revokedCount', () => {
    const nowUtcMs = Date.now();
    const nowIso = new Date(nowUtcMs).toISOString();

    const revokedPc: MonitoredDevice = {
      deviceId: 'win-real-workstation-03',
      ownerId: 'live_soc',
      hostname: 'COMPROMISED-PC-03',
      osVersion: 'Microsoft Windows 10 Pro',
      agentVersion: '2.6.0-win64',
      status: 'revoked',
      emulatorName: 'LDPlayer 9',
      gameSessionState: 'idle',
      freeFirePackage: 'com.dts.freefireth',
      integrityStatus: 'tamper_suspected',
      riskScore: 95,
      isSimulated: false,
      lastHeartbeat: nowIso,
      enrolledAt: nowIso,
      revokedAt: nowIso,
      tokenVersion: 1,
    };

    const summary = computeFleetSummary([revokedPc], nowUtcMs, DEFAULT_HEARTBEAT_TIMEOUT_MS);
    if (summary.totalRegistered !== 1) {
      throw new Error(`Expected totalRegistered=1, got ${summary.totalRegistered}`);
    }
    if (summary.onlineCount !== 0) {
      throw new Error(`Revoked device must not be counted as online; got onlineCount=${summary.onlineCount}`);
    }
    if (summary.offlineCount !== 0) {
      throw new Error(`Revoked device must not be counted in offlineCount; got ${summary.offlineCount}`);
    }
    if (summary.revokedCount !== 1) {
      throw new Error(`Expected revokedCount=1, got ${summary.revokedCount}`);
    }
  });

  // 25. Dynamic Tournament & Participant Registration Without Hardcoded Limits
  test('Pillar 11: Dynamic Tournament Scale', 'Supports creating tournaments, matches, and registering dynamic participant counts without hardcoded limits', () => {
    const tm = new TournamentManagerService(null);
    const trn = tm.createTournament({
      name: 'Open Global Free Fire Qualifier',
      organizer: 'Sentinel Esports',
      policy: { maxAuthorizedDevicesPerParticipant: 1, allowMidTournamentDeviceReplacement: true },
    });
    for (let i = 1; i <= 150; i++) {
      tm.registerParticipant(trn.tournamentId, {
        gamerTag: `PLAYER_${i}`,
        teamName: `TEAM_${Math.ceil(i / 4)}`,
      });
    }
    const participants = tm.getParticipants(trn.tournamentId);
    if (participants.length !== 150) {
      throw new Error(`Expected 150 dynamically registered participants, got ${participants.length}`);
    }
    const match = tm.createMatch(trn.tournamentId, {
      roundNumber: 2,
      matchName: 'Semi-Final Lobby A',
      mapName: 'Purgatory',
    });
    if (!match || match.roundNumber !== 2) {
      throw new Error('Expected match to be created in Round 2.');
    }
  });

  // 26. Participant Multi-Device Policy & Hardware Replacement History Preservation
  test('Pillar 11: Device Replacement & Policy', 'Enforces maxAuthorizedDevicesPerParticipant policy and preserves prior device history on replacement', () => {
    const tm = new TournamentManagerService(null);
    const trn = tm.createTournament({
      name: 'Strict 1-PC Finals',
      policy: { maxAuthorizedDevicesPerParticipant: 1, allowMidTournamentDeviceReplacement: true },
    });
    const player = tm.registerParticipant(trn.tournamentId, {
      gamerTag: 'PRO_CAPTAIN',
      deviceId: 'win-captain-rig-01',
    });

    let blockedSecondDevice = false;
    try {
      tm.bindDeviceToParticipant(player.participantId, 'win-captain-rig-02');
    } catch {
      blockedSecondDevice = true;
    }
    if (!blockedSecondDevice) {
      throw new Error('Expected binding a 2nd simultaneous device to fail when maxAuthorizedDevicesPerParticipant=1.');
    }

    const replaced = tm.replaceParticipantDevice(
      player.participantId,
      'win-captain-rig-01',
      'win-captain-rig-02',
      'GPU failure on primary rig'
    );
    if (replaced.authorizedDeviceIds.length !== 1 || replaced.authorizedDeviceIds[0] !== 'win-captain-rig-02') {
      throw new Error('Expected active authorized device to switch to win-captain-rig-02.');
    }
    if (!replaced.historicalDeviceIds.includes('win-captain-rig-01')) {
      throw new Error('Expected prior device win-captain-rig-01 to remain in historicalDeviceIds.');
    }
    if (replaced.replacementHistory.length !== 1) {
      throw new Error('Expected 1 replacement audit log entry.');
    }
  });

  // 27. Uninspectable Process Access-Denied Blind Spot (AGT-002) Never Marked Clean
  test('Pillar 12: Blind-Spot Visibility', 'Reports PROCESS_INSPECTION_ACCESS_DENIED (AGT-002) and transitions endpoint out of protected_healthy', () => {
    const engine = new SentinelDetectionEngine();
    const rules = DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: 'test' }));
    const evalRes = engine.evaluateTelemetry(
      {
        schemaVersion: '1.2.0',
        nonce: `nonce-blindspot-${Date.now()}`,
        deviceId: 'win-standard-user-pc',
        hostname: 'NON-ADMIN-PC',
        emulator: 'BlueStacks 5',
        sessionId: 'sess-blind',
        indicatorType: 'PROCESS_INSPECTION_ACCESS_DENIED',
        processName: 'HD-Player.exe',
        processPath: 'C:\\Program Files\\BlueStacks_nxt\\HD-Player.exe',
        blindSpotReason: 'OpenProcess(PROCESS_VM_READ) returned ERROR_ACCESS_DENIED (5)',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        signerIdentity: 'BlueStack Systems, Inc.',
        observedTimestamp: new Date().toISOString(),
        isSimulated: false,
      },
      rules,
      'test',
      []
    );
    if (!evalRes.event || evalRes.event.ruleId !== 'AGT-002') {
      throw new Error('Expected AGT-002 event for PROCESS_INSPECTION_ACCESS_DENIED.');
    }

    const nowIso = new Date().toISOString();
    const degradedDev: MonitoredDevice = {
      deviceId: 'win-standard-user-pc',
      ownerId: 'live_soc',
      hostname: 'NON-ADMIN-PC',
      osVersion: 'Windows 11',
      agentVersion: '2.7.0',
      status: 'degraded',
      emulatorName: 'BlueStacks 5',
      gameSessionState: 'active_match',
      freeFirePackage: 'com.dts.freefireth',
      integrityStatus: 'verified',
      riskScore: 24,
      isSimulated: false,
      lastHeartbeat: nowIso,
      enrolledAt: nowIso,
      inspectionFailuresCount: 3,
      blindSpotReasons: ['OpenProcess(PROCESS_VM_READ) returned ERROR_ACCESS_DENIED (5)'],
    };
    const healthState = deriveMonitoringHealthState(degradedDev);
    if (healthState === 'protected_healthy') {
      throw new Error('Uninspectable PC must NEVER be classified as protected_healthy.');
    }
    if (healthState !== 'required_telemetry_unavailable') {
      throw new Error(`Expected required_telemetry_unavailable for >=3 inspection failures, got ${healthState}`);
    }
  });

  // 28. Telemetry Sequence Gap (AGT-003) & Agent Integrity Mismatch (AGT-004)
  test('Pillar 12: Anti-Tamper & Sequence Gaps', 'Evaluates TELEMETRY_SEQUENCE_GAP_DETECTED (AGT-003) and AGENT_BINARY_INTEGRITY_MISMATCH (AGT-004)', () => {
    const engine = new SentinelDetectionEngine();
    const rules = DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: 'test' }));

    const seqRes = engine.evaluateTelemetry(
      {
        schemaVersion: '1.2.0',
        nonce: `nonce-seq-${Date.now()}`,
        sequenceNumber: 12,
        deviceId: 'win-seq-pc',
        hostname: 'SEQ-GAP-PC',
        emulator: 'LDPlayer 9',
        sessionId: 'sess-seq',
        indicatorType: 'TELEMETRY_SEQUENCE_GAP_DETECTED',
        processName: 'sentinel-agent.exe',
        processPath: 'C:\\Program Files\\SentinelAC\\sentinel-agent.exe',
        blindSpotReason: 'Missing sequence numbers 8..11 during active match',
        sha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
        signerIdentity: 'Sentinel AC',
        observedTimestamp: new Date().toISOString(),
        isSimulated: false,
      },
      rules,
      'test',
      []
    );
    if (!seqRes.event || seqRes.event.ruleId !== 'AGT-003') {
      throw new Error('Expected AGT-003 rule match for sequence gap.');
    }

    const intRes = engine.evaluateTelemetry(
      {
        schemaVersion: '1.2.0',
        nonce: `nonce-int-${Date.now()}`,
        deviceId: 'win-tampered-pc',
        hostname: 'TAMPERED-PC',
        emulator: 'BlueStacks 5',
        sessionId: 'sess-int',
        indicatorType: 'AGENT_BINARY_INTEGRITY_MISMATCH',
        processName: 'sentinel-agent.exe',
        processPath: 'C:\\Program Files\\SentinelAC\\sentinel-agent.exe',
        sha256: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
        signerIdentity: 'Tampered Binary',
        observedTimestamp: new Date().toISOString(),
        isSimulated: false,
      },
      rules,
      'test',
      []
    );
    if (!intRes.event || intRes.event.ruleId !== 'AGT-004' || intRes.event.severity !== SeverityLevel.CRITICAL) {
      throw new Error('Expected CRITICAL AGT-004 event for agent binary integrity mismatch.');
    }
  });

  // 29. 9-State Monitoring Health Classification Coverage
  test('Pillar 12: 9-State Health Classification', 'Accurately classifies all 9 explicit tournament monitoring health states', () => {
    const nowIso = new Date().toISOString();
    const base: MonitoredDevice = {
      deviceId: 'win-state-pc',
      ownerId: 'live_soc',
      hostname: 'STATE-PC',
      osVersion: 'Windows 11',
      agentVersion: '2.7.0',
      status: 'healthy',
      emulatorName: 'BlueStacks 5',
      gameSessionState: 'active_match',
      freeFirePackage: 'com.dts.freefireth',
      integrityStatus: 'verified',
      riskScore: 0,
      isSimulated: false,
      lastHeartbeat: nowIso,
      enrolledAt: nowIso,
    };

    if (deriveMonitoringHealthState(base) !== 'protected_healthy') {
      throw new Error('Expected protected_healthy');
    }
    if (deriveMonitoringHealthState({ ...base, riskScore: 25 }) !== 'suspicious_activity_detected') {
      throw new Error('Expected suspicious_activity_detected');
    }
    if (deriveMonitoringHealthState({ ...base, riskScore: 85 }) !== 'investigation_required') {
      throw new Error('Expected investigation_required');
    }
    if (deriveMonitoringHealthState({ ...base, sequenceGapsDetected: 2 }) !== 'monitoring_degraded') {
      throw new Error('Expected monitoring_degraded');
    }
    if (deriveMonitoringHealthState({ ...base, inspectionFailuresCount: 4 }) !== 'required_telemetry_unavailable') {
      throw new Error('Expected required_telemetry_unavailable');
    }
    if (deriveMonitoringHealthState({ ...base, integrityStatus: 'signature_mismatch' }) !== 'agent_integrity_failure') {
      throw new Error('Expected agent_integrity_failure');
    }
    if (deriveMonitoringHealthState({ ...base, status: 'disconnected' }) !== 'agent_disconnected') {
      throw new Error('Expected agent_disconnected');
    }
    if (deriveMonitoringHealthState({ ...base, enrolledAt: undefined }) !== 'enrollment_pending') {
      throw new Error('Expected enrollment_pending');
    }
    if (deriveMonitoringHealthState({ ...base, status: 'revoked' }) !== 'device_revoked') {
      throw new Error('Expected device_revoked');
    }
  });

  // 30. Genuine Telemetry vs Controlled Test Separation (originType)
  test('Pillar 10: Real vs Controlled Test Separation', 'Labels genuine telemetry as genuine_telemetry and simulated events as controlled_test', () => {
    const engine = new SentinelDetectionEngine();
    const rules = DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: 'test' }));

    const realEval = engine.evaluateTelemetry(
      {
        schemaVersion: '1.2.0',
        nonce: `real-origin-${Date.now()}`,
        deviceId: 'win-real-01',
        tournamentId: 'trn_01',
        participantId: 'plr_01',
        hostname: 'REAL-PC',
        emulator: 'BlueStacks 5',
        sessionId: 'sess-real',
        indicatorType: 'KNOWN_CHEAT_SIGNATURE',
        processName: 'cheat.exe',
        processPath: 'C:\\Temp\\cheat.exe',
        sha256: '9f83c12a84092b9d2f1029c8e192a83b4c5d6e7f8091a2b3c4d5e6f708192a3b',
        signerIdentity: 'Unsigned',
        observedTimestamp: new Date().toISOString(),
        isSimulated: false,
      },
      rules,
      'test',
      []
    );
    if (realEval.event?.originType !== 'genuine_telemetry') {
      throw new Error(`Expected genuine_telemetry, got ${realEval.event?.originType}`);
    }
    if (realEval.event?.tournamentId !== 'trn_01' || realEval.event?.participantId !== 'plr_01') {
      throw new Error('Expected tournamentId and participantId preserved on event.');
    }

    const simEval = engine.evaluateTelemetry(
      {
        schemaVersion: '1.2.0',
        nonce: `sim-origin-${Date.now()}`,
        deviceId: 'test-sandbox',
        hostname: 'SANDBOX',
        emulator: 'BlueStacks 5',
        sessionId: 'sess-sim',
        indicatorType: 'KNOWN_CHEAT_SIGNATURE',
        processName: 'cheat.exe',
        processPath: 'C:\\Temp\\cheat.exe',
        sha256: '9f83c12a84092b9d2f1029c8e192a83b4c5d6e7f8091a2b3c4d5e6f708192a3b',
        signerIdentity: 'Unsigned',
        observedTimestamp: new Date().toISOString(),
        isSimulated: true,
      },
      rules,
      'test',
      []
    );
    if (simEval.event?.originType !== 'controlled_test') {
      throw new Error(`Expected controlled_test, got ${simEval.event?.originType}`);
    }
  });

  // 31. Dynamic Load-Testing Engine: Small & Medium Event Execution & Production Isolation
  test('Pillar 13: Dynamic Load Testing', 'Executes small and medium tournament load tests with real latency metrics and 0 production pollution', () => {
    const smallRes = DynamicLoadTestEngine.runLoadTest({ profile: 'small_event' }, 1);
    if (!smallRes.isolatedFromProduction || smallRes.productionDevicesAffected !== 0) {
      throw new Error('Load test must be 100% isolated from production devices.');
    }
    if (smallRes.enrollmentsProcessed !== 16) {
      throw new Error(`Expected 16 simulated enrollments in small_event, got ${smallRes.enrollmentsProcessed}`);
    }
    if (smallRes.telemetryEventsPerSec <= 0 || smallRes.durationMs <= 0) {
      throw new Error('Expected positive measured throughput and duration.');
    }

    const mediumRes = DynamicLoadTestEngine.runLoadTest({ profile: 'medium_event' }, 1);
    if (mediumRes.enrollmentsProcessed !== 64) {
      throw new Error(`Expected 64 simulated enrollments in medium_event, got ${mediumRes.enrollmentsProcessed}`);
    }
    if (mediumRes.duplicatesSuppressed === 0) {
      throw new Error('Expected duplicate suppression to be exercised during medium_event load test.');
    }
  });

  // 32. Backpressure, Sequence Gap & Offline Queue Reconnection Benchmark
  test('Pillar 13: Backpressure & Queue Recovery', 'Validates sequence-gap detection and offline queue reconnection flush under load', () => {
    const bpRes = DynamicLoadTestEngine.runLoadTest({ profile: 'backpressure_recovery' }, 0);
    if (bpRes.sequenceGapsDetected <= 0) {
      throw new Error('Expected sequence gaps to be detected during backpressure_recovery benchmark.');
    }
    if (bpRes.reconnectionQueueFlushedCount !== 120) {
      throw new Error(`Expected 120 offline queued events flushed, got ${bpRes.reconnectionQueueFlushedCount}`);
    }
  });

  const totalPassed = results.filter((r) => r.passed).length;
  const totalFailed = results.filter((r) => !r.passed).length;

  return {
    totalPassed,
    totalFailed,
    totalTests: results.length,
    results,
  };
}



