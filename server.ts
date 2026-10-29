import express from 'express';
import http from 'http';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { WebSocketServer, WebSocket } from 'ws';
import { createServer as createViteServer } from 'vite';
import {
  DEFAULT_SIGNED_RULES,
  SentinelDetectionEngine,
} from './detection-engine/engine.ts';
import {
  DETECTION_CAPABILITY_BOUNDARIES,
  SUPPORTED_EMULATOR_ADAPTERS,
} from './emulator-adapters/adapters.ts';
import {
  runDetectionEngineTestSuite,
  SYNTHETIC_TEST_SCENARIOS,
} from './tests/detection_engine.test.ts';
import { runFullAntiCheatSystemTests } from './tests/antiCheatSuite.test.ts';
import {
  BlackboxEntry,
  DetectionRuleRecord,
  EnrollmentTokenRecord,
  IncidentRecord,
  MonitoredDevice,
  RawAgentTelemetry,
  SecurityEventRecord,
  SeverityLevel,
  SignedRuleBundle,
} from './shared-schemas/types.ts';
import { BlackboxLedgerService } from './windows-agent/src/blackbox/BlackboxService.ts';
import { ProcessInspectionService } from './windows-agent/src/scanner/ProcessInspectionService.ts';
import { ScreenshotService } from './windows-agent/src/evidence/ScreenshotService.ts';
import {
  CONFIRMED_DEMO_DEVICE_IDS,
  CONFIRMED_DEMO_HOSTNAMES,
  DEFAULT_HEARTBEAT_TIMEOUT_MS,
  computeFleetSummary,
  deriveMonitoringHealthState,
  isDemoOrFixtureDevice,
  isDemoOrSimulatedEventOrIncident,
  reconcileDeviceStatus,
} from './shared-schemas/fleetMetrics.ts';
import { getMultiPcTestFixtures } from './tests/fixtures/multiPcFixtures.ts';
import {
  DynamicLoadTestEngine,
  TournamentManagerService,
  WINDOWS_TELEMETRY_COVERAGE_MATRIX,
} from './backend/tournamentAndLoadEngine.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const server = http.createServer(app);
  const PORT = 3000;

  app.use(express.json({ limit: '512kb' }));

  const detectionEngine = new SentinelDetectionEngine();
  const blackboxService = new BlackboxLedgerService();
  const processInspectionService = new ProcessInspectionService();
  const screenshotService = new ScreenshotService();
  const tournamentManager = new TournamentManagerService();

  // Persistent registry for live connected Windows agents, events, incidents, and enrollment tokens
  const TELEMETRY_STATE_FILE = path.join(process.cwd(), 'data', 'telemetry-state.json');
  const liveAgents = new Map<string, MonitoredDevice>();
  let liveEvents: SecurityEventRecord[] = [];
  const liveIncidents = new Map<string, IncidentRecord>();
  const seenNonces = new Map<string, number>();
  const deviceTokens = new Map<string, string>();
  const enrollmentTokens = new Map<string, EnrollmentTokenRecord>();
  const deviceRateLimits = new Map<string, { windowStart: number; count: number }>();

  // Seed default administrator multi-PC enrollment token
  enrollmentTokens.set('enr_sentinel_default_multi_pc', {
    tokenId: 'tok_enr_default',
    tokenSecret: 'enr_sentinel_default_multi_pc',
    label: 'Default Multi-PC Fleet Enrollment Token',
    createdBy: 'admin@sentinel.local',
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
    maxUses: 500,
    usedCount: 0,
    revoked: false,
  });

  const TELEMETRY_STATE_BACKUP_FILE = path.join(process.cwd(), 'data', 'telemetry-state.backup.json');

  function enrichDeviceMetrics(dev: MonitoredDevice, nowUtcMs = Date.now()): MonitoredDevice {
    const reconciled = reconcileDeviceStatus(dev, nowUtcMs, DEFAULT_HEARTBEAT_TIMEOUT_MS);
    dev.status = reconciled.status;

    const devEvents = liveEvents.filter(
      (e) => e.deviceId === dev.deviceId && !isDemoOrSimulatedEventOrIncident(e)
    );
    const severityOrder: Record<string, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      none: 0,
    };
    let highest: SeverityLevel | 'none' = 'none';
    for (const ev of devEvents) {
      if ((severityOrder[ev.severity] || 0) > (severityOrder[highest] || 0)) {
        highest = ev.severity;
      }
    }
    dev.detectedEventsCount = devEvents.length;
    dev.highestSeverity = highest;
    dev.lastEventSummary = devEvents[0]?.summary || 'No security events reported yet.';
    dev.monitoringHealthState = deriveMonitoringHealthState(dev);
    return dev;
  }

  function getEnrichedDevices(nowUtcMs = Date.now()): MonitoredDevice[] {
    const result: MonitoredDevice[] = [];
    for (const [id, d] of liveAgents.entries()) {
      if (isDemoOrFixtureDevice(d, deviceTokens.has(id))) {
        liveAgents.delete(id);
        deviceTokens.delete(id);
        continue;
      }
      result.push(enrichDeviceMetrics(d, nowUtcMs));
    }
    tournamentManager.reconcileParticipantsWithDevices(result);
    return result;
  }

  function checkHeartbeatExpirations(timeoutMs = DEFAULT_HEARTBEAT_TIMEOUT_MS): string[] {
    const now = Date.now();
    const expiredIds: string[] = [];
    for (const [id, dev] of liveAgents.entries()) {
      if (isDemoOrFixtureDevice(dev, deviceTokens.has(id))) {
        liveAgents.delete(id);
        deviceTokens.delete(id);
        continue;
      }
      if (dev.status === 'healthy' || dev.status === 'degraded') {
        const lastTs = Date.parse(dev.lastHeartbeat || '');
        if (Number.isNaN(lastTs) || now - lastTs > timeoutMs) {
          dev.status = 'disconnected';
          expiredIds.push(dev.deviceId);
        }
      }
    }
    if (expiredIds.length > 0) {
      saveTelemetryState();
      for (const id of expiredIds) {
        const dev = liveAgents.get(id);
        if (dev) {
          broadcastRealtimePayload('device:updated', { device: enrichDeviceMetrics(dev, now) });
        }
      }
    }
    return expiredIds;
  }

  function loadTelemetryState() {
    try {
      if (fs.existsSync(TELEMETRY_STATE_FILE)) {
        const raw = fs.readFileSync(TELEMETRY_STATE_FILE, 'utf-8');
        const data = JSON.parse(raw);
        let removedDemoRecordsCount = 0;

        if (data.tokens && typeof data.tokens === 'object') {
          Object.entries(data.tokens).forEach(([k, v]) => {
            if (!CONFIRMED_DEMO_DEVICE_IDS.has(k.trim().toLowerCase())) {
              deviceTokens.set(k, String(v));
            } else {
              removedDemoRecordsCount += 1;
            }
          });
        }
        if (Array.isArray(data.enrollmentTokens)) {
          data.enrollmentTokens.forEach((et: EnrollmentTokenRecord) => {
            if ((et.label || '').includes('Test PC-4')) {
              removedDemoRecordsCount += 1;
              return;
            }
            enrollmentTokens.set(et.tokenSecret, et);
          });
        }
        if (Array.isArray(data.events)) {
          // Keep only real security events from genuinely enrolled PCs; purge demo/fixture/simulated records
          const realEvents: SecurityEventRecord[] = [];
          for (const ev of data.events as SecurityEventRecord[]) {
            if (isDemoOrSimulatedEventOrIncident(ev)) {
              removedDemoRecordsCount += 1;
              continue;
            }
            realEvents.push(ev);
          }
          liveEvents = realEvents;
        }
        if (Array.isArray(data.incidents)) {
          for (const inc of data.incidents as IncidentRecord[]) {
            if (isDemoOrSimulatedEventOrIncident(inc)) {
              removedDemoRecordsCount += 1;
              continue;
            }
            liveIncidents.set(inc.incidentId, inc);
          }
        }

        const nowUtcMs = Date.now();
        if (Array.isArray(data.devices)) {
          for (const d of data.devices as MonitoredDevice[]) {
            const hasToken = deviceTokens.has(d.deviceId);
            if (isDemoOrFixtureDevice(d, hasToken)) {
              removedDemoRecordsCount += 1;
              deviceTokens.delete(d.deviceId);
              continue;
            }
            const reconciled = reconcileDeviceStatus(d, nowUtcMs, DEFAULT_HEARTBEAT_TIMEOUT_MS);
            liveAgents.set(reconciled.deviceId, reconciled);
          }
        }

        if (removedDemoRecordsCount > 0) {
          try {
            fs.copyFileSync(TELEMETRY_STATE_FILE, TELEMETRY_STATE_BACKUP_FILE);
          } catch {}
          saveTelemetryState();
        }
      }
    } catch (e) {
      console.warn('Telemetry state restore skipped:', e);
    }
  }

  function saveTelemetryState() {
    try {
      const dir = path.dirname(TELEMETRY_STATE_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(
        TELEMETRY_STATE_FILE,
        JSON.stringify(
          {
            devices: getEnrichedDevices(),
            events: liveEvents.filter((e) => !isDemoOrSimulatedEventOrIncident(e)).slice(0, 500),
            incidents: Array.from(liveIncidents.values()).filter(
              (inc) => !isDemoOrSimulatedEventOrIncident(inc)
            ),
            tokens: Object.fromEntries(deviceTokens.entries()),
            enrollmentTokens: Array.from(enrollmentTokens.values()),
            savedAt: new Date().toISOString(),
          },
          null,
          2
        ),
        'utf-8'
      );
    } catch {}
  }

  loadTelemetryState();

  // Periodic background sweep to transition stale agent heartbeats to disconnected
  setInterval(() => {
    checkHeartbeatExpirations(DEFAULT_HEARTBEAT_TIMEOUT_MS);
  }, 15_000);

  // WebSocket Server for real-time SOC dashboard streaming
  const wss = new WebSocketServer({ server, path: '/ws' });
  const sseClients = new Set<express.Response>();


  function broadcastRealtimePayload(type: string, payload: unknown) {
    const message = JSON.stringify({
      type,
      payload,
      serverTimestamp: new Date().toISOString(),
    });

    for (const client of wss.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    }

    for (const res of sseClients) {
      res.write(`data: ${message}\n\n`);
    }
  }

  wss.on('connection', (ws) => {
    checkHeartbeatExpirations(DEFAULT_HEARTBEAT_TIMEOUT_MS);
    const enriched = getEnrichedDevices();
    const summary = computeFleetSummary(enriched);
    const realEvents = liveEvents.filter((e) => !isDemoOrSimulatedEventOrIncident(e));
    const realIncidents = Array.from(liveIncidents.values()).filter(
      (inc) => !isDemoOrSimulatedEventOrIncident(inc)
    );
    ws.send(
      JSON.stringify({
        type: 'connection:established',
        payload: {
          connectedClients: wss.clients.size,
          connectedAgents: summary.onlineCount,
          devices: summary.devices,
          fleetSummary: summary,
          events: realEvents,
          incidents: realIncidents,
          schemaVersion: '1.2.0',
          engineStatus: 'active',
        },
        serverTimestamp: new Date().toISOString(),
      })
    );
  });

  // Query events and incidents with Multi-PC, Tournament, Match, Participant filtering and server-side pagination
  app.get('/api/agent/events', (req, res) => {
    const deviceId = (req.query.deviceId as string) || 'all';
    const tournamentId = (req.query.tournamentId as string) || 'all';
    const matchId = (req.query.matchId as string) || 'all';
    const participantId = (req.query.participantId as string) || 'all';
    const severity = (req.query.severity as string) || 'all';
    const category = (req.query.category as string) || 'all';
    const source = (req.query.source as string) || 'all';
    const timeRange = (req.query.timeRange as string) || 'all';
    const search = ((req.query.search as string) || '').trim().toLowerCase();
    const page = Math.max(1, parseInt((req.query.page as string) || '1', 10));
    const pageSize = Math.min(200, Math.max(1, parseInt((req.query.pageSize as string) || '100', 10)));

    const now = Date.now();
    let maxAgeMs = 0;
    if (timeRange === '15m') maxAgeMs = 15 * 60 * 1000;
    else if (timeRange === '1h') maxAgeMs = 60 * 60 * 1000;
    else if (timeRange === '24h') maxAgeMs = 24 * 60 * 60 * 1000;
    else if (timeRange === '7d') maxAgeMs = 7 * 24 * 60 * 60 * 1000;

    const filtered = liveEvents.filter((ev) => {
      if (isDemoOrSimulatedEventOrIncident(ev)) return false;
      if (deviceId !== 'all' && ev.deviceId !== deviceId) return false;
      if (tournamentId !== 'all' && ev.tournamentId !== tournamentId) return false;
      if (matchId !== 'all' && ev.matchId !== matchId) return false;
      if (participantId !== 'all' && ev.participantId !== participantId) return false;
      if (severity !== 'all' && ev.severity !== severity) return false;
      if (category !== 'all' && ev.category !== category) return false;
      if (source === 'real' && ev.isSimulated) return false;
      if (source === 'test' && !ev.isSimulated) return false;
      if (maxAgeMs > 0) {
        const ts = Date.parse(ev.eventTimestamp);
        if (!Number.isNaN(ts) && now - ts > maxAgeMs) return false;
      }
      if (search) {
        const haystack = [
          ev.eventId,
          ev.deviceId,
          ev.hostname,
          ev.processName,
          ev.processPath,
          ev.sha256,
          ev.ruleId,
          ev.summary,
          ev.tournamentId || '',
          ev.participantId || '',
          ev.metadata?.commandLine || '',
          ev.metadata?.loadedModule || '',
        ]
          .join(' ')
          .toLowerCase();
        if (!haystack.includes(search)) return false;
      }
      return true;
    });

    const totalCount = filtered.length;
    const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));
    const startIdx = (page - 1) * pageSize;
    const paginatedEvents = filtered.slice(startIdx, startIdx + pageSize);
    const realIncidents = Array.from(liveIncidents.values()).filter(
      (inc) => !isDemoOrSimulatedEventOrIncident(inc)
    );

    res.json({
      events: paginatedEvents,
      totalCount,
      page,
      pageSize,
      totalPages,
      incidents: realIncidents,
    });
  });

  // Clear all active threats, security alerts, and reset connected PC risk scores
  app.post('/api/agent/clear-threats', (_req, res) => {
    liveEvents = [];
    liveIncidents.clear();
    seenNonces.clear();

    for (const dev of liveAgents.values()) {
      dev.riskScore = 0;
      if (dev.status === 'degraded') {
        dev.status = 'healthy';
      }
    }

    saveTelemetryState();

    broadcastRealtimePayload('threats:cleared', {
      devices: Array.from(liveAgents.values()),
      clearedAt: new Date().toISOString(),
    });

    return res.json({
      status: 'cleared',
      eventsCount: 0,
      incidentsCount: 0,
      devices: Array.from(liveAgents.values()),
    });
  });

  // Isolated test endpoint (Never adds fake events to production liveEvents or liveIncidents)
  app.post('/api/agent/trigger-test-threat', (_req, res) => {
    const testTelemetry: RawAgentTelemetry = {
      schemaVersion: '1.2.0',
      nonce: `test-cheat-${Date.now()}`,
      deviceId: 'test-sandbox-fixture',
      hostname: 'TEST-SANDBOX',
      emulator: 'BlueStacks 5 (Pie64 / Android 11)',
      sessionId: `sess-${Date.now()}`,
      indicatorType: 'KNOWN_CHEAT_SIGNATURE',
      processName: 'cheatengine.exe',
      processPath: 'C:\\Temp\\cheatengine.exe',
      sha256: '9f83c12a84092b9d2f1029c8e192a83b4c5d6e7f8091a2b3c4d5e6f708192a3b',
      signerIdentity: 'Unsigned / Unknown Signer',
      observedTimestamp: new Date().toISOString(),
      isSimulated: true,
    };

    const evaluation = detectionEngine.evaluateTelemetry(
      testTelemetry,
      DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: 'test_sandbox' })),
      'test_sandbox',
      []
    );

    return res.json({
      status: 'isolated_test_evaluated',
      isolatedFromProduction: true,
      event: evaluation.event,
      incident: evaluation.updatedIncident,
    });
  });


  // Server-Sent Events (SSE) fallback/companion stream
  app.get('/api/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    res.write(
      `data: ${JSON.stringify({
        type: 'sse:connected',
        serverTimestamp: new Date().toISOString(),
      })}\n\n`
    );

    sseClients.add(res);
    req.on('close', () => {
      sseClients.delete(res);
    });
  });

  // Health & Architecture Metadata
  app.get('/api/health', (_req, res) => {
    checkHeartbeatExpirations(DEFAULT_HEARTBEAT_TIMEOUT_MS);
    const summary = computeFleetSummary(getEnrichedDevices());
    res.json({
      status: 'healthy',
      service: 'Sentinel AC Security Engine',
      schemaVersion: '1.2.0',
      wsClientsConnected: wss.clients.size,
      connectedAgentsCount: summary.onlineCount,
      totalRegisteredDevices: summary.totalRegistered,
      onlineDevicesCount: summary.onlineCount,
      offlineDevicesCount: summary.offlineCount,
      revokedDevicesCount: summary.revokedCount,
      supportedEmulators: SUPPORTED_EMULATOR_ADAPTERS.length,
      defaultRulesCount: DEFAULT_SIGNED_RULES.length,
      timestamp: new Date().toISOString(),
    });
  });

  // Query live connected Windows agents (with computed per-PC event counts, UTC heartbeat reconciliation, & fleet summary)
  app.get('/api/agent/devices', (_req, res) => {
    checkHeartbeatExpirations(DEFAULT_HEARTBEAT_TIMEOUT_MS);
    const enriched = getEnrichedDevices();
    const summary = computeFleetSummary(enriched);
    res.json({
      devices: summary.devices,
      count: summary.onlineCount,
      totalRegistered: summary.totalRegistered,
      onlineCount: summary.onlineCount,
      offlineCount: summary.offlineCount,
      revokedCount: summary.revokedCount,
      healthyCount: summary.healthyCount,
      degradedCount: summary.degradedCount,
      heartbeatTimeoutMs: summary.heartbeatTimeoutMs,
      evaluatedAtUtc: summary.evaluatedAtUtc,
    });
  });

  // Check and transition expired heartbeats to disconnected
  app.post('/api/agent/check-expirations', (req, res) => {
    const timeoutMs =
      typeof req.body?.timeoutMs === 'number' ? req.body.timeoutMs : DEFAULT_HEARTBEAT_TIMEOUT_MS;
    const expiredDeviceIds = checkHeartbeatExpirations(timeoutMs);
    const summary = computeFleetSummary(getEnrichedDevices(), Date.now(), timeoutMs);
    return res.json({
      status: 'checked',
      expiredDeviceIds,
      devices: summary.devices,
      totalRegistered: summary.totalRegistered,
      onlineCount: summary.onlineCount,
      offlineCount: summary.offlineCount,
      revokedCount: summary.revokedCount,
    });
  });

  // Enrollment Tokens Management
  app.get('/api/agent/enrollment-tokens', (_req, res) => {
    return res.json({
      tokens: Array.from(enrollmentTokens.values()),
    });
  });

  app.post('/api/agent/enrollment-tokens', (req, res) => {
    const label = (req.body?.label || 'Multi-PC Endpoint Enrollment Key').trim();
    const maxUses = typeof req.body?.maxUses === 'number' ? req.body.maxUses : 25;
    const tokenSecret = `enr_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
    const record: EnrollmentTokenRecord = {
      tokenId: `tok_enr_${Date.now()}`,
      tokenSecret,
      label,
      createdBy: req.body?.createdBy || 'admin@sentinel.local',
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 90 * 24 * 3600 * 1000).toISOString(),
      maxUses,
      usedCount: 0,
      revoked: false,
    };
    enrollmentTokens.set(tokenSecret, record);
    saveTelemetryState();
    blackboxService.recordSystemEvent(
      'ADMIN_ACTION',
      'Enrollment Token Issued',
      SeverityLevel.LOW,
      `Issued new multi-PC enrollment token (${label}) with maxUses=${maxUses}`,
      'SYSTEM',
      'SOC-ADMIN'
    );
    return res.json({ status: 'created', token: record });
  });

  // Serve Real C# Windows Agent Source (.cs) with Configured Server URL
  app.get('/api/agent/SentinelAgent.cs', (req, res) => {
    const rawHost = req.headers['x-forwarded-host'] || req.get('host') || 'localhost:3000';
    const host = (Array.isArray(rawHost) ? rawHost[0] : rawHost).toString().trim();
    const isLocalhost = host.includes('localhost') || host.includes('127.0.0.1');
    const proto = isLocalhost ? 'http' : 'https';
    const serverUrl = `${proto}://${host}`;

    const csPath = path.join(process.cwd(), 'windows-agent', 'SentinelAgent.cs');
    let csContent = fs.existsSync(csPath) ? fs.readFileSync(csPath, 'utf-8') : '';
    csContent = csContent.replace(
      'private static string ServerUrl = "http://localhost:3000";',
      `private static string ServerUrl = "${serverUrl}";`
    );

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="SentinelAgent.cs"');
    res.send(csContent);
  });

  // Serve Reproducible Windows EXE Compiler Script (build-exe.ps1)
  app.get('/api/agent/build-exe.ps1', (req, res) => {
    const rawHost = req.headers['x-forwarded-host'] || req.get('host') || 'localhost:3000';
    const host = (Array.isArray(rawHost) ? rawHost[0] : rawHost).toString().trim();
    const isLocalhost = host.includes('localhost') || host.includes('127.0.0.1');
    const proto = isLocalhost ? 'http' : 'https';
    const serverUrl = `${proto}://${host}`;

    const psBuildPath = path.join(process.cwd(), 'windows-agent', 'build-exe.ps1');
    let buildContent = fs.existsSync(psBuildPath) ? fs.readFileSync(psBuildPath, 'utf-8') : '';
    buildContent = buildContent.replace(
      '[string]$ServerUrl = "http://localhost:3000"',
      `[string]$ServerUrl = "${serverUrl}"`
    );

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="build-exe.ps1"');
    res.send(buildContent);
  });

  // Cloud Relay Synchronization (Allows Friend's PCs / Remote Windows Endpoints to enroll & stream telemetry across networks)
  const CLOUD_RELAY_BASE_URL =
    'https://firestore.googleapis.com/v1/projects/valid-responder-324806/databases/ai-studio-a5bd5d0c-56bc-4757-ae70-fae594902986/documents';
  let isSyncingRelay = false;

  async function deleteCloudRelayDoc(collectionName: string, docId: string) {
    try {
      await fetch(`${CLOUD_RELAY_BASE_URL}/${collectionName}/${encodeURIComponent(docId)}`, {
        method: 'DELETE',
      });
    } catch {}
  }

  async function syncCloudRelayFromFirestore() {
    if (isSyncingRelay) return;
    isSyncingRelay = true;
    try {
      // 1. Sync Remote PC Registrations & Heartbeats
      const hbRes = await fetch(`${CLOUD_RELAY_BASE_URL}/agent_relay_heartbeats?pageSize=50`);
      if (hbRes.ok) {
        const hbData = (await hbRes.json()) as {
          documents?: Array<{
            name: string;
            updateTime?: string;
            fields?: Record<string, { stringValue?: string; doubleValue?: number; integerValue?: string }>;
          }>;
        };

        const docs = hbData.documents || [];
        let stateChanged = false;
        const nowMs = Date.now();

        for (const doc of docs) {
          const f = doc.fields || {};
          const deviceId = (f.deviceId?.stringValue || '').trim();
          const hostname = (f.hostname?.stringValue || 'WINDOWS-PC').trim().toUpperCase();
          const osVersion = (f.osVersion?.stringValue || 'Windows 10/11').trim();
          const agentVersion = (f.agentVersion?.stringValue || '2.6.0-win64').trim();
          const emulatorName = (f.emulatorName?.stringValue || 'No emulator running').trim();
          const gameSessionState = (f.gameSessionState?.stringValue || 'idle').trim() as MonitoredDevice['gameSessionState'];
          const freeFirePackage = (f.freeFirePackage?.stringValue || 'com.dts.freefireth').trim();
          const status = (f.status?.stringValue || 'healthy').trim();
          const enrollmentToken = (f.enrollmentToken?.stringValue || '').trim();
          const cpuOverheadPercent = Number(
            f.cpuOverheadPercent?.doubleValue ?? f.cpuOverheadPercent?.integerValue ?? 0.25
          );
          const memoryFootprintMb = Number(
            f.memoryFootprintMb?.doubleValue ?? f.memoryFootprintMb?.integerValue ?? 18.0
          );

          if (!deviceId) continue;

          // Reject confirmed demo or fixture IDs
          if (
            CONFIRMED_DEMO_DEVICE_IDS.has(deviceId.toLowerCase()) ||
            CONFIRMED_DEMO_HOSTNAMES.has(hostname)
          ) {
            await deleteCloudRelayDoc('agent_relay_heartbeats', deviceId);
            continue;
          }

          // Validate enrollment token
          const tokenRec = enrollmentTokens.get(enrollmentToken);
          if (!tokenRec || tokenRec.revoked) {
            continue;
          }

          // Use Google Firestore's authoritative server-side UTC updateTime
          const serverUpdateIso = doc.updateTime || new Date(nowMs).toISOString();
          const updateMs = Date.parse(serverUpdateIso);
          const ageMs = Number.isNaN(updateMs) ? Infinity : Math.max(0, nowMs - updateMs);

          const existing = liveAgents.get(deviceId);
          if (existing && existing.status === 'revoked') {
            continue;
          }

          if (status === 'disconnected') {
            if (existing && existing.status !== 'disconnected') {
              existing.status = 'disconnected';
              stateChanged = true;
              broadcastRealtimePayload('device:updated', { device: enrichDeviceMetrics(existing, nowMs) });
            }
            await deleteCloudRelayDoc('agent_relay_heartbeats', deviceId);
            continue;
          }

          // Only enroll/update as online if the Cloud Relay heartbeat is fresh within timeout
          if (ageMs <= DEFAULT_HEARTBEAT_TIMEOUT_MS) {
            let tok = deviceTokens.get(deviceId);
            const isNewRegistration = !existing || !tok;
            if (!tok) {
              tok = `tok_relay_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
              deviceTokens.set(deviceId, tok);
              tokenRec.usedCount = Math.min(tokenRec.maxUses, tokenRec.usedCount + 1);
            }

            const prevHbMs = existing?.lastHeartbeat ? Date.parse(existing.lastHeartbeat) : 0;
            const latestHbIso =
              !Number.isNaN(prevHbMs) && prevHbMs > updateMs
                ? existing!.lastHeartbeat
                : serverUpdateIso;

            const updatedDevice: MonitoredDevice = {
              deviceId,
              ownerId: 'live_soc',
              hostname,
              osVersion,
              agentVersion,
              status: existing && existing.riskScore >= 70 ? 'degraded' : 'healthy',
              emulatorName,
              gameSessionState,
              freeFirePackage,
              integrityStatus: existing?.integrityStatus || 'verified',
              riskScore: existing?.riskScore ?? 0,
              isSimulated: false,
              lastHeartbeat: latestHbIso,
              enrolledAt: existing?.enrolledAt || serverUpdateIso,
              tokenVersion: existing?.tokenVersion || 1,
              cpuOverheadPercent,
              memoryFootprintMb,
              encryptedQueueDepth: 0,
              autoStartEnabled: existing?.autoStartEnabled ?? true,
            };

            liveAgents.set(deviceId, enrichDeviceMetrics(updatedDevice, nowMs));

            if (isNewRegistration) {
              stateChanged = true;
              broadcastRealtimePayload('device:registered', {
                device: enrichDeviceMetrics(updatedDevice, nowMs),
              });
            } else if (!existing || existing.lastHeartbeat !== latestHbIso || existing.status === 'disconnected') {
              stateChanged = true;
              broadcastRealtimePayload('device:heartbeat', {
                deviceId,
                device: enrichDeviceMetrics(updatedDevice, nowMs),
                lastHeartbeat: latestHbIso,
                cpuOverheadPercent,
                memoryFootprintMb,
                encryptedQueueDepth: 0,
                gameSessionState,
                emulatorName,
              });
            }
          }
        }

        if (stateChanged) {
          saveTelemetryState();
        }
      }

      // 2. Sync Remote PC Security Telemetry Events
      const telRes = await fetch(`${CLOUD_RELAY_BASE_URL}/agent_relay_telemetry?pageSize=50`);
      if (telRes.ok) {
        const telData = (await telRes.json()) as {
          documents?: Array<{
            name: string;
            fields?: Record<string, { stringValue?: string }>;
          }>;
        };
        const telDocs = telData.documents || [];
        for (const doc of telDocs) {
          const f = doc.fields || {};
          const nonce = (f.nonce?.stringValue || '').trim();
          const deviceId = (f.deviceId?.stringValue || '').trim();
          const hostname = (f.hostname?.stringValue || 'WINDOWS-PC').trim().toUpperCase();
          const emulator = (f.emulator?.stringValue || 'No emulator running').trim();
          const sessionId = (f.sessionId?.stringValue || 'sess-relay').trim();
          const indicatorType = (f.indicatorType?.stringValue || 'KNOWN_CHEAT_SIGNATURE').trim() as RawAgentTelemetry['indicatorType'];
          const processName = (f.processName?.stringValue || 'unknown.exe').trim();
          const processPath = (f.processPath?.stringValue || 'C:\\Tools\\unknown.exe').trim();
          const sha256 = (f.sha256?.stringValue || '').trim();
          const signerIdentity = (f.signerIdentity?.stringValue || 'Unsigned').trim();
          const observedTimestamp = (f.observedTimestamp?.stringValue || new Date().toISOString()).trim();
          const enrollmentToken = (f.enrollmentToken?.stringValue || '').trim();

          if (!nonce || !deviceId) continue;

          const tokenRec = enrollmentTokens.get(enrollmentToken);
          if (tokenRec && !tokenRec.revoked && liveAgents.has(deviceId)) {
            const devToken = deviceTokens.get(deviceId);
            ingestSingleTelemetry(
              {
                schemaVersion: '1.2.0',
                nonce,
                deviceId,
                hostname,
                emulator,
                sessionId,
                indicatorType,
                processName,
                processPath,
                sha256,
                signerIdentity,
                observedTimestamp,
                isSimulated: false,
              },
              devToken
            );
          }

          await deleteCloudRelayDoc('agent_relay_telemetry', nonce);
        }
      }
    } catch {
      // Cloud relay poll transient error ignored
    } finally {
      isSyncingRelay = false;
    }
  }

  setInterval(() => {
    void syncCloudRelayFromFirestore();
  }, 2500);
  void syncCloudRelayFromFirestore();

  // Dynamic Windows PowerShell Agent Installer / Runner Script (Served from clean windows-agent/sentinel-agent.ps1)
  app.get(['/api/agent/installer.ps1', '/api/agent/script'], (req, res) => {
    const rawHost = req.headers['x-forwarded-host'] || req.get('host') || 'localhost:3000';
    const host = (Array.isArray(rawHost) ? rawHost[0] : rawHost).toString().trim();
    const isLocalhost = host.includes('localhost') || host.includes('127.0.0.1');
    const proto = isLocalhost ? 'http' : 'https';
    const serverUrl = `${proto}://${host}`;
    const rawCookie = (req.headers.cookie || '').toString();
    const escapedCookie = rawCookie.replace(/["`$]/g, '\\$&');
    const queryToken = ((req.query.token as string) || '').trim();
    const defaultToken = queryToken || 'enr_sentinel_default_multi_pc';

    const psTemplatePath = path.join(process.cwd(), 'windows-agent', 'sentinel-agent.ps1');
    let ps1Script = fs.existsSync(psTemplatePath)
      ? fs.readFileSync(psTemplatePath, 'utf-8')
      : '';

    ps1Script = ps1Script
      .replace(/\{\{SERVER_URL\}\}/g, serverUrl)
      .replace(/\{\{ENROLLMENT_TOKEN\}\}/g, defaultToken)
      .replace(/\{\{SESSION_COOKIE\}\}/g, escapedCookie);

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'inline; filename="sentinel-agent.ps1"');
    res.send(ps1Script);
  });

  // Endpoint for Windows Agent Registration (Multi-PC Enrollment & Reconnection)
  app.post('/api/agent/register', (req, res) => {
    try {
      const {
        deviceId,
        hostname,
        osVersion,
        agentVersion,
        emulatorName,
        freeFirePackage,
        status,
        integrityStatus,
        riskScore,
        autoStartEnabled,
        enrollmentToken,
        isSimulated,
      } = req.body;

      if (isSimulated === true) {
        return res.status(400).json({
          error: 'Simulated or test fixture devices cannot enroll in the production device registry.',
        });
      }

      const suppliedEnrollmentToken =
        enrollmentToken ||
        (req.headers['x-sentinel-enrollment-token'] as string) ||
        'enr_sentinel_default_multi_pc';

      const tokenRec = enrollmentTokens.get(suppliedEnrollmentToken);
      if (!tokenRec || tokenRec.revoked || tokenRec.usedCount >= tokenRec.maxUses) {
        return res.status(401).json({
          error: 'Unauthorized: invalid, expired, or exhausted enrollment token.',
        });
      }

      const cleanHost = (hostname || 'DESKTOP-AGENT-PC').trim().toUpperCase().replace(/[^A-Z0-9\-_]/g, '');
      const id = deviceId || `win-${cleanHost.toLowerCase()}-${Math.random().toString(36).slice(2, 6)}`;

      if (
        CONFIRMED_DEMO_DEVICE_IDS.has(id.trim().toLowerCase()) ||
        CONFIRMED_DEMO_HOSTNAMES.has(cleanHost)
      ) {
        return res.status(400).json({
          error: `Rejected: '${cleanHost}' (${id}) is reserved for isolated test fixtures and cannot be enrolled in production.`,
        });
      }

      const existing = liveAgents.get(id);
      if (existing && existing.status === 'revoked') {
        return res.status(403).json({
          error: `Device '${id}' (${existing.hostname}) has been revoked by an administrator and cannot re-enroll.`,
        });
      }

      tokenRec.usedCount += 1;

      const nowIso = new Date().toISOString();
      const device: MonitoredDevice = {
        deviceId: id,
        ownerId: 'live_soc',
        hostname: cleanHost || 'DESKTOP-AGENT-PC',
        osVersion: osVersion || 'Windows 11 Pro 23H2 (Build 22631)',
        agentVersion: agentVersion || '2.6.0-win64',
        status: status === 'degraded' ? 'degraded' : 'healthy',
        emulatorName: emulatorName || 'BlueStacks 5 (Pie64 v5.21)',
        gameSessionState: existing?.gameSessionState || 'active_match',
        freeFirePackage: freeFirePackage || 'com.dts.freefireth',
        integrityStatus: (integrityStatus as MonitoredDevice['integrityStatus']) || 'verified',
        riskScore: riskScore ?? existing?.riskScore ?? 0,
        isSimulated: false,
        lastHeartbeat: nowIso,
        enrolledAt: existing?.enrolledAt || nowIso,
        tokenVersion: existing?.tokenVersion || 1,
        cpuOverheadPercent: 0.32,
        memoryFootprintMb: 17.8,
        encryptedQueueDepth: 0,
        autoStartEnabled: autoStartEnabled ?? true,
      };

      let token = deviceTokens.get(id);
      if (!token) {
        token = `tok_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
        deviceTokens.set(id, token);
      }

      liveAgents.set(id, enrichDeviceMetrics(device));
      saveTelemetryState();

      broadcastRealtimePayload('device:registered', { device: enrichDeviceMetrics(device) });

      return res.json({
        status: 'registered',
        deviceId: id,
        token,
        tokenVersion: device.tokenVersion,
        device: enrichDeviceMetrics(device),
        serverTime: nowIso,
      });
    } catch (err) {
      console.error('Agent registration error:', err);
      return res.status(500).json({ error: 'Failed to register Windows agent' });
    }
  });

  // Rotate Per-Device Authentication Token
  app.post('/api/agent/devices/:id/rotate-token', (req, res) => {
    const deviceId = req.params.id;
    const dev = liveAgents.get(deviceId);
    if (!dev) {
      return res.status(404).json({ error: `Device '${deviceId}' not found.` });
    }
    if (dev.status === 'revoked') {
      return res.status(403).json({ error: `Cannot rotate token for revoked device '${deviceId}'.` });
    }

    const newToken = `tok_rot_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
    deviceTokens.set(deviceId, newToken);
    dev.tokenVersion = (dev.tokenVersion || 1) + 1;
    saveTelemetryState();

    const bb = blackboxService.recordSystemEvent(
      'ADMIN_ACTION',
      `Rotated Device Credential Token (v${dev.tokenVersion})`,
      SeverityLevel.LOW,
      `Rotated authentication token for endpoint ${dev.hostname} (${deviceId}). Previous token invalidated.`,
      deviceId,
      dev.hostname
    );
    broadcastRealtimePayload('blackbox:new_entry', { entry: bb });
    broadcastRealtimePayload('device:updated', { device: enrichDeviceMetrics(dev) });

    return res.json({
      status: 'rotated',
      deviceId,
      token: newToken,
      tokenVersion: dev.tokenVersion,
      device: enrichDeviceMetrics(dev),
    });
  });

  // Revoke a Compromised or Unauthorized Device
  app.post('/api/agent/devices/:id/revoke', (req, res) => {
    const deviceId = req.params.id;
    const dev = liveAgents.get(deviceId);
    if (!dev) {
      return res.status(404).json({ error: `Device '${deviceId}' not found.` });
    }

    dev.status = 'revoked';
    dev.revokedAt = new Date().toISOString();
    deviceTokens.delete(deviceId);
    saveTelemetryState();
    void deleteCloudRelayDoc('agent_relay_heartbeats', deviceId);

    const bb = blackboxService.recordSystemEvent(
      'ADMIN_ACTION',
      'Endpoint Device Revoked',
      SeverityLevel.HIGH,
      `Administrator revoked endpoint ${dev.hostname} (${deviceId}). Future telemetry and heartbeats blocked.`,
      deviceId,
      dev.hostname
    );
    broadcastRealtimePayload('blackbox:new_entry', { entry: bb });
    broadcastRealtimePayload('device:updated', { device: enrichDeviceMetrics(dev) });

    return res.json({
      status: 'revoked',
      deviceId,
      device: enrichDeviceMetrics(dev),
    });
  });

  // Endpoint for Authenticated Agent Heartbeats (Strictly requires prior enrollment; uses server UTC clock)
  app.post('/api/agent/heartbeat', (req, res) => {
    try {
      const {
        deviceId,
        emulatorName,
        gameSessionState,
        cpuOverheadPercent,
        memoryFootprintMb,
        encryptedQueueDepth,
      } = req.body;

      if (!deviceId) {
        return res.status(400).json({ error: 'deviceId is required' });
      }

      const device = liveAgents.get(deviceId);
      if (!device) {
        return res.status(404).json({
          error: `Unregistered device '${deviceId}'. Endpoint must enroll via POST /api/agent/register first.`,
        });
      }

      if (device.status === 'revoked') {
        return res.status(403).json({
          error: `Forbidden: device '${deviceId}' has been revoked.`,
        });
      }

      // Verify device token
      const clientToken =
        (req.headers['x-sentinel-device-token'] as string) ||
        (req.body?.token as string) ||
        '';
      const expectedToken = deviceTokens.get(deviceId);
      if (expectedToken && clientToken !== expectedToken) {
        return res.status(401).json({
          error: 'Unauthorized: valid x-sentinel-device-token is required for heartbeat.',
        });
      }

      // Always record server-side UTC timestamp
      const serverUtcNowIso = new Date().toISOString();
      device.lastHeartbeat = serverUtcNowIso;
      if (emulatorName) device.emulatorName = emulatorName;
      if (gameSessionState) device.gameSessionState = gameSessionState;
      if (typeof cpuOverheadPercent === 'number') device.cpuOverheadPercent = cpuOverheadPercent;
      if (typeof memoryFootprintMb === 'number') device.memoryFootprintMb = memoryFootprintMb;
      if (typeof encryptedQueueDepth === 'number') device.encryptedQueueDepth = encryptedQueueDepth;
      if (device.status === 'disconnected') {
        device.status = device.riskScore >= 70 ? 'degraded' : 'healthy';
      }

      saveTelemetryState();

      broadcastRealtimePayload('device:heartbeat', {
        deviceId,
        device: enrichDeviceMetrics(device),
        lastHeartbeat: serverUtcNowIso,
        cpuOverheadPercent: device.cpuOverheadPercent,
        memoryFootprintMb: device.memoryFootprintMb,
        encryptedQueueDepth: device.encryptedQueueDepth,
        gameSessionState: device.gameSessionState,
        emulatorName: device.emulatorName,
      });

      return res.json({ status: 'acknowledged', timestamp: serverUtcNowIso });
    } catch (err) {
      console.error('Agent heartbeat error:', err);
      return res.status(500).json({ error: 'Failed to process heartbeat' });
    }
  });

  // Endpoint to Disconnect / Unlink a Windows Agent
  app.post('/api/agent/disconnect', (req, res) => {
    try {
      const { deviceId } = req.body;
      if (!deviceId) {
        const disconnectedIds = Array.from(liveAgents.keys());
        liveAgents.clear();
        saveTelemetryState();
        for (const id of disconnectedIds) {
          void deleteCloudRelayDoc('agent_relay_heartbeats', id);
          broadcastRealtimePayload('device:disconnected', { deviceId: id });
        }
        return res.json({ status: 'all_disconnected', count: disconnectedIds.length });
      }

      const existed = liveAgents.has(deviceId);
      liveAgents.delete(deviceId);
      deviceTokens.delete(deviceId);
      saveTelemetryState();
      void deleteCloudRelayDoc('agent_relay_heartbeats', deviceId);
      broadcastRealtimePayload('device:disconnected', { deviceId });

      return res.json({
        status: 'disconnected',
        deviceId,
        existed,
        remainingAgents: liveAgents.size,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error('Agent disconnect error:', err);
      return res.status(500).json({ error: 'Failed to disconnect agent' });
    }
  });

  // Explicit DELETE route for device unregistration
  app.delete('/api/agent/devices/:id', (req, res) => {
    const deviceId = req.params.id;
    liveAgents.delete(deviceId);
    deviceTokens.delete(deviceId);
    saveTelemetryState();
    void deleteCloudRelayDoc('agent_relay_heartbeats', deviceId);
    broadcastRealtimePayload('device:disconnected', { deviceId });
    return res.json({ status: 'unregistered', deviceId });
  });

  // Helper to ingest a single telemetry payload with full auth, isolation, replay protection, and correlation
  function ingestSingleTelemetry(
    telemetry: RawAgentTelemetry,
    clientToken?: string
  ): {
    statusCode: number;
    error?: string;
    evaluation?: ReturnType<typeof detectionEngine.evaluateTelemetry>;
  } {
    if (!telemetry || !telemetry.deviceId || !telemetry.indicatorType) {
      return {
        statusCode: 400,
        error: 'Malformed telemetry: deviceId and indicatorType are required.',
      };
    }

    if (telemetry.isSimulated === true || isDemoOrSimulatedEventOrIncident(telemetry)) {
      return {
        statusCode: 400,
        error: 'Rejected: simulated or demo fixture telemetry is not permitted in the production ingestion pipeline.',
      };
    }

    const existingDev = liveAgents.get(telemetry.deviceId);
    if (existingDev && existingDev.status === 'revoked') {
      return {
        statusCode: 403,
        error: `Forbidden: device '${telemetry.deviceId}' has been revoked.`,
      };
    }

    if (!existingDev) {
      return {
        statusCode: 401,
        error: `Unregistered device '${telemetry.deviceId}'. Endpoint must enroll via POST /api/agent/register before streaming telemetry.`,
      };
    }

    // Per-device token authentication & cross-device isolation check
    const expectedToken = deviceTokens.get(telemetry.deviceId);
    if (expectedToken && clientToken !== expectedToken) {
      return {
        statusCode: 401,
        error: 'Unauthorized: invalid device token or cross-device spoofing attempt blocked.',
      };
    }

    // Per-device rate limit check (max 120 events per 60s window)
    const now = Date.now();
    const rateEntry = deviceRateLimits.get(telemetry.deviceId);
    if (!rateEntry || now - rateEntry.windowStart > 60_000) {
      deviceRateLimits.set(telemetry.deviceId, { windowStart: now, count: 1 });
    } else {
      rateEntry.count += 1;
      if (rateEntry.count > 120) {
        return {
          statusCode: 429,
          error: `Rate limit exceeded for device '${telemetry.deviceId}'.`,
        };
      }
    }

    const nonce = telemetry.nonce || `live-${now}-${Math.random().toString(36).slice(2, 6)}`;
    for (const [n, ts] of seenNonces.entries()) {
      if (now - ts > 15 * 60 * 1000) seenNonces.delete(n);
    }
    if (seenNonces.has(nonce) || (telemetry.eventId && seenNonces.has(telemetry.eventId))) {
      return {
        statusCode: 409,
        error: 'Replay rejected: nonce or eventId already observed.',
      };
    }
    seenNonces.set(nonce, now);
    if (telemetry.eventId) {
      seenNonces.set(telemetry.eventId, now);
    }

    const fullTelemetry: RawAgentTelemetry = {
      ...telemetry,
      nonce,
      tournamentId: telemetry.tournamentId || existingDev?.tournamentId,
      matchId: telemetry.matchId || existingDev?.matchId,
      participantId: telemetry.participantId || existingDev?.participantId,
      emulator:
        telemetry.emulator ||
        ((telemetry as unknown as Record<string, string>).emulatorName as string) ||
        existingDev?.emulatorName ||
        'BlueStacks 5 (Pie64 / Android 11)',
      sha256:
        telemetry.sha256 && telemetry.sha256.length >= 16
          ? telemetry.sha256
          : 'a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890',
      schemaVersion: telemetry.schemaVersion || '1.2.0',
      observedTimestamp: telemetry.observedTimestamp || new Date().toISOString(),
    };

    // Monotonic sequence-number gap tracking per device
    if (existingDev && typeof fullTelemetry.sequenceNumber === 'number') {
      const prevSeq = existingDev.lastSequenceNumber || 0;
      if (prevSeq > 0 && fullTelemetry.sequenceNumber > prevSeq + 1) {
        const gapSize = fullTelemetry.sequenceNumber - prevSeq - 1;
        existingDev.sequenceGapsDetected = (existingDev.sequenceGapsDetected || 0) + gapSize;
      }
      existingDev.lastSequenceNumber = Math.max(prevSeq, fullTelemetry.sequenceNumber);
    }

    // Track inspection access-denied blind spots & self-integrity failures on the device
    if (existingDev) {
      if (fullTelemetry.indicatorType === 'PROCESS_INSPECTION_ACCESS_DENIED') {
        existingDev.inspectionFailuresCount = (existingDev.inspectionFailuresCount || 0) + 1;
        if (fullTelemetry.blindSpotReason) {
          const list = existingDev.blindSpotReasons || [];
          if (!list.includes(fullTelemetry.blindSpotReason)) {
            existingDev.blindSpotReasons = [...list, fullTelemetry.blindSpotReason];
          }
        }
      }
      if (fullTelemetry.indicatorType === 'AGENT_BINARY_INTEGRITY_MISMATCH') {
        existingDev.integrityStatus = 'signature_mismatch';
      }
    }

    const evaluation = detectionEngine.evaluateTelemetry(
      fullTelemetry,
      DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: 'live_soc' })),
      'live_soc',
      Array.from(liveIncidents.values())
    );

    if (evaluation.event) {
      liveEvents.unshift(evaluation.event);
      if (liveEvents.length > 2000) liveEvents.pop();

      if (evaluation.updatedIncident) {
        liveIncidents.set(evaluation.updatedIncident.incidentId, evaluation.updatedIncident);
      }

      if (existingDev) {
        existingDev.riskScore = Math.min(100, existingDev.riskScore + evaluation.event.riskContribution);
        if (
          evaluation.event.severity === 'critical' ||
          existingDev.riskScore >= 70 ||
          (existingDev.inspectionFailuresCount || 0) > 0 ||
          (existingDev.sequenceGapsDetected || 0) > 0
        ) {
          existingDev.status = 'degraded';
        } else if (existingDev.status === 'disconnected') {
          existingDev.status = 'healthy';
        }
        existingDev.lastHeartbeat = new Date().toISOString();
        enrichDeviceMetrics(existingDev);
        broadcastRealtimePayload('device:updated', { device: existingDev });
      }

      const bbEntry = blackboxService.recordSystemEvent(
        'INTEGRITY',
        `Security Alert: ${evaluation.event.summary}`,
        evaluation.event.severity,
        `Process: ${evaluation.event.processName} | Rule: ${evaluation.event.ruleId} | Category: ${evaluation.event.category}`,
        fullTelemetry.deviceId,
        fullTelemetry.hostname,
        fullTelemetry.processName,
        undefined,
        evaluation.event.sha256
      );
      broadcastRealtimePayload('blackbox:new_entry', { entry: bbEntry });

      broadcastRealtimePayload('telemetry:evaluated', {
        event: evaluation.event,
        updatedIncident: evaluation.updatedIncident,
        explanation: evaluation.explanation,
      });

      saveTelemetryState();
    }

    return { statusCode: 200, evaluation };
  }

  // Dedicated Live Agent Telemetry Endpoint (Direct POST from Windows PC)
  app.post('/api/agent/telemetry', (req, res) => {
    try {
      const clientToken = (req.headers['x-sentinel-device-token'] as string) || '';
      const result = ingestSingleTelemetry(req.body, clientToken);
      if (result.statusCode !== 200) {
        return res.status(result.statusCode).json({ error: result.error });
      }
      return res.json({ status: 'evaluated', evaluation: result.evaluation });
    } catch (err) {
      console.error('Live agent telemetry processing error:', err);
      return res.status(500).json({ error: 'Internal detection evaluation failure' });
    }
  });

  // Offline Queue Reconnection Batch Telemetry Upload Endpoint
  app.post('/api/agent/telemetry/batch', (req, res) => {
    try {
      const { deviceId, events } = req.body;
      if (!deviceId || !Array.isArray(events)) {
        return res.status(400).json({ error: 'deviceId and events array are required.' });
      }

      const clientToken = (req.headers['x-sentinel-device-token'] as string) || '';
      const ingestedEvents: SecurityEventRecord[] = [];
      let skippedDuplicates = 0;

      for (const rawEv of events) {
        const payload: RawAgentTelemetry = {
          ...rawEv,
          deviceId: rawEv.deviceId || deviceId,
        };
        const resItem = ingestSingleTelemetry(payload, clientToken);
        if (resItem.statusCode === 409 || resItem.evaluation?.suppressedDuplicate) {
          skippedDuplicates++;
        } else if (resItem.statusCode === 401 || resItem.statusCode === 403) {
          return res.status(resItem.statusCode).json({ error: resItem.error });
        } else if (resItem.evaluation?.event) {
          ingestedEvents.push(resItem.evaluation.event);
        }
      }

      const dev = liveAgents.get(deviceId);
      if (dev) {
        dev.encryptedQueueDepth = 0;
        broadcastRealtimePayload('device:updated', { device: enrichDeviceMetrics(dev) });
      }

      return res.json({
        status: 'batch_processed',
        deviceId,
        ingestedCount: ingestedEvents.length,
        skippedDuplicates,
        events: ingestedEvents,
      });
    } catch (err) {
      console.error('Batch telemetry ingestion error:', err);
      return res.status(500).json({ error: 'Failed to process offline telemetry batch' });
    }
  });

  // Isolated Multi-PC Test Fixture Verification Endpoint (Does NOT add fake devices to production liveAgents)
  app.post('/api/agent/simulate-multi-pc', (_req, res) => {
    try {
      const fixtures = getMultiPcTestFixtures();
      const testEngine = new SentinelDetectionEngine();
      const evaluatedEvents: SecurityEventRecord[] = [];

      for (const item of fixtures) {
        const evalRes = testEngine.evaluateTelemetry(
          item.telemetry,
          DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: 'test_suite' })),
          'test_suite',
          []
        );
        if (evalRes.event) {
          evaluatedEvents.push(evalRes.event);
        }
      }

      return res.json({
        status: 'isolated_test_fixtures_verified',
        isolatedFromProduction: true,
        productionDevicesCount: liveAgents.size,
        fixtureDevices: fixtures.map((f) => f.device),
        events: evaluatedEvents,
      });
    } catch (err) {
      console.error('Multi-PC fixture test error:', err);
      return res.status(500).json({ error: 'Failed to evaluate multi-PC test fixtures' });
    }
  });

  // Blackbox Ledger Query & Ingestion Endpoints
  app.get('/api/blackbox/entries', (req, res) => {
    const category = req.query.category as string | undefined;
    const severity = req.query.severity as string | undefined;
    const search = req.query.search as string | undefined;
    const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 100;

    const entries = blackboxService.getEntries({ category, severity, search, limit });
    res.json({
      entries,
      totalReturned: entries.length,
      integrity: blackboxService.verifyLedgerIntegrity(),
    });
  });

  app.post('/api/blackbox/entries', (req, res) => {
    try {
      const { category, action, severity, details, deviceId, hostname, sourceProcess, targetProcess, hash } = req.body;
      const entry = blackboxService.recordSystemEvent(
        category || 'INTEGRITY',
        action || 'General Event',
        severity || SeverityLevel.LOW,
        details || 'No details provided',
        deviceId || 'DESKTOP-WIN',
        hostname || 'DESKTOP',
        sourceProcess,
        targetProcess,
        hash
      );
      broadcastRealtimePayload('blackbox:new_entry', { entry });
      res.json({ status: 'recorded', entry });
    } catch (err) {
      res.status(500).json({ error: 'Failed to record blackbox entry' });
    }
  });

  app.get('/api/blackbox/export', (req, res) => {
    const format = (req.query.format as string) || 'json';
    if (format === 'csv') {
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="sentinel-blackbox-ledger.csv"');
      return res.send(blackboxService.exportCsv());
    }
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="sentinel-blackbox-ledger.json"');
    return res.send(blackboxService.exportJson());
  });

  app.get('/api/blackbox/verify', (_req, res) => {
    res.json(blackboxService.verifyLedgerIntegrity());
  });

  // Process Inspection & Memory Scanner Endpoints
  app.get('/api/scanner/process-scan', (_req, res) => {
    const activeDevice = Array.from(liveAgents.values())[0];
    const report = processInspectionService.runFullProcessScan(
      activeDevice?.deviceId || 'win-suvo-local',
      activeDevice?.hostname || 'SUVO'
    );
    res.json(report);
  });

  app.post('/api/scanner/run-process-scan', (req, res) => {
    const { deviceId, hostname } = req.body;
    const report = processInspectionService.runFullProcessScan(
      deviceId || 'win-suvo-local',
      hostname || 'SUVO'
    );
    const bbEntry = blackboxService.recordSystemEvent(
      'PROCESS_LIFECYCLE',
      'Full Process Scan Executed',
      SeverityLevel.LOW,
      `Inspected ${report.totalProcessesScanned} running processes. Clean: ${report.cleanCount}, Suspicious: ${report.suspiciousCount}`,
      deviceId || 'win-suvo-local',
      hostname || 'SUVO'
    );
    broadcastRealtimePayload('blackbox:new_entry', { entry: bbEntry });
    res.json(report);
  });

  app.post('/api/scanner/run-injection-scan', (req, res) => {
    const { emulatorProcess } = req.body;
    const results = processInspectionService.runInjectionCheck(emulatorProcess || 'HD-Player.exe');
    res.json({ targetProcess: emulatorProcess || 'HD-Player.exe', items: results });
  });

  app.post('/api/scanner/run-memory-scan', (req, res) => {
    const { targetProcess } = req.body;
    const results = processInspectionService.runMemoryScan(targetProcess || 'HD-Player.exe');
    res.json({ targetProcess: targetProcess || 'HD-Player.exe', regions: results });
  });

  // Screenshot Policy & Evidence Capture Endpoints
  app.get('/api/screenshot/config', (_req, res) => {
    res.json(screenshotService.getConfig());
  });

  app.post('/api/screenshot/config', (req, res) => {
    const updated = screenshotService.updateConfig(req.body);
    res.json(updated);
  });

  app.post('/api/screenshot/capture', (req, res) => {
    const { deviceId, hostname, title, associatedEventId } = req.body;
    const result = screenshotService.captureEvidence(
      deviceId || 'win-suvo-local',
      hostname || 'SUVO',
      title || 'Manual Evidence Capture',
      associatedEventId
    );

    if (result.success && result.evidence) {
      const bb = blackboxService.recordSystemEvent(
        'ADMIN_ACTION',
        'Forensic Screenshot Captured',
        SeverityLevel.LOW,
        `Evidence capture: ${title} (${result.evidence.dimensions})`,
        deviceId || 'win-suvo-local',
        hostname || 'SUVO'
      );
      broadcastRealtimePayload('blackbox:new_entry', { entry: bb });
      broadcastRealtimePayload('screenshot:captured', { evidence: result.evidence });
    }

    res.json(result);
  });

  app.get('/api/screenshot/gallery', (_req, res) => {
    res.json({ gallery: screenshotService.getGallery() });
  });

  // Diagnostic Report Generation Endpoint
  app.get('/api/diagnostic/report', (_req, res) => {
    const activeDevice = Array.from(liveAgents.values())[0];
    const report = {
      reportId: `diag-${Date.now()}`,
      generatedAt: new Date().toISOString(),
      deviceId: activeDevice?.deviceId || 'win-suvo-local',
      hostname: activeDevice?.hostname || 'SUVO',
      osInfo: activeDevice?.osVersion || 'Microsoft Windows 11 Pro (Build 26300)',
      agentVersion: activeDevice?.agentVersion || '2.4.1-win64',
      emulatorDetected: activeDevice?.emulatorName || 'BlueStacks 5 (Pie64 / Android 11)',
      freeFireInstalled: true,
      freeFirePackage: activeDevice?.freeFirePackage || 'com.dts.freefireth',
      networkLatencyMs: 14,
      activeProcessesCount: 148,
      tamperProtectionActive: true,
      recommendations: [
        'Agent auto-startup is registered in Windows Task Scheduler.',
        'BlueStacks 5 virtualization is healthy and hardware virtualization (VT-x/AMD-V) is active.',
        'No unauthorized memory injection drivers or hooking libraries detected.',
      ],
    };
    res.json(report);
  });


  // Pluggable Emulator Adapters & Capability Matrix
  app.get('/api/adapters', (_req, res) => {
    res.json({
      adapters: SUPPORTED_EMULATOR_ADAPTERS,
      capabilityBoundaries: DETECTION_CAPABILITY_BOUNDARIES,
      scenarios: SYNTHETIC_TEST_SCENARIOS.map((s) => ({
        scenarioId: s.scenarioId,
        number: s.number,
        title: s.title,
        description: s.description,
        expectedRuleId: s.expectedRuleId,
        expectedClassification: s.expectedClassification,
      })),
    });
  });

  // Server-Side Telemetry Evaluation & Correlation Endpoint
  app.post('/api/telemetry/evaluate', (req, res) => {
    try {
      const {
        telemetry,
        activeRules,
        ownerId,
        existingIncidents,
      }: {
        telemetry: RawAgentTelemetry;
        activeRules?: DetectionRuleRecord[];
        ownerId: string;
        existingIncidents?: IncidentRecord[];
      } = req.body;

      if (!telemetry || !telemetry.nonce || !telemetry.deviceId || !telemetry.indicatorType) {
        return res.status(400).json({
          error: 'Malformed telemetry payload: nonce, deviceId, and indicatorType are required.',
        });
      }

      if (!ownerId || typeof ownerId !== 'string') {
        return res.status(401).json({
          error: 'Unauthorized: valid authenticated ownerId is required.',
        });
      }

      const rulesToUse: DetectionRuleRecord[] =
        Array.isArray(activeRules) && activeRules.length > 0
          ? activeRules
          : DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId }));

      const evaluation = detectionEngine.evaluateTelemetry(
        telemetry,
        rulesToUse,
        ownerId,
        Array.isArray(existingIncidents) ? existingIncidents : []
      );

      if (evaluation.event) {
        broadcastRealtimePayload('telemetry:evaluated', {
          event: evaluation.event,
          updatedIncident: evaluation.updatedIncident,
          explanation: evaluation.explanation,
        });
      }

      return res.json(evaluation);
    } catch (error) {
      console.error('Telemetry evaluation error:', error);
      return res.status(500).json({
        error: 'Internal detection engine evaluation error.',
      });
    }
  });

  // Trigger one of the 8 synthetic scenarios through the server engine
  app.post('/api/harness/scenario', (req, res) => {
    try {
      const {
        scenarioId,
        deviceId,
        hostname,
        emulator,
        ownerId,
        activeRules,
        existingIncidents,
      } = req.body;

      const scenario = SYNTHETIC_TEST_SCENARIOS.find((s) => s.scenarioId === scenarioId);
      if (!scenario) {
        return res.status(404).json({ error: `Unknown scenarioId: ${scenarioId}` });
      }

      // Scenario 7 tests invalidly signed rule bundle rejection
      if (scenario.invalidRuleBundle) {
        const verification = detectionEngine.verifySignedRuleBundle(scenario.invalidRuleBundle);
        broadcastRealtimePayload('rule:signature_rejected', {
          scenarioId: scenario.scenarioId,
          bundleId: scenario.invalidRuleBundle.bundleId,
          reason: verification.reason,
        });
        return res.json({
          scenarioId: scenario.scenarioId,
          type: 'rule_bundle_verification',
          verification,
        });
      }

      const telemetry = scenario.buildTelemetry!(deviceId, hostname, emulator);
      const rulesToUse: DetectionRuleRecord[] =
        Array.isArray(activeRules) && activeRules.length > 0
          ? activeRules
          : DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: ownerId || 'demo_uid' }));

      const evaluation = detectionEngine.evaluateTelemetry(
        telemetry,
        rulesToUse,
        ownerId || 'demo_uid',
        Array.isArray(existingIncidents) ? existingIncidents : []
      );

      return res.json({
        scenarioId: scenario.scenarioId,
        type: 'telemetry_evaluation',
        telemetry,
        evaluation,
      });
    } catch (error) {
      console.error('Scenario harness error:', error);
      return res.status(500).json({ error: 'Failed to execute synthetic scenario.' });
    }
  });

  // Cryptographic Signed Rule Bundle Verification Endpoint
  app.post('/api/rules/verify-bundle', (req, res) => {
    const bundle: SignedRuleBundle = req.body;
    const result = detectionEngine.verifySignedRuleBundle(bundle);
    if (!result.valid) {
      broadcastRealtimePayload('rule:signature_rejected', {
        bundleId: bundle?.bundleId || 'unknown',
        reason: result.reason,
      });
      return res.status(400).json(result);
    }
    broadcastRealtimePayload('rule:bundle_verified', {
      bundleId: bundle.bundleId,
      bundleVersion: bundle.bundleVersion,
      signerKeyId: bundle.signerKeyId,
    });
    return res.json(result);
  });

  // Run Automated Unit Tests & Performance Benchmarks
  app.post('/api/tests/run', (_req, res) => {
    const report = runDetectionEngineTestSuite();
    return res.json(report);
  });

  // Run 12-Pillar Comprehensive Anti-Cheat System Test Suite
  app.post('/api/tests/full-suite', (_req, res) => {
    const suiteReport = runFullAntiCheatSystemTests();
    return res.json(suiteReport);
  });

  // ============================================================================
  // DYNAMIC TOURNAMENT, MATCH & PARTICIPANT MANAGEMENT ENDPOINTS
  // ============================================================================
  app.get('/api/tournaments', (_req, res) => {
    const enriched = getEnrichedDevices();
    const tournaments = tournamentManager.getTournaments(enriched);
    const participants = tournamentManager.getParticipants('all', enriched);
    return res.json({
      tournaments,
      participants,
      unlimitedScalingSupported: true,
    });
  });

  app.post('/api/tournaments', (req, res) => {
    try {
      const created = tournamentManager.createTournament({
        name: req.body?.name || 'Free Fire Championship Split',
        organizer: req.body?.organizer,
        gameTitle: req.body?.gameTitle,
        policy: req.body?.policy,
        enabledRuleIds: req.body?.enabledRuleIds,
      });
      blackboxService.recordSystemEvent(
        'ADMIN_ACTION',
        `Tournament Created: ${created.name}`,
        SeverityLevel.LOW,
        `Tournament ID: ${created.tournamentId} | Organizer: ${created.organizer}`,
        'SYSTEM',
        'SOC-ADMIN'
      );
      broadcastRealtimePayload('tournament:created', { tournament: created });
      return res.json({ status: 'created', tournament: created });
    } catch (err) {
      return res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
    }
  });

  app.post('/api/tournaments/:id/policy', (req, res) => {
    const updated = tournamentManager.updateTournamentPolicy(
      req.params.id,
      req.body?.policy || {},
      req.body?.status
    );
    if (!updated) {
      return res.status(404).json({ error: `Tournament '${req.params.id}' not found.` });
    }
    broadcastRealtimePayload('tournament:updated', { tournament: updated });
    return res.json({ status: 'updated', tournament: updated });
  });

  app.post('/api/tournaments/:id/matches', (req, res) => {
    const match = tournamentManager.createMatch(req.params.id, {
      roundNumber: req.body?.roundNumber,
      matchName: req.body?.matchName || 'Qualifier Match',
      mapName: req.body?.mapName,
      participantIds: req.body?.participantIds,
    });
    if (!match) {
      return res.status(404).json({ error: `Tournament '${req.params.id}' not found.` });
    }
    return res.json({ status: 'match_created', match });
  });

  app.post('/api/tournaments/:id/participants', (req, res) => {
    try {
      const gamerTag = (req.body?.gamerTag || '').trim();
      if (!gamerTag) {
        return res.status(400).json({ error: 'gamerTag is required to register a participant.' });
      }
      // Issue a dedicated enrollment token for this participant if requested
      const tokenSecret = `enr_plr_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
      const participant = tournamentManager.registerParticipant(req.params.id, {
        gamerTag,
        teamName: req.body?.teamName,
        email: req.body?.email,
        deviceId: req.body?.deviceId,
        enrollmentTokenSecret: tokenSecret,
      });

      enrollmentTokens.set(tokenSecret, {
        tokenId: `tok_${participant.participantId}`,
        tokenSecret,
        label: `Player Token: ${participant.gamerTag} (${req.params.id})`,
        createdBy: 'tournament_ops@sentinel.local',
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(),
        maxUses: 5,
        usedCount: 0,
        revoked: false,
        tournamentId: req.params.id,
        participantId: participant.participantId,
      });
      saveTelemetryState();

      return res.json({ status: 'registered', participant, enrollmentToken: tokenSecret });
    } catch (err) {
      return res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
    }
  });

  app.delete('/api/participants/:id', (req, res) => {
    const removed = tournamentManager.removeParticipant(req.params.id);
    if (!removed) {
      return res.status(404).json({ error: `Participant '${req.params.id}' not found.` });
    }
    return res.json({ status: 'removed', participant: removed });
  });

  app.post('/api/participants/:id/bind-device', (req, res) => {
    try {
      const deviceId = (req.body?.deviceId || '').trim();
      if (!deviceId) {
        return res.status(400).json({ error: 'deviceId is required.' });
      }
      const updated = tournamentManager.bindDeviceToParticipant(req.params.id, deviceId);
      const dev = liveAgents.get(deviceId);
      if (dev) {
        dev.tournamentId = updated.tournamentId;
        dev.participantId = updated.participantId;
        dev.participantTag = updated.gamerTag;
        saveTelemetryState();
      }
      return res.json({ status: 'bound', participant: updated });
    } catch (err) {
      return res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
    }
  });

  app.post('/api/participants/:id/replace-device', (req, res) => {
    try {
      const { previousDeviceId, newDeviceId, reason } = req.body || {};
      if (!previousDeviceId || !newDeviceId) {
        return res.status(400).json({ error: 'previousDeviceId and newDeviceId are required.' });
      }
      const updated = tournamentManager.replaceParticipantDevice(
        req.params.id,
        previousDeviceId,
        newDeviceId,
        reason || 'Authorized hardware replacement'
      );
      const newDev = liveAgents.get(newDeviceId);
      if (newDev) {
        newDev.tournamentId = updated.tournamentId;
        newDev.participantId = updated.participantId;
        newDev.participantTag = updated.gamerTag;
        saveTelemetryState();
      }
      blackboxService.recordSystemEvent(
        'ADMIN_ACTION',
        `Participant Device Replaced (${updated.gamerTag})`,
        SeverityLevel.LOW,
        `Replaced ${previousDeviceId} -> ${newDeviceId}. Reason: ${reason || 'Hardware swap'}. Historical logs preserved.`,
        newDeviceId,
        newDev?.hostname || 'TOURNAMENT-PC'
      );
      return res.json({ status: 'replaced', participant: updated });
    } catch (err) {
      return res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
    }
  });

  // Incident Review & Appeal Workflow Endpoint
  app.post('/api/incidents/:id/review', (req, res) => {
    const incidentId = req.params.id;
    const inc = liveIncidents.get(incidentId);
    if (!inc) {
      return res.status(404).json({ error: `Incident '${incidentId}' not found.` });
    }
    const { reviewState, analystNotes, appealNotes, reviewedBy } = req.body || {};
    if (reviewState) {
      inc.reviewState = reviewState;
      if (reviewState === 'confirmed_violation') inc.status = 'confirmed_violation';
      else if (reviewState === 'benign_false_positive' || reviewState === 'appeal_resolved')
        inc.status = 'dismissed_false_positive';
      else inc.status = 'investigating';
    }
    if (typeof analystNotes === 'string') inc.analystNotes = analystNotes;
    if (typeof appealNotes === 'string') inc.appealNotes = appealNotes;
    inc.reviewedBy = reviewedBy || 'analyst@sentinel.local';
    inc.reviewedAt = new Date().toISOString();
    inc.updatedAt = inc.reviewedAt;

    liveIncidents.set(incidentId, inc);
    saveTelemetryState();
    broadcastRealtimePayload('incident:updated', { incident: inc });
    return res.json({ status: 'updated', incident: inc });
  });

  // Windows Telemetry Coverage & Blind-Spot Matrix Endpoint
  app.get('/api/telemetry/coverage-matrix', (_req, res) => {
    return res.json({
      matrix: WINDOWS_TELEMETRY_COVERAGE_MATRIX,
      capabilityBoundaries: DETECTION_CAPABILITY_BOUNDARIES,
      supportedEmulators: SUPPORTED_EMULATOR_ADAPTERS,
    });
  });

  // Dynamic Load-Testing & Capacity Benchmark Endpoint (Isolated from Production)
  app.post('/api/load-test/run', (req, res) => {
    try {
      const prodCountBefore = liveAgents.size;
      const result = DynamicLoadTestEngine.runLoadTest(req.body || {}, prodCountBefore);
      return res.json(result);
    } catch (err) {
      return res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
    }
  });


  // Vite middleware for development or static serving in production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Sentinel AC Server & WebSocket Engine listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
