import express from 'express';
import http from 'http';
import path from 'path';
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
import {
  DetectionRuleRecord,
  IncidentRecord,
  RawAgentTelemetry,
  SignedRuleBundle,
} from './shared-schemas/types.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const server = http.createServer(app);
  const PORT = 3000;

  app.use(express.json({ limit: '256kb' }));

  const detectionEngine = new SentinelDetectionEngine();

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
    ws.send(
      JSON.stringify({
        type: 'connection:established',
        payload: {
          connectedClients: wss.clients.size,
          schemaVersion: '1.2.0',
          engineStatus: 'active',
        },
        serverTimestamp: new Date().toISOString(),
      })
    );
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
    res.json({
      status: 'healthy',
      service: 'Sentinel AC Security Engine',
      schemaVersion: '1.2.0',
      wsClientsConnected: wss.clients.size,
      supportedEmulators: SUPPORTED_EMULATOR_ADAPTERS.length,
      defaultRulesCount: DEFAULT_SIGNED_RULES.length,
      timestamp: new Date().toISOString(),
    });
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

      if (evaluation.event) {
        broadcastRealtimePayload('telemetry:evaluated', {
          event: evaluation.event,
          updatedIncident: evaluation.updatedIncident,
          explanation: evaluation.explanation,
          scenarioTitle: scenario.title,
        });
      }

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
