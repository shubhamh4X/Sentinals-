import React, { useEffect, useState, useCallback } from 'react';
import { onAuthStateChanged, User } from 'firebase/auth';
import {
  auth,
  signInWithGoogle,
  signOutUser,
} from './lib/firebase.ts';
import {
  appendAuditLogToFirestore,
  clearAllWorkspaceRecords,
  ensureUserProfileAndCleanWorkspace,
  persistDeviceUpdateToFirestore,
  persistIncidentToFirestore,
  persistNewDeviceToFirestore,
  persistRuleUpdateToFirestore,
  persistSecurityEventToFirestore,
  subscribeToWorkspaceCollections,
} from './lib/firestoreRepo.ts';
import { DEFAULT_SIGNED_RULES } from '../detection-engine/engine.ts';
import {
  computeFleetSummary,
  isDemoOrSimulatedEventOrIncident,
} from '../shared-schemas/fleetMetrics.ts';
import {
  AuditLogRecord,
  DetectionRuleRecord,
  IncidentRecord,
  MonitoredDevice,
  SecurityEventRecord,
  UserRole,
} from '../shared-schemas/types.ts';
import { OverviewTab } from './components/OverviewTab.tsx';
import { WindowsControlPanelTab } from './components/WindowsControlPanelTab.tsx';
import { ConnectMyPcTab } from './components/ConnectMyPcTab.tsx';
import { SetupWizard } from './components/SetupWizard.tsx';
import { LiveMonitoringTab } from './components/LiveMonitoringTab.tsx';
import { ThreatInvestigationTab } from './components/ThreatInvestigationTab.tsx';
import { AdvancedSocTab } from './components/AdvancedSocTab.tsx';
import { ConnectAgentModal } from './components/ConnectAgentModal.tsx';

type ActiveTab =
  | 'overview'
  | 'controlpanel'
  | 'connect'
  | 'wizard'
  | 'live'
  | 'investigation'
  | 'advanced';


export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [userRole, setUserRole] = useState<UserRole>(UserRole.ADMINISTRATOR);
  const [isConnectModalOpen, setIsConnectModalOpen] = useState(false);

  // Clean Real-Time Operational State: ZERO pre-populated mock records
  const [devices, setDevices] = useState<MonitoredDevice[]>([]);
  const [rules, setRules] = useState<DetectionRuleRecord[]>(() =>
    DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: 'system' }))
  );
  const [events, setEvents] = useState<SecurityEventRecord[]>([]);
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogRecord[]>([]);

  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [selectedDeviceFilter, setSelectedDeviceFilter] = useState<string>('all');
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [isRunningScenario, setIsRunningScenario] = useState<string | null>(null);
  const [toastNotification, setToastNotification] = useState<string | null>(null);

  const showToast = useCallback((msg: string) => {
    setToastNotification(msg);
    setTimeout(() => {
      setToastNotification((prev) => (prev === msg ? null : prev));
    }, 4500);
  }, []);

  // Firebase Auth & Firestore Real-Time Synchronization
  useEffect(() => {
    let unsubFirestore: (() => void)[] = [];
    const unsubAuth = onAuthStateChanged(auth, async (user) => {
      unsubFirestore.forEach((u) => u());
      unsubFirestore = [];
      setCurrentUser(user);

      if (user) {
        try {
          const role = await ensureUserProfileAndCleanWorkspace(
            user.uid,
            user.email || 'analyst@sentinel.local',
            user.displayName || 'SOC Analyst'
          );
          setUserRole(role);
          unsubFirestore = subscribeToWorkspaceCollections(user.uid, {
            // Authoritative device enrollment & live heartbeat status come strictly from backend /api/agent/devices
            onDevices: () => {},
            onRules: (updatedRules) => {
              if (updatedRules.length > 0) setRules(updatedRules);
            },
            onEvents: setEvents,
            onIncidents: setIncidents,
            onAuditLogs: setAuditLogs,
          });
        } catch (err) {
          console.error('Firestore initialization error:', err);
        }
      } else {
        // If logged out of Firebase auth, sync real-time devices from backend registry
        fetch('/api/agent/devices')
          .then((r) => r.json())
          .then((data) => {
            if (Array.isArray(data?.devices)) {
              setDevices(data.devices);
            }
          })
          .catch(() => {});
        setEvents([]);
        setIncidents([]);
        setAuditLogs([]);
      }
    });

    return () => {
      unsubAuth();
      unsubFirestore.forEach((u) => u());
    };
  }, []);

  // WebSocket Real-Time Event Stream Connection & Device Sync
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    // Fetch authoritative enrolled Windows agents from backend registry
    const fetchLiveDevices = () => {
      fetch('/api/agent/devices')
        .then((r) => r.json())
        .then((data) => {
          if (Array.isArray(data?.devices)) {
            setDevices(data.devices);
          }
        })
        .catch(() => {});

      fetch('/api/agent/events')
        .then((r) => r.json())
        .then((data) => {
          if (Array.isArray(data?.events)) {
            const realEvents = (data.events as SecurityEventRecord[]).filter(
              (e) => !isDemoOrSimulatedEventOrIncident(e)
            );
            setEvents((prev) => {
              const map = new Map<string, SecurityEventRecord>();
              for (const e of realEvents) map.set(e.eventId, e);
              for (const e of prev) {
                if (!map.has(e.eventId) && !isDemoOrSimulatedEventOrIncident(e)) {
                  map.set(e.eventId, e);
                }
              }
              return Array.from(map.values());
            });
          }
          if (Array.isArray(data?.incidents)) {
            const realIncidents = (data.incidents as IncidentRecord[]).filter(
              (inc) => !isDemoOrSimulatedEventOrIncident(inc)
            );
            setIncidents((prev) => {
              const map = new Map<string, IncidentRecord>();
              for (const inc of realIncidents) map.set(inc.incidentId, inc);
              for (const inc of prev) {
                if (!map.has(inc.incidentId) && !isDemoOrSimulatedEventOrIncident(inc)) {
                  map.set(inc.incidentId, inc);
                }
              }
              return Array.from(map.values());
            });
          }
        })
        .catch(() => {});
    };

    const bridgeDeviceTokens = new Map<string, string>();
    const pollLocalBridge = async () => {
      try {
        const res = await fetch('http://127.0.0.1:19450/poll', {
          method: 'GET',
          mode: 'cors',
        });
        if (!res.ok) return;
        const data = await res.json();

        const devId = data?.device?.deviceId || data?.heartbeat?.deviceId;
        if (data?.device && data.device.deviceId && !bridgeDeviceTokens.has(data.device.deviceId)) {
          try {
            const regRes = await fetch('/api/agent/register', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(data.device),
            });
            if (regRes.ok) {
              const regJson = await regRes.json();
              if (regJson?.token) {
                bridgeDeviceTokens.set(data.device.deviceId, String(regJson.token));
              }
            }
          } catch {}
        }

        const cachedToken = devId ? bridgeDeviceTokens.get(devId) || '' : '';
        const authHeaders: Record<string, string> = {
          'Content-Type': 'application/json',
        };
        if (cachedToken) {
          authHeaders['x-sentinel-device-token'] = cachedToken;
        }

        if (data?.heartbeat && data.heartbeat.deviceId) {
          const hbRes = await fetch('/api/agent/heartbeat', {
            method: 'POST',
            headers: authHeaders,
            body: JSON.stringify(data.heartbeat),
          });
          if (hbRes.status === 404 || hbRes.status === 401) {
            bridgeDeviceTokens.delete(data.heartbeat.deviceId);
          }
        }

        if (Array.isArray(data?.events) && data.events.length > 0) {
          for (const ev of data.events) {
            const telRes = await fetch('/api/agent/telemetry', {
              method: 'POST',
              headers: authHeaders,
              body: JSON.stringify(ev),
            });
            if (telRes.ok) {
              const evalData = await telRes.json();
              const evaluatedEvent: SecurityEventRecord | undefined = evalData?.evaluation?.event;
              const evaluatedIncident: IncidentRecord | undefined =
                evalData?.evaluation?.updatedIncident;
              if (evaluatedEvent) {
                setEvents((prev) =>
                  prev.some((e) => e.eventId === evaluatedEvent.eventId)
                    ? prev
                    : [evaluatedEvent, ...prev]
                );
                setToastNotification(
                  `[LIVE WINDOWS AGENT] Threat Detected: ${evaluatedEvent.processName} (${evaluatedEvent.ruleId})`
                );
              }
              if (evaluatedIncident) {
                setIncidents((prev) => {
                  const idx = prev.findIndex(
                    (i) => i.incidentId === evaluatedIncident.incidentId
                  );
                  if (idx >= 0) {
                    const copy = [...prev];
                    copy[idx] = evaluatedIncident;
                    return copy;
                  }
                  return [evaluatedIncident, ...prev];
                });
                setSelectedIncidentId((prev) => prev || evaluatedIncident.incidentId);
              }
            }
          }
        }
      } catch {
        // Local bridge not active yet
      }
    };

    fetchLiveDevices();
    pollLocalBridge();
    const pollInterval = setInterval(() => {
      fetchLiveDevices();
      pollLocalBridge();
    }, 1500);

    const connectWs = () => {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws`;
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        setWsConnected(true);
      };

      ws.onmessage = (msg) => {
        try {
          const parsed = JSON.parse(msg.data);

          if (parsed.type === 'connection:established') {
            if (Array.isArray(parsed.payload?.devices)) {
              setDevices(parsed.payload.devices);
            }
            if (Array.isArray(parsed.payload?.events)) {
              setEvents(
                (parsed.payload.events as SecurityEventRecord[]).filter(
                  (e) => !isDemoOrSimulatedEventOrIncident(e)
                )
              );
            }
            if (Array.isArray(parsed.payload?.incidents)) {
              setIncidents(
                (parsed.payload.incidents as IncidentRecord[]).filter(
                  (inc) => !isDemoOrSimulatedEventOrIncident(inc)
                )
              );
            }
          }


          if (parsed.type === 'device:registered' && parsed.payload?.device) {
            const newDev: MonitoredDevice = parsed.payload.device;
            setDevices((prev) => {
              if (prev.some((d) => d.deviceId === newDev.deviceId)) {
                return prev.map((d) => (d.deviceId === newDev.deviceId ? newDev : d));
              }
              return [newDev, ...prev];
            });
            setToastNotification(`[LIVE WINDOWS AGENT] Endpoint connected: ${newDev.hostname} (${newDev.deviceId})`);
          }

          if (parsed.type === 'device:heartbeat' && parsed.payload?.deviceId) {
            const hb = parsed.payload;
            setDevices((prev) => {
              const existingIdx = prev.findIndex((d) => d.deviceId === hb.deviceId);
              if (existingIdx < 0) {
                return prev;
              }
              const updated = [...prev];
              updated[existingIdx] = {
                ...updated[existingIdx],
                ...(hb.device || {}),
                lastHeartbeat: hb.lastHeartbeat || new Date().toISOString(),
                cpuOverheadPercent: hb.cpuOverheadPercent ?? updated[existingIdx].cpuOverheadPercent,
                memoryFootprintMb: hb.memoryFootprintMb ?? updated[existingIdx].memoryFootprintMb,
                encryptedQueueDepth: hb.encryptedQueueDepth ?? updated[existingIdx].encryptedQueueDepth,
                gameSessionState: hb.gameSessionState ?? updated[existingIdx].gameSessionState,
                emulatorName: hb.emulatorName || updated[existingIdx].emulatorName,
                status: updated[existingIdx].riskScore >= 70 ? 'degraded' : 'healthy',
              };
              return updated;
            });
          }

          if (parsed.type === 'device:updated' && parsed.payload?.device) {
            const updatedDev: MonitoredDevice = parsed.payload.device;
            setDevices((prev) =>
              prev.map((d) => (d.deviceId === updatedDev.deviceId ? updatedDev : d))
            );
          }

          if (parsed.type === 'device:disconnected' && parsed.payload?.deviceId) {
            const discId = parsed.payload.deviceId;
            setDevices((prev) => prev.filter((d) => d.deviceId !== discId));
            setToastNotification(`[AGENT UNLINKED] Device disconnected: ${discId}`);
          }

          if (parsed.type === 'telemetry:evaluated' && parsed.payload?.event) {
            const incomingEvent: SecurityEventRecord = parsed.payload.event;
            const incomingIncident: IncidentRecord | undefined =
              parsed.payload.updatedIncident;

            if (!isDemoOrSimulatedEventOrIncident(incomingEvent)) {
              setEvents((prev) => {
                if (prev.some((e) => e.eventId === incomingEvent.eventId)) {
                  return prev;
                }
                return [incomingEvent, ...prev];
              });
            }

            if (incomingIncident && !isDemoOrSimulatedEventOrIncident(incomingIncident)) {
              setIncidents((prev) => {
                const idx = prev.findIndex(
                  (i) => i.incidentId === incomingIncident.incidentId
                );
                if (idx >= 0) {
                  const copy = [...prev];
                  copy[idx] = incomingIncident;
                  return copy;
                }
                return [incomingIncident, ...prev];
              });
              setSelectedIncidentId((prev) => prev || incomingIncident.incidentId);
            }
          }

          if (parsed.type === 'threats:cleared') {
            setEvents([]);
            setIncidents([]);
            setSelectedIncidentId(null);
            if (Array.isArray(parsed.payload?.devices)) {
              setDevices(parsed.payload.devices);
            } else {
              setDevices((prev) =>
                prev.map((d) => ({ ...d, riskScore: 0, status: 'healthy' }))
              );
            }
          }
        } catch (e) {
          console.error('WebSocket message parse error:', e);
        }
      };

      ws.onclose = () => {
        setWsConnected(false);
        reconnectTimer = setTimeout(connectWs, 3000);
      };
    };

    connectWs();

    return () => {
      clearInterval(pollInterval);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws) ws.close();
    };
  }, []);

  // Authoritative Fleet Summary (Total Registered, Online, Offline, Revoked)
  const fleetSummary = computeFleetSummary(devices);

  const recordAudit = useCallback(
    async (
      action: string,
      targetType: AuditLogRecord['targetType'],
      targetId: string,
      details: string
    ) => {
      const logEntry: AuditLogRecord = {
        logId: `log_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
        ownerId: currentUser?.uid || 'realtime_user',
        actorEmail: currentUser?.email || 'local.analyst@sentinel.local',
        actorRole: userRole,
        action,
        targetType,
        targetId,
        details,
        timestamp: new Date().toISOString(),
      };
      setAuditLogs((prev) => [logEntry, ...prev]);
      if (currentUser) {
        try {
          await appendAuditLogToFirestore(logEntry);
        } catch (e) {
          console.error('Failed to persist audit log:', e);
        }
      }
    },
    [currentUser, userRole]
  );

  const handleTriggerScenario = async (scenarioId: string) => {
    setIsRunningScenario(scenarioId);
    try {
      const ownerId = currentUser?.uid || 'realtime_user';
      // Never invent a fake production device for synthetic test scenarios
      const activeOnlineDevice = fleetSummary.onlineDevices[0];
      const activeHost = activeOnlineDevice?.hostname || 'TEST-SANDBOX';
      const activeDevId = activeOnlineDevice?.deviceId || 'test-sandbox-fixture';

      const response = await fetch('/api/harness/scenario', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenarioId,
          deviceId: activeDevId,
          hostname: activeHost,
          emulator: 'BlueStacks 5',
          ownerId,
          activeRules: rules,
          existingIncidents: incidents,
        }),
      });
      const data = await response.json();

      if (data.type === 'rule_bundle_verification') {
        await recordAudit(
          'INVALID_RULE_SIGNATURE_BLOCKED',
          'rule',
          'bundle_tampered_999',
          data.verification?.reason || 'Tampered rule update blocked.'
        );
        showToast(
          `Scenario 7 Verified: Rejected invalid rule signature (${data.verification?.reason})`
        );
        return;
      }

      const evaluation = data.evaluation;
      if (evaluation?.event) {
        const newEvent: SecurityEventRecord = {
          ...evaluation.event,
          isSimulated: true,
        };

        await recordAudit(
          'RULE_VERIFICATION_SCENARIO_TESTED',
          'session',
          newEvent.eventId,
          `Isolated Rule Verification (${scenarioId}): ${evaluation.explanation}`
        );

        showToast(`[ISOLATED RULE VERIFICATION] ${newEvent.ruleId}: ${evaluation.explanation}`);
      }
    } catch (error) {
      console.error('Failed to trigger scenario:', error);
      showToast('Error executing real-time telemetry scenario.');
    } finally {
      setIsRunningScenario(null);
    }
  };

  const handleUpdateIncident = async (
    incidentId: string,
    status: IncidentRecord['status'],
    notes: string,
    actionDescription: string
  ) => {
    const target = incidents.find((i) => i.incidentId === incidentId);
    if (!target) return;
    const updated: IncidentRecord = {
      ...target,
      status,
      analystNotes: notes,
      updatedAt: new Date().toISOString(),
    };
    setIncidents((prev) =>
      prev.map((i) => (i.incidentId === incidentId ? updated : i))
    );
    if (currentUser) {
      await persistIncidentToFirestore(updated, false);
    }
    await recordAudit('INCIDENT_DISPOSITION_UPDATED', 'incident', incidentId, actionDescription);
    showToast(actionDescription);
  };

  const handleUpdateDevice = async (
    updatedDevice: MonitoredDevice,
    auditDetails: string
  ) => {
    setDevices((prev) =>
      prev.map((d) => (d.deviceId === updatedDevice.deviceId ? updatedDevice : d))
    );
    if (currentUser) {
      await persistDeviceUpdateToFirestore(updatedDevice);
    }
    await recordAudit(
      'DEVICE_STATE_UPDATED',
      'device',
      updatedDevice.deviceId,
      auditDetails
    );
  };

  const handleRegisterDevice = async (newDevice: MonitoredDevice) => {
    setDevices((prev) => [newDevice, ...prev]);
    if (currentUser) {
      await persistNewDeviceToFirestore(newDevice);
    }
    await recordAudit(
      'DEVICE_REGISTERED',
      'device',
      newDevice.deviceId,
      `Registered Windows PC ${newDevice.hostname} (${newDevice.emulatorName}).`
    );
    showToast(`Registered endpoint ${newDevice.hostname} in real time.`);
  };

  const handleDisconnectDevice = async (deviceId?: string) => {
    try {
      await fetch('/api/agent/disconnect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deviceId }),
      });

      if (deviceId) {
        setDevices((prev) => prev.filter((d) => d.deviceId !== deviceId));
        showToast(`Disconnected and unlinked Windows PC (${deviceId})`);
      } else {
        setDevices([]);
        showToast('All connected Windows PCs have been unlinked.');
      }

      await recordAudit(
        'DEVICE_DISCONNECTED',
        'device',
        deviceId || 'all',
        `User disconnected Windows agent ${deviceId || 'endpoints'} from dashboard.`
      );
    } catch (err) {
      console.error('Error disconnecting device:', err);
      if (deviceId) {
        setDevices((prev) => prev.filter((d) => d.deviceId !== deviceId));
      } else {
        setDevices([]);
      }
      showToast('Agent unlinked locally.');
    }
  };

  const handleUpdateRule = async (
    updatedRule: DetectionRuleRecord,
    auditDetail: string
  ) => {
    setRules((prev) =>
      prev.map((r) => (r.ruleId === updatedRule.ruleId ? updatedRule : r))
    );
    if (currentUser) {
      await persistRuleUpdateToFirestore(updatedRule);
    }
    await recordAudit('DETECTION_RULE_MODIFIED', 'rule', updatedRule.ruleId, auditDetail);
    showToast(auditDetail);
  };

  const handleClearThreats = async () => {
    try {
      await fetch('/api/agent/clear-threats', { method: 'POST' });
    } catch {}
    setEvents([]);
    setIncidents([]);
    setSelectedIncidentId(null);
    setDevices((prev) =>
      prev.map((d) => ({
        ...d,
        riskScore: 0,
        status: d.status === 'degraded' ? 'healthy' : d.status,
      }))
    );
    showToast('All security alerts and threat cases cleared. Connected PC risk score reset to 0.');
  };

  const handleClearAllRecords = async () => {
    try {
      await fetch('/api/agent/clear-threats', { method: 'POST' });
      await fetch('/api/agent/disconnect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
    } catch {}
    setDevices([]);
    setEvents([]);
    setIncidents([]);
    setAuditLogs([]);
    setSelectedIncidentId(null);
    if (currentUser) {
      await clearAllWorkspaceRecords(currentUser.uid);
    }
    showToast('All stored records cleared. System reset to clean real-time operational zero.');
  };

  return (
    <div className="min-h-screen bg-[#0B0F19] text-slate-100 flex flex-col">
      {/* Strict 3-Zone Top Bar Contract */}
      <header className="flex items-center justify-between gap-8 px-6 py-3.5 border-b border-slate-800/90 bg-[#0B0F19]">
        {/* Zone 1: Wordmark & Real Protection Status */}
        <div className="flex items-center gap-3">
          <a
            href="#overview"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab('overview');
            }}
            className="text-lg font-bold tracking-tight text-slate-100 font-display whitespace-nowrap shrink-0 flex items-center gap-2"
          >
            <span className="w-2.5 h-2.5 rounded-full bg-sky-400" />
            <span>Sentinel AC</span>
          </a>

          {/* Real Live Protection Status Indicator */}
          {fleetSummary.onlineCount > 0 ? (
            <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/15 border border-emerald-500/40 text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Protected ({fleetSummary.onlineCount} Online)
            </span>
          ) : (
            <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-amber-500/15 border border-amber-500/40 text-amber-400">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
              Agent Offline (0 Connected)
            </span>
          )}
        </div>

        {/* Zone 2: Navigation Links */}
        <nav className="flex flex-wrap items-center gap-4 md:gap-6 text-xs font-medium text-slate-400">
          <button
            onClick={() => setActiveTab('overview')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'overview' ? 'text-slate-100 underline underline-offset-8 decoration-sky-400 font-semibold' : ''
            }`}
          >
            Overview
          </button>
          <button
            onClick={() => setActiveTab('connect')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'connect' ? 'text-slate-100 underline underline-offset-8 decoration-sky-400 font-semibold' : ''
            }`}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                fleetSummary.onlineCount > 0 ? 'bg-emerald-400' : 'bg-amber-400'
              }`}
            />
            Endpoints / PCs ({fleetSummary.onlineCount} Online / {fleetSummary.totalRegistered} Enrolled)
          </button>
          <button
            onClick={() => setActiveTab('controlpanel')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'controlpanel' ? 'text-slate-100 underline underline-offset-8 decoration-sky-400 font-semibold' : ''
            }`}
          >
            Windows Control Panel
          </button>
          <button
            onClick={() => setActiveTab('wizard')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'wizard' ? 'text-slate-100 underline underline-offset-8 decoration-sky-400 font-semibold' : ''
            }`}
          >
            Setup Wizard
          </button>
          <button
            onClick={() => setActiveTab('live')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'live' ? 'text-slate-100 underline underline-offset-8 decoration-sky-400 font-semibold' : ''
            }`}
          >
            Security Alerts ({events.length})
          </button>
          <button
            onClick={() => setActiveTab('investigation')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'investigation' ? 'text-slate-100 underline underline-offset-8 decoration-sky-400 font-semibold' : ''
            }`}
          >
            Threats ({incidents.length})
          </button>
          <button
            onClick={() => setActiveTab('advanced')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'advanced' ? 'text-slate-100 underline underline-offset-8 decoration-sky-400 font-semibold' : ''
            }`}
          >
            Advanced Tools
          </button>
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={() => setActiveTab('controlpanel')}
            className="px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-sky-400 hover:bg-sky-300 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer shadow-sm"
          >
            Control Panel
          </button>

          {currentUser ? (
            <button
              onClick={() => signOutUser()}
              className="px-3.5 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Sign Out ({currentUser.email?.split('@')[0]})
            </button>
          ) : (
            <button
              onClick={() => signInWithGoogle().catch(console.error)}
              className="px-3.5 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Sign In
            </button>
          )}
        </div>
      </header>

      {/* Main Content Viewport */}
      <div className="flex-1 flex flex-col">
        <main className="flex-1 p-6 lg:p-8 max-w-[1440px] w-full mx-auto space-y-6">
          {toastNotification && (
            <div className="bg-sky-950/60 border border-sky-500/50 text-sky-200 px-4 py-3 rounded-lg text-xs font-mono flex items-center justify-between shadow-lg">
              <span>{toastNotification}</span>
              <button
                onClick={() => setToastNotification(null)}
                className="text-sky-300 hover:text-white ml-4 cursor-pointer"
              >
                ✕
              </button>
            </div>
          )}

          {activeTab === 'overview' && (
            <OverviewTab
              devices={fleetSummary.devices}
              events={events}
              incidents={incidents}
              onNavigateTab={(t) => setActiveTab(t as ActiveTab)}
              onSelectIncident={setSelectedIncidentId}
              onSelectDeviceForLogs={(devId) => {
                setSelectedDeviceFilter(devId);
                setActiveTab('live');
              }}
              onDisconnectDevice={handleDisconnectDevice}
            />
          )}

          {activeTab === 'controlpanel' && (
            <WindowsControlPanelTab
              devices={fleetSummary.devices}
              onRegisterDevice={handleRegisterDevice}
              onDisconnectDevice={handleDisconnectDevice}
              onNavigateToWizard={() => setActiveTab('wizard')}
              onShowToast={showToast}
            />
          )}

          {activeTab === 'connect' && (
            <ConnectMyPcTab
              devices={fleetSummary.devices}
              events={events}
              onRegisterDevice={handleRegisterDevice}
              onDisconnectDevice={handleDisconnectDevice}
              onNavigateTab={(t) => setActiveTab(t as ActiveTab)}
              onSelectDeviceForLogs={(devId) => {
                setSelectedDeviceFilter(devId);
                setActiveTab('live');
              }}
              onRefreshDevices={() => {
                fetch('/api/agent/devices')
                  .then((r) => r.json())
                  .then((data) => {
                    if (Array.isArray(data?.devices)) setDevices(data.devices);
                  })
                  .catch(() => {});
              }}
            />
          )}

          {activeTab === 'wizard' && (
            <SetupWizard
              devices={fleetSummary.devices}
              onRegisterDevice={handleRegisterDevice}
              onNavigateTab={(t) => setActiveTab(t as ActiveTab)}
            />
          )}

          {activeTab === 'live' && (
            <LiveMonitoringTab
              events={events}
              devices={fleetSummary.devices}
              wsConnected={wsConnected}
              selectedDeviceFilter={selectedDeviceFilter}
              onChangeDeviceFilter={setSelectedDeviceFilter}
              onClearAllThreats={handleClearThreats}
            />
          )}

          {activeTab === 'investigation' && (
            <ThreatInvestigationTab
              incidents={incidents}
              events={events}
              selectedIncidentId={selectedIncidentId}
              onSelectIncident={setSelectedIncidentId}
              userRole={userRole}
              onUpdateIncident={handleUpdateIncident}
              onClearAllThreats={handleClearThreats}
            />
          )}

          {activeTab === 'advanced' && (
            <AdvancedSocTab
              rules={rules}
              userRole={userRole}
              onChangeRole={(newRole) => {
                setUserRole(newRole);
                recordAudit(
                  'RBAC_ROLE_SWITCHED',
                  'policy',
                  newRole,
                  `Switched active role to ${newRole}.`
                );
              }}
              auditLogs={auditLogs}
              onUpdateRule={handleUpdateRule}
              onClearAllRecords={handleClearAllRecords}
              onTriggerScenario={handleTriggerScenario}
              isRunningScenario={isRunningScenario}
              onLogRuleBundleVerification={(bundleId, valid, reason) => {
                recordAudit(
                  valid ? 'SIGNED_RULE_BUNDLE_APPLIED' : 'INVALID_RULE_BUNDLE_REJECTED',
                  'rule',
                  bundleId,
                  reason
                );
              }}
            />
          )}
        </main>
      </div>

      <ConnectAgentModal
        isOpen={isConnectModalOpen}
        onClose={() => setIsConnectModalOpen(false)}
        onRegisterDevice={(newDev) => {
          handleRegisterDevice(newDev);
          setActiveTab('connect');
        }}
      />
    </div>
  );
}
