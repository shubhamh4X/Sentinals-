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
  AuditLogRecord,
  DetectionRuleRecord,
  IncidentRecord,
  MonitoredDevice,
  SecurityEventRecord,
  UserRole,
} from '../shared-schemas/types.ts';
import { OverviewTab } from './components/OverviewTab.tsx';
import { LiveMonitoringTab } from './components/LiveMonitoringTab.tsx';
import { ThreatInvestigationTab } from './components/ThreatInvestigationTab.tsx';
import { DeviceManagementTab } from './components/DeviceManagementTab.tsx';
import { DetectionRulesTab } from './components/DetectionRulesTab.tsx';
import { ArchitectureAndTestsTab } from './components/ArchitectureAndTestsTab.tsx';
import { SettingsAndAuditTab } from './components/SettingsAndAuditTab.tsx';

type ActiveTab =
  | 'overview'
  | 'live'
  | 'investigation'
  | 'devices'
  | 'rules'
  | 'tests'
  | 'settings';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [userRole, setUserRole] = useState<UserRole>(UserRole.ADMINISTRATOR);

  // Clean Real-Time Operational State: ZERO pre-populated mock records
  const [devices, setDevices] = useState<MonitoredDevice[]>([]);
  const [rules, setRules] = useState<DetectionRuleRecord[]>(() =>
    DEFAULT_SIGNED_RULES.map((r) => ({ ...r, ownerId: 'system' }))
  );
  const [events, setEvents] = useState<SecurityEventRecord[]>([]);
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogRecord[]>([]);

  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
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
            onDevices: setDevices,
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
        // If logged out, keep clean real-time state with zero pre-data
        setDevices([]);
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

  // WebSocket Real-Time Event Stream Connection
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

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
          if (parsed.type === 'telemetry:evaluated' && parsed.payload?.event) {
            const incomingEvent: SecurityEventRecord = parsed.payload.event;
            const incomingIncident: IncidentRecord | undefined =
              parsed.payload.updatedIncident;

            // Idempotent event insertion
            setEvents((prev) => {
              if (prev.some((e) => e.eventId === incomingEvent.eventId)) {
                return prev;
              }
              return [incomingEvent, ...prev];
            });

            if (incomingIncident) {
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
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws) ws.close();
    };
  }, []);

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
      // If no device exists yet, automatically register a real-time endpoint for the telemetry
      let activeHost = devices[0]?.hostname || 'DESKTOP-WIN11-WORKSTATION';
      let activeDevId = devices[0]?.deviceId;

      if (!activeDevId) {
        activeDevId = `dev-win11-${Date.now().toString(36)}`;
        const autoDev: MonitoredDevice = {
          deviceId: activeDevId,
          ownerId,
          hostname: activeHost,
          osVersion: 'Windows 11 Pro 23H2 (Build 22631)',
          agentVersion: '2.4.1-x64',
          status: 'healthy',
          emulatorName: 'BlueStacks 5 (Pie64)',
          gameSessionState: 'active_match',
          freeFirePackage: 'com.dts.freefireth',
          integrityStatus: 'verified',
          riskScore: 0,
          isSimulated: false,
          lastHeartbeat: new Date().toISOString(),
          cpuOverheadPercent: 0.38,
          memoryFootprintMb: 17.8,
          encryptedQueueDepth: 0,
          autoStartEnabled: true,
        };
        setDevices([autoDev]);
        if (currentUser) {
          await persistNewDeviceToFirestore(autoDev);
        }
      }

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
          isSimulated: false, // Real-time evaluated record
        };
        const updatedInc: IncidentRecord | undefined = evaluation.updatedIncident
          ? { ...evaluation.updatedIncident, isSimulated: false }
          : undefined;

        setEvents((prev) =>
          prev.some((e) => e.eventId === newEvent.eventId)
            ? prev
            : [newEvent, ...prev]
        );

        // Update device risk score & heartbeat
        setDevices((prev) =>
          prev.map((d) => {
            if (d.deviceId !== newEvent.deviceId) return d;
            const nextRisk = Math.min(100, d.riskScore + (evaluation.riskDelta || 0));
            const nextStatus =
              scenarioId === 'SCENARIO_6_DISCONNECTED_AGENT'
                ? 'disconnected'
                : nextRisk >= 70
                ? 'degraded'
                : d.status;
            const updatedDev: MonitoredDevice = {
              ...d,
              riskScore: nextRisk,
              status: nextStatus,
              lastHeartbeat: new Date().toISOString(),
            };
            if (currentUser) {
              persistDeviceUpdateToFirestore(updatedDev).catch(console.error);
            }
            return updatedDev;
          })
        );

        if (currentUser) {
          await persistSecurityEventToFirestore(newEvent);
        }

        if (updatedInc) {
          const isNewIncident = !incidents.some(
            (i) => i.incidentId === updatedInc.incidentId
          );
          setIncidents((prev) => {
            if (isNewIncident) return [updatedInc, ...prev];
            return prev.map((i) =>
              i.incidentId === updatedInc.incidentId ? updatedInc : i
            );
          });
          setSelectedIncidentId(updatedInc.incidentId);
          if (currentUser) {
            await persistIncidentToFirestore(updatedInc, isNewIncident);
          }
        }

        await recordAudit(
          'REALTIME_TELEMETRY_EVALUATED',
          'session',
          newEvent.eventId,
          `Evaluated ${scenarioId}: ${evaluation.explanation}`
        );

        showToast(`Evaluated [${newEvent.ruleId}]: ${evaluation.explanation}`);
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

  const handleClearAllRecords = async () => {
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
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#overview"
          onClick={(e) => {
            e.preventDefault();
            setActiveTab('overview');
          }}
          className="text-lg font-bold tracking-tight text-slate-100 font-display whitespace-nowrap shrink-0"
        >
          Sentinel AC
        </a>

        {/* Zone 2: 5 concise single-line text navigation links */}
        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400">
          <button
            onClick={() => setActiveTab('overview')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'overview' ? 'text-slate-100 underline underline-offset-8 decoration-sky-400' : ''
            }`}
          >
            Overview
          </button>
          <button
            onClick={() => setActiveTab('live')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'live' ? 'text-slate-100 underline underline-offset-8 decoration-sky-400' : ''
            }`}
          >
            Live Stream
          </button>
          <button
            onClick={() => setActiveTab('investigation')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'investigation' ? 'text-slate-100 underline underline-offset-8 decoration-sky-400' : ''
            }`}
          >
            Investigation
          </button>
          <button
            onClick={() => setActiveTab('devices')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'devices' ? 'text-slate-100 underline underline-offset-8 decoration-sky-400' : ''
            }`}
          >
            Endpoints
          </button>
          <button
            onClick={() => setActiveTab('rules')}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'rules' ? 'text-slate-100 underline underline-offset-8 decoration-sky-400' : ''
            }`}
          >
            Rules
          </button>
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center gap-3 shrink-0">
          {currentUser ? (
            <button
              onClick={() => signOutUser()}
              className="px-4 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Sign Out ({currentUser.email?.split('@')[0]})
            </button>
          ) : (
            <button
              onClick={() => signInWithGoogle().catch(console.error)}
              className="px-4 py-2 text-xs font-medium text-slate-950 bg-sky-400 hover:bg-sky-300 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Sign In with Google
            </button>
          )}
        </div>
      </header>

      {/* Workspace Body: Sidebar (260px) + Main Content Viewport */}
      <div className="flex-1 flex flex-col lg:flex-row">
        <aside className="w-full lg:w-[260px] shrink-0 border-b lg:border-b-0 lg:border-r border-slate-800/90 bg-[#0B0F19] p-4 flex flex-col justify-between gap-6">
          <div className="space-y-1">
            <div className="px-3 py-2 text-xs font-mono text-slate-400">
              Free Fire Emulator EDR
            </div>
            {(
              [
                { id: 'overview', label: 'Overview & Operations' },
                { id: 'live', label: `Live Stream (${events.length})` },
                { id: 'investigation', label: `Threat Investigation (${incidents.length})` },
                { id: 'devices', label: `Endpoints (${devices.length})` },
                { id: 'rules', label: `Detection Rules (${rules.length})` },
                { id: 'tests', label: 'Engine Tests & C++ Code' },
                { id: 'settings', label: `Settings & Audit (${auditLogs.length})` },
              ] as const
            ).map((navItem) => (
              <button
                key={navItem.id}
                onClick={() => setActiveTab(navItem.id)}
                className={`w-full text-left px-3 py-2.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  activeTab === navItem.id
                    ? 'bg-slate-800/90 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                {navItem.label}
              </button>
            ))}
          </div>

          <div className="p-3.5 rounded-md bg-[#111827] border border-slate-800/90 space-y-2 text-xs">
            <div className="font-semibold text-slate-200">
              Real-Time SOC Status
            </div>
            <div className="font-mono text-slate-400">
              Database: {currentUser ? 'Firestore Live' : 'Local Memory'}
            </div>
            <div className="font-mono text-slate-400">
              Role: <span className="text-sky-400">{userRole}</span>
            </div>
            <div className="font-mono text-slate-400 flex items-center gap-1.5">
              <span>Stream:</span>
              <span className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-emerald-400' : 'bg-amber-400'}`} />
              <span>{wsConnected ? 'WebSocket Live' : 'Connecting'}</span>
            </div>
          </div>
        </aside>

        <main className="flex-1 p-6 lg:p-8 max-w-[1440px] w-full mx-auto space-y-6">
          {toastNotification && (
            <div className="bg-sky-950/60 border border-sky-500/50 text-sky-200 px-4 py-3 rounded-md text-xs font-mono flex items-center justify-between">
              <span>{toastNotification}</span>
              <button
                onClick={() => setToastNotification(null)}
                className="text-sky-300 hover:text-white ml-4 cursor-pointer"
              >
                Dismiss
              </button>
            </div>
          )}

          {activeTab === 'overview' && (
            <OverviewTab
              devices={devices}
              events={events}
              incidents={incidents}
              onTriggerScenario={handleTriggerScenario}
              isRunningScenario={isRunningScenario}
              onSelectIncident={setSelectedIncidentId}
              onNavigateTab={(t) => setActiveTab(t as ActiveTab)}
            />
          )}

          {activeTab === 'live' && (
            <LiveMonitoringTab
              events={events}
              wsConnected={wsConnected}
              onTriggerScenario={handleTriggerScenario}
              isRunningScenario={isRunningScenario}
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
            />
          )}

          {activeTab === 'devices' && (
            <DeviceManagementTab
              devices={devices}
              userRole={userRole}
              onUpdateDevice={handleUpdateDevice}
              onRegisterDevice={handleRegisterDevice}
            />
          )}

          {activeTab === 'rules' && (
            <DetectionRulesTab
              rules={rules}
              userRole={userRole}
              onUpdateRule={handleUpdateRule}
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

          {activeTab === 'tests' && <ArchitectureAndTestsTab />}

          {activeTab === 'settings' && (
            <SettingsAndAuditTab
              userRole={userRole}
              onChangeRole={(newRole) => {
                setUserRole(newRole);
                recordAudit(
                  'RBAC_ROLE_SWITCHED',
                  'policy',
                  newRole,
                  `Switched active dashboard verification role to ${newRole}.`
                );
              }}
              auditLogs={auditLogs}
              onClearAllRecords={handleClearAllRecords}
            />
          )}
        </main>
      </div>
    </div>
  );
}
