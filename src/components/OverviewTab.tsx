import React from 'react';
import {
  DetectionCategory,
  IncidentRecord,
  MonitoredDevice,
  SecurityEventRecord,
  SeverityLevel,
} from '../../shared-schemas/types.ts';
import {
  DETECTION_CAPABILITY_BOUNDARIES,
  SUPPORTED_EMULATOR_ADAPTERS,
} from '../../emulator-adapters/adapters.ts';
import { SYNTHETIC_TEST_SCENARIOS } from '../../tests/detection_engine.test.ts';

interface OverviewTabProps {
  devices: MonitoredDevice[];
  events: SecurityEventRecord[];
  incidents: IncidentRecord[];
  onTriggerScenario: (scenarioId: string) => void;
  isRunningScenario: string | null;
  onSelectIncident: (incidentId: string) => void;
  onNavigateTab: (tab: string) => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  devices,
  events,
  incidents,
  onTriggerScenario,
  isRunningScenario,
  onSelectIncident,
  onNavigateTab,
}) => {
  const totalPcs = devices.length;
  const activeSessions = devices.filter(
    (d) => d.gameSessionState === 'active_match' || d.gameSessionState === 'launching'
  ).length;
  const healthyAgents = devices.filter((d) => d.status === 'healthy').length;
  const disconnectedAgents = devices.filter(
    (d) => d.status === 'disconnected' || d.status === 'degraded'
  ).length;

  const criticalAlerts = events.filter((e) => e.severity === SeverityLevel.CRITICAL).length;
  const highAlerts = events.filter((e) => e.severity === SeverityLevel.HIGH).length;
  const mediumAlerts = events.filter((e) => e.severity === SeverityLevel.MEDIUM).length;
  const lowAlerts = events.filter((e) => e.severity === SeverityLevel.LOW).length;

  const categoryCounts = [
    DetectionCategory.PROCESS_INTEGRITY,
    DetectionCategory.MEMORY_INJECTION,
    DetectionCategory.EMULATOR_INTEGRITY,
    DetectionCategory.ESP_GAMEPLAY,
    DetectionCategory.AGENT_INTEGRITY,
  ].map((cat) => {
    const count = events.filter((e) => e.category === cat).length;
    const pct = events.length > 0 ? Math.round((count / events.length) * 100) : 0;
    return { category: cat, count, pct };
  });

  return (
    <div className="space-y-8">
      {/* Real-time Operational Banner */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="space-y-1">
          <div className="text-xs font-mono text-sky-400 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>REAL-TIME ENDPOINT TELEMETRY ENGINE ACTIVE</span>
          </div>
          <p className="text-sm text-slate-300 max-w-4xl">
            Clean real-time operational state. Zero pre-loaded mock records. Telemetry events, endpoint heartbeats, and incidents are recorded live as Windows agents stream data or security verification tests are triggered.
          </p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={() => onNavigateTab('devices')}
            className="px-4 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Register / Connect Endpoint
          </button>
          <button
            onClick={() => onNavigateTab('live')}
            className="px-4 py-2 text-xs font-medium text-slate-950 bg-sky-400 hover:bg-sky-300 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            View Live Stream ({events.length})
          </button>
        </div>
      </div>

      {/* Primary KPI Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-2">
          <div className="text-xs text-slate-400">Total Monitored PCs</div>
          <div className="text-3xl font-semibold font-mono tabular-nums text-slate-100">
            {totalPcs}
          </div>
          <div className="text-xs text-slate-400 font-mono tabular-nums">
            {healthyAgents} Healthy · {disconnectedAgents} Degraded/Offline
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-2">
          <div className="text-xs text-slate-400">Active Emulator Sessions</div>
          <div className="text-3xl font-semibold font-mono tabular-nums text-sky-400">
            {activeSessions}
          </div>
          <div className="text-xs text-slate-400 font-mono tabular-nums">
            Free Fire (com.dts.freefireth / max)
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-2">
          <div className="text-xs text-slate-400">Security Alerts (Live)</div>
          <div className="text-3xl font-semibold font-mono tabular-nums text-rose-400">
            {criticalAlerts + highAlerts} <span className="text-base font-normal text-slate-400">Crit/High</span>
          </div>
          <div className="text-xs text-slate-400 font-mono tabular-nums">
            {criticalAlerts} Crit · {highAlerts} High · {mediumAlerts} Med · {lowAlerts} Low
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-2">
          <div className="text-xs text-slate-400">Open Correlated Incidents</div>
          <div className="text-3xl font-semibold font-mono tabular-nums text-amber-400">
            {incidents.filter((i) => i.status === 'open' || i.status === 'investigating').length}
          </div>
          <div className="text-xs text-slate-400 font-mono tabular-nums">
            Total Cases: {incidents.length}
          </div>
        </div>
      </div>

      {/* Real-time Indicator Test Harness (Allows triggering live verifiable events) */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Real-Time Security Event Generator & Engine Scenarios
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Send live telemetry from your agent or trigger security scenarios directly into the live WebSocket stream and persistent storage.
            </p>
          </div>
          <div className="text-xs font-mono text-slate-400 shrink-0">
            Schema v1.2.0 · Live Replay Guard Active
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          {SYNTHETIC_TEST_SCENARIOS.map((scen) => {
            const isRunning = isRunningScenario === scen.scenarioId;
            return (
              <div
                key={scen.scenarioId}
                className="p-4 rounded-md bg-[#0B0F19] border border-slate-800/90 flex flex-col justify-between gap-3"
              >
                <div className="space-y-1.5">
                  <div className="text-xs font-mono text-sky-400">
                    Scenario 0{scen.number} · {scen.expectedRuleId}
                  </div>
                  <div className="text-sm font-medium text-slate-100">
                    {scen.title}
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    {scen.description}
                  </p>
                </div>
                <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between gap-2">
                  <span className="text-xs font-mono text-slate-400">
                    {scen.expectedClassification}
                  </span>
                  <button
                    onClick={() => onTriggerScenario(scen.scenarioId)}
                    disabled={Boolean(isRunningScenario)}
                    className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-sky-500 hover:text-slate-950 text-slate-200 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                  >
                    {isRunning ? 'Evaluating...' : 'Dispatch Live Event'}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Two-Column Split: Detection Trends + Monitored Endpoints */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Detection Trends & Pluggable Emulator Adapters */}
        <div className="lg:col-span-5 bg-[#111827] border border-slate-800 rounded-lg p-6 flex flex-col justify-between space-y-6">
          <div className="space-y-4">
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                Detection Distribution by Category
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Real-time breakdown of evaluated telemetry indicators across the 5 detection modules.
              </p>
            </div>

            <div className="space-y-3 pt-2">
              {categoryCounts.map((item) => (
                <div key={item.category} className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-300 font-medium">{item.category}</span>
                    <span className="font-mono tabular-nums text-slate-400">
                      {item.count} events {events.length > 0 ? `· ${item.pct}%` : ''}
                    </span>
                  </div>
                  <div className="w-full h-2 bg-slate-900 rounded overflow-hidden">
                    <div
                      className="h-full bg-sky-500 transition-all duration-200"
                      style={{ width: `${item.pct}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800 space-y-3">
            <div className="text-xs font-semibold text-slate-300">
              Loaded Emulator Adapter Plugins ({SUPPORTED_EMULATOR_ADAPTERS.length})
            </div>
            <div className="divide-y divide-slate-800/80 text-xs">
              {SUPPORTED_EMULATOR_ADAPTERS.map((adapter) => (
                <div key={adapter.adapterId} className="py-2 flex items-center justify-between gap-2">
                  <span className="text-slate-200 font-medium">{adapter.displayName}</span>
                  <span className="font-mono text-slate-400 shrink-0">
                    {adapter.processes.map((p) => p.executableName).join(', ')}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Agent Health & Live Connected Endpoints */}
        <div className="lg:col-span-7 bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                Live Connected Endpoints ({devices.length})
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Real-time heartbeat status, emulator process binding, and corroborated risk score (0–100).
              </p>
            </div>
            <button
              onClick={() => onNavigateTab('devices')}
              className="px-3 py-1.5 text-xs font-medium text-sky-400 hover:text-sky-300 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              + Add / Manage Endpoints
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-xs text-slate-400">
                  <th className="py-2.5 pr-4 font-medium">Hostname / Device ID</th>
                  <th className="py-2.5 px-3 font-medium">Emulator & Package</th>
                  <th className="py-2.5 px-3 font-medium">Agent State</th>
                  <th className="py-2.5 px-3 font-medium text-right">Risk Score</th>
                  <th className="py-2.5 pl-3 font-medium text-right">Last Heartbeat</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 text-xs">
                {devices.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-400">
                      No Windows endpoints connected yet. Start the Sentinel agent service on your PC or register an endpoint in the Endpoints tab.
                    </td>
                  </tr>
                ) : (
                  devices.map((dev) => (
                    <tr key={dev.deviceId} className="hover:bg-slate-900/60 transition-colors">
                      <td className="py-3 pr-4">
                        <div className="font-medium text-slate-100">{dev.hostname}</div>
                        <div className="font-mono text-slate-400">{dev.deviceId}</div>
                      </td>
                      <td className="py-3 px-3">
                        <div className="text-slate-200">{dev.emulatorName}</div>
                        <div className="font-mono text-slate-400">
                          {dev.freeFirePackage} · {dev.gameSessionState}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <div className="text-slate-200 capitalize">{dev.status}</div>
                        <div className="font-mono text-slate-400">{dev.integrityStatus}</div>
                      </td>
                      <td className="py-3 px-3 text-right font-mono tabular-nums">
                        <span
                          className={
                            dev.riskScore >= 70
                              ? 'text-rose-400 font-semibold'
                              : dev.riskScore >= 40
                              ? 'text-amber-400 font-semibold'
                              : 'text-emerald-400'
                          }
                        >
                          {dev.riskScore}/100
                        </span>
                      </td>
                      <td className="py-3 pl-3 text-right font-mono tabular-nums text-slate-400">
                        {new Date(dev.lastHeartbeat).toLocaleTimeString()}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Recent Correlated Incidents */}
          <div className="pt-4 border-t border-slate-800 space-y-3">
            <div className="text-xs font-semibold text-slate-300">
              Active Correlated Incidents Requiring Analyst Review ({incidents.length})
            </div>
            {incidents.length === 0 ? (
              <div className="py-6 text-center text-xs text-slate-400">
                Zero active incidents. All monitored sessions are nominal.
              </div>
            ) : (
              <div className="divide-y divide-slate-800/80">
                {incidents.slice(0, 3).map((inc) => (
                  <div
                    key={inc.incidentId}
                    className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  >
                    <div className="space-y-1">
                      <div className="text-xs font-mono text-slate-400">
                        {inc.primaryRuleId} · Severity: <span className="uppercase text-slate-200">{inc.severity}</span> · Status: {inc.status} · Risk: {inc.aggregatedRiskScore}/100
                      </div>
                      <div className="text-sm font-medium text-slate-100">{inc.title}</div>
                    </div>
                    <button
                      onClick={() => {
                        onSelectIncident(inc.incidentId);
                        onNavigateTab('investigation');
                      }}
                      className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Inspect Evidence
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Explicit Detection Capability & Architectural Boundary Matrix */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100">
            Supported Windows User-Mode Capabilities vs. Architectural Limitations
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            In accordance with defensible anti-cheat engineering, Sentinel AC explicitly distinguishes observable user-mode Win32 indicators from attacks requiring kernel drivers or authoritative game-server telemetry.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-xs text-slate-400">
                <th className="py-2.5 pr-4 font-medium">Capability / Threat Vector</th>
                <th className="py-2.5 px-3 font-medium">Domain</th>
                <th className="py-2.5 px-3 font-medium">Support Boundary</th>
                <th className="py-2.5 px-3 font-medium">Win32 / Verification Method</th>
                <th className="py-2.5 pl-3 font-medium">Explicit Limitation & False-Positive Guidance</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 text-xs">
              {DETECTION_CAPABILITY_BOUNDARIES.map((b) => (
                <tr key={b.capability} className="hover:bg-slate-900/50">
                  <td className="py-3 pr-4 font-medium text-slate-100">{b.capability}</td>
                  <td className="py-3 px-3 text-slate-300">{b.category}</td>
                  <td className="py-3 px-3 font-mono text-sky-400">{b.supportStatus}</td>
                  <td className="py-3 px-3 font-mono text-slate-300">{b.verificationMethod}</td>
                  <td className="py-3 pl-3 text-slate-400">{b.architecturalLimitation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
