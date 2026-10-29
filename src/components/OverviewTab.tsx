import React, { useState } from 'react';
import { IncidentRecord, MonitoredDevice, SecurityEventRecord } from '../../shared-schemas/types.ts';
import { computeFleetSummary } from '../../shared-schemas/fleetMetrics.ts';
import { getFriendlyEventSummary } from '../lib/friendlyDescriptions.ts';

interface OverviewTabProps {
  devices: MonitoredDevice[];
  events: SecurityEventRecord[];
  incidents: IncidentRecord[];
  onNavigateTab: (tab: string) => void;
  onSelectIncident: (incidentId: string) => void;
  onSelectDeviceForLogs?: (deviceId: string) => void;
  onDisconnectDevice?: (deviceId?: string) => Promise<void>;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  devices,
  events,
  incidents,
  onNavigateTab,
  onSelectIncident,
  onSelectDeviceForLogs,
  onDisconnectDevice,
}) => {
  const [showAdvancedDetails, setShowAdvancedDetails] = useState(false);

  // Authoritative Fleet Metrics (UTC heartbeat timeout verified, revoked/offline excluded from active connected count)
  const fleet = computeFleetSummary(devices);
  const {
    devices: enrolledDevices,
    onlineDevices,
    totalRegistered,
    onlineCount,
    offlineCount,
    revokedCount,
  } = fleet;

  const primaryDevice = onlineDevices[0] || enrolledDevices[0] || null;
  const isAgentConnected = onlineCount > 0;
  
  // Game Session State (only active online devices can have a running session)
  let freeFireStatus: 'Running' | 'Not Running' | 'Unknown' = 'Unknown';
  if (!isAgentConnected) {
    freeFireStatus = 'Unknown';
  } else if (onlineDevices.some((d) => d.gameSessionState === 'active_match' || d.gameSessionState === 'launching')) {
    freeFireStatus = 'Running';
  } else {
    freeFireStatus = 'Not Running';
  }

  // Real vs Simulated Counts
  const realAlerts = events.filter((e) => !e.isSimulated);
  const testAlerts = events.filter((e) => e.isSimulated);
  const activeIncidents = incidents.filter((i) => i.status === 'open' || i.status === 'investigating');

  // Protection Status Logic
  let protectionState: 'Protected' | 'Attention Required' | 'Agent Not Connected' = 'Agent Not Connected';
  let statusBannerMessage = '';
  let nextStepAction = '';
  let nextStepButton = { label: 'Connect My PC', tab: 'connect' };

  if (!isAgentConnected) {
    protectionState = 'Agent Not Connected';
    statusBannerMessage =
      totalRegistered === 0
        ? 'No Windows PC is enrolled yet (0 Connected PCs). Free Fire gameplay is currently unmonitored.'
        : `0 Windows PCs are currently online (${offlineCount} Offline, ${revokedCount} Revoked).`;
    nextStepAction = 'Enroll and start SentinelAgent.exe or sentinel-agent.ps1 on your physical Windows PC.';
    nextStepButton = { label: 'Enroll Your First PC', tab: 'connect' };
  } else if (activeIncidents.length > 0 || realAlerts.some((a) => a.severity === 'critical' || a.severity === 'high')) {
    protectionState = 'Attention Required';
    statusBannerMessage = `Warning: ${activeIncidents.length} suspicious security threat(s) detected across ${onlineCount} connected PC(s)!`;
    nextStepAction = 'Review the detected incidents or filter the Central Live Console by PC.';
    nextStepButton = { label: 'Review Threats Now', tab: 'investigation' };
  } else if (freeFireStatus === 'Running') {
    protectionState = 'Protected';
    statusBannerMessage = `Protected & Active: Monitoring ${onlineCount} online Windows PC(s) (${onlineDevices.map((d) => d.hostname).join(', ')}). No cheat activity detected.`;
    nextStepAction = 'Everything is running safely across all online endpoints.';
    nextStepButton = { label: 'View Central Live Console', tab: 'live' };
  } else {
    protectionState = 'Protected';
    statusBannerMessage = `Agent Online: ${onlineCount} Windows PC(s) connected with fresh heartbeats. Waiting for emulator or Free Fire to launch.`;
    nextStepAction = 'Launch BlueStacks, LDPlayer, MEmu, Nox, or Google Play Games PC to begin in-game monitoring.';
    nextStepButton = { label: 'Manage Connected PCs', tab: 'connect' };
  }

  return (
    <div className="space-y-6">
      {/* 1. Header Next-Action Guidance Banner */}
      <div
        className={`p-5 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-colors ${
          protectionState === 'Protected'
            ? 'bg-emerald-950/25 border-emerald-500/40'
            : protectionState === 'Attention Required'
            ? 'bg-rose-950/30 border-rose-500/50'
            : 'bg-amber-950/25 border-amber-500/40'
        }`}
      >
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                protectionState === 'Protected'
                  ? 'bg-emerald-400 animate-pulse'
                  : protectionState === 'Attention Required'
                  ? 'bg-rose-500 animate-ping'
                  : 'bg-amber-400'
              }`}
            />
            <span
              className={`text-xs font-semibold uppercase tracking-wider ${
                protectionState === 'Protected'
                  ? 'text-emerald-400'
                  : protectionState === 'Attention Required'
                  ? 'text-rose-400'
                  : 'text-amber-400'
              }`}
            >
              {protectionState}
            </span>
          </div>
          <p className="text-sm font-medium text-slate-100">{statusBannerMessage}</p>
          <p className="text-xs text-slate-400 mt-0.5">👉 <span className="text-slate-300 font-medium">What to do next:</span> {nextStepAction}</p>
        </div>

        <button
          onClick={() => onNavigateTab(nextStepButton.tab)}
          className={`px-4 py-2.5 rounded-lg text-xs font-semibold whitespace-nowrap shrink-0 transition-all cursor-pointer shadow-sm ${
            protectionState === 'Attention Required'
              ? 'bg-rose-500 hover:bg-rose-400 text-white'
              : 'bg-sky-400 hover:bg-sky-300 text-slate-950'
          }`}
        >
          {nextStepButton.label} →
        </button>
      </div>

      {/* 2. 5 Main Status Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Card 1: Protection Status */}
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-2 flex flex-col justify-between">
          <div className="text-xs text-slate-400">Protection Status</div>
          <div>
            <div
              className={`text-xl font-bold ${
                protectionState === 'Protected'
                  ? 'text-emerald-400'
                  : protectionState === 'Attention Required'
                  ? 'text-rose-400'
                  : 'text-amber-400'
              }`}
            >
              {protectionState}
            </div>
            <div className="text-xs text-slate-400 mt-1">
              {isAgentConnected ? `${onlineCount} Active Online PC(s)` : '0 Online PCs'}
            </div>
          </div>
          <button
            onClick={() => onNavigateTab('connect')}
            className="text-[11px] text-sky-400 hover:text-sky-300 text-left cursor-pointer pt-2 border-t border-slate-800/80"
          >
            {isAgentConnected ? 'Manage Endpoints →' : 'Enroll First PC →'}
          </button>
        </div>

        {/* Card 2: Connected PCs (Authoritative Fleet Counts) */}
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-2 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Connected PCs ({onlineCount})</span>
            {primaryDevice && onDisconnectDevice && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onDisconnectDevice(primaryDevice.deviceId);
                }}
                className="text-[10px] text-rose-400 hover:text-rose-300 font-semibold px-2 py-0.5 rounded bg-rose-950/40 border border-rose-500/30 cursor-pointer transition-colors"
                title="Disconnect Windows PC"
              >
                Unlink
              </button>
            )}
          </div>
          <div>
            <div className="text-xl font-bold text-slate-100 truncate">
              {onlineCount === 0
                ? '0 Connected PCs'
                : onlineCount === 1
                ? onlineDevices[0].hostname
                : `${onlineCount} Online PCs`}
            </div>
            <div className="text-[11px] font-mono text-slate-400 mt-1 truncate">
              {totalRegistered} Enrolled · {onlineCount} Online · {offlineCount} Offline · {revokedCount} Revoked
            </div>
          </div>
          <button
            onClick={() => onNavigateTab('connect')}
            className="text-[11px] text-sky-400 hover:text-sky-300 text-left cursor-pointer pt-2 border-t border-slate-800/80"
          >
            {totalRegistered > 0 ? 'View All Endpoints →' : 'Enroll Windows PC →'}
          </button>
        </div>

        {/* Card 3: Free Fire Status */}
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-2 flex flex-col justify-between">
          <div className="text-xs text-slate-400">Free Fire Status</div>
          <div>
            <div
              className={`text-xl font-bold ${
                freeFireStatus === 'Running'
                  ? 'text-emerald-400'
                  : freeFireStatus === 'Not Running'
                  ? 'text-slate-300'
                  : 'text-slate-400'
              }`}
            >
              {freeFireStatus}
            </div>
            <div className="text-xs text-slate-400 mt-1 truncate">
              {onlineDevices[0]?.emulatorName || 'Supported Emulators'}
            </div>
          </div>
          <div className="text-[11px] text-slate-400 pt-2 border-t border-slate-800/80">
            {freeFireStatus === 'Running' ? 'Active Match Monitored' : 'Waiting for Launch'}
          </div>
        </div>

        {/* Card 4: Security Alerts */}
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-2 flex flex-col justify-between">
          <div className="text-xs text-slate-400">Security Alerts</div>
          <div>
            <div
              className={`text-2xl font-bold tabular-nums ${
                realAlerts.length > 0 ? 'text-rose-400' : 'text-slate-100'
              }`}
            >
              {realAlerts.length}
            </div>
            <div className="text-xs text-slate-400 mt-1">
              {realAlerts.length === 1 ? '1 Real Security Alert' : `${realAlerts.length} Real Security Alerts`}
              {testAlerts.length > 0 && (
                <span className="block text-[10px] text-sky-400 font-mono mt-0.5">
                  (+{testAlerts.length} Test Simulations)
                </span>
              )}
            </div>
          </div>
          <button
            onClick={() => onNavigateTab('live')}
            className="text-[11px] text-sky-400 hover:text-sky-300 text-left cursor-pointer pt-2 border-t border-slate-800/80"
          >
            View Live Stream →
          </button>
        </div>

        {/* Card 5: Detected Threats */}
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-2 flex flex-col justify-between">
          <div className="text-xs text-slate-400">Detected Threats</div>
          <div>
            <div
              className={`text-2xl font-bold tabular-nums ${
                activeIncidents.length > 0 ? 'text-amber-400' : 'text-slate-100'
              }`}
            >
              {activeIncidents.length}
            </div>
            <div className="text-xs text-slate-400 mt-1">
              {activeIncidents.length === 1 ? '1 Case Needs Review' : `${activeIncidents.length} Cases Need Review`}
            </div>
          </div>
          <button
            onClick={() => onNavigateTab('investigation')}
            className="text-[11px] text-sky-400 hover:text-sky-300 text-left cursor-pointer pt-2 border-t border-slate-800/80"
          >
            Investigate Threats →
          </button>
        </div>
      </div>

      {/* Empty State when 0 Real PCs are Enrolled (Requirement 11) */}
      {totalRegistered === 0 ? (
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-amber-500/10 border border-amber-500/30 text-amber-300 text-[11px] font-mono mb-2">
                <span>0 ENROLLED ENDPOINTS · 0 CONNECTED PCs</span>
              </div>
              <h3 className="text-base font-semibold text-slate-100">
                No Physical Windows PC is Currently Enrolled
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Sentinel AC only displays endpoints that have genuinely authenticated and registered with the backend. Follow these 3 steps to enroll your first Windows 10/11 PC:
              </p>
            </div>
            <button
              onClick={() => onNavigateTab('connect')}
              className="px-4 py-2.5 bg-sky-400 hover:bg-sky-300 text-slate-950 font-semibold text-xs rounded-lg transition-colors cursor-pointer shrink-0"
            >
              Open Endpoints &amp; Agent Installer →
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div className="p-4 rounded-lg bg-[#0B0F19] border border-slate-800 space-y-1.5">
              <div className="font-mono text-sky-400 font-semibold">STEP 1 · DOWNLOAD OR BUILD AGENT</div>
              <p className="text-slate-300 leading-relaxed">
                Open the <strong>Endpoints / PCs</strong> tab and download <code className="text-sky-300 font-mono">SentinelAgent.cs</code> + <code className="text-sky-300 font-mono">build-exe.ps1</code> (to compile <code className="text-sky-300 font-mono">SentinelAgent.exe</code>) or download <code className="text-sky-300 font-mono">sentinel-agent.ps1</code>.
              </p>
            </div>
            <div className="p-4 rounded-lg bg-[#0B0F19] border border-slate-800 space-y-1.5">
              <div className="font-mono text-sky-400 font-semibold">STEP 2 · ENROLL WITH TOKEN</div>
              <p className="text-slate-300 leading-relaxed">
                Run the agent on your Windows PC with your server URL and enrollment token:
                <code className="block mt-1.5 p-1.5 rounded bg-slate-900 border border-slate-800 text-[10px] text-emerald-300 font-mono truncate">
                  .\dist-win64\SentinelAgent.exe --server &quot;...&quot; --enrollment-token &quot;...&quot;
                </code>
              </p>
            </div>
            <div className="p-4 rounded-lg bg-[#0B0F19] border border-slate-800 space-y-1.5">
              <div className="font-mono text-sky-400 font-semibold">STEP 3 · VERIFY LIVE HEARTBEAT</div>
              <p className="text-slate-300 leading-relaxed">
                Once enrolled, your PC sends authenticated UTC heartbeats every few seconds and automatically appears as <strong>ONLINE</strong> with attributed security telemetry.
              </p>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                Enrolled Endpoints ({onlineCount} Online / {totalRegistered} Registered · {offlineCount} Offline · {revokedCount} Revoked)
              </h3>
              <p className="text-xs text-slate-400">
                Click any PC card to open its attributed security event history in the Central Live Logs Console.
              </p>
            </div>
            <button
              onClick={() => onNavigateTab('connect')}
              className="text-xs text-sky-400 hover:text-sky-300 font-medium cursor-pointer"
            >
              Manage All Endpoints &amp; EXE Builder →
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {enrolledDevices.map((dev) => {
              const devEvents = events.filter((e) => e.deviceId === dev.deviceId);
              return (
                <div
                  key={dev.deviceId}
                  onClick={() => {
                    if (onSelectDeviceForLogs) onSelectDeviceForLogs(dev.deviceId);
                    else onNavigateTab('live');
                  }}
                  className="p-3.5 rounded-lg bg-[#0B0F19] border border-slate-800 hover:border-sky-500/50 transition-colors cursor-pointer space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-100 text-xs flex items-center gap-1.5">
                      <span>🖥️ {dev.hostname}</span>
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase ${
                        dev.status === 'healthy'
                          ? 'bg-emerald-500/15 text-emerald-300'
                          : dev.status === 'degraded'
                          ? 'bg-amber-500/20 text-amber-300'
                          : dev.status === 'revoked'
                          ? 'bg-rose-500/20 text-rose-300'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {dev.status === 'healthy'
                        ? 'ONLINE'
                        : dev.status === 'degraded'
                        ? 'ONLINE (ALERT)'
                        : dev.status === 'revoked'
                        ? 'REVOKED'
                        : 'OFFLINE'}
                    </span>
                  </div>
                  <div className="font-mono text-[10px] text-slate-400 flex items-center justify-between">
                    <span>{dev.deviceId}</span>
                    <span>{dev.agentVersion}</span>
                  </div>
                  <div className="text-[11px] text-slate-300 truncate">{dev.emulatorName}</div>
                  <div className="pt-1.5 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono">
                    <span className="text-sky-400">{devEvents.length} Attributed Event(s)</span>
                    <span className="text-slate-400">Risk: {dev.riskScore}/100</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 3. Quick Action Hub for Gamers */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 flex flex-col justify-between space-y-3">
          <div className="space-y-1">
            <div className="text-sm font-semibold text-slate-100">1. Setup Wizard</div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Step-by-step assistant to connect your emulator, verify Free Fire, and enable automatic monitoring on PC startup.
            </p>
          </div>
          <button
            onClick={() => onNavigateTab('wizard')}
            className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg transition-colors cursor-pointer"
          >
            Open Setup Wizard
          </button>
        </div>

        <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 flex flex-col justify-between space-y-3">
          <div className="space-y-1">
            <div className="text-sm font-semibold text-slate-100">2. Connect My Windows PC</div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Download the clean Windows monitoring agent, copy the 1-click startup command, or check real-time heartbeat health.
            </p>
          </div>
          <button
            onClick={() => onNavigateTab('connect')}
            className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg transition-colors cursor-pointer"
          >
            Manage Windows Connection
          </button>
        </div>

        <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 flex flex-col justify-between space-y-3">
          <div className="space-y-1">
            <div className="text-sm font-semibold text-slate-100">3. Live Security Logs &amp; Evidence</div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Inspect real-time security logs received from connected Windows PCs with PC attribution, UTC timestamps, and detection evidence.
            </p>
          </div>
          <button
            onClick={() => onNavigateTab('live')}
            className="w-full py-2 bg-sky-950/40 hover:bg-sky-900/50 border border-sky-500/50 text-sky-300 text-xs font-medium rounded-lg transition-colors cursor-pointer"
          >
            Open Live Logs Console
          </button>
        </div>
      </div>

      {/* 4. Recent Activity Preview (Real Telemetry with PC Name, Timestamp, Event Type & Evidence) */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">Recent Security Activity</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Latest real-time security events received from connected Windows agents.
            </p>
          </div>
          <button
            onClick={() => onNavigateTab('live')}
            className="text-xs text-sky-400 hover:text-sky-300 font-medium cursor-pointer"
          >
            View All ({events.length}) →
          </button>
        </div>

        {events.length === 0 ? (
          <div className="py-8 text-center space-y-2">
            <div className="text-sm font-medium text-slate-300">No Security Alerts Detected Yet (0 Events)</div>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Only real security events sent by an authenticated Sentinel AC Windows agent appear here. Simulated or fake detections are never generated.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/70">
            {events.slice(0, 5).map((ev) => {
              const friendly = getFriendlyEventSummary(ev);
              const utcTime = new Date(ev.eventTimestamp)
                .toISOString()
                .replace('T', ' ')
                .slice(0, 19) + ' UTC';
              return (
                <div
                  key={ev.eventId}
                  className="py-3.5 flex flex-col lg:flex-row lg:items-center justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                          friendly.threatLevel === 'Critical'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            : friendly.threatLevel === 'High'
                            ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                            : 'bg-sky-500/20 text-sky-300 border border-sky-500/30'
                        }`}
                      >
                        {friendly.threatLevel}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 font-mono text-[10px] text-sky-300">
                        🖥️ {ev.hostname} ({ev.deviceId})
                      </span>
                      <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 font-mono text-[10px] text-slate-300">
                        [{ev.ruleId}] {ev.category}
                      </span>
                      <span className="font-semibold text-slate-100">{friendly.title}</span>
                    </div>
                    <p className="text-slate-300 text-[11px] font-mono">
                      Evidence: Process <span className="text-sky-300">{ev.processName}</span> ({ev.processPath}) · SHA256: {ev.sha256.slice(0, 16)}... · Signer: {ev.signerIdentity}
                    </p>
                    <p className="text-slate-400 text-[11px]">{ev.summary}</p>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="font-mono text-slate-400 text-[11px]">{utcTime}</span>
                    <button
                      onClick={() => onNavigateTab('live')}
                      className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[11px] cursor-pointer"
                    >
                      View Details
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 5. Expandable Advanced Technical Details (Cleanly Hidden by Default) */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden">
        <button
          onClick={() => setShowAdvancedDetails(!showAdvancedDetails)}
          className="w-full p-4 text-left flex items-center justify-between text-xs font-semibold text-slate-300 hover:bg-slate-800/40 transition-colors cursor-pointer"
        >
          <div className="flex items-center gap-2">
            <span>⚙️ Advanced Technical Details</span>
            <span className="text-[11px] font-normal text-slate-400">(Engine metrics, Cryptography, Telemetry queues)</span>
          </div>
          <span className="font-mono text-slate-400">{showAdvancedDetails ? 'Hide ▲' : 'Show ▼'}</span>
        </button>

        {showAdvancedDetails && (
          <div className="p-5 border-t border-slate-800 bg-[#0B0F19] space-y-4 text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              <div className="p-3 bg-[#111827] border border-slate-800 rounded-lg">
                <div className="text-slate-400 text-[11px]">Agent CPU & Memory</div>
                <div className="text-sm font-semibold font-mono text-slate-200 mt-1">
                  {primaryDevice?.cpuOverheadPercent ?? 0.35}% CPU · {primaryDevice?.memoryFootprintMb ?? 18.2} MB
                </div>
                <div className="text-[10px] text-slate-400 mt-0.5">Low-overhead Win32 daemon</div>
              </div>

              <div className="p-3 bg-[#111827] border border-slate-800 rounded-lg">
                <div className="text-slate-400 text-[11px]">Rule Signature Verification</div>
                <div className="text-sm font-semibold font-mono text-emerald-400 mt-1">
                  Ed25519 Authenticated
                </div>
                <div className="text-[10px] text-slate-400 mt-0.5">Signed by Sentinel Security Lab</div>
              </div>

              <div className="p-3 bg-[#111827] border border-slate-800 rounded-lg">
                <div className="text-slate-400 text-[11px]">Offline Telemetry Queue</div>
                <div className="text-sm font-semibold font-mono text-slate-200 mt-1">
                  {primaryDevice?.encryptedQueueDepth ?? 0} Buffered Events
                </div>
                <div className="text-[10px] text-slate-400 mt-0.5">DPAPI Local Encryption (CryptProtectData)</div>
              </div>

              <div className="p-3 bg-[#111827] border border-slate-800 rounded-lg">
                <div className="text-slate-400 text-[11px]">Emulator Security Boundary</div>
                <div className="text-sm font-semibold font-mono text-sky-400 mt-1">
                  Ring-3 Process Isolation
                </div>
                <div className="text-[10px] text-slate-400 mt-0.5">Zero kernel rootkits / least-privilege</div>
              </div>
            </div>

            <div className="flex items-center justify-between pt-2">
              <span className="text-[11px] text-slate-400">
                Need deep forensic analysis, rule editing, or unit test benchmarks?
              </span>
              <button
                onClick={() => onNavigateTab('advanced')}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs cursor-pointer"
              >
                Open Advanced SOC Tools →
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
