import React, { useState, useEffect } from 'react';
import {
  EnrollmentTokenRecord,
  MonitoredDevice,
  SecurityEventRecord,
  SeverityLevel,
} from '../../shared-schemas/types.ts';
import { computeFleetSummary } from '../../shared-schemas/fleetMetrics.ts';

interface ConnectMyPcTabProps {
  devices: MonitoredDevice[];
  events?: SecurityEventRecord[];
  onRegisterDevice: (device: MonitoredDevice) => void;
  onNavigateTab: (tab: string) => void;
  onSelectDeviceForLogs?: (deviceId: string) => void;
  onDisconnectDevice?: (deviceId?: string) => Promise<void>;
  onRefreshDevices?: () => void;
}

export const ConnectMyPcTab: React.FC<ConnectMyPcTabProps> = ({
  devices,
  events = [],
  onNavigateTab,
  onSelectDeviceForLogs,
  onDisconnectDevice,
  onRefreshDevices,
}) => {
  const [enrollmentTokens, setEnrollmentTokens] = useState<EnrollmentTokenRecord[]>([]);
  const [newTokenLabel, setNewTokenLabel] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [deviceFilterStatus, setDeviceFilterStatus] = useState<'all' | 'healthy' | 'degraded' | 'disconnected' | 'revoked'>('all');

  const serverOrigin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000';
  const activeEnrollmentToken =
    enrollmentTokens[0]?.tokenSecret || 'enr_sentinel_default_multi_pc';

  const loadEnrollmentTokens = async () => {
    try {
      const res = await fetch('/api/agent/enrollment-tokens');
      const data = await res.json();
      if (Array.isArray(data.tokens)) {
        setEnrollmentTokens(data.tokens);
      }
    } catch {}
  };

  useEffect(() => {
    loadEnrollmentTokens();
  }, []);

  const copyText = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey((prev) => (prev === key ? null : prev)), 2500);
  };

  const handleGenerateToken = async () => {
    try {
      const res = await fetch('/api/agent/enrollment-tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          label: newTokenLabel.trim() || `PC Enrollment Token (${new Date().toLocaleTimeString()})`,
          maxUses: 50,
        }),
      });
      const data = await res.json();
      if (data.token) {
        setEnrollmentTokens((prev) => [data.token, ...prev]);
        setNewTokenLabel('');
        setActionMessage(`Issued new enrollment token: ${data.token.tokenSecret}`);
      }
    } catch {
      setActionMessage('Failed to issue enrollment token.');
    }
  };

  const handleRotateDeviceToken = async (e: React.MouseEvent, deviceId: string) => {
    e.stopPropagation();
    try {
      const res = await fetch(`/api/agent/devices/${encodeURIComponent(deviceId)}/rotate-token`, {
        method: 'POST',
      });
      const data = await res.json();
      if (res.ok) {
        setActionMessage(`Rotated device credential token for ${deviceId} (Token v${data.tokenVersion}).`);
        if (onRefreshDevices) onRefreshDevices();
      } else {
        setActionMessage(data.error || 'Token rotation failed.');
      }
    } catch {
      setActionMessage('Token rotation request failed.');
    }
  };

  const handleRevokeDevice = async (e: React.MouseEvent, deviceId: string) => {
    e.stopPropagation();
    try {
      const res = await fetch(`/api/agent/devices/${encodeURIComponent(deviceId)}/revoke`, {
        method: 'POST',
      });
      const data = await res.json();
      if (res.ok) {
        setActionMessage(`Revoked device ${deviceId}. Future connections and telemetry from this PC are blocked.`);
        if (onRefreshDevices) onRefreshDevices();
      } else {
        setActionMessage(data.error || 'Revocation failed.');
      }
    } catch {
      setActionMessage('Revocation request failed.');
    }
  };

  const handleDownloadFile = async (endpoint: string, filename: string) => {
    try {
      const res = await fetch(endpoint);
      const text = await res.text();
      const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error('Download failed:', e);
    }
  };

  // Authoritative Fleet Summary
  const fleet = computeFleetSummary(devices);
  const {
    devices: reconciledDevices,
    totalRegistered,
    onlineCount,
    offlineCount,
    revokedCount,
    healthyCount,
    degradedCount,
  } = fleet;

  // Compute per-device event stats dynamically from both server props and live events list
  const enrichedDevices = reconciledDevices.map((dev) => {
    const devEvents = events.filter((e) => e.deviceId === dev.deviceId);
    const sevOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
    let highest: SeverityLevel | 'none' = dev.highestSeverity || 'none';
    for (const ev of devEvents) {
      if ((sevOrder[ev.severity] || 0) > (sevOrder[highest] || 0)) {
        highest = ev.severity;
      }
    }
    return {
      ...dev,
      computedEventsCount: Math.max(dev.detectedEventsCount || 0, devEvents.length),
      computedHighestSeverity: highest,
      computedLastEvent: devEvents[0]?.summary || dev.lastEventSummary || 'No security events reported yet.',
    };
  });

  const filteredDevices = enrichedDevices.filter((d) => {
    if (deviceFilterStatus === 'all') return true;
    return d.status === deviceFilterStatus;
  });

  const buildExeCommand = `powershell -ExecutionPolicy Bypass -File .\\build-exe.ps1 -ServerUrl "${serverOrigin}" -EnrollmentToken "${activeEnrollmentToken}"`;
  const runExeCommand = `.\\dist-win64\\SentinelAgent.exe --server "${serverOrigin}" --enrollment-token "${activeEnrollmentToken}"`;
  const startupOptInCommand = `.\\dist-win64\\SentinelAgent.exe --server "${serverOrigin}" --install-startup`;
  const uninstallExeCommand = `.\\dist-win64\\SentinelAgent.exe --uninstall`;

  return (
    <div className="space-y-6">
      {/* 1. Multi-PC Header & Fleet Action Bar */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                onlineCount > 0 ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
              }`}
            />
            <h2 className="text-base font-semibold text-slate-100">
              Endpoints / Devices &amp; Multi-PC Windows EXE Agent Hub
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Monitor all genuinely enrolled Windows 10/11 PCs from one central dashboard. Only endpoints with authenticated enrollment and fresh UTC heartbeats are marked Online.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            onClick={() => handleDownloadFile('/api/agent/SentinelAgent.cs', 'SentinelAgent.cs')}
            className="px-3.5 py-2 bg-sky-400 hover:bg-sky-300 text-slate-950 font-semibold text-xs rounded-lg transition-colors cursor-pointer"
          >
            Download C# Agent (SentinelAgent.cs)
          </button>
          <button
            onClick={() => handleDownloadFile('/api/agent/build-exe.ps1', 'build-exe.ps1')}
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-medium text-xs rounded-lg transition-colors cursor-pointer"
          >
            Download EXE Builder (build-exe.ps1)
          </button>
          <button
            onClick={() =>
              handleDownloadFile(
                `/api/agent/installer.ps1?token=${encodeURIComponent(activeEnrollmentToken)}`,
                'sentinel-agent.ps1'
              )
            }
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-medium text-xs rounded-lg transition-colors cursor-pointer"
          >
            Download PowerShell Agent (.ps1)
          </button>
        </div>
      </div>

      {/* Authoritative 4-Metric Fleet Summary Bar */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <div className="text-[11px] font-mono uppercase text-slate-400">Total Enrolled Devices</div>
          <div className="text-2xl font-bold text-slate-100 tabular-nums mt-1">{totalRegistered}</div>
          <div className="text-[11px] text-slate-400 mt-0.5">Authenticated via /api/agent/register</div>
        </div>
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <div className="text-[11px] font-mono uppercase text-emerald-400">Currently Online PCs</div>
          <div className="text-2xl font-bold text-emerald-400 tabular-nums mt-1">{onlineCount}</div>
          <div className="text-[11px] text-slate-400 mt-0.5">Fresh UTC heartbeat (&le;90s timeout)</div>
        </div>
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <div className="text-[11px] font-mono uppercase text-slate-400">Offline / Stale PCs</div>
          <div className="text-2xl font-bold text-slate-300 tabular-nums mt-1">{offlineCount}</div>
          <div className="text-[11px] text-slate-400 mt-0.5">Heartbeat expired or agent stopped</div>
        </div>
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <div className="text-[11px] font-mono uppercase text-rose-400">Revoked Endpoints</div>
          <div className="text-2xl font-bold text-rose-400 tabular-nums mt-1">{revokedCount}</div>
          <div className="text-[11px] text-slate-400 mt-0.5">Excluded from active connected PCs</div>
        </div>
      </div>

      {actionMessage && (
        <div className="p-3.5 bg-sky-950/50 border border-sky-500/40 rounded-xl text-xs font-mono text-sky-200 flex items-center justify-between">
          <span>{actionMessage}</span>
          <button
            onClick={() => setActionMessage(null)}
            className="text-sky-300 hover:text-white ml-4 cursor-pointer"
          >
            ✕
          </button>
        </div>
      )}

      {/* 2. Registered Multi-PC Endpoints Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">
              Registered Endpoints ({onlineCount} Online / {totalRegistered} Total Enrolled)
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Click any PC to open its filtered event history in the Central Live Logs Console.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-1.5 text-xs">
            {(
              [
                { id: 'all', label: `All Enrolled (${totalRegistered})` },
                { id: 'healthy', label: `Online Healthy (${healthyCount})` },
                { id: 'degraded', label: `Online Alert (${degradedCount})` },
                { id: 'disconnected', label: `Offline (${offlineCount})` },
                { id: 'revoked', label: `Revoked (${revokedCount})` },
              ] as const
            ).map((f) => (
              <button
                key={f.id}
                onClick={() => setDeviceFilterStatus(f.id)}
                className={`px-2.5 py-1 rounded-md font-medium transition-colors cursor-pointer ${
                  deviceFilterStatus === f.id
                    ? 'bg-sky-400 text-slate-950 font-semibold'
                    : 'bg-[#0B0F19] text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        {totalRegistered === 0 ? (
          <div className="p-8 text-center space-y-4">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-mono">
              0 Enrolled PCs · 0 Connected PCs
            </div>
            <div className="text-base font-semibold text-slate-100">
              No Physical Windows PC Enrolled Yet
            </div>
            <p className="text-xs text-slate-400 max-w-xl mx-auto leading-relaxed">
              This table displays only physical Windows machines that have completed authenticated registration via <code className="text-sky-300 font-mono">POST /api/agent/register</code>. Stored or simulated test records are never shown as connected endpoints.
            </p>
            <div className="max-w-2xl mx-auto text-left bg-[#0B0F19] border border-slate-800 rounded-xl p-4 space-y-2 text-xs font-mono">
              <div className="text-sky-400 font-semibold">How to Enroll Your First Windows PC:</div>
              <div className="text-slate-300">
                1. Download <span className="text-sky-300">SentinelAgent.cs</span> + <span className="text-sky-300">build-exe.ps1</span> (or <span className="text-sky-300">sentinel-agent.ps1</span>) using the buttons above.
              </div>
              <div className="text-slate-300">
                2. Build the native executable on your Windows 10/11 PC:
                <div className="mt-1 p-2 rounded bg-slate-900 border border-slate-800 text-emerald-300 break-all">
                  {buildExeCommand}
                </div>
              </div>
              <div className="text-slate-300">
                3. Launch the agent to enroll and begin streaming authenticated UTC heartbeats:
                <div className="mt-1 p-2 rounded bg-slate-900 border border-slate-800 text-emerald-300 break-all">
                  {runExeCommand}
                </div>
              </div>
            </div>
          </div>
        ) : filteredDevices.length === 0 ? (
          <div className="py-10 px-4 text-center space-y-2">
            <div className="text-sm font-semibold text-slate-200">No Enrolled Endpoints Match Filter ({deviceFilterStatus})</div>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Switch the filter above to <strong>All Enrolled ({totalRegistered})</strong> to view all registered endpoints.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] font-mono uppercase text-slate-400 bg-[#0B0F19]/60">
                  <th className="py-3 px-4">Device Name &amp; Unique ID</th>
                  <th className="py-3 px-3">Status &amp; Heartbeat</th>
                  <th className="py-3 px-3">Windows &amp; Agent Ver.</th>
                  <th className="py-3 px-3">Monitoring Health &amp; Emulator</th>
                  <th className="py-3 px-3">Events &amp; Highest Severity</th>
                  <th className="py-3 px-4">Last Reported Security Event</th>
                  <th className="py-3 px-4 text-right">Endpoint Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 text-xs">
                {filteredDevices.map((dev) => {
                  const isOnline = dev.status === 'healthy' || dev.status === 'degraded';
                  return (
                    <tr
                      key={dev.deviceId}
                      onClick={() => {
                        if (onSelectDeviceForLogs) {
                          onSelectDeviceForLogs(dev.deviceId);
                        } else {
                          onNavigateTab('live');
                        }
                      }}
                      className="hover:bg-slate-900/60 transition-colors cursor-pointer"
                      title="Click to open this PC's event history in the Central Live Console"
                    >
                      {/* Device Name & Unique ID */}
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <div className="font-bold text-slate-100 flex items-center gap-1.5">
                          <span>🖥️ {dev.hostname}</span>
                        </div>
                        <div className="font-mono text-[10px] text-sky-400 mt-0.5">{dev.deviceId}</div>
                        <div className="font-mono text-[10px] text-slate-500">
                          Token v{dev.tokenVersion || 1} · {dev.autoStartEnabled ? 'Auto-Start Opt-In' : 'Manual Start'}
                        </div>
                      </td>

                      {/* Online / Offline / Revoked Status & Last Heartbeat */}
                      <td className="py-3.5 px-3 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                            dev.status === 'healthy'
                              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                              : dev.status === 'degraded'
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                              : dev.status === 'revoked'
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                              : 'bg-slate-800 text-slate-400 border border-slate-700'
                          }`}
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              dev.status === 'healthy'
                                ? 'bg-emerald-400 animate-pulse'
                                : dev.status === 'degraded'
                                ? 'bg-amber-400 animate-pulse'
                                : dev.status === 'revoked'
                                ? 'bg-rose-400'
                                : 'bg-slate-500'
                            }`}
                          />
                          {dev.status === 'healthy'
                            ? 'Online'
                            : dev.status === 'degraded'
                            ? 'Online (Alert)'
                            : dev.status === 'revoked'
                            ? 'Revoked'
                            : 'Offline'}
                        </span>
                        <div className="font-mono text-[10px] text-slate-400 mt-1">
                          HB: {new Date(dev.lastHeartbeat).toISOString().slice(11, 19)} UTC
                        </div>
                      </td>

                      {/* Windows & Agent Version */}
                      <td className="py-3.5 px-3">
                        <div className="text-slate-200 truncate max-w-[180px]" title={dev.osVersion}>
                          {dev.osVersion}
                        </div>
                        <div className="font-mono text-[10px] text-slate-400 mt-0.5">
                          Agent: {dev.agentVersion}
                        </div>
                      </td>

                      {/* Current Monitoring Health & Emulator */}
                      <td className="py-3.5 px-3">
                        <div className="text-slate-200 font-medium truncate max-w-[180px]">
                          {dev.emulatorName}
                        </div>
                        <div className="font-mono text-[10px] text-slate-400 mt-0.5">
                          Integrity: <span className="text-emerald-400">{dev.integrityStatus}</span> · Risk: {dev.riskScore}/100
                        </div>
                        <div className="font-mono text-[10px] text-slate-500">
                          CPU: {dev.cpuOverheadPercent ?? 0.3}% · RAM: {dev.memoryFootprintMb ?? 17.8} MB
                        </div>
                      </td>

                      {/* Number of Detected Events & Highest Severity */}
                      <td className="py-3.5 px-3 whitespace-nowrap">
                        <div className="font-mono font-bold text-slate-100">
                          {dev.computedEventsCount} Event{dev.computedEventsCount === 1 ? '' : 's'}
                        </div>
                        <div className="mt-1">
                          {dev.computedHighestSeverity === 'none' ? (
                            <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-400">
                              CLEAN
                            </span>
                          ) : (
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase ${
                                dev.computedHighestSeverity === SeverityLevel.CRITICAL
                                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                  : dev.computedHighestSeverity === SeverityLevel.HIGH
                                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                  : 'bg-sky-500/20 text-sky-300 border border-sky-500/30'
                              }`}
                            >
                              MAX: {dev.computedHighestSeverity}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Last Reported Security Event */}
                      <td className="py-3.5 px-4 max-w-xs">
                        <div className="text-[11px] text-slate-300 line-clamp-2 leading-relaxed">
                          {dev.computedLastEvent}
                        </div>
                      </td>

                      {/* Actions */}
                      <td className="py-3.5 px-4 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => {
                              if (onSelectDeviceForLogs) onSelectDeviceForLogs(dev.deviceId);
                              else onNavigateTab('live');
                            }}
                            className="px-2.5 py-1 bg-sky-950/60 hover:bg-sky-900 border border-sky-500/40 text-sky-300 rounded text-[11px] font-semibold cursor-pointer"
                          >
                            Logs ({dev.computedEventsCount})
                          </button>
                          {dev.status !== 'revoked' && (
                            <button
                              onClick={(e) => handleRotateDeviceToken(e, dev.deviceId)}
                              className="px-2 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded text-[11px] cursor-pointer"
                              title="Rotate per-device authentication token"
                            >
                              Rotate Key
                            </button>
                          )}
                          {dev.status !== 'revoked' && (
                            <button
                              onClick={(e) => handleRevokeDevice(e, dev.deviceId)}
                              className="px-2 py-1 bg-amber-950/60 hover:bg-amber-900 border border-amber-500/40 text-amber-300 rounded text-[11px] cursor-pointer"
                              title="Revoke device credentials and block future connections"
                            >
                              Revoke
                            </button>
                          )}
                          {isOnline && onDisconnectDevice && (
                            <button
                              onClick={() => onDisconnectDevice(dev.deviceId)}
                              className="px-2 py-1 bg-rose-950/60 hover:bg-rose-900 border border-rose-500/40 text-rose-300 rounded text-[11px] cursor-pointer"
                              title="Remove / Unlink endpoint"
                            >
                              Remove
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 3. Administrator Enrollment Tokens & Per-Device Security */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">
              1. Multi-PC Device Enrollment Tokens
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Each Windows PC authenticates during initial enrollment using an administrator-issued enrollment token, then receives its own isolated DPAPI-encrypted device credential.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="text"
              value={newTokenLabel}
              onChange={(e) => setNewTokenLabel(e.target.value)}
              placeholder="Label (e.g. Tournament Room PCs, Second Gaming Rig)..."
              className="flex-1 px-3 py-1.5 text-xs bg-[#0B0F19] border border-slate-800 rounded-lg text-slate-100 placeholder-slate-500"
            />
            <button
              onClick={handleGenerateToken}
              className="px-3.5 py-1.5 bg-sky-400 hover:bg-sky-300 text-slate-950 font-semibold text-xs rounded-lg cursor-pointer shrink-0"
            >
              + Issue Enrollment Token
            </button>
          </div>

          <div className="space-y-2 max-h-48 overflow-y-auto">
            {enrollmentTokens.map((tok) => (
              <div
                key={tok.tokenSecret}
                className="p-3 bg-[#0B0F19] border border-slate-800 rounded-lg flex items-center justify-between gap-3 text-xs"
              >
                <div className="min-w-0">
                  <div className="font-semibold text-slate-200 truncate">{tok.label}</div>
                  <div className="font-mono text-[11px] text-emerald-400 truncate mt-0.5">
                    {tok.tokenSecret}
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono">
                    Uses: {tok.usedCount} / {tok.maxUses} · Expires: {new Date(tok.expiresAt).toLocaleDateString()}
                  </div>
                </div>
                <button
                  onClick={() => copyText(tok.tokenSecret, tok.tokenSecret)}
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[11px] font-mono shrink-0 cursor-pointer"
                >
                  {copiedKey === tok.tokenSecret ? '✓ Copied' : 'Copy Token'}
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* 4. Build & Run Real Windows EXE Instructions */}
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">
              2. Build &amp; Run Real Windows <code className="text-sky-400 font-mono">SentinelAgent.exe</code>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Compiles natively on any Windows 10/11 PC using the built-in Windows .NET Framework C# compiler (<code className="text-slate-300">csc.exe</code>) or <code className="text-slate-300">dotnet publish</code> — zero third-party SDK installation required.
            </p>
          </div>

          <div className="space-y-3 text-xs">
            <div className="p-3 bg-[#0B0F19] border border-slate-800 rounded-lg space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-300">Step A: Compile SentinelAgent.exe on Windows</span>
                <button
                  onClick={() => copyText('buildCmd', buildExeCommand)}
                  className="text-[11px] font-mono text-sky-400 hover:text-sky-300 cursor-pointer"
                >
                  {copiedKey === 'buildCmd' ? '✓ Copied' : 'Copy'}
                </button>
              </div>
              <pre className="font-mono text-[11px] text-emerald-400 overflow-x-auto whitespace-pre-wrap">
                {buildExeCommand}
              </pre>
            </div>

            <div className="p-3 bg-[#0B0F19] border border-slate-800 rounded-lg space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-300">Step B: Enroll &amp; Start Monitoring on PC 1, PC 2, PC 3...</span>
                <button
                  onClick={() => copyText('runCmd', runExeCommand)}
                  className="text-[11px] font-mono text-sky-400 hover:text-sky-300 cursor-pointer"
                >
                  {copiedKey === 'runCmd' ? '✓ Copied' : 'Copy'}
                </button>
              </div>
              <pre className="font-mono text-[11px] text-sky-300 overflow-x-auto whitespace-pre-wrap">
                {runExeCommand}
              </pre>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <div className="p-2.5 bg-[#0B0F19] border border-slate-800 rounded-lg space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-300 text-[11px]">Opt-In Windows Startup</span>
                  <button
                    onClick={() => copyText('startupCmd', startupOptInCommand)}
                    className="text-[10px] font-mono text-sky-400 cursor-pointer"
                  >
                    {copiedKey === 'startupCmd' ? '✓ Copied' : 'Copy'}
                  </button>
                </div>
                <pre className="font-mono text-[10px] text-amber-300 overflow-x-auto">
                  {startupOptInCommand}
                </pre>
              </div>

              <div className="p-2.5 bg-[#0B0F19] border border-slate-800 rounded-lg space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-300 text-[11px]">Clean Uninstall &amp; Unlink</span>
                  <button
                    onClick={() => copyText('uninstallCmd', uninstallExeCommand)}
                    className="text-[10px] font-mono text-sky-400 cursor-pointer"
                  >
                    {copiedKey === 'uninstallCmd' ? '✓ Copied' : 'Copy'}
                  </button>
                </div>
                <pre className="font-mono text-[10px] text-rose-300 overflow-x-auto">
                  {uninstallExeCommand}
                </pre>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
