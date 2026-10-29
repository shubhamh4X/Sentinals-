import React, { useState, useEffect } from 'react';
import {
  DetectionCategory,
  MonitoredDevice,
  SecurityEventRecord,
  SeverityLevel,
} from '../../shared-schemas/types.ts';
import {
  computeFleetSummary,
  isDemoOrSimulatedEventOrIncident,
} from '../../shared-schemas/fleetMetrics.ts';
import { getFriendlyEventSummary } from '../lib/friendlyDescriptions.ts';

interface LiveMonitoringTabProps {
  events: SecurityEventRecord[];
  devices?: MonitoredDevice[];
  wsConnected: boolean;
  selectedDeviceFilter?: string;
  onChangeDeviceFilter?: (deviceId: string) => void;
  onTriggerScenario?: (scenarioId: string) => void;
  isRunningScenario?: string | null;
  onClearAllThreats?: () => void;
}

export const LiveMonitoringTab: React.FC<LiveMonitoringTabProps> = ({
  events,
  devices = [],
  wsConnected,
  selectedDeviceFilter = 'all',
  onChangeDeviceFilter,
  onClearAllThreats,
}) => {
  const [deviceFilter, setDeviceFilter] = useState<string>(selectedDeviceFilter);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [timeRangeFilter, setTimeRangeFilter] = useState<'all' | '15m' | '1h' | '24h' | '7d'>('all');
  const [sourceFilter, setSourceFilter] = useState<'all' | 'real' | 'test'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [isPaused, setIsPaused] = useState(false);
  const [pausedSnapshot, setPausedSnapshot] = useState<SecurityEventRecord[]>([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [selectedEventForModal, setSelectedEventForModal] = useState<SecurityEventRecord | null>(null);

  useEffect(() => {
    setDeviceFilter(selectedDeviceFilter);
    setPage(1);
  }, [selectedDeviceFilter]);

  const handleDeviceChange = (val: string) => {
    setDeviceFilter(val);
    setPage(1);
    if (onChangeDeviceFilter) {
      onChangeDeviceFilter(val);
    }
  };

  const togglePause = () => {
    if (!isPaused) {
      setPausedSnapshot(events);
      setIsPaused(true);
    } else {
      setIsPaused(false);
      setPausedSnapshot([]);
    }
  };

  const activeEventPool = isPaused ? pausedSnapshot : events;
  const bufferedCount = isPaused ? Math.max(0, events.length - pausedSnapshot.length) : 0;

  // Build endpoint filter strictly from authoritative enrolled backend devices
  const fleet = computeFleetSummary(devices);
  const allDeviceOptions = fleet.devices.map((d) => ({
    deviceId: d.deviceId,
    hostname: d.hostname,
    status: d.status,
  }));

  // Filter events (strictly real Windows agent telemetry)
  const now = Date.now();
  const filteredEvents = activeEventPool.filter((ev) => {
    if (isDemoOrSimulatedEventOrIncident(ev)) return false;
    if (deviceFilter !== 'all' && ev.deviceId !== deviceFilter) return false;
    if (selectedSeverity !== 'all' && ev.severity !== selectedSeverity) return false;
    if (categoryFilter !== 'all' && ev.category !== categoryFilter) return false;
    if (sourceFilter === 'real' && ev.isSimulated) return false;

    if (timeRangeFilter !== 'all') {
      const ts = Date.parse(ev.eventTimestamp);
      if (!Number.isNaN(ts)) {
        const ageMs = now - ts;
        if (timeRangeFilter === '15m' && ageMs > 15 * 60 * 1000) return false;
        if (timeRangeFilter === '1h' && ageMs > 60 * 60 * 1000) return false;
        if (timeRangeFilter === '24h' && ageMs > 24 * 60 * 60 * 1000) return false;
        if (timeRangeFilter === '7d' && ageMs > 7 * 24 * 60 * 60 * 1000) return false;
      }
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      const friendly = getFriendlyEventSummary(ev);
      const matches =
        ev.eventId.toLowerCase().includes(q) ||
        ev.deviceId.toLowerCase().includes(q) ||
        ev.hostname.toLowerCase().includes(q) ||
        ev.processName.toLowerCase().includes(q) ||
        ev.processPath.toLowerCase().includes(q) ||
        ev.sha256.toLowerCase().includes(q) ||
        ev.ruleId.toLowerCase().includes(q) ||
        friendly.title.toLowerCase().includes(q) ||
        friendly.simpleDescription.toLowerCase().includes(q) ||
        (ev.metadata?.commandLine || '').toLowerCase().includes(q) ||
        (ev.metadata?.loadedModule || '').toLowerCase().includes(q);
      if (!matches) return false;
    }
    return true;
  });

  const totalCount = filteredEvents.length;
  const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));
  const currentPage = Math.min(page, totalPages);
  const paginatedEvents = filteredEvents.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const realCount = activeEventPool.filter((e) => !isDemoOrSimulatedEventOrIncident(e)).length;

  const formatUtcTimestamp = (iso: string) => {
    try {
      const d = new Date(iso);
      return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    } catch {
      return iso;
    }
  };

  const handleExportLogs = (format: 'json' | 'csv') => {
    if (format === 'json') {
      const payload = JSON.stringify(
        {
          exportedAtUtc: new Date().toISOString(),
          totalEvents: filteredEvents.length,
          deviceFilter,
          events: filteredEvents,
        },
        null,
        2
      );
      const blob = new Blob([payload], { type: 'application/json;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sentinel-central-logs-${deviceFilter}-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      return;
    }

    const headers = [
      'TimestampUTC',
      'EventID',
      'DeviceID',
      'Hostname',
      'Category',
      'RuleID',
      'RuleVersion',
      'Severity',
      'Confidence',
      'ProcessName',
      'PID',
      'ParentProcess',
      'FilePath',
      'SHA256',
      'DigitalSignature',
      'Emulator',
      'TelemetryOrigin',
      'Summary',
    ];
    const rows = filteredEvents.map((e) => [
      e.eventTimestamp,
      e.eventId,
      e.deviceId,
      e.hostname,
      `"${(e.category || '').replace(/"/g, '""')}"`,
      e.ruleId,
      e.ruleVersion,
      e.severity,
      e.confidence,
      `"${(e.processName || '').replace(/"/g, '""')}"`,
      e.metadata?.processPid ?? '',
      `"${(e.metadata?.parentProcessName || '').replace(/"/g, '""')}"`,
      `"${(e.processPath || '').replace(/"/g, '""')}"`,
      e.sha256,
      `"${(e.signerIdentity || '').replace(/"/g, '""')}"`,
      `"${(e.emulator || '').replace(/"/g, '""')}"`,
      e.isSimulated ? 'TEST_EVENT' : 'REAL_TELEMETRY',
      `"${(e.summary || '').replace(/"/g, '""')}"`,
    ]);
    const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-central-logs-${deviceFilter}-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* 1. Header with Live Stream Controls, Pause/Resume & Export */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                isPaused
                  ? 'bg-amber-400'
                  : wsConnected
                  ? 'bg-emerald-400 animate-pulse'
                  : 'bg-amber-400'
              }`}
            />
            <h2 className="text-base font-semibold text-slate-100">
              Central Multi-PC Live Logs Console (
              {isPaused
                ? `Stream Paused${bufferedCount > 0 ? ` · +${bufferedCount} Buffered` : ''}`
                : wsConnected
                ? 'Real-Time WebSocket & SSE Stream Active'
                : 'Connecting Stream...'}
              )
            </h2>
          </div>
          <p className="text-xs text-slate-400">
            Centralized security event stream across all enrolled Windows PCs with per-device attribution, UTC timestamps, and offline history retention.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs font-mono shrink-0">
          <span className="px-2.5 py-1 bg-slate-900 border border-slate-800 rounded-md text-emerald-400">
            {realCount} Real Telemetry Event(s)
          </span>

          <button
            onClick={togglePause}
            className={`px-3 py-1 rounded-md font-sans font-semibold border transition-colors cursor-pointer ${
              isPaused
                ? 'bg-amber-500/20 border-amber-500/40 text-amber-300 hover:bg-amber-500/30'
                : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-200'
            }`}
          >
            {isPaused ? `▶ Resume Stream${bufferedCount > 0 ? ` (+${bufferedCount})` : ''}` : '⏸ Pause Stream'}
          </button>

          <button
            onClick={() => handleExportLogs('json')}
            className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-md font-sans font-medium transition-colors cursor-pointer"
          >
            Export JSON
          </button>
          <button
            onClick={() => handleExportLogs('csv')}
            className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-md font-sans font-medium transition-colors cursor-pointer"
          >
            Export CSV
          </button>

          {onClearAllThreats && events.length > 0 && (
            <button
              onClick={onClearAllThreats}
              className="px-3 py-1 bg-rose-950/60 hover:bg-rose-900/80 border border-rose-500/40 text-rose-300 rounded-md font-sans font-semibold transition-colors cursor-pointer"
            >
              Clear All Alerts
            </button>
          )}
        </div>
      </div>

      {/* 2. Multi-Dimensional Filter Bar (PC, Time Range, Category, Severity, Origin, Search) */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Filter by Individual PC or All PCs */}
          <div>
            <label className="block text-[10px] font-mono uppercase text-slate-400 mb-1">
              Endpoint / Monitored PC
            </label>
            <select
              value={deviceFilter}
              onChange={(e) => handleDeviceChange(e.target.value)}
              className="w-full px-3 py-1.5 text-xs bg-[#0B0F19] border border-slate-800 rounded-lg text-slate-100 focus:outline-none focus:border-sky-500"
            >
              <option value="all">All Connected &amp; Historical PCs ({allDeviceOptions.length})</option>
              {allDeviceOptions.map((d) => (
                <option key={d.deviceId} value={d.deviceId}>
                  {d.hostname} ({d.deviceId}) {d.status === 'disconnected' ? '[Offline]' : d.status === 'revoked' ? '[Revoked]' : ''}
                </option>
              ))}
            </select>
          </div>

          {/* Filter by Event Category */}
          <div>
            <label className="block text-[10px] font-mono uppercase text-slate-400 mb-1">
              Detection Category
            </label>
            <select
              value={categoryFilter}
              onChange={(e) => {
                setCategoryFilter(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-1.5 text-xs bg-[#0B0F19] border border-slate-800 rounded-lg text-slate-100 focus:outline-none focus:border-sky-500"
            >
              <option value="all">All Detection Categories</option>
              <option value={DetectionCategory.PROCESS_INTEGRITY}>{DetectionCategory.PROCESS_INTEGRITY}</option>
              <option value={DetectionCategory.MEMORY_INJECTION}>{DetectionCategory.MEMORY_INJECTION}</option>
              <option value={DetectionCategory.EMULATOR_INTEGRITY}>{DetectionCategory.EMULATOR_INTEGRITY}</option>
              <option value={DetectionCategory.ESP_GAMEPLAY}>{DetectionCategory.ESP_GAMEPLAY}</option>
              <option value={DetectionCategory.AGENT_INTEGRITY}>{DetectionCategory.AGENT_INTEGRITY}</option>
            </select>
          </div>

          {/* Filter by Time Range */}
          <div>
            <label className="block text-[10px] font-mono uppercase text-slate-400 mb-1">
              Time Range (UTC)
            </label>
            <select
              value={timeRangeFilter}
              onChange={(e) => {
                setTimeRangeFilter(e.target.value as 'all' | '15m' | '1h' | '24h' | '7d');
                setPage(1);
              }}
              className="w-full px-3 py-1.5 text-xs bg-[#0B0F19] border border-slate-800 rounded-lg text-slate-100 focus:outline-none focus:border-sky-500"
            >
              <option value="all">All Historical &amp; Live Logs</option>
              <option value="15m">Last 15 Minutes</option>
              <option value="1h">Last 1 Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
            </select>
          </div>

          {/* Search Box */}
          <div>
            <label className="block text-[10px] font-mono uppercase text-slate-400 mb-1">
              Search Process / Hash / Event ID / PC
            </label>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setPage(1);
              }}
              placeholder="Process, SHA-256, evt_..., rule, PC..."
              className="w-full px-3 py-1.5 text-xs bg-[#0B0F19] border border-slate-800 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>
        </div>

        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 pt-2 border-t border-slate-800/80">
          {/* Severity Filters */}
          <div className="flex flex-wrap items-center gap-1.5">
            {(['all', SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW] as const).map(
              (sev) => (
                <button
                  key={sev}
                  onClick={() => {
                    setSelectedSeverity(sev);
                    setPage(1);
                  }}
                  className={`px-3 py-1 text-xs font-medium rounded-lg transition-colors capitalize cursor-pointer ${
                    selectedSeverity === sev
                      ? 'bg-sky-400 text-slate-950 font-semibold'
                      : 'bg-[#0B0F19] text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  {sev === 'all' ? 'All Severities' : sev}
                </button>
              )
            )}
          </div>

          {/* Active PC Pill */}
          <div className="flex flex-wrap items-center gap-2">
            {deviceFilter !== 'all' && (
              <button
                onClick={() => handleDeviceChange('all')}
                className="px-2.5 py-1 text-xs font-mono bg-sky-950/60 border border-sky-500/40 text-sky-300 rounded-md cursor-pointer"
              >
                Filtering PC: {deviceFilter} ✕
              </button>
            )}
            <span className="px-2.5 py-1 text-xs font-mono bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 rounded-md">
              Origin: Authenticated Windows Agent Only
            </span>
          </div>
        </div>
      </div>

      {/* 3. Central Security Event Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden">
        {paginatedEvents.length === 0 ? (
          <div className="py-12 px-4 text-center space-y-2">
            <div className="text-sm font-semibold text-slate-200">No Security Events Match Current Filter</div>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              {events.length === 0
                ? 'All enrolled Windows PCs are currently clean. When suspicious processes, memory hooks, or emulator modifications occur on any connected PC, they will appear here with per-device attribution.'
                : 'No events matched your active device, category, or search filter. Click "All Connected & Historical PCs" or clear search to view all records.'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] font-mono uppercase text-slate-400 bg-[#0B0F19]/60">
                  <th className="py-3 px-4">UTC Timestamp &amp; Event ID</th>
                  <th className="py-3 px-3">Endpoint / PC</th>
                  <th className="py-3 px-4">Detection &amp; Evidence</th>
                  <th className="py-3 px-3">Process / PID / Parent</th>
                  <th className="py-3 px-3">Severity &amp; Conf.</th>
                  <th className="py-3 px-3">Telemetry Origin</th>
                  <th className="py-3 px-4 text-right">Forensics</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 text-xs">
                {paginatedEvents.map((ev) => {
                  const friendly = getFriendlyEventSummary(ev);
                  return (
                    <tr key={ev.eventId} className="hover:bg-slate-900/50 transition-colors">
                      {/* UTC Timestamp + Event ID */}
                      <td className="py-3 px-4 font-mono whitespace-nowrap">
                        <div className="text-slate-200 text-[11px]">{formatUtcTimestamp(ev.eventTimestamp)}</div>
                        <div className="text-slate-500 text-[10px] mt-0.5">{ev.eventId}</div>
                      </td>

                      {/* Endpoint / PC Attribution */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <button
                          onClick={() => handleDeviceChange(ev.deviceId)}
                          className="text-left group cursor-pointer"
                          title="Filter logs to this PC"
                        >
                          <div className="font-semibold text-sky-300 group-hover:underline flex items-center gap-1.5">
                            <span>🖥️ {ev.hostname}</span>
                          </div>
                          <div className="font-mono text-[10px] text-slate-400">{ev.deviceId}</div>
                          <div className="text-[10px] text-slate-500 truncate max-w-[140px]">{ev.emulator}</div>
                        </button>
                      </td>

                      {/* Detection & Rule */}
                      <td className="py-3 px-4 max-w-md">
                        <div className="flex items-center gap-2">
                          <span className="px-1.5 py-0.5 bg-slate-800 border border-slate-700 rounded font-mono text-[10px] text-sky-400">
                            {ev.ruleId} v{ev.ruleVersion}
                          </span>
                          <span className="font-semibold text-slate-100">{friendly.title}</span>
                        </div>
                        <div className="text-slate-400 text-[11px] mt-1 leading-relaxed line-clamp-2">
                          {ev.summary}
                        </div>
                        <div className="text-[10px] text-slate-500 mt-0.5">{ev.category}</div>
                      </td>

                      {/* Process / PID / Parent */}
                      <td className="py-3 px-3 font-mono text-[11px]">
                        <div className="text-slate-200 font-medium">
                          {ev.processName || 'Unknown'}
                          {ev.metadata?.processPid ? (
                            <span className="text-slate-400 ml-1">[PID {ev.metadata.processPid}]</span>
                          ) : null}
                        </div>
                        {ev.metadata?.parentProcessName && (
                          <div className="text-[10px] text-slate-400">
                            Parent: {ev.metadata.parentProcessName}
                            {ev.metadata?.parentProcessPid ? ` (${ev.metadata.parentProcessPid})` : ''}
                          </div>
                        )}
                        <div className="text-[10px] text-slate-500 truncate max-w-[180px]" title={ev.sha256}>
                          SHA256: {ev.sha256.slice(0, 14)}...
                        </div>
                      </td>

                      {/* Severity & Confidence */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                            ev.severity === SeverityLevel.CRITICAL
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                              : ev.severity === SeverityLevel.HIGH
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                              : ev.severity === SeverityLevel.MEDIUM
                              ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30'
                              : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                          }`}
                        >
                          {ev.severity}
                        </span>
                        <div className="font-mono text-[10px] text-slate-400 mt-1">
                          Conf: {ev.confidence}% (+{ev.riskContribution} risk)
                        </div>
                      </td>

                      {/* Telemetry Origin */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        {ev.isSimulated ? (
                          <span className="px-2 py-0.5 rounded bg-sky-950/60 border border-sky-500/30 text-[10px] font-mono text-sky-300">
                            [TEST EVENT]
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/30 text-[10px] font-mono text-emerald-300">
                            [REAL TELEMETRY]
                          </span>
                        )}
                      </td>

                      {/* View Details Button */}
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <button
                          onClick={() => setSelectedEventForModal(ev)}
                          className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md text-xs font-medium transition-colors cursor-pointer"
                        >
                          View Details
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        {totalCount > 0 && (
          <div className="px-4 py-3 bg-[#0B0F19]/80 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
            <div>
              Showing <span className="text-slate-200 font-semibold">{(currentPage - 1) * pageSize + 1}</span>–
              <span className="text-slate-200 font-semibold">{Math.min(totalCount, currentPage * pageSize)}</span> of{' '}
              <span className="text-slate-200 font-semibold">{totalCount}</span> security events
            </div>

            <div className="flex items-center gap-3">
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(1);
                }}
                className="px-2 py-1 bg-slate-900 border border-slate-800 rounded text-xs text-slate-200"
              >
                <option value={25}>25 per page</option>
                <option value={50}>50 per page</option>
                <option value={100}>100 per page</option>
              </select>

              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={currentPage <= 1}
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 rounded cursor-pointer"
                >
                  ← Prev
                </button>
                <span className="px-2 font-mono text-slate-300">
                  Page {currentPage} / {totalPages}
                </span>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={currentPage >= totalPages}
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 rounded cursor-pointer"
                >
                  Next →
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 4. Technical Evidence Modal */}
      {selectedEventForModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-[#111827] border border-slate-800 rounded-xl shadow-2xl max-w-2xl w-full p-6 space-y-5 overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-sky-400">
                    Rule ID: {selectedEventForModal.ruleId} (v{selectedEventForModal.ruleVersion})
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    · Event ID: {selectedEventForModal.eventId}
                  </span>
                  {selectedEventForModal.isSimulated ? (
                    <span className="px-1.5 py-0.5 text-[10px] bg-sky-950 text-sky-300 rounded font-mono">
                      [TEST EVENT]
                    </span>
                  ) : (
                    <span className="px-1.5 py-0.5 text-[10px] bg-emerald-950 text-emerald-300 rounded font-mono">
                      [REAL TELEMETRY]
                    </span>
                  )}
                </div>
                <h3 className="text-base font-bold text-slate-100 mt-1">
                  {getFriendlyEventSummary(selectedEventForModal).title}
                </h3>
              </div>
              <button
                onClick={() => setSelectedEventForModal(null)}
                className="text-slate-400 hover:text-slate-100 text-sm p-1 rounded cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4 text-xs">
              <div>
                <div className="text-slate-400 font-medium">Full Detection Evidence Summary</div>
                <div className="text-slate-200 mt-0.5 leading-relaxed font-mono text-[11px] bg-slate-900/70 p-2.5 rounded border border-slate-800">
                  {selectedEventForModal.summary}
                </div>
              </div>

              {/* Technical Evidence Table */}
              <div className="p-3.5 bg-[#0B0F19] border border-slate-800 rounded-lg space-y-2 font-mono text-[11px]">
                <div className="font-semibold text-slate-300 pb-1 border-b border-slate-800">
                  Endpoint &amp; Forensic Attribution
                </div>
                <div className="flex justify-between gap-4">
                  <span className="text-slate-500">Originating Endpoint:</span>
                  <span className="text-sky-300 font-semibold">
                    {selectedEventForModal.hostname} ({selectedEventForModal.deviceId})
                  </span>
                </div>
                <div className="flex justify-between gap-4">
                  <span className="text-slate-500">UTC Timestamp:</span>
                  <span className="text-slate-200">{formatUtcTimestamp(selectedEventForModal.eventTimestamp)}</span>
                </div>
                <div className="flex justify-between gap-4">
                  <span className="text-slate-500">Category:</span>
                  <span className="text-slate-200">{selectedEventForModal.category}</span>
                </div>
                <div className="flex justify-between gap-4">
                  <span className="text-slate-500">Process &amp; PID:</span>
                  <span className="text-slate-200">
                    {selectedEventForModal.processName}
                    {selectedEventForModal.metadata?.processPid
                      ? ` (PID: ${selectedEventForModal.metadata.processPid})`
                      : ''}
                  </span>
                </div>
                {selectedEventForModal.metadata?.parentProcessName && (
                  <div className="flex justify-between gap-4">
                    <span className="text-slate-500">Parent Process:</span>
                    <span className="text-slate-200">
                      {selectedEventForModal.metadata.parentProcessName}
                      {selectedEventForModal.metadata?.parentProcessPid
                        ? ` (PID: ${selectedEventForModal.metadata.parentProcessPid})`
                        : ''}
                    </span>
                  </div>
                )}
                <div className="flex justify-between gap-4">
                  <span className="text-slate-500">File / Module Path:</span>
                  <span className="text-slate-200 truncate max-w-md">{selectedEventForModal.processPath}</span>
                </div>
                {selectedEventForModal.metadata?.loadedModule && (
                  <div className="flex justify-between gap-4">
                    <span className="text-slate-500">Injected Module:</span>
                    <span className="text-rose-300">{selectedEventForModal.metadata.loadedModule}</span>
                  </div>
                )}
                {selectedEventForModal.metadata?.commandLine && (
                  <div className="flex justify-between gap-4">
                    <span className="text-slate-500">Command Line:</span>
                    <span className="text-amber-300 truncate max-w-md">{selectedEventForModal.metadata.commandLine}</span>
                  </div>
                )}
                {selectedEventForModal.metadata?.memoryAddress && (
                  <div className="flex justify-between gap-4">
                    <span className="text-slate-500">Memory Region:</span>
                    <span className="text-rose-300">{selectedEventForModal.metadata.memoryAddress}</span>
                  </div>
                )}
                <div className="flex justify-between gap-4">
                  <span className="text-slate-500">SHA-256 Digest:</span>
                  <span className="text-slate-200 break-all">{selectedEventForModal.sha256}</span>
                </div>
                <div className="flex justify-between gap-4">
                  <span className="text-slate-500">Digital Signature:</span>
                  <span className="text-slate-200">{selectedEventForModal.signerIdentity}</span>
                </div>
                <div className="flex justify-between gap-4">
                  <span className="text-slate-500">Game / Emulator Context:</span>
                  <span className="text-slate-200">
                    {selectedEventForModal.emulator} · Session {selectedEventForModal.sessionId}
                  </span>
                </div>
                <div className="flex justify-between gap-4">
                  <span className="text-slate-500">Confidence &amp; Risk:</span>
                  <span className="text-emerald-400">
                    {selectedEventForModal.confidence}% Confidence (+{selectedEventForModal.riskContribution} Risk)
                  </span>
                </div>
              </div>
            </div>

            <div className="pt-2 flex justify-between items-center">
              <button
                onClick={() => {
                  handleDeviceChange(selectedEventForModal.deviceId);
                  setSelectedEventForModal(null);
                }}
                className="px-3.5 py-2 bg-sky-950/60 hover:bg-sky-900 border border-sky-500/40 text-sky-300 rounded-lg text-xs font-semibold cursor-pointer"
              >
                Filter Console to {selectedEventForModal.hostname}
              </button>
              <button
                onClick={() => setSelectedEventForModal(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium cursor-pointer"
              >
                Close Details
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
