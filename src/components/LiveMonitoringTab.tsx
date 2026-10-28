import React, { useState } from 'react';
import {
  DetectionCategory,
  SecurityEventRecord,
  SeverityLevel,
} from '../../shared-schemas/types.ts';

interface LiveMonitoringTabProps {
  events: SecurityEventRecord[];
  wsConnected: boolean;
  onTriggerScenario: (scenarioId: string) => void;
  isRunningScenario: string | null;
}

export const LiveMonitoringTab: React.FC<LiveMonitoringTabProps> = ({
  events,
  wsConnected,
  onTriggerScenario,
  isRunningScenario,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventRecord | null>(
    events[0] || null
  );
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 8;

  React.useEffect(() => {
    if (!selectedEvent && events.length > 0) {
      setSelectedEvent(events[0]);
    }
  }, [events, selectedEvent]);

  const filteredEvents = events.filter((ev) => {
    const matchesSeverity =
      severityFilter === 'all' || ev.severity === severityFilter;
    const matchesCategory =
      categoryFilter === 'all' || ev.category === categoryFilter;
    const q = searchQuery.toLowerCase().trim();
    const matchesQuery =
      !q ||
      ev.hostname.toLowerCase().includes(q) ||
      ev.processName.toLowerCase().includes(q) ||
      ev.ruleId.toLowerCase().includes(q) ||
      ev.sha256.toLowerCase().includes(q) ||
      ev.emulator.toLowerCase().includes(q) ||
      ev.summary.toLowerCase().includes(q);
    return matchesSeverity && matchesCategory && matchesQuery;
  });

  const totalPages = Math.max(1, Math.ceil(filteredEvents.length / pageSize));
  const paginatedEvents = filteredEvents.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize
  );

  return (
    <div className="space-y-6">
      {/* Live Stream Control Header */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <span
              className={`w-2 h-2 rounded-full ${
                wsConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
              }`}
            />
            <h2 className="text-base font-semibold text-slate-100">
              Real-Time Telemetry Stream ({wsConnected ? 'WebSocket + SSE Connected' : 'Reconnecting Stream'})
            </h2>
          </div>
          <p className="text-xs text-slate-400">
            Ingesting validated Windows agent telemetry events across process creation, handle table inspection, module loads, and emulator asset integrity.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            onClick={() => onTriggerScenario('SCENARIO_2_KNOWN_SUSPICIOUS_EXECUTABLE')}
            disabled={Boolean(isRunningScenario)}
            className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
          >
            + Simulate Cheat Exe (PROC-001)
          </button>
          <button
            onClick={() => onTriggerScenario('SCENARIO_4_SUSPICIOUS_PROCESS_ACCESS')}
            disabled={Boolean(isRunningScenario)}
            className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
          >
            + Simulate VM_WRITE Handle (MEM-001)
          </button>
          <button
            onClick={() => onTriggerScenario('SCENARIO_8_FALSE_POSITIVE_OVERLAY')}
            disabled={Boolean(isRunningScenario)}
            className="px-3 py-1.5 text-xs font-medium bg-sky-400 hover:bg-sky-300 text-slate-950 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
          >
            + Simulate Overlay Event (ESP-001)
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-1 p-1 bg-[#0B0F19] border border-slate-800 rounded-lg">
          {(['all', SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW] as const).map(
            (sev) => (
              <button
                key={sev}
                onClick={() => {
                  setSeverityFilter(sev);
                  setCurrentPage(1);
                }}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors capitalize whitespace-nowrap shrink-0 cursor-pointer ${
                  severityFilter === sev
                    ? 'bg-slate-800 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev === 'all' ? 'All Severities' : sev}
              </button>
            )
          )}
        </div>

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <select
            value={categoryFilter}
            onChange={(e) => {
              setCategoryFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="px-3 py-2 text-xs bg-[#0B0F19] border border-slate-800 rounded-md text-slate-200 focus:outline-none focus:border-sky-500"
          >
            <option value="all">All Detection Categories</option>
            <option value={DetectionCategory.PROCESS_INTEGRITY}>{DetectionCategory.PROCESS_INTEGRITY}</option>
            <option value={DetectionCategory.MEMORY_INJECTION}>{DetectionCategory.MEMORY_INJECTION}</option>
            <option value={DetectionCategory.EMULATOR_INTEGRITY}>{DetectionCategory.EMULATOR_INTEGRITY}</option>
            <option value={DetectionCategory.ESP_GAMEPLAY}>{DetectionCategory.ESP_GAMEPLAY}</option>
            <option value={DetectionCategory.AGENT_INTEGRITY}>{DetectionCategory.AGENT_INTEGRITY}</option>
          </select>

          <input
            type="text"
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
            placeholder="Search host, process, rule ID, SHA-256..."
            className="px-3 py-2 text-xs bg-[#0B0F19] border border-slate-800 rounded-md text-slate-100 placeholder-slate-500 w-full sm:w-64 focus:outline-none focus:border-sky-500"
          />
        </div>
      </div>

      {/* Main Split Grid: Event Table + Forensic Event Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-8 bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-xs text-slate-400 bg-[#0B0F19]/60">
                  <th className="py-3 px-4 font-medium">Timestamp / Mode</th>
                  <th className="py-3 px-3 font-medium">Rule & Severity</th>
                  <th className="py-3 px-3 font-medium">Host & Emulator</th>
                  <th className="py-3 px-3 font-medium">Process & Signer</th>
                  <th className="py-3 px-4 font-medium text-right">Confidence / Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 text-xs">
                {paginatedEvents.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-10 text-center text-slate-400">
                      {events.length === 0
                        ? 'No telemetry events ingested yet. Run a live engine test or connect an agent to stream Windows telemetry.'
                        : 'No telemetry events match your current filter criteria. Adjust your filters or trigger a live test.'}
                    </td>
                  </tr>
                ) : (
                  paginatedEvents.map((ev) => {
                    const isSelected = selectedEvent?.eventId === ev.eventId;
                    return (
                      <tr
                        key={ev.eventId}
                        onClick={() => setSelectedEvent(ev)}
                        className={`cursor-pointer transition-colors ${
                          isSelected ? 'bg-sky-950/30' : 'hover:bg-slate-900/60'
                        }`}
                      >
                        <td className="py-3 px-4 font-mono tabular-nums">
                          <div className="text-slate-200">
                            {new Date(ev.eventTimestamp).toLocaleTimeString()}
                          </div>
                          <div className="text-slate-400">
                            {ev.isSimulated ? '[SIMULATED]' : '[LIVE]'}
                          </div>
                        </td>
                        <td className="py-3 px-3">
                          <div className="font-mono font-medium text-slate-100">
                            {ev.ruleId} ·{' '}
                            <span
                              className={
                                ev.severity === 'critical'
                                  ? 'text-rose-400 uppercase'
                                  : ev.severity === 'high'
                                  ? 'text-amber-400 uppercase'
                                  : ev.severity === 'medium'
                                  ? 'text-sky-400 uppercase'
                                  : 'text-emerald-400 uppercase'
                              }
                            >
                              {ev.severity}
                            </span>
                          </div>
                          <div className="text-slate-400">{ev.category}</div>
                        </td>
                        <td className="py-3 px-3">
                          <div className="font-medium text-slate-200">{ev.hostname}</div>
                          <div className="text-slate-400 font-mono">{ev.emulator}</div>
                        </td>
                        <td className="py-3 px-3">
                          <div className="font-mono text-slate-200 truncate max-w-[200px]">
                            {ev.processName}
                          </div>
                          <div className="text-slate-400 truncate max-w-[200px]">
                            {ev.signerIdentity}
                          </div>
                        </td>
                        <td className="py-3 px-4 text-right font-mono tabular-nums">
                          <div className="text-slate-200">{ev.confidence}% conf</div>
                          <div className="text-slate-400">+{ev.riskContribution} risk</div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Footer */}
          <div className="px-4 py-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <div className="font-mono tabular-nums">
              Showing {paginatedEvents.length} of {filteredEvents.length} events
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                disabled={currentPage <= 1}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded disabled:opacity-40 cursor-pointer"
              >
                Previous
              </button>
              <span className="font-mono tabular-nums">
                Page {currentPage} / {totalPages}
              </span>
              <button
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                disabled={currentPage >= totalPages}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded disabled:opacity-40 cursor-pointer"
              >
                Next
              </button>
            </div>
          </div>
        </div>

        {/* Forensic Event Detail Panel */}
        <div className="lg:col-span-4 bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-4">
          {selectedEvent ? (
            <>
              <div className="border-b border-slate-800 pb-3 space-y-1">
                <div className="text-xs font-mono text-sky-400">
                  {selectedEvent.ruleId} (v{selectedEvent.ruleVersion}) · {selectedEvent.classification}
                </div>
                <h3 className="text-sm font-semibold text-slate-100">
                  Forensic Telemetry Breakdown
                </h3>
              </div>

              <div className="space-y-3 text-xs">
                <div>
                  <div className="text-slate-400">Summary</div>
                  <div className="text-slate-200 mt-0.5 leading-relaxed">
                    {selectedEvent.summary}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3 pt-2 border-t border-slate-800/80">
                  <div>
                    <div className="text-slate-400">Host & Session</div>
                    <div className="font-mono text-slate-200 mt-0.5">
                      {selectedEvent.hostname} · {selectedEvent.sessionId}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-400">Confidence & Risk</div>
                    <div className="font-mono tabular-nums text-slate-200 mt-0.5">
                      {selectedEvent.confidence}% · +{selectedEvent.riskContribution} pts
                    </div>
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-800/80">
                  <div className="text-slate-400">Executable Path</div>
                  <div className="font-mono text-slate-200 break-all mt-0.5">
                    {selectedEvent.processPath}
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-800/80">
                  <div className="text-slate-400">File SHA-256 Digest</div>
                  <div className="font-mono text-slate-200 break-all mt-0.5">
                    {selectedEvent.sha256}
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-800/80">
                  <div className="text-slate-400">Authenticode / Signer Identity</div>
                  <div className="font-mono text-slate-200 mt-0.5">
                    {selectedEvent.signerIdentity}
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-800/80">
                  <div className="text-slate-400">Detection Source</div>
                  <div className="font-mono text-slate-300 mt-0.5">
                    {selectedEvent.detectionSource}
                  </div>
                </div>

                {selectedEvent.metadata?.falsePositiveNotes && (
                  <div className="pt-2 border-t border-slate-800/80">
                    <div className="text-slate-400">False-Positive Considerations</div>
                    <div className="text-slate-300 mt-0.5 leading-relaxed">
                      {selectedEvent.metadata.falsePositiveNotes}
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="text-xs text-slate-400 py-8 text-center">
              Select any event row from the stream to inspect its SHA-256 hash, Authenticode signer, and detection source.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
