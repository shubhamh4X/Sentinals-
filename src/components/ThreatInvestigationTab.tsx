import React, { useState } from 'react';
import { IncidentRecord, SecurityEventRecord, UserRole } from '../../shared-schemas/types.ts';

interface ThreatInvestigationTabProps {
  incidents: IncidentRecord[];
  events: SecurityEventRecord[];
  selectedIncidentId: string | null;
  onSelectIncident: (id: string) => void;
  userRole: UserRole;
  onUpdateIncident: (
    incidentId: string,
    status: IncidentRecord['status'],
    notes: string,
    actionDescription: string
  ) => void;
  onClearAllThreats?: () => void;
}

export const ThreatInvestigationTab: React.FC<ThreatInvestigationTabProps> = ({
  incidents,
  events,
  selectedIncidentId,
  onSelectIncident,
  userRole,
  onUpdateIncident,
  onClearAllThreats,
}) => {
  const [filterStatus, setFilterStatus] = useState<'all' | 'open' | 'investigating' | 'confirmed_violation' | 'dismissed_false_positive'>('all');
  const [activeNotes, setActiveNotes] = useState<{ [incidentId: string]: string }>({});
  const [actionFeedback, setActionFeedback] = useState<{ [incidentId: string]: string }>({});

  const filteredIncidents = incidents.filter((inc) => {
    if (filterStatus === 'all') return true;
    return inc.status === filterStatus;
  });

  const getSuspicionReason = (inc: IncidentRecord): string => {
    if (inc.primaryRuleId?.startsWith('PROC-001') || inc.title.toLowerCase().includes('cheat')) {
      return 'The detected program matches the cryptographic signature of a known cheat tool or injector used to manipulate game data.';
    }
    if (inc.primaryRuleId?.startsWith('MEM') || inc.evidenceSummary?.toLowerCase().includes('write')) {
      return 'An unauthorized program attempted to open a direct write handle to emulator memory while Free Fire was active.';
    }
    if (inc.primaryRuleId?.startsWith('ESP') || inc.evidenceSummary?.toLowerCase().includes('overlay')) {
      return 'A transparent, click-through window was drawing over the game screen, which is typical behavior of aimbots or ESP wallhacks.';
    }
    if (inc.primaryRuleId?.startsWith('EMU') || inc.evidenceSummary?.toLowerCase().includes('libil2cpp')) {
      return 'The core Free Fire application library (libil2cpp.so) has been tampered with or replaced.';
    }
    return inc.evidenceSummary || 'Activity deviated from standard Free Fire gameplay baseline.';
  };

  const handleAction = (
    inc: IncidentRecord,
    newStatus: IncidentRecord['status'],
    actionLabel: string
  ) => {
    const note = activeNotes[inc.incidentId] || inc.analystNotes || '';
    onUpdateIncident(
      inc.incidentId,
      newStatus,
      note,
      `Analyst marked incident "${inc.title}" as ${actionLabel}. Note: ${note || 'No notes provided'}`
    );
    setActionFeedback((prev) => ({
      ...prev,
      [inc.incidentId]: `Updated status to "${actionLabel}". Recorded in audit trail.`,
    }));
    setTimeout(() => {
      setActionFeedback((prev) => {
        const copy = { ...prev };
        delete copy[inc.incidentId];
        return copy;
      });
    }, 3500);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* 1. Header with Policy Notice */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
            <h2 className="text-base font-semibold text-slate-100">
              Threat Investigation &amp; Case Review
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Review suspicious activity detected by Sentinel AC. Every case includes supporting evidence and confidence scores.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs font-mono shrink-0">
          <span className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-slate-300">
            {incidents.filter((i) => i.status === 'open' || i.status === 'investigating').length} Active Threat Cases
          </span>
          {onClearAllThreats && (incidents.length > 0 || events.length > 0) && (
            <button
              onClick={onClearAllThreats}
              className="px-3.5 py-1.5 bg-rose-950/60 hover:bg-rose-900/80 border border-rose-500/40 text-rose-300 rounded-lg font-sans font-semibold transition-colors cursor-pointer"
            >
              Clear All Threats
            </button>
          )}
        </div>
      </div>

      {/* 2. Anti-Cheat Policy Callout Banner */}
      <div className="p-4 bg-sky-950/20 border border-sky-500/40 rounded-xl flex items-start gap-3 text-xs">
        <span className="text-sky-400 text-sm">⚖️</span>
        <div className="space-y-0.5 text-slate-300 leading-relaxed">
          <span className="font-semibold text-sky-300">Responsible Security Policy:</span>{' '}
          Never automatically ban anyone or declare cheating confirmed based on a single uncertain indicator. Always corroborate evidence, verify software provenance, and consider legitimate background tools (e.g., Discord overlays, game recording software).
        </div>
      </div>

      {/* 3. Filter Bar */}
      <div className="flex flex-wrap items-center gap-2">
        {(
          [
            { id: 'all', label: `All Cases (${incidents.length})` },
            { id: 'open', label: 'Open' },
            { id: 'investigating', label: 'Investigating' },
            { id: 'confirmed_violation', label: 'Confirmed Violations' },
            { id: 'dismissed_false_positive', label: 'Dismissed False Positives' },
          ] as const
        ).map((st) => (
          <button
            key={st.id}
            onClick={() => setFilterStatus(st.id)}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors cursor-pointer ${
              filterStatus === st.id
                ? 'bg-sky-400 text-slate-950 font-semibold'
                : 'bg-[#111827] text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            {st.label}
          </button>
        ))}
      </div>

      {/* 4. Incident Cards (Requirement 5) */}
      {filteredIncidents.length === 0 ? (
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-12 text-center space-y-2">
          <div className="text-sm font-semibold text-slate-200">No Threat Incidents Found</div>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            {incidents.length === 0
              ? 'Zero threat incidents recorded. As real-time security events trigger detection thresholds, correlated incident cards will appear here for review.'
              : 'No incidents match the selected status filter.'}
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredIncidents.map((inc) => {
            const suspicionReason = getSuspicionReason(inc);
            const related = events.filter((e) => e.deviceId === inc.deviceId);

            return (
              <div
                key={inc.incidentId}
                className={`bg-[#111827] border rounded-xl p-6 space-y-5 transition-all ${
                  selectedIncidentId === inc.incidentId
                    ? 'border-sky-500/80 shadow-lg shadow-sky-950/20'
                    : 'border-slate-800 hover:border-slate-700'
                }`}
              >
                {/* Card Top: Title, Severity, and Status */}
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 pb-4 border-b border-slate-800">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                          inc.severity === 'critical'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            : inc.severity === 'high'
                            ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                            : 'bg-sky-500/20 text-sky-300 border border-sky-500/30'
                        }`}
                      >
                        {inc.severity} Threat
                      </span>
                      <span className="text-xs font-mono text-slate-400">
                        Case ID: {inc.incidentId} · Rule: {inc.primaryRuleId}
                      </span>
                    </div>
                    <h3 className="text-base font-bold text-slate-100">{inc.title}</h3>
                    <div className="text-xs text-slate-400 font-mono">
                      Target Host: {inc.hostname} · Emulator: {inc.emulator || 'BlueStacks / LDPlayer'}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <span
                      className={`px-2.5 py-1 text-xs font-mono font-medium rounded-lg uppercase ${
                        inc.status === 'open'
                          ? 'bg-rose-950/50 text-rose-400 border border-rose-800/60'
                          : inc.status === 'investigating'
                          ? 'bg-amber-950/50 text-amber-400 border border-amber-800/60'
                          : inc.status === 'confirmed_violation'
                          ? 'bg-rose-950/50 text-rose-400 border border-rose-800/60'
                          : 'bg-emerald-950/50 text-emerald-400 border border-emerald-800/60'
                      }`}
                    >
                      Status: {inc.status}
                    </span>
                  </div>
                </div>

                {/* What Was Detected & Why It Is Suspicious */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="p-4 bg-[#0B0F19] border border-slate-800/80 rounded-xl space-y-1">
                    <div className="font-semibold text-slate-300">1. What was detected</div>
                    <p className="text-slate-200 leading-relaxed">
                      {inc.evidenceSummary || inc.title}
                    </p>
                  </div>

                  <div className="p-4 bg-[#0B0F19] border border-slate-800/80 rounded-xl space-y-1">
                    <div className="font-semibold text-slate-300">2. Why it is suspicious</div>
                    <p className="text-slate-200 leading-relaxed">
                      {suspicionReason}
                    </p>
                  </div>
                </div>

                {/* Supporting Evidence & Confidence */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                  {/* Evidence Column */}
                  <div className="md:col-span-2 p-4 bg-[#0B0F19] border border-slate-800/80 rounded-xl space-y-2">
                    <div className="font-semibold text-slate-300">3. Supporting Forensic Evidence</div>
                    <div className="space-y-1 font-mono text-[11px]">
                      <div className="flex justify-between py-1 border-b border-slate-800/60">
                        <span className="text-slate-500">Executable Path:</span>
                        <span className="text-slate-200 truncate max-w-sm">{inc.executablePath || 'N/A'}</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/60">
                        <span className="text-slate-500">File SHA-256 Digest:</span>
                        <span className="text-slate-200 truncate max-w-sm">{inc.fileSha256 || 'N/A'}</span>
                      </div>
                      <div className="flex justify-between py-1">
                        <span className="text-slate-500">Digital Signer:</span>
                        <span className="text-slate-200">{inc.digitalSignature || 'Unsigned'}</span>
                      </div>
                    </div>
                  </div>

                  {/* Confidence Column */}
                  <div className="p-4 bg-[#0B0F19] border border-slate-800/80 rounded-xl space-y-2 flex flex-col justify-between">
                    <div>
                      <div className="font-semibold text-slate-300">4. Detection Confidence</div>
                      <div className="text-2xl font-bold font-mono tabular-nums text-sky-400 mt-1">
                        {inc.confidenceScore}%
                      </div>
                      <div className="text-xs text-slate-400 mt-0.5">
                        {inc.confidenceScore >= 90
                          ? 'High Confidence (Direct Hash/Memory Match)'
                          : inc.confidenceScore >= 70
                          ? 'Moderate (Heuristic Indicator)'
                          : 'Low (Needs Verification)'}
                      </div>
                    </div>
                    <div className="text-[11px] font-mono text-slate-400">
                      Aggregated Risk: +{inc.aggregatedRiskScore} pts
                    </div>
                  </div>
                </div>

                {/* Recommended Next Steps */}
                <div className="p-4 bg-[#0B0F19] border border-slate-800/80 rounded-xl space-y-1 text-xs">
                  <div className="font-semibold text-slate-300">5. Recommended Next Steps</div>
                  <p className="text-slate-300 leading-relaxed">
                    {inc.recommendedAction || '1. Review if player is running authorized game recording tools. 2. Verify file SHA-256 in threat intelligence database. 3. Check parent process ancestry.'}
                  </p>
                </div>

                {/* Analyst Notes Field */}
                <div className="space-y-1.5 text-xs">
                  <label className="text-slate-400 font-medium">Analyst Case Notes &amp; Disposition Log:</label>
                  <input
                    type="text"
                    value={activeNotes[inc.incidentId] ?? (inc.analystNotes || '')}
                    onChange={(e) =>
                      setActiveNotes((prev) => ({
                        ...prev,
                        [inc.incidentId]: e.target.value,
                      }))
                    }
                    placeholder="Enter case investigation notes (e.g. 'Player verified using OBS overlay, dismissing false positive')..."
                    className="w-full px-3 py-2 bg-[#0B0F19] border border-slate-800 rounded-lg text-slate-100 placeholder-slate-500 text-xs focus:outline-none focus:border-sky-500"
                  />
                </div>

                {/* Action Buttons as Requested */}
                <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      onClick={() => handleAction(inc, 'investigating', 'Investigating')}
                      disabled={inc.status === 'investigating'}
                      className="px-3.5 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 text-xs font-semibold rounded-lg transition-colors cursor-pointer disabled:opacity-50"
                    >
                      Mark as Investigating
                    </button>
                    <button
                      onClick={() => handleAction(inc, 'confirmed_violation', 'Confirmed Threat')}
                      className="px-3.5 py-1.5 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 text-xs font-semibold rounded-lg transition-colors cursor-pointer"
                    >
                      Confirm Threat
                    </button>
                    <button
                      onClick={() => handleAction(inc, 'dismissed_false_positive', 'Dismissed as False Positive')}
                      className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg transition-colors cursor-pointer"
                    >
                      Dismiss as False Positive
                    </button>
                  </div>

                  {actionFeedback[inc.incidentId] && (
                    <span className="text-xs font-mono text-emerald-400 animate-pulse">
                      {actionFeedback[inc.incidentId]}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
