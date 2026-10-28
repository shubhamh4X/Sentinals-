import React, { useState, useEffect } from 'react';
import {
  IncidentRecord,
  SecurityEventRecord,
  UserRole,
} from '../../shared-schemas/types.ts';

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
}

export const ThreatInvestigationTab: React.FC<ThreatInvestigationTabProps> = ({
  incidents,
  events,
  selectedIncidentId,
  onSelectIncident,
  userRole,
  onUpdateIncident,
}) => {
  const activeIncident =
    incidents.find((i) => i.incidentId === selectedIncidentId) ||
    incidents[0] ||
    null;

  const [notesDraft, setNotesDraft] = useState('');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  useEffect(() => {
    if (activeIncident) {
      setNotesDraft(activeIncident.analystNotes || '');
    } else {
      setNotesDraft('');
    }
  }, [activeIncident?.incidentId, activeIncident?.analystNotes]);

  const canModify =
    userRole === UserRole.ADMINISTRATOR ||
    userRole === UserRole.SECURITY_ANALYST;

  const relatedEvents = activeIncident
    ? events.filter((e) => e.deviceId === activeIncident.deviceId)
    : [];

  const handleExportIncidentReport = (inc: IncidentRecord) => {
    const exportPayload = {
      reportType: 'Sentinel_AC_Forensic_Incident_Report',
      schemaVersion: '1.2.0',
      exportedAt: new Date().toISOString(),
      incident: inc,
      correlatedTelemetryEvents: relatedEvents,
    };
    const blob = new Blob([JSON.stringify(exportPayload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${inc.incidentId}_forensic_report.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100">
            Threat Investigation & Evidence Provenance Console
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Correlate multi-module indicators, review false-positive guidance, record analyst notes, and export forensic case reports in real time.
          </p>
        </div>
        <div className="text-xs font-mono text-slate-400 shrink-0">
          Active Role: <span className="text-sky-400">{userRole}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left List of Incidents */}
        <div className="lg:col-span-4 bg-[#111827] border border-slate-800 rounded-lg divide-y divide-slate-800">
          <div className="p-4">
            <h3 className="text-xs font-semibold text-slate-300">
              Correlated Investigation Cases ({incidents.length})
            </h3>
          </div>
          {incidents.length === 0 ? (
            <div className="p-8 text-xs text-slate-400 text-center leading-relaxed">
              Zero security incidents recorded. System is actively monitoring connected game sessions. Correlated threat cases will appear here in real time.
            </div>
          ) : (
            incidents.map((inc) => {
              const isSelected = activeIncident?.incidentId === inc.incidentId;
              return (
                <button
                  key={inc.incidentId}
                  onClick={() => onSelectIncident(inc.incidentId)}
                  className={`w-full text-left p-4 transition-colors cursor-pointer space-y-1.5 ${
                    isSelected ? 'bg-sky-950/30' : 'hover:bg-slate-900/60'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-sky-400">
                      {inc.primaryRuleId} · {inc.hostname}
                    </span>
                    <span
                      className={
                        inc.severity === 'critical'
                          ? 'text-rose-400 uppercase font-semibold'
                          : inc.severity === 'high'
                          ? 'text-amber-400 uppercase font-semibold'
                          : 'text-slate-300 uppercase'
                      }
                    >
                      {inc.severity}
                    </span>
                  </div>
                  <div className="text-sm font-medium text-slate-100 line-clamp-2">
                    {inc.title}
                  </div>
                  <div className="text-xs font-mono tabular-nums text-slate-400">
                    Status: {inc.status} · Risk: {inc.aggregatedRiskScore}/100 · {inc.correlatedEventCount} events
                  </div>
                </button>
              );
            })
          )}
        </div>

        {/* Right Incident Forensic Detail & Disposition */}
        <div className="lg:col-span-8 bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-6">
          {activeIncident ? (
            <>
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 border-b border-slate-800 pb-4">
                <div className="space-y-1">
                  <div className="text-xs font-mono text-sky-400">
                    Case ID: {activeIncident.incidentId} · [LIVE INVESTIGATION] · Status: {activeIncident.status}
                  </div>
                  <h3 className="text-lg font-semibold text-slate-100">
                    {activeIncident.title}
                  </h3>
                  <div className="text-xs font-mono tabular-nums text-slate-400">
                    Device: {activeIncident.hostname} ({activeIncident.deviceId}) · Emulator: {activeIncident.emulator}
                  </div>
                </div>

                <button
                  onClick={() => handleExportIncidentReport(activeIncident)}
                  className="px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  Export Incident Report (JSON)
                </button>
              </div>

              {/* Scoring & Limitations Row */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="p-4 rounded-md bg-[#0B0F19] border border-slate-800/80">
                  <div className="text-xs text-slate-400">Aggregated Risk Score</div>
                  <div className="text-2xl font-semibold font-mono tabular-nums text-rose-400 mt-1">
                    {activeIncident.aggregatedRiskScore}/100
                  </div>
                  <div className="text-xs text-slate-400 mt-1 font-mono">
                    Correlated Events: {activeIncident.correlatedEventCount}
                  </div>
                </div>

                <div className="p-4 rounded-md bg-[#0B0F19] border border-slate-800/80">
                  <div className="text-xs text-slate-400">Detection Confidence</div>
                  <div className="text-2xl font-semibold font-mono tabular-nums text-sky-400 mt-1">
                    {activeIncident.confidenceScore}%
                  </div>
                  <div className="text-xs text-slate-400 mt-1 font-mono">
                    Primary Rule: {activeIncident.primaryRuleId}
                  </div>
                </div>

                <div className="p-4 rounded-md bg-[#0B0F19] border border-slate-800/80">
                  <div className="text-xs text-slate-400">Digital Signature Status</div>
                  <div className="text-sm font-medium font-mono text-slate-200 mt-1 line-clamp-2">
                    {activeIncident.digitalSignature}
                  </div>
                </div>
              </div>

              {/* Forensic Artifact Provenance */}
              <div className="space-y-3 text-xs bg-[#0B0F19] border border-slate-800/80 rounded-md p-4">
                <div className="font-semibold text-slate-200">
                  Artifact & Module Provenance
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <span className="text-slate-400">Executable / Module Path:</span>
                    <div className="font-mono text-slate-200 break-all mt-0.5">
                      {activeIncident.executablePath}
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-400">File SHA-256 Digest:</span>
                    <div className="font-mono text-slate-200 break-all mt-0.5">
                      {activeIncident.fileSha256}
                    </div>
                  </div>
                </div>
                <div className="pt-2 border-t border-slate-800/80">
                  <span className="text-slate-400">Evidence Correlation Summary:</span>
                  <p className="text-slate-200 mt-0.5 leading-relaxed">
                    {activeIncident.evidenceSummary}
                  </p>
                </div>
                <div className="pt-2 border-t border-slate-800/80">
                  <span className="text-amber-400 font-medium">Defensible Limitations & False-Positive Notice:</span>
                  <p className="text-slate-300 mt-0.5 leading-relaxed">
                    {activeIncident.limitationsNotice}
                  </p>
                </div>
                <div className="pt-2 border-t border-slate-800/80">
                  <span className="text-slate-400">Recommended Analyst Steps:</span>
                  <p className="text-slate-300 mt-0.5 leading-relaxed">
                    {activeIncident.recommendedAction}
                  </p>
                </div>
              </div>

              {/* Correlated Event Timeline */}
              <div className="space-y-3">
                <div className="text-xs font-semibold text-slate-300">
                  Incident Telemetry Timeline ({relatedEvents.length} events on {activeIncident.hostname})
                </div>
                <div className="divide-y divide-slate-800/80 border border-slate-800 rounded-md bg-[#0B0F19]">
                  {relatedEvents.map((ev) => (
                    <div key={ev.eventId} className="p-3 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="space-y-0.5">
                        <div className="font-mono text-sky-400">
                          {new Date(ev.eventTimestamp).toLocaleTimeString()} · {ev.ruleId} · {ev.processName}
                        </div>
                        <div className="text-slate-300">{ev.summary}</div>
                      </div>
                      <div className="font-mono tabular-nums text-slate-400 shrink-0">
                        +{ev.riskContribution} risk ({ev.confidence}%)
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Analyst Notes & Incident Response Controls */}
              <div className="space-y-4 pt-4 border-t border-slate-800">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold text-slate-200">
                    Analyst Investigation Notes & Disposition
                  </label>
                  {statusMessage && (
                    <span className="text-xs font-mono text-emerald-400">
                      {statusMessage}
                    </span>
                  )}
                </div>

                <textarea
                  rows={3}
                  value={notesDraft}
                  disabled={!canModify}
                  onChange={(e) => setNotesDraft(e.target.value)}
                  placeholder="Document corroborating evidence, signer verification, or reason for false-positive dismissal..."
                  className="w-full p-3 text-xs bg-[#0B0F19] border border-slate-800 rounded-md text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 disabled:opacity-50"
                />

                {!canModify ? (
                  <div className="text-xs text-amber-400">
                    Read-Only Viewer role active. Switch to Security Analyst or Administrator in Settings & Audit Logs to modify incident disposition.
                  </div>
                ) : (
                  <div className="flex flex-wrap items-center gap-2.5">
                    <button
                      onClick={() => {
                        onUpdateIncident(
                          activeIncident.incidentId,
                          'investigating',
                          notesDraft,
                          `Marked incident ${activeIncident.incidentId} as Under Investigation.`
                        );
                        setStatusMessage('Saved: Under Investigation');
                      }}
                      className="px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Mark Under Investigation
                    </button>

                    <button
                      onClick={() => {
                        const updatedNotes = `${notesDraft}\n[Diagnostic Bundle Requested at ${new Date().toLocaleTimeString()}]: Agent collected process handle table & Authenticode certificate chain.`.trim();
                        setNotesDraft(updatedNotes);
                        onUpdateIncident(
                          activeIncident.incidentId,
                          'investigating',
                          updatedNotes,
                          `Requested controlled diagnostic collection from ${activeIncident.hostname}.`
                        );
                        setStatusMessage('Diagnostic Collection Logged');
                      }}
                      className="px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-sky-400 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Request Controlled Diagnostic Collection
                    </button>

                    <button
                      onClick={() => {
                        onUpdateIncident(
                          activeIncident.incidentId,
                          'confirmed_violation',
                          notesDraft || 'Confirmed violation after multi-indicator corroboration.',
                          `Confirmed violation on incident ${activeIncident.incidentId} and authorized artifact quarantine.`
                        );
                        setStatusMessage('Saved: Confirmed Violation');
                      }}
                      className="px-3.5 py-2 text-xs font-medium bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Confirm Violation & Quarantine Artifact
                    </button>

                    <button
                      onClick={() => {
                        onUpdateIncident(
                          activeIncident.incidentId,
                          'dismissed_false_positive',
                          notesDraft || 'Dismissed as benign utility / false-positive overlay.',
                          `Dismissed incident ${activeIncident.incidentId} as a False Positive.`
                        );
                        setStatusMessage('Saved: Dismissed as False Positive');
                      }}
                      className="px-3.5 py-2 text-xs font-medium bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Dismiss as False Positive
                    </button>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="text-xs text-slate-400 py-16 text-center space-y-2">
              <div className="text-sm font-semibold text-slate-300">
                No Incidents Currently Open
              </div>
              <p className="max-w-md mx-auto leading-relaxed">
                All connected Free Fire emulator sessions are nominal. Correlated incidents and artifact provenance will display here as security indicators are detected.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
