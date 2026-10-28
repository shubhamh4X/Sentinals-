import React, { useState } from 'react';
import {
  AuditLogRecord,
  UserRole,
} from '../../shared-schemas/types.ts';

interface SettingsAndAuditTabProps {
  userRole: UserRole;
  onChangeRole: (role: UserRole) => void;
  auditLogs: AuditLogRecord[];
  onClearAllRecords: () => void;
}

export const SettingsAndAuditTab: React.FC<SettingsAndAuditTabProps> = ({
  userRole,
  onChangeRole,
  auditLogs,
  onClearAllRecords,
}) => {
  const [retentionDays, setRetentionDays] = useState(90);
  const [dupSuppressionSec, setDupSuppressionSec] = useState(15);
  const [savedBanner, setSavedBanner] = useState<string | null>(null);

  const handleExportAuditLog = () => {
    const blob = new Blob([JSON.stringify(auditLogs, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel_ac_audit_logs_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Role-Based Access Control & Policy Configuration */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-5 bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-5">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Role-Based Access Control (RBAC) & Session Policy
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Test RBAC permission enforcement across Administrator, Security Analyst, and Read-Only Viewer roles.
            </p>
          </div>

          <div className="space-y-2">
            <label className="block text-xs font-medium text-slate-300">
              Active SOC Session Role
            </label>
            <div className="flex flex-col gap-2">
              {([
                {
                  role: UserRole.ADMINISTRATOR,
                  desc: 'Full access: manage detection rules, verify signed rule bundles, revoke devices, and resolve incidents.',
                },
                {
                  role: UserRole.SECURITY_ANALYST,
                  desc: 'Investigation access: triage incidents, request diagnostic collections, rotate device keys, and dismiss false positives.',
                },
                {
                  role: UserRole.READ_ONLY_VIEWER,
                  desc: 'Audit & read-only access: view telemetry streams, incidents, and rule definitions without mutation rights.',
                },
              ] as const).map((item) => (
                <button
                  key={item.role}
                  onClick={() => onChangeRole(item.role)}
                  className={`p-3 rounded-md border text-left transition-colors cursor-pointer ${
                    userRole === item.role
                      ? 'bg-sky-950/30 border-sky-500/60 text-slate-100'
                      : 'bg-[#0B0F19] border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="text-xs font-semibold font-mono text-sky-400">
                    {item.role} {userRole === item.role ? '· [ACTIVE]' : ''}
                  </div>
                  <div className="text-xs text-slate-400 mt-1">{item.desc}</div>
                </button>
              ))}
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800 space-y-4 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-300">Telemetry Alert Retention Policy (Days)</span>
              <input
                type="number"
                min={7}
                max={365}
                value={retentionDays}
                onChange={(e) => setRetentionDays(Number(e.target.value) || 90)}
                className="w-20 px-2.5 py-1 bg-[#0B0F19] border border-slate-800 rounded font-mono text-right text-slate-100"
              />
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-300">Duplicate Suppression Window (Seconds)</span>
              <input
                type="number"
                min={5}
                max={120}
                value={dupSuppressionSec}
                onChange={(e) => setDupSuppressionSec(Number(e.target.value) || 15)}
                className="w-20 px-2.5 py-1 bg-[#0B0F19] border border-slate-800 rounded font-mono text-right text-slate-100"
              />
            </div>

            <div className="flex items-center justify-between pt-2">
              <button
                onClick={() =>
                  setSavedBanner(
                    `Policy saved: ${retentionDays}d retention, ${dupSuppressionSec}s duplicate suppression.`
                  )
                }
                className="px-3.5 py-2 bg-sky-400 hover:bg-sky-300 text-slate-950 font-medium rounded-md transition-colors cursor-pointer"
              >
                Save Retention Policy
              </button>

              <button
                onClick={onClearAllRecords}
                className="px-3.5 py-2 bg-rose-950/40 hover:bg-rose-900/50 border border-rose-800/60 text-rose-300 font-medium rounded-md transition-colors cursor-pointer"
              >
                Clear All Stored Records (Reset to Zero)
              </button>
            </div>

            {savedBanner && (
              <div className="text-xs font-mono text-emerald-400">{savedBanner}</div>
            )}
          </div>
        </div>

        {/* Immutable Audit Log Table */}
        <div className="lg:col-span-7 bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                Immutable Administrator & Analyst Audit Trail
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Append-only record of all rule modifications, incident dispositions, credential rotations, and signature checks.
              </p>
            </div>
            <button
              onClick={handleExportAuditLog}
              className="px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Export Audit Logs (JSON)
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-xs text-slate-400">
                  <th className="py-2.5 pr-3 font-medium">Timestamp</th>
                  <th className="py-2.5 px-3 font-medium">Actor & Role</th>
                  <th className="py-2.5 px-3 font-medium">Action & Target</th>
                  <th className="py-2.5 pl-3 font-medium">Audit Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 text-xs">
                {auditLogs.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-8 px-4 text-center text-slate-400">
                      <div className="text-slate-300 font-medium">No audit entries recorded yet</div>
                      <div className="text-xs text-slate-400 mt-1">Actions taken by operators (rules toggles, incident notes, credential rotations) will be recorded here in real time.</div>
                    </td>
                  </tr>
                ) : (
                  auditLogs.map((log) => (
                    <tr key={log.logId} className="hover:bg-slate-900/50">
                      <td className="py-3 pr-3 font-mono tabular-nums text-slate-400 whitespace-nowrap">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-3 px-3">
                        <div className="font-mono text-slate-200">{log.actorEmail}</div>
                        <div className="text-slate-400">{log.actorRole}</div>
                      </td>
                      <td className="py-3 px-3 font-mono">
                        <div className="text-sky-400">{log.action}</div>
                        <div className="text-slate-400">
                          {log.targetType}:{log.targetId}
                        </div>
                      </td>
                      <td className="py-3 pl-3 text-slate-300 leading-relaxed">
                        {log.details}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
