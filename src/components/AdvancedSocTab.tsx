import React, { useState } from 'react';
import {
  AuditLogRecord,
  DetectionRuleRecord,
  UserRole,
} from '../../shared-schemas/types.ts';
import { SYNTHETIC_TEST_SCENARIOS } from '../../tests/detection_engine.test.ts';
import { ArchitectureAndTestsTab } from './ArchitectureAndTestsTab.tsx';
import { DetectionRulesTab } from './DetectionRulesTab.tsx';
import { SettingsAndAuditTab } from './SettingsAndAuditTab.tsx';

interface AdvancedSocTabProps {
  rules: DetectionRuleRecord[];
  userRole: UserRole;
  onChangeRole: (role: UserRole) => void;
  auditLogs: AuditLogRecord[];
  onUpdateRule: (rule: DetectionRuleRecord, auditDetails: string) => void;
  onClearAllRecords: () => void;
  onTriggerScenario: (scenarioId: string) => void;
  isRunningScenario: string | null;
  onLogRuleBundleVerification: (bundleId: string, valid: boolean, reason: string) => void;
}

export const AdvancedSocTab: React.FC<AdvancedSocTabProps> = ({
  rules,
  userRole,
  onChangeRole,
  auditLogs,
  onUpdateRule,
  onClearAllRecords,
  onTriggerScenario,
  isRunningScenario,
  onLogRuleBundleVerification,
}) => {
  const [subTab, setSubTab] = useState<'tests' | 'rules' | 'audit'>('tests');

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Advanced Section Header */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-sm">⚙️</span>
            <h2 className="text-base font-semibold text-slate-100">
              Advanced Security Engineering &amp; Test Sandbox
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Developer tools, synthetic test simulations, cryptographic rule signature verification, and immutable audit logs.
          </p>
        </div>

        <div className="flex items-center gap-1.5 p-1 bg-[#0B0F19] border border-slate-800 rounded-lg text-xs font-medium">
          <button
            onClick={() => setSubTab('tests')}
            className={`px-3 py-1.5 rounded-md transition-colors cursor-pointer ${
              subTab === 'tests' ? 'bg-sky-400 text-slate-950 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Engine Tests &amp; Scenarios
          </button>
          <button
            onClick={() => setSubTab('rules')}
            className={`px-3 py-1.5 rounded-md transition-colors cursor-pointer ${
              subTab === 'rules' ? 'bg-sky-400 text-slate-950 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Detection Rules ({rules.length})
          </button>
          <button
            onClick={() => setSubTab('audit')}
            className={`px-3 py-1.5 rounded-md transition-colors cursor-pointer ${
              subTab === 'audit' ? 'bg-sky-400 text-slate-950 font-semibold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Audit Trail &amp; RBAC ({auditLogs.length})
          </button>
        </div>
      </div>

      {/* SUBTAB 1: Tests & Synthetic Scenarios (Requirement 7: Explicitly labeled as TEST DATA) */}
      {subTab === 'tests' && (
        <div className="space-y-6">
          {/* Explicit TEST DATA Notice Banner */}
          <div className="p-4 bg-sky-950/25 border border-sky-500/40 rounded-xl space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-sky-400 font-semibold text-xs">[TEST DATA DISCLAIMER]</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Triggering the scenarios below feeds synthetic test payloads into the detection engine to verify rule firing, duplicate suppression, and correlation. All generated events are explicitly tagged with <code className="bg-black/40 px-1 py-0.5 rounded text-sky-300 font-mono">[TEST DATA]</code> so they are never confused with real security alerts.
            </p>
          </div>

          {/* 8 Synthetic Test Scenarios */}
          <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="border-b border-slate-800 pb-3">
              <h3 className="text-sm font-semibold text-slate-100">8 Synthetic Test Scenarios</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Click any scenario to inject test telemetry and verify the live engine response.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
              {SYNTHETIC_TEST_SCENARIOS.map((scen) => {
                const isRunning = isRunningScenario === scen.scenarioId;
                return (
                  <div
                    key={scen.scenarioId}
                    className="p-4 bg-[#0B0F19] border border-slate-800/80 rounded-xl flex flex-col justify-between space-y-3"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center justify-between text-[11px] font-mono text-sky-400">
                        <span>Scenario 0{scen.number}</span>
                        <span className="text-slate-500">{scen.expectedRuleId}</span>
                      </div>
                      <div className="text-xs font-semibold text-slate-200">{scen.title}</div>
                      <p className="text-[11px] text-slate-400 leading-relaxed line-clamp-3">
                        {scen.description}
                      </p>
                    </div>

                    <button
                      onClick={() => onTriggerScenario(scen.scenarioId)}
                      disabled={Boolean(isRunningScenario)}
                      className="w-full py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg transition-colors cursor-pointer disabled:opacity-50"
                    >
                      {isRunning ? 'Running Test...' : 'Simulate [TEST DATA]'}
                    </button>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Unit Test & Performance Benchmark Runner */}
          <ArchitectureAndTestsTab />
        </div>
      )}

      {/* SUBTAB 2: Rules Catalog & Verification */}
      {subTab === 'rules' && (
        <DetectionRulesTab
          rules={rules}
          userRole={userRole}
          onUpdateRule={onUpdateRule}
          onLogRuleBundleVerification={onLogRuleBundleVerification}
        />
      )}

      {/* SUBTAB 3: Settings & Audit Trail */}
      {subTab === 'audit' && (
        <SettingsAndAuditTab
          userRole={userRole}
          onChangeRole={onChangeRole}
          auditLogs={auditLogs}
          onClearAllRecords={onClearAllRecords}
        />
      )}
    </div>
  );
};
