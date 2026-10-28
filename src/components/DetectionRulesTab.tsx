import React, { useState } from 'react';
import {
  DetectionRuleRecord,
  SeverityLevel,
  SignedRuleBundle,
  UserRole,
} from '../../shared-schemas/types.ts';
import { DEFAULT_SIGNED_RULES } from '../../detection-engine/engine.ts';

interface DetectionRulesTabProps {
  rules: DetectionRuleRecord[];
  userRole: UserRole;
  onUpdateRule: (updated: DetectionRuleRecord, auditDetail: string) => void;
  onLogRuleBundleVerification: (
    bundleId: string,
    valid: boolean,
    reason: string
  ) => void;
}

export const DetectionRulesTab: React.FC<DetectionRulesTabProps> = ({
  rules,
  userRole,
  onUpdateRule,
  onLogRuleBundleVerification,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [bundleStatus, setBundleStatus] = useState<{
    valid: boolean;
    message: string;
  } | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  const canEditRules = userRole === UserRole.ADMINISTRATOR;

  const filteredRules = rules.filter((r) => {
    const q = searchQuery.toLowerCase().trim();
    return (
      !q ||
      r.ruleId.toLowerCase().includes(q) ||
      r.name.toLowerCase().includes(q) ||
      r.category.toLowerCase().includes(q) ||
      r.detectionSource.toLowerCase().includes(q)
    );
  });

  const handleVerifyAndApplyBundle = async (tampered: boolean) => {
    setIsVerifying(true);
    setBundleStatus(null);
    const bundle: SignedRuleBundle = tampered
      ? {
          bundleId: 'bundle_tampered_unsigned_99',
          bundleVersion: '9.9.0-forged',
          issuedAt: new Date().toISOString(),
          signerKeyId: 'untrusted_external_key',
          ed25519Signature: 'forged_sig_0000000000000000',
          payloadSha256:
            'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
          rules: [],
        }
      : {
          bundleId: `bundle_signed_${Date.now()}`,
          bundleVersion: '2.5.0-release',
          issuedAt: new Date().toISOString(),
          signerKeyId: 'sentinel_root_ed25519_key_01',
          ed25519Signature:
            'sig_ed25519_valid_8f9e0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a',
          payloadSha256:
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          rules: DEFAULT_SIGNED_RULES,
        };

    try {
      const response = await fetch('/api/rules/verify-bundle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(bundle),
      });
      const result = await response.json();
      setBundleStatus({
        valid: Boolean(result.valid),
        message: result.reason,
      });
      onLogRuleBundleVerification(
        bundle.bundleId,
        Boolean(result.valid),
        result.reason
      );
    } catch (err) {
      setBundleStatus({
        valid: false,
        message: 'Failed to contact signature verification endpoint.',
      });
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Cryptographic Signed Rule Bundle Control Bar */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Modular Detection Rules & Cryptographically Signed Rule Updates
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Every rule update package requires a verified Ed25519 digital signature and SHA-256 payload digest before installation.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              onClick={() => handleVerifyAndApplyBundle(false)}
              disabled={isVerifying}
              className="px-3.5 py-2 text-xs font-medium bg-sky-400 hover:bg-sky-300 text-slate-950 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              Verify & Apply Signed Rule Bundle (v2.5.0)
            </button>
            <button
              onClick={() => handleVerifyAndApplyBundle(true)}
              disabled={isVerifying}
              className="px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-rose-500/20 hover:text-rose-300 text-slate-200 border border-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              Test Invalid Signature Rejection (Scenario 7)
            </button>
          </div>
        </div>

        {bundleStatus && (
          <div
            className={`p-3.5 rounded-md border text-xs font-mono ${
              bundleStatus.valid
                ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
                : 'bg-rose-950/30 border-rose-500/40 text-rose-300'
            }`}
          >
            {bundleStatus.valid ? '[SIGNATURE VERIFIED]' : '[SIGNATURE REJECTED]'}{' '}
            {bundleStatus.message}
          </div>
        )}
      </div>

      {/* Search & RBAC Info */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search by rule ID (e.g. PROC-001, MEM-001, EMU-001), category, or source..."
          className="px-3 py-2 text-xs bg-[#0B0F19] border border-slate-800 rounded-md text-slate-100 placeholder-slate-500 w-full sm:w-96 focus:outline-none focus:border-sky-500"
        />
        <div className="text-xs text-slate-400 font-mono">
          {canEditRules
            ? 'Administrator privileges active: Rule state & threshold editing enabled'
            : `Current role (${userRole}): Read-only rule inspection`}
        </div>
      </div>

      {/* Rules List */}
      <div className="space-y-4">
        {filteredRules.map((rule) => (
          <div
            key={rule.ruleId}
            className="bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-4"
          >
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
              <div className="space-y-1">
                <div className="text-xs font-mono text-sky-400">
                  {rule.ruleId} · v{rule.version} · {rule.category} · Classification: {rule.classification}
                </div>
                <h3 className="text-base font-semibold text-slate-100">
                  {rule.name}
                </h3>
                <div className="text-xs font-mono text-slate-400">
                  Source: {rule.detectionSource} · Signature: {rule.signatureHash.slice(0, 32)}...
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-3 shrink-0">
                <div className="flex items-center gap-2 text-xs font-mono">
                  <span className="text-slate-400">Severity:</span>
                  <select
                    value={rule.severity}
                    disabled={!canEditRules}
                    onChange={(e) =>
                      onUpdateRule(
                        { ...rule, severity: e.target.value as SeverityLevel },
                        `Changed severity of rule ${rule.ruleId} to ${e.target.value}.`
                      )
                    }
                    className="px-2.5 py-1 bg-[#0B0F19] border border-slate-800 rounded text-slate-100 uppercase focus:outline-none"
                  >
                    <option value={SeverityLevel.CRITICAL}>CRITICAL</option>
                    <option value={SeverityLevel.HIGH}>HIGH</option>
                    <option value={SeverityLevel.MEDIUM}>MEDIUM</option>
                    <option value={SeverityLevel.LOW}>LOW</option>
                  </select>
                </div>

                <div className="flex items-center gap-2 text-xs font-mono tabular-nums">
                  <span className="text-slate-400">Risk Weight:</span>
                  <input
                    type="number"
                    min={0}
                    max={100}
                    disabled={!canEditRules}
                    value={rule.riskScoreContribution}
                    onChange={(e) => {
                      const val = Math.min(100, Math.max(0, Number(e.target.value) || 0));
                      onUpdateRule(
                        { ...rule, riskScoreContribution: val },
                        `Updated risk score contribution of ${rule.ruleId} to +${val}.`
                      );
                    }}
                    className="w-16 px-2 py-1 bg-[#0B0F19] border border-slate-800 rounded text-slate-100 text-right focus:outline-none"
                  />
                </div>

                <button
                  onClick={() =>
                    onUpdateRule(
                      { ...rule, enabled: !rule.enabled },
                      `${rule.enabled ? 'Disabled' : 'Enabled'} detection rule ${rule.ruleId}.`
                    )
                  }
                  disabled={!canEditRules}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-40 ${
                    rule.enabled
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : 'bg-slate-800 text-slate-400 border border-slate-700'
                  }`}
                >
                  {rule.enabled ? 'Enabled' : 'Disabled'}
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div>
                <div className="font-semibold text-slate-300 mb-1">
                  Detection Logic & Scope
                </div>
                <p className="text-slate-400 leading-relaxed">{rule.description}</p>
              </div>
              <div>
                <div className="font-semibold text-amber-400/90 mb-1">
                  False-Positive Considerations
                </div>
                <p className="text-slate-400 leading-relaxed">
                  {rule.falsePositiveConsiderations}
                </p>
              </div>
              <div>
                <div className="font-semibold text-sky-400 mb-1">
                  Recommended Investigation Steps
                </div>
                <p className="text-slate-400 leading-relaxed">
                  {rule.investigationSteps}
                </p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
