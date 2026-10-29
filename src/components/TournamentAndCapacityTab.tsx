import React, { useEffect, useState } from 'react';
import {
  LoadTestMetricsResult,
  LoadTestProfile,
  MonitoredDevice,
  MonitoringHealthState,
  TournamentParticipant,
  TournamentRecord,
} from '../../shared-schemas/types.ts';
import { WindowsTelemetrySourceEntry } from '../../backend/tournamentAndLoadEngine.ts';

interface TournamentAndCapacityTabProps {
  devices: MonitoredDevice[];
  onShowToast: (msg: string) => void;
}

const HEALTH_STATE_BADGES: Record<
  MonitoringHealthState,
  { label: string; colorClass: string }
> = {
  protected_healthy: {
    label: 'Protected Healthy',
    colorClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
  },
  suspicious_activity_detected: {
    label: 'Suspicious Activity',
    colorClass: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  },
  monitoring_degraded: {
    label: 'Monitoring Degraded',
    colorClass: 'bg-orange-500/15 text-orange-300 border-orange-500/40',
  },
  required_telemetry_unavailable: {
    label: 'Telemetry Unavailable (Blind Spot)',
    colorClass: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
  },
  agent_integrity_failure: {
    label: 'Agent Integrity Failure',
    colorClass: 'bg-red-600/20 text-red-300 border-red-500/50',
  },
  agent_disconnected: {
    label: 'Agent Disconnected',
    colorClass: 'bg-slate-700/40 text-slate-300 border-slate-600',
  },
  enrollment_pending: {
    label: 'Enrollment Pending',
    colorClass: 'bg-sky-500/15 text-sky-300 border-sky-500/40',
  },
  device_revoked: {
    label: 'Device Revoked',
    colorClass: 'bg-rose-950/60 text-rose-400 border-rose-700/50',
  },
  investigation_required: {
    label: 'Investigation Required',
    colorClass: 'bg-rose-500/20 text-rose-200 border-rose-500/50',
  },
};

export const TournamentAndCapacityTab: React.FC<TournamentAndCapacityTabProps> = ({
  devices,
  onShowToast,
}) => {
  const [subView, setSubView] = useState<'tournaments' | 'loadtest' | 'matrix'>('tournaments');
  const [tournaments, setTournaments] = useState<TournamentRecord[]>([]);
  const [participants, setParticipants] = useState<TournamentParticipant[]>([]);
  const [selectedTournamentId, setSelectedTournamentId] = useState<string>('');
  const [matrix, setMatrix] = useState<WindowsTelemetrySourceEntry[]>([]);

  // Tournament creation form
  const [newTournamentName, setNewTournamentName] = useState('');
  const [newOrganizer, setNewOrganizer] = useState('Sentinel Esports Operations');
  const [maxDevicesPerPlayer, setMaxDevicesPerPlayer] = useState<number>(1);
  const [requireElevated, setRequireElevated] = useState<boolean>(true);

  // Participant registration form
  const [gamerTag, setGamerTag] = useState('');
  const [teamName, setTeamName] = useState('');
  const [bindDeviceId, setBindDeviceId] = useState('');

  // Match creation form
  const [matchName, setMatchName] = useState('');
  const [mapName, setMapName] = useState('Bermuda Remastered');

  // Device replacement modal state
  const [replacingParticipantId, setReplacingParticipantId] = useState<string | null>(null);
  const [replacementNewDeviceId, setReplacementNewDeviceId] = useState('');
  const [replacementReason, setReplacementReason] = useState('Primary PC crash / hardware swap');

  // Load testing state
  const [selectedProfile, setSelectedProfile] = useState<LoadTestProfile>('small_event');
  const [customAgentCount, setCustomAgentCount] = useState<number>(64);
  const [customEventsPerAgent, setCustomEventsPerAgent] = useState<number>(15);
  const [isRunningLoadTest, setIsRunningLoadTest] = useState<boolean>(false);
  const [loadTestResults, setLoadTestResults] = useState<LoadTestMetricsResult[]>([]);

  const fetchTournamentsAndMatrix = async () => {
    try {
      const [trnRes, matRes] = await Promise.all([
        fetch('/api/tournaments'),
        fetch('/api/telemetry/coverage-matrix'),
      ]);
      if (trnRes.ok) {
        const data = await trnRes.json();
        const trns: TournamentRecord[] = data.tournaments || [];
        setTournaments(trns);
        setParticipants(data.participants || []);
        if (!selectedTournamentId && trns.length > 0) {
          setSelectedTournamentId(trns[0].tournamentId);
        }
      }
      if (matRes.ok) {
        const matData = await matRes.json();
        setMatrix(matData.matrix || []);
      }
    } catch {}
  };

  useEffect(() => {
    void fetchTournamentsAndMatrix();
  }, [devices.length]);

  const handleCreateTournament = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTournamentName.trim()) return;
    try {
      const res = await fetch('/api/tournaments', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newTournamentName.trim(),
          organizer: newOrganizer.trim(),
          policy: {
            maxAuthorizedDevicesPerParticipant: maxDevicesPerPlayer,
            requireElevatedAgent: requireElevated,
            heartbeatTimeoutSeconds: 90,
            allowMidTournamentDeviceReplacement: true,
          },
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setNewTournamentName('');
        await fetchTournamentsAndMatrix();
        if (data.tournament?.tournamentId) {
          setSelectedTournamentId(data.tournament.tournamentId);
        }
        onShowToast(`Created tournament: ${data.tournament?.name}`);
      }
    } catch {
      onShowToast('Failed to create tournament.');
    }
  };

  const handleRegisterParticipant = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTournamentId || !gamerTag.trim()) return;
    try {
      const res = await fetch(`/api/tournaments/${selectedTournamentId}/participants`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          gamerTag: gamerTag.trim(),
          teamName: teamName.trim() || 'Solo Competitor',
          deviceId: bindDeviceId || undefined,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setGamerTag('');
        setTeamName('');
        setBindDeviceId('');
        await fetchTournamentsAndMatrix();
        onShowToast(
          `Registered player ${data.participant.gamerTag} (Token: ${data.enrollmentToken})`
        );
      } else {
        onShowToast(data.error || 'Failed to register participant');
      }
    } catch {
      onShowToast('Error registering participant.');
    }
  };

  const handleCreateMatch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTournamentId || !matchName.trim()) return;
    try {
      const res = await fetch(`/api/tournaments/${selectedTournamentId}/matches`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          matchName: matchName.trim(),
          mapName,
        }),
      });
      if (res.ok) {
        setMatchName('');
        await fetchTournamentsAndMatrix();
        onShowToast(`Match created in tournament.`);
      }
    } catch {}
  };

  const handleReplaceDevice = async (participant: TournamentParticipant) => {
    if (!replacementNewDeviceId.trim()) return;
    const prevDev = participant.authorizedDeviceIds[0] || 'unassigned-device';
    try {
      const res = await fetch(`/api/participants/${participant.participantId}/replace-device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          previousDeviceId: prevDev,
          newDeviceId: replacementNewDeviceId.trim(),
          reason: replacementReason,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setReplacingParticipantId(null);
        setReplacementNewDeviceId('');
        await fetchTournamentsAndMatrix();
        onShowToast(
          `Replaced device for ${participant.gamerTag} (${prevDev} -> ${replacementNewDeviceId}). Historical logs preserved.`
        );
      } else {
        onShowToast(data.error || 'Device replacement failed.');
      }
    } catch {
      onShowToast('Failed to replace device.');
    }
  };

  const handleRemoveParticipant = async (participantId: string, tag: string) => {
    try {
      const res = await fetch(`/api/participants/${participantId}`, { method: 'DELETE' });
      if (res.ok) {
        await fetchTournamentsAndMatrix();
        onShowToast(`Removed participant ${tag} from active roster.`);
      }
    } catch {}
  };

  const handleRunLoadTest = async (profileOverride?: LoadTestProfile) => {
    const profileToRun = profileOverride || selectedProfile;
    setIsRunningLoadTest(true);
    try {
      const payload =
        profileToRun === 'custom'
          ? {
              profile: 'custom',
              agentCount: customAgentCount,
              eventsPerAgent: customEventsPerAgent,
            }
          : { profile: profileToRun };

      const res = await fetch('/api/load-test/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const result: LoadTestMetricsResult = await res.json();
        setLoadTestResults((prev) => [result, ...prev]);
        onShowToast(
          `Load Test [${result.profile}] Complete: ${result.config.agentCount} PCs, ${result.telemetryEventsPerSec} events/sec, p95=${result.latencyP95Ms}ms (100% isolated)`
        );
      }
    } catch {
      onShowToast('Failed to run load test benchmark.');
    } finally {
      setIsRunningLoadTest(false);
    }
  };

  const activeTournament = tournaments.find((t) => t.tournamentId === selectedTournamentId);
  const activeParticipants = participants.filter(
    (p) => p.tournamentId === selectedTournamentId
  );

  return (
    <div className="space-y-6">
      {/* Header & Sub-Navigation */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="px-2.5 py-0.5 rounded text-[11px] font-mono uppercase tracking-wider bg-sky-500/15 text-sky-300 border border-sky-500/30">
              Dynamic Tournament Scale
            </span>
            <span className="text-xs text-slate-400 font-mono">
              Zero Hardcoded Player or Device Limits
            </span>
          </div>
          <h1 className="text-xl font-bold text-slate-100 mt-1.5">
            Tournament Operations, Telemetry Coverage & Capacity Benchmarks
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Manage multi-round tournaments, dynamic participant rosters, hardware replacements, 9-state monitoring health, and real isolated load benchmarks.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setSubView('tournaments')}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
              subView === 'tournaments'
                ? 'bg-sky-400 text-slate-950'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            1. Tournament & Player Roster ({tournaments.length})
          </button>
          <button
            onClick={() => setSubView('loadtest')}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
              subView === 'loadtest'
                ? 'bg-sky-400 text-slate-950'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            2. Dynamic Load & Stress Benchmarks
          </button>
          <button
            onClick={() => setSubView('matrix')}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
              subView === 'matrix'
                ? 'bg-sky-400 text-slate-950'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            3. Detection & Blind-Spot Matrix ({matrix.length})
          </button>
        </div>
      </div>

      {/* SUBVIEW 1: DYNAMIC TOURNAMENT & PARTICIPANT MANAGEMENT */}
      {subView === 'tournaments' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Create Tournament & Select Active Tournament */}
          <div className="lg:col-span-4 space-y-6">
            <form
              onSubmit={handleCreateTournament}
              className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4"
            >
              <h2 className="text-sm font-bold text-slate-100">Create New Tournament</h2>
              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">
                  Tournament Name
                </label>
                <input
                  type="text"
                  value={newTournamentName}
                  onChange={(e) => setNewTournamentName(e.target.value)}
                  placeholder="e.g., Free Fire Pro Series 2026 Qualifier"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100 focus:outline-none focus:border-sky-500"
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">
                  Organizer / League
                </label>
                <input
                  type="text"
                  value={newOrganizer}
                  onChange={(e) => setNewOrganizer(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100 focus:outline-none focus:border-sky-500"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-medium text-slate-400 mb-1">
                    Max PCs / Player Policy
                  </label>
                  <select
                    value={maxDevicesPerPlayer}
                    onChange={(e) => setMaxDevicesPerPlayer(Number(e.target.value))}
                    className="w-full px-2.5 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100"
                  >
                    <option value={1}>Strict (1 PC / Player)</option>
                    <option value={2}>Primary + Backup (2 PCs)</option>
                    <option value={0}>Unlimited Authorized PCs</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[11px] font-medium text-slate-400 mb-1">
                    Admin Elevation Policy
                  </label>
                  <select
                    value={requireElevated ? 'yes' : 'no'}
                    onChange={(e) => setRequireElevated(e.target.value === 'yes')}
                    className="w-full px-2.5 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100"
                  >
                    <option value="yes">Require Admin (Full Scan)</option>
                    <option value="no">Allow Standard User</option>
                  </select>
                </div>
              </div>
              <button
                type="submit"
                className="w-full py-2 bg-sky-400 hover:bg-sky-300 text-slate-950 font-semibold text-xs rounded-lg transition-colors cursor-pointer"
              >
                + Create Dynamic Tournament
              </button>
            </form>

            {/* Tournament List */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-bold text-slate-100">Active Tournaments</h2>
                <span className="text-[11px] font-mono text-slate-400">
                  {tournaments.length} total
                </span>
              </div>
              {tournaments.length === 0 ? (
                <p className="text-xs text-slate-400 py-4 text-center">
                  No tournaments created yet. Create your first tournament above to register players and bind PCs.
                </p>
              ) : (
                <div className="space-y-2">
                  {tournaments.map((t) => (
                    <div
                      key={t.tournamentId}
                      onClick={() => setSelectedTournamentId(t.tournamentId)}
                      className={`p-3 rounded-lg border transition-colors cursor-pointer ${
                        selectedTournamentId === t.tournamentId
                          ? 'bg-sky-950/40 border-sky-500/60'
                          : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-slate-100">{t.name}</span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                          {t.status.toUpperCase()}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between font-mono">
                        <span>ID: {t.tournamentId}</span>
                        <span>{t.participantCount || 0} Players</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Right Column: Selected Tournament Roster, Matches & Device Replacement */}
          <div className="lg:col-span-8 space-y-6">
            {!activeTournament ? (
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-8 text-center">
                <h3 className="text-sm font-bold text-slate-200">
                  Select or Create a Tournament
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Create a tournament on the left to enroll players, issue per-participant tokens, and monitor match eligibility.
                </p>
              </div>
            ) : (
              <>
                {/* Tournament Summary & Match Creation */}
                <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-slate-800 pb-4">
                    <div>
                      <h2 className="text-base font-bold text-slate-100">
                        {activeTournament.name}
                      </h2>
                      <p className="text-xs text-slate-400 font-mono">
                        {activeTournament.organizer} • Policy:{' '}
                        {activeTournament.policy.maxAuthorizedDevicesPerParticipant === 0
                          ? 'Unlimited PCs/Player'
                          : `Max ${activeTournament.policy.maxAuthorizedDevicesPerParticipant} PC(s)/Player`}{' '}
                        • Heartbeat Timeout: {activeTournament.policy.heartbeatTimeoutSeconds}s
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="px-2.5 py-1 rounded bg-slate-800 text-xs font-mono text-slate-200">
                        {activeParticipants.length} Registered Participants
                      </span>
                      <span className="px-2.5 py-1 rounded bg-slate-800 text-xs font-mono text-sky-300">
                        {activeTournament.matches.length} Matches
                      </span>
                    </div>
                  </div>

                  {/* Register Participant & Create Match Forms */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <form
                      onSubmit={handleRegisterParticipant}
                      className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800/90 space-y-2.5"
                    >
                      <div className="text-xs font-semibold text-slate-200">
                        Register Participant (Dynamic Roster)
                      </div>
                      <div className="grid grid-cols-2 gap-2">
                        <input
                          type="text"
                          value={gamerTag}
                          onChange={(e) => setGamerTag(e.target.value)}
                          placeholder="GamerTag (e.g. FF_SHADOW)"
                          className="px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100"
                        />
                        <input
                          type="text"
                          value={teamName}
                          onChange={(e) => setTeamName(e.target.value)}
                          placeholder="Team Name (Optional)"
                          className="px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100"
                        />
                      </div>
                      <div className="flex items-center gap-2">
                        <select
                          value={bindDeviceId}
                          onChange={(e) => setBindDeviceId(e.target.value)}
                          className="flex-1 px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-200"
                        >
                          <option value="">Bind Enrolled PC Later (Pending Enrollment)</option>
                          {devices.map((d) => (
                            <option key={d.deviceId} value={d.deviceId}>
                              {d.hostname} ({d.deviceId})
                            </option>
                          ))}
                        </select>
                        <button
                          type="submit"
                          className="px-3 py-1.5 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs rounded transition-colors cursor-pointer shrink-0"
                        >
                          + Add Player
                        </button>
                      </div>
                    </form>

                    <form
                      onSubmit={handleCreateMatch}
                      className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800/90 space-y-2.5"
                    >
                      <div className="text-xs font-semibold text-slate-200">
                        Add Match / Round Lobby
                      </div>
                      <div className="grid grid-cols-2 gap-2">
                        <input
                          type="text"
                          value={matchName}
                          onChange={(e) => setMatchName(e.target.value)}
                          placeholder="Match Name (e.g. Finals Game 1)"
                          className="px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100"
                        />
                        <select
                          value={mapName}
                          onChange={(e) => setMapName(e.target.value)}
                          className="px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-200"
                        >
                          <option value="Bermuda Remastered">Bermuda Remastered</option>
                          <option value="Purgatory">Purgatory</option>
                          <option value="Kalahari">Kalahari</option>
                          <option value="Alpine">Alpine</option>
                          <option value="NexTerra">NexTerra</option>
                        </select>
                      </div>
                      <div className="flex items-center justify-between pt-0.5">
                        <span className="text-[11px] text-slate-400 font-mono">
                          Active Matches: {activeTournament.matches.map((m) => m.matchName).join(', ') || 'None'}
                        </span>
                        <button
                          type="submit"
                          className="px-3 py-1.5 bg-sky-400 hover:bg-sky-300 text-slate-950 font-semibold text-xs rounded transition-colors cursor-pointer shrink-0"
                        >
                          + Create Match
                        </button>
                      </div>
                    </form>
                  </div>
                </div>

                {/* Participant Roster & 9-State Monitoring Health Table */}
                <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-slate-100">
                      Participant Eligibility & 9-State Monitoring Health
                    </h3>
                    <span className="text-[11px] text-slate-400">
                      Uninspectable or sequence-gapped PCs are automatically flagged as degraded
                    </span>
                  </div>

                  {activeParticipants.length === 0 ? (
                    <div className="p-6 text-center border border-dashed border-slate-800 rounded-lg text-xs text-slate-400">
                      No participants registered in this tournament yet. Use the form above to register players dynamically.
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left border-collapse text-xs">
                        <thead>
                          <tr className="border-b border-slate-800 text-[11px] text-slate-400 uppercase">
                            <th className="py-2.5 px-3">Player / Team</th>
                            <th className="py-2.5 px-3">Authorized PC(s)</th>
                            <th className="py-2.5 px-3">Monitoring Health (9-State)</th>
                            <th className="py-2.5 px-3">Match Eligibility</th>
                            <th className="py-2.5 px-3">Enrollment Token</th>
                            <th className="py-2.5 px-3 text-right">Actions</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60">
                          {activeParticipants.map((p) => {
                            const badge =
                              HEALTH_STATE_BADGES[p.monitoringHealthState] ||
                              HEALTH_STATE_BADGES.enrollment_pending;
                            return (
                              <tr key={p.participantId} className="hover:bg-slate-800/30">
                                <td className="py-2.5 px-3">
                                  <div className="font-bold text-slate-100">{p.gamerTag}</div>
                                  <div className="text-[11px] text-slate-400 font-mono">
                                    {p.teamName} • {p.participantId}
                                  </div>
                                </td>
                                <td className="py-2.5 px-3 font-mono text-[11px]">
                                  {p.authorizedDeviceIds.length > 0 ? (
                                    <div className="space-y-0.5">
                                      {p.authorizedDeviceIds.map((id) => (
                                        <div key={id} className="text-sky-300">
                                          {id}
                                        </div>
                                      ))}
                                      {p.replacementHistory.length > 0 && (
                                        <div className="text-[10px] text-amber-400">
                                          Replaced ({p.replacementHistory.length}x history kept)
                                        </div>
                                      )}
                                    </div>
                                  ) : (
                                    <span className="text-slate-500">No PC bound yet</span>
                                  )}
                                </td>
                                <td className="py-2.5 px-3">
                                  <span
                                    className={`inline-flex items-center px-2 py-0.5 rounded border text-[11px] font-medium ${badge.colorClass}`}
                                  >
                                    {badge.label}
                                  </span>
                                </td>
                                <td className="py-2.5 px-3 font-mono text-[11px]">
                                  {p.eligibilityStatus === 'eligible' ? (
                                    <span className="text-emerald-400 font-semibold">
                                      ELIGIBLE
                                    </span>
                                  ) : p.eligibilityStatus === 'under_investigation' ? (
                                    <span className="text-rose-400 font-semibold">
                                      HOLD: INVESTIGATION
                                    </span>
                                  ) : p.eligibilityStatus === 'degraded_telemetry' ? (
                                    <span className="text-amber-400 font-semibold">
                                      HOLD: TELEMETRY GAP
                                    </span>
                                  ) : (
                                    <span className="text-slate-400">
                                      PENDING AGENT
                                    </span>
                                  )}
                                </td>
                                <td className="py-2.5 px-3 font-mono text-[11px] text-slate-300">
                                  {p.enrollmentTokenSecret || 'enr_sentinel_default_multi_pc'}
                                </td>
                                <td className="py-2.5 px-3 text-right space-x-2">
                                  <button
                                    onClick={() =>
                                      setReplacingParticipantId(
                                        replacingParticipantId === p.participantId
                                          ? null
                                          : p.participantId
                                      )
                                    }
                                    className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-sky-300 text-[11px] cursor-pointer"
                                  >
                                    Swap / Bind PC
                                  </button>
                                  <button
                                    onClick={() =>
                                      handleRemoveParticipant(p.participantId, p.gamerTag)
                                    }
                                    className="px-2 py-1 rounded bg-rose-950/50 hover:bg-rose-900/60 text-rose-300 text-[11px] cursor-pointer"
                                  >
                                    Remove
                                  </button>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {/* Inline Device Replacement / Swap Panel */}
                  {replacingParticipantId && (
                    <div className="p-4 rounded-lg bg-slate-950 border border-sky-500/40 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-sky-300">
                          Hardware Replacement / Re-Enrollment (Preserves Prior Device Security History)
                        </span>
                        <button
                          onClick={() => setReplacingParticipantId(null)}
                          className="text-xs text-slate-400 hover:text-white cursor-pointer"
                        >
                          Cancel
                        </button>
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <input
                          type="text"
                          value={replacementNewDeviceId}
                          onChange={(e) => setReplacementNewDeviceId(e.target.value)}
                          placeholder="New Device ID (e.g. win-backup-rig-02)"
                          className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100"
                        />
                        <input
                          type="text"
                          value={replacementReason}
                          onChange={(e) => setReplacementReason(e.target.value)}
                          placeholder="Reason for replacement"
                          className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-100"
                        />
                        <button
                          onClick={() => {
                            const target = activeParticipants.find(
                              (x) => x.participantId === replacingParticipantId
                            );
                            if (target) void handleReplaceDevice(target);
                          }}
                          className="px-3 py-1.5 bg-sky-400 hover:bg-sky-300 text-slate-950 font-semibold text-xs rounded cursor-pointer"
                        >
                          Confirm Device Replacement
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* SUBVIEW 2: DYNAMIC LOAD & CAPACITY BENCHMARKS */}
      {subView === 'loadtest' && (
        <div className="space-y-6">
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
              <div>
                <h2 className="text-base font-bold text-slate-100">
                  Dynamic Load-Testing & Capacity Validation Engine
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Executes genuine Ed25519/SHA-256 detection evaluation, replay deduplication, sequence-gap tracking, and incident correlation under configurable tournament workloads. 100% isolated from production connected PCs.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {(
                  [
                    { id: 'small_event', label: 'Small Event (16 PCs)' },
                    { id: 'medium_event', label: 'Medium Event (64 PCs)' },
                    { id: 'large_event', label: 'Large Event (200 PCs)' },
                    { id: 'enrollment_burst', label: 'Enrollment Burst (300 PCs)' },
                    { id: 'event_burst', label: 'Event Burst (4,000 Events)' },
                    { id: 'backpressure_recovery', label: 'Backpressure & Queue Flush' },
                  ] as Array<{ id: LoadTestProfile; label: string }>
                ).map((preset) => (
                  <button
                    key={preset.id}
                    disabled={isRunningLoadTest}
                    onClick={() => {
                      setSelectedProfile(preset.id);
                      void handleRunLoadTest(preset.id);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-sky-500/20 hover:border-sky-500/50 border border-slate-700 text-xs font-medium text-slate-200 transition-colors cursor-pointer disabled:opacity-50"
                  >
                    Run {preset.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Custom Workload Runner */}
            <div className="pt-3 border-t border-slate-800 flex flex-wrap items-end gap-4">
              <div>
                <label className="block text-[11px] text-slate-400 mb-1">
                  Custom Concurrent Agent Count (1–2,000)
                </label>
                <input
                  type="number"
                  min={1}
                  max={2000}
                  value={customAgentCount}
                  onChange={(e) => setCustomAgentCount(Number(e.target.value))}
                  className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-100 w-44 font-mono"
                />
              </div>
              <div>
                <label className="block text-[11px] text-slate-400 mb-1">
                  Events Per Agent (1–200)
                </label>
                <input
                  type="number"
                  min={1}
                  max={200}
                  value={customEventsPerAgent}
                  onChange={(e) => setCustomEventsPerAgent(Number(e.target.value))}
                  className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-100 w-36 font-mono"
                />
              </div>
              <button
                disabled={isRunningLoadTest}
                onClick={() => {
                  setSelectedProfile('custom');
                  void handleRunLoadTest('custom');
                }}
                className="px-4 py-1.5 bg-sky-400 hover:bg-sky-300 text-slate-950 font-semibold text-xs rounded-lg transition-colors cursor-pointer"
              >
                {isRunningLoadTest ? 'Executing Benchmark...' : 'Execute Custom Load Benchmark'}
              </button>
            </div>
          </div>

          {/* Measured Results */}
          {loadTestResults.length === 0 ? (
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-8 text-center">
              <p className="text-xs text-slate-400">
                Click any workload profile above to run a live benchmark against the backend engine and inspect measured latency, throughput, memory delta, and sizing recommendations.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {loadTestResults.map((res) => (
                <div
                  key={res.testRunId}
                  className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
                    <div className="flex items-center gap-2.5">
                      <span className="px-2.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 text-xs font-mono font-bold">
                        {res.profile.toUpperCase()}
                      </span>
                      <span className="text-xs font-mono text-slate-300">
                        Run ID: {res.testRunId} • Duration: {res.durationMs} ms
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-sky-300">
                      Isolated from Production: {res.isolatedFromProduction ? 'YES (0 Prod PCs Affected)' : 'NO'}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="text-[10px] text-slate-400 uppercase">Simulated PCs</div>
                      <div className="text-base font-bold font-mono text-slate-100 mt-0.5">
                        {res.enrollmentsProcessed}
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="text-[10px] text-slate-400 uppercase">Events Ingested</div>
                      <div className="text-base font-bold font-mono text-sky-300 mt-0.5">
                        {res.totalTelemetrySubmitted}
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="text-[10px] text-slate-400 uppercase">Throughput</div>
                      <div className="text-base font-bold font-mono text-emerald-400 mt-0.5">
                        {res.telemetryEventsPerSec}/s
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="text-[10px] text-slate-400 uppercase">p50 / p95 / p99</div>
                      <div className="text-xs font-bold font-mono text-slate-100 mt-1">
                        {res.latencyP50Ms} / {res.latencyP95Ms} / {res.latencyP99Ms} ms
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="text-[10px] text-slate-400 uppercase">Deduplicated</div>
                      <div className="text-base font-bold font-mono text-amber-300 mt-0.5">
                        {res.duplicatesSuppressed}
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="text-[10px] text-slate-400 uppercase">Seq Gaps Caught</div>
                      <div className="text-base font-bold font-mono text-rose-300 mt-0.5">
                        {res.sequenceGapsDetected}
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="text-[10px] text-slate-400 uppercase">Heap Memory</div>
                      <div className="text-xs font-bold font-mono text-slate-200 mt-1">
                        {res.heapUsedMbAfter} MB ({res.heapDeltaMb >= 0 ? `+${res.heapDeltaMb}` : res.heapDeltaMb} MB)
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="text-[10px] text-slate-400 uppercase">CPU Time</div>
                      <div className="text-xs font-bold font-mono text-slate-200 mt-1">
                        U:{res.cpuUserMs}ms S:{res.cpuSystemMs}ms
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                    <div className="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800 space-y-1.5">
                      <div className="font-semibold text-slate-200">
                        Observed Bottleneck Analysis
                      </div>
                      <ul className="list-disc list-inside text-slate-400 space-y-1 text-[11px]">
                        {res.bottleneckAnalysis.map((b, i) => (
                          <li key={i}>{b}</li>
                        ))}
                      </ul>
                    </div>
                    <div className="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800 space-y-1.5">
                      <div className="font-semibold text-sky-300">
                        Infrastructure Sizing Recommendation: {res.sizingRecommendations.tier}
                      </div>
                      <div className="text-[11px] text-slate-300 font-mono">
                        Compute: {res.sizingRecommendations.recommendedCpuCores} vCPU /{' '}
                        {res.sizingRecommendations.recommendedRamGb} GB RAM
                      </div>
                      <div className="text-[11px] text-slate-400">
                        DB: {res.sizingRecommendations.databaseGuidance}
                      </div>
                      <div className="text-[11px] text-slate-400">
                        Realtime: {res.sizingRecommendations.websocketGuidance}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* SUBVIEW 3: TELEMETRY COVERAGE, FAILURE MODES & BLIND-SPOT MATRIX */}
      {subView === 'matrix' && (
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 space-y-4">
          <div>
            <h2 className="text-base font-bold text-slate-100">
              Windows Telemetry Coverage, Required Permissions, Failure Modes & Known Blind Spots
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Sentinel AC operates as a transparent, user-authorized Windows user-mode/elevated telemetry platform. It never claims 100% unbypassability and explicitly exposes when required telemetry is degraded or unavailable.
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] text-slate-400 uppercase">
                  <th className="py-2.5 px-3">Source & Win32 APIs</th>
                  <th className="py-2.5 px-3">Permissions & Support</th>
                  <th className="py-2.5 px-3">What It Detects</th>
                  <th className="py-2.5 px-3">False-Positive / Benign Causes</th>
                  <th className="py-2.5 px-3">Failure Mode & Resulting State</th>
                  <th className="py-2.5 px-3">Known Architectural Blind Spots</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {matrix.map((row) => (
                  <tr key={row.sourceId} className="hover:bg-slate-800/30 align-top">
                    <td className="py-3 px-3">
                      <div className="font-bold text-slate-100">{row.telemetrySource}</div>
                      <div className="text-[11px] font-mono text-sky-300 mt-0.5">
                        {row.windowsApisUsed}
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono ${
                          row.supportedInCurrentBuild
                            ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                            : 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                        }`}
                      >
                        {row.supportedInCurrentBuild ? 'SUPPORTED' : 'BOUNDARY / NOT CLAIMED'}
                      </span>
                      <div className="text-[11px] text-slate-300 mt-1 font-mono">
                        {row.requiredPermissions}
                      </div>
                    </td>
                    <td className="py-3 px-3 text-[11px] text-slate-200 space-y-1">
                      {row.cheatCategoriesDetected.map((c, idx) => (
                        <div key={idx}>• {c}</div>
                      ))}
                    </td>
                    <td className="py-3 px-3 text-[11px] text-slate-400">
                      {row.benignExplanations}
                    </td>
                    <td className="py-3 px-3 text-[11px]">
                      <div className="text-slate-300">{row.failureModeWhenBlocked}</div>
                      <div className="mt-1 font-mono text-[10px] text-amber-300">
                        State: {row.resultingHealthStateOnFailure}
                      </div>
                    </td>
                    <td className="py-3 px-3 text-[11px] text-rose-300/90">
                      {row.knownBlindSpots}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
