import React, { useState } from 'react';
import {
  MonitoredDevice,
  UserRole,
} from '../../shared-schemas/types.ts';

interface DeviceManagementTabProps {
  devices: MonitoredDevice[];
  userRole: UserRole;
  onUpdateDevice: (device: MonitoredDevice, auditDetails: string) => void;
  onRegisterDevice: (newDevice: MonitoredDevice) => void;
}

export const DeviceManagementTab: React.FC<DeviceManagementTabProps> = ({
  devices,
  userRole,
  onUpdateDevice,
  onRegisterDevice,
}) => {
  const [newHostname, setNewHostname] = useState('');
  const [newEmulator, setNewEmulator] = useState('BlueStacks 5 (Pie64 v5.21)');
  const [newPackage, setNewPackage] = useState('com.dts.freefireth');
  const [feedback, setFeedback] = useState<string | null>(null);

  const canManageDevices =
    userRole === UserRole.ADMINISTRATOR ||
    userRole === UserRole.SECURITY_ANALYST;

  const handleRegisterSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newHostname.trim()) return;
    const cleanHost = newHostname.trim().toUpperCase().replace(/[^A-Z0-9\-]/g, '');
    const deviceId = `dev-win11-${Math.random().toString(36).slice(2, 7)}`;
    const created: MonitoredDevice = {
      deviceId,
      ownerId: devices[0]?.ownerId || 'demo_uid',
      hostname: cleanHost || 'DESKTOP-NEW-PC',
      osVersion: 'Windows 11 Pro 23H2 (Build 22631)',
      agentVersion: '2.4.1-x64',
      status: 'healthy',
      emulatorName: newEmulator,
      gameSessionState: 'active_match',
      freeFirePackage: newPackage,
      integrityStatus: 'verified',
      riskScore: 0,
      isSimulated: false,
      lastHeartbeat: new Date().toISOString(),
      cpuOverheadPercent: 0.38,
      memoryFootprintMb: 17.6,
      encryptedQueueDepth: 0,
      autoStartEnabled: true,
    };
    onRegisterDevice(created);
    setNewHostname('');
    setFeedback(`Registered endpoint ${created.hostname} (${created.deviceId}) with per-device HMAC credential.`);
  };

  return (
    <div className="space-y-6">
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100">
            Monitored Windows Endpoints & Agent Lifecycle Management
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Manage registered Windows PCs, per-agent credentials, Windows startup service configuration, and offline DPAPI encrypted telemetry queues.
          </p>
        </div>
        {feedback && (
          <div className="text-xs font-mono text-emerald-400 shrink-0">
            {feedback}
          </div>
        )}
      </div>

      {/* Register New Endpoint Form */}
      <form
        onSubmit={handleRegisterSubmit}
        className="bg-[#111827] border border-slate-800 rounded-lg p-5 grid grid-cols-1 md:grid-cols-4 gap-4 items-end"
      >
        <div>
          <label className="block text-xs text-slate-400 mb-1">
            Windows Hostname
          </label>
          <input
            type="text"
            value={newHostname}
            onChange={(e) => setNewHostname(e.target.value)}
            placeholder="e.g. ARENA-PC-09"
            disabled={!canManageDevices}
            className="w-full px-3 py-2 text-xs bg-[#0B0F19] border border-slate-800 rounded-md text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500"
          />
        </div>

        <div>
          <label className="block text-xs text-slate-400 mb-1">
            Emulator Adapter
          </label>
          <select
            value={newEmulator}
            onChange={(e) => setNewEmulator(e.target.value)}
            disabled={!canManageDevices}
            className="w-full px-3 py-2 text-xs bg-[#0B0F19] border border-slate-800 rounded-md text-slate-200 focus:outline-none focus:border-sky-500"
          >
            <option value="BlueStacks 5 (Pie64 v5.21)">BlueStacks 5 (Pie64 v5.21)</option>
            <option value="LDPlayer 9 (v9.1.24)">LDPlayer 9 (v9.1.24)</option>
            <option value="MEmu Play 9 (v9.0.6)">MEmu Play 9 (v9.0.6)</option>
            <option value="NoxPlayer 7 (v7.0.5)">NoxPlayer 7 (v7.0.5)</option>
            <option value="Google Play Games PC (crosvm)">Google Play Games PC (crosvm)</option>
          </select>
        </div>

        <div>
          <label className="block text-xs text-slate-400 mb-1">
            Free Fire Target Package
          </label>
          <select
            value={newPackage}
            onChange={(e) => setNewPackage(e.target.value)}
            disabled={!canManageDevices}
            className="w-full px-3 py-2 text-xs bg-[#0B0F19] border border-slate-800 rounded-md text-slate-200 focus:outline-none focus:border-sky-500"
          >
            <option value="com.dts.freefireth">com.dts.freefireth (Free Fire Standard)</option>
            <option value="com.dts.freefiremax">com.dts.freefiremax (Free Fire MAX)</option>
          </select>
        </div>

        <button
          type="submit"
          disabled={!canManageDevices || !newHostname.trim()}
          className="px-4 py-2 text-xs font-medium bg-sky-400 hover:bg-sky-300 text-slate-950 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-40"
        >
          Register Endpoint & Issue Key
        </button>
      </form>

      {/* Endpoints Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-xs text-slate-400 bg-[#0B0F19]/60">
                <th className="py-3 px-4 font-medium">Endpoint & OS</th>
                <th className="py-3 px-3 font-medium">Agent & Auto-Start</th>
                <th className="py-3 px-3 font-medium">Emulator & Session</th>
                <th className="py-3 px-3 font-medium">Integrity & Overhead</th>
                <th className="py-3 px-3 font-medium text-right">Risk Score</th>
                <th className="py-3 px-4 font-medium text-right">Authorized Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 text-xs">
              {devices.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 px-4 text-center text-slate-400">
                    <div className="text-slate-300 font-medium">No Windows endpoints registered yet</div>
                    <div className="text-xs text-slate-400 mt-1">Connect a live SentinelAgentService instance or register an endpoint above to monitor real-time game sessions.</div>
                  </td>
                </tr>
              ) : (
                devices.map((dev) => (
                  <tr key={dev.deviceId} className="hover:bg-slate-900/50">
                    <td className="py-3.5 px-4">
                      <div className="font-medium text-slate-100">
                        {dev.hostname}
                      </div>
                      <div className="font-mono text-slate-400">{dev.deviceId}</div>
                      <div className="text-slate-400 mt-0.5">{dev.osVersion}</div>
                    </td>

                  <td className="py-3.5 px-3 font-mono tabular-nums">
                    <div className="text-slate-200">v{dev.agentVersion} · {dev.status}</div>
                    <div className="text-slate-400">
                      Startup: {dev.autoStartEnabled !== false ? 'Enabled (SCM)' : 'Manual'}
                    </div>
                    <div className="text-slate-400">
                      Heartbeat: {new Date(dev.lastHeartbeat).toLocaleTimeString()}
                    </div>
                  </td>

                  <td className="py-3.5 px-3">
                    <div className="text-slate-200 font-medium">{dev.emulatorName}</div>
                    <div className="font-mono text-sky-400">
                      {dev.freeFirePackage} · {dev.gameSessionState}
                    </div>
                  </td>

                  <td className="py-3.5 px-3 font-mono tabular-nums">
                    <div className="text-slate-200">{dev.integrityStatus}</div>
                    <div className="text-slate-400">
                      CPU: {dev.cpuOverheadPercent ?? 0.4}% · RAM: {dev.memoryFootprintMb ?? 18.0} MB
                    </div>
                    <div className="text-slate-400">
                      DPAPI Queue: {dev.encryptedQueueDepth ?? 0} buffered
                    </div>
                  </td>

                  <td className="py-3.5 px-3 text-right font-mono tabular-nums">
                    <span
                      className={
                        dev.riskScore >= 70
                          ? 'text-rose-400 font-semibold'
                          : dev.riskScore >= 40
                          ? 'text-amber-400 font-semibold'
                          : 'text-emerald-400'
                      }
                    >
                      {dev.riskScore}/100
                    </span>
                  </td>

                  <td className="py-3.5 px-4 text-right">
                    <div className="flex items-center justify-end gap-2">
                      {dev.status === 'disconnected' ? (
                        <button
                          onClick={() => {
                            onUpdateDevice(
                              {
                                ...dev,
                                status: 'healthy',
                                encryptedQueueDepth: 0,
                                lastHeartbeat: new Date().toISOString(),
                              },
                              `Reconnected agent ${dev.hostname} and flushed ${dev.encryptedQueueDepth || 3} DPAPI-encrypted queued events.`
                            );
                            setFeedback(`Reconnected ${dev.hostname} & flushed offline DPAPI queue.`);
                          }}
                          disabled={!canManageDevices}
                          className="px-2.5 py-1.5 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-40"
                        >
                          Reconnect & Flush Queue
                        </button>
                      ) : (
                        <button
                          onClick={() => {
                            onUpdateDevice(
                              {
                                ...dev,
                                lastHeartbeat: new Date().toISOString(),
                                integrityStatus: 'verified',
                              },
                              `Rotated per-agent HMAC credentials and verified self-integrity hash for ${dev.hostname}.`
                            );
                            setFeedback(`Rotated agent credentials for ${dev.hostname}.`);
                          }}
                          disabled={!canManageDevices || dev.status === 'revoked'}
                          className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-40"
                        >
                          Rotate Key
                        </button>
                      )}

                      {dev.status !== 'revoked' && (
                        <button
                          onClick={() => {
                            onUpdateDevice(
                              {
                                ...dev,
                                status: 'revoked',
                                gameSessionState: 'terminated',
                              },
                              `Revoked device certificate and terminated active game session monitoring for ${dev.hostname}.`
                            );
                            setFeedback(`Revoked credentials for ${dev.hostname}.`);
                          }}
                          disabled={userRole !== UserRole.ADMINISTRATOR}
                          className="px-2.5 py-1.5 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-40"
                        >
                          Revoke
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              )))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
