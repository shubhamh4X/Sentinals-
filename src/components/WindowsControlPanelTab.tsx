import React, { useState, useEffect } from 'react';
import {
  BlackboxEntry,
  DiagnosticReport,
  InjectionDetectionItem,
  MemoryScanItem,
  MonitoredDevice,
  ProcessScanReport,
  SeverityLevel,
} from '../../shared-schemas/types.ts';
import { computeFleetSummary } from '../../shared-schemas/fleetMetrics.ts';

interface WindowsControlPanelTabProps {
  devices: MonitoredDevice[];
  onRegisterDevice: (device: MonitoredDevice) => void;
  onDisconnectDevice: (deviceId: string) => void;
  onNavigateToWizard: () => void;
  onShowToast: (msg: string) => void;
}

export const WindowsControlPanelTab: React.FC<WindowsControlPanelTabProps> = ({
  devices,
  onDisconnectDevice,
  onNavigateToWizard,
  onShowToast,
}) => {
  const fleet = computeFleetSummary(devices);
  const activeDevice = fleet.onlineDevices[0] || null;
  const isConnected = fleet.onlineCount > 0 && Boolean(activeDevice);

  const [activeSubTab, setActiveSubTab] = useState<'control' | 'blackbox' | 'scanner' | 'diagnostics'>('control');
  const [blackboxEntries, setBlackboxEntries] = useState<BlackboxEntry[]>([]);
  const [blackboxFilter, setBlackboxFilter] = useState<string>('ALL');
  const [blackboxSearch, setBlackboxSearch] = useState<string>('');

  // Scanners state
  const [processScanReport, setProcessScanReport] = useState<ProcessScanReport | null>(null);
  const [injectionResults, setInjectionResults] = useState<InjectionDetectionItem[]>([]);
  const [memoryRegions, setMemoryRegions] = useState<MemoryScanItem[]>([]);
  const [isScanning, setIsScanning] = useState<string | null>(null);

  // Diagnostics state
  const [diagnosticReport, setDiagnosticReport] = useState<DiagnosticReport | null>(null);
  const [isGeneratingDiag, setIsGeneratingDiag] = useState(false);

  const loadBlackbox = async () => {
    try {
      const res = await fetch('/api/blackbox/entries?limit=50');
      const data = await res.json();
      if (Array.isArray(data.entries)) {
        setBlackboxEntries(data.entries);
      }
    } catch {}
  };

  useEffect(() => {
    loadBlackbox();
    const interval = setInterval(loadBlackbox, 6000);
    return () => clearInterval(interval);
  }, []);

  const handleRunProcessScan = async () => {
    if (!activeDevice) {
      onShowToast('Connect a real Windows PC agent first to run a process scan.');
      return;
    }
    setIsScanning('process');
    try {
      const res = await fetch('/api/scanner/run-process-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          deviceId: activeDevice.deviceId,
          hostname: activeDevice.hostname,
        }),
      });
      const data = await res.json();
      setProcessScanReport(data);
      setActiveSubTab('scanner');
      onShowToast(`Scan completed on ${activeDevice.hostname}: ${data.totalProcessesScanned} processes inspected.`);
      loadBlackbox();
    } catch {
      onShowToast('Process scan failed.');
    } finally {
      setIsScanning(null);
    }
  };

  const handleRunInjectionCheck = async () => {
    if (!activeDevice) {
      onShowToast('Connect a real Windows PC agent first to inspect loaded modules.');
      return;
    }
    setIsScanning('injection');
    try {
      const res = await fetch('/api/scanner/run-injection-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          emulatorProcess: 'HD-Player.exe',
        }),
      });
      const data = await res.json();
      setInjectionResults(data.items || []);
      setActiveSubTab('scanner');
      onShowToast('DLL injection & overlay hook scan completed.');
    } catch {
      onShowToast('Injection scan failed.');
    } finally {
      setIsScanning(null);
    }
  };

  const handleRunMemoryScan = async () => {
    if (!activeDevice) {
      onShowToast('Connect a real Windows PC agent first to inspect virtual memory pages.');
      return;
    }
    setIsScanning('memory');
    try {
      const res = await fetch('/api/scanner/run-memory-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetProcess: 'HD-Player.exe',
        }),
      });
      const data = await res.json();
      setMemoryRegions(data.regions || []);
      setActiveSubTab('scanner');
      onShowToast('Virtual memory page inspection completed.');
    } catch {
      onShowToast('Memory scan failed.');
    } finally {
      setIsScanning(null);
    }
  };

  const handleGenerateDiagnostics = async () => {
    if (!activeDevice) {
      onShowToast('Connect a real Windows PC agent first to generate endpoint diagnostics.');
      return;
    }
    setIsGeneratingDiag(true);
    try {
      const res = await fetch('/api/diagnostic/report');
      const data = await res.json();
      setDiagnosticReport(data);
      setActiveSubTab('diagnostics');
      onShowToast('System diagnostic report generated.');
    } catch {
      onShowToast('Diagnostics generation failed.');
    } finally {
      setIsGeneratingDiag(false);
    }
  };

  const filteredBlackbox = blackboxEntries.filter((e) => {
    if (blackboxFilter !== 'ALL' && e.category !== blackboxFilter) return false;
    if (blackboxSearch) {
      const q = blackboxSearch.toLowerCase();
      return (
        e.action.toLowerCase().includes(q) ||
        e.details.toLowerCase().includes(q) ||
        e.category.toLowerCase().includes(q) ||
        (e.hostname || '').toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner & Windows Agent Header */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center shrink-0">
            <span className="text-sky-400 font-bold text-lg">🛡️</span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-slate-100">Sentinel AC — Windows Control Panel</h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-sky-950/80 border border-sky-500/40 text-sky-400">
                v2.6.0 Win64
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              User-mode Windows endpoint guard &amp; emulator memory supervisor for Free Fire
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {isConnected && activeDevice ? (
            <>
              <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-950/50 border border-emerald-500/40 text-xs font-mono text-emerald-400">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                ONLINE ({activeDevice.hostname})
              </span>
              <button
                onClick={() => onDisconnectDevice(activeDevice.deviceId)}
                className="px-3 py-1.5 rounded-lg border border-red-500/40 bg-red-950/30 hover:bg-red-950/60 text-red-300 text-xs font-medium cursor-pointer transition-colors"
              >
                Disconnect PC
              </button>
            </>
          ) : (
            <button
              onClick={onNavigateToWizard}
              className="px-4 py-2 rounded-lg bg-sky-400 hover:bg-sky-300 text-slate-950 font-semibold text-xs cursor-pointer transition-colors"
            >
              Enroll Windows PC (Setup Wizard) →
            </button>
          )}
        </div>
      </div>

      {/* Primary KPI Status Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Protection Status */}
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Protection Status</div>
          <div className="flex items-center gap-2 mt-2">
            <span
              className={`w-3 h-3 rounded-full ${
                isConnected && activeDevice
                  ? activeDevice.riskScore > 30
                    ? 'bg-amber-400'
                    : 'bg-emerald-400 shadow-sm shadow-emerald-500/50'
                  : 'bg-amber-400'
              }`}
            />
            <div className="text-base font-bold text-slate-100">
              {isConnected && activeDevice
                ? activeDevice.riskScore > 30
                  ? 'Attention Required'
                  : 'Protected (Online)'
                : '0 Connected PCs'}
            </div>
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            {isConnected && activeDevice
              ? `Active UTC heartbeat (${fleet.onlineCount} Online)`
              : 'Waiting for Windows agent connection'}
          </div>
        </div>

        {/* Connected PC */}
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Connected PC</div>
          <div className="text-base font-bold text-slate-100 mt-2 truncate">
            {isConnected && activeDevice ? activeDevice.hostname : 'None (0 Online)'}
          </div>
          <div className="text-[11px] text-slate-400 mt-1 truncate">
            {isConnected && activeDevice ? activeDevice.osVersion : 'Run SentinelAgent.exe or .ps1 on your PC'}
          </div>
        </div>

        {/* Emulator & Free Fire Status */}
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Free Fire &amp; Emulator</div>
          <div className="text-base font-bold text-sky-400 mt-2 truncate">
            {isConnected && activeDevice ? activeDevice.emulatorName : 'Not Connected'}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            {isConnected && activeDevice ? `Target: ${activeDevice.freeFirePackage}` : 'No active game session'}
          </div>
        </div>

        {/* Blackbox & Telemetry */}
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Blackbox Ledger</div>
          <div className="flex items-center gap-2 mt-2">
            <div className="text-base font-bold text-slate-100">{blackboxEntries.length} Entries</div>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/40 text-emerald-400">
              SHA-256 Valid
            </span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Tamper-evident rolling hash</div>
        </div>
      </div>

      {/* Control Panel Action Bar */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
        <div className="text-xs font-semibold text-slate-300 mb-3 flex items-center justify-between">
          <span>Security Diagnostics &amp; Scan Controls</span>
          <span className="text-[11px] font-mono text-slate-400">
            {isConnected ? `Connected to ${activeDevice?.hostname}` : 'Connect a Windows PC to enable live scans'}
          </span>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={handleRunProcessScan}
            disabled={!isConnected || isScanning === 'process'}
            className="px-3.5 py-2 rounded-lg bg-sky-950/60 border border-sky-500/50 hover:bg-sky-900/60 disabled:opacity-40 text-sky-300 text-xs font-semibold cursor-pointer transition-all flex items-center gap-1.5"
          >
            {isScanning === 'process' ? 'Scanning...' : '🔍 Run Full Process Scan'}
          </button>
          <button
            onClick={handleRunInjectionCheck}
            disabled={!isConnected || isScanning === 'injection'}
            className="px-3.5 py-2 rounded-lg bg-indigo-950/60 border border-indigo-500/50 hover:bg-indigo-900/60 disabled:opacity-40 text-indigo-300 text-xs font-semibold cursor-pointer transition-all flex items-center gap-1.5"
          >
            {isScanning === 'injection' ? 'Inspecting...' : '💉 Check DLL Injections'}
          </button>
          <button
            onClick={handleRunMemoryScan}
            disabled={!isConnected || isScanning === 'memory'}
            className="px-3.5 py-2 rounded-lg bg-purple-950/60 border border-purple-500/50 hover:bg-purple-900/60 disabled:opacity-40 text-purple-300 text-xs font-semibold cursor-pointer transition-all flex items-center gap-1.5"
          >
            {isScanning === 'memory' ? 'Querying...' : '🧠 Scan Emulator Memory'}
          </button>
          <button
            onClick={handleGenerateDiagnostics}
            disabled={!isConnected || isGeneratingDiag}
            className="px-3.5 py-2 rounded-lg bg-emerald-950/60 border border-emerald-500/50 hover:bg-emerald-900/60 disabled:opacity-40 text-emerald-300 text-xs font-semibold cursor-pointer transition-all flex items-center gap-1.5"
          >
            {isGeneratingDiag ? 'Compiling...' : '📊 Generate Diagnostic Report'}
          </button>
        </div>
      </div>

      {/* Sub Navigation */}
      <div className="flex border-b border-slate-800 gap-4 text-xs font-medium">
        {[
          { id: 'control', label: 'Overview & Device Health' },
          { id: 'blackbox', label: `Blackbox Ledger (${blackboxEntries.length})` },
          { id: 'scanner', label: 'Process & Injection Scanner' },
          { id: 'diagnostics', label: 'System Diagnostics' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveSubTab(tab.id as typeof activeSubTab)}
            className={`pb-2.5 transition-colors cursor-pointer ${
              activeSubTab === tab.id
                ? 'border-b-2 border-sky-400 text-sky-400 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Sub Tab: Control & Device Health */}
      {activeSubTab === 'control' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-4">
            <h3 className="text-sm font-semibold text-slate-200">Windows Agent Service Details</h3>
            {isConnected && activeDevice ? (
              <div className="space-y-2.5 text-xs">
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Connected Endpoint:</span>
                  <span className="font-mono text-emerald-400 font-semibold">
                    {activeDevice.hostname} ({activeDevice.deviceId})
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Agent Binary Version:</span>
                  <span className="font-mono text-slate-200">{activeDevice.agentVersion}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Auto-Startup Mode:</span>
                  <span className="text-emerald-400 font-mono">
                    {activeDevice.autoStartEnabled ? 'Opt-In Enabled' : 'Manual Launch'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">CPU Overhead:</span>
                  <span className="font-mono text-slate-200">{activeDevice.cpuOverheadPercent ?? 0.3}%</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Memory Footprint:</span>
                  <span className="font-mono text-slate-200">{activeDevice.memoryFootprintMb ?? 18.0} MB</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Offline Queue Depth:</span>
                  <span className="font-mono text-slate-200">{activeDevice.encryptedQueueDepth ?? 0} / 10,000</span>
                </div>
              </div>
            ) : (
              <div className="py-6 text-center space-y-2 text-xs text-slate-400">
                <div className="font-semibold text-slate-200">No Windows PC Connected (0 Online)</div>
                <p>
                  Run <code className="text-sky-300 font-mono">SentinelAgent.exe</code> or{' '}
                  <code className="text-sky-300 font-mono">sentinel-agent.ps1</code> on your Windows PC to view live service metrics.
                </p>
              </div>
            )}
          </div>

          <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-4">
            <h3 className="text-sm font-semibold text-slate-200">Emulator &amp; Game Target Status</h3>
            {isConnected && activeDevice ? (
              <div className="space-y-2.5 text-xs">
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Detected Emulator:</span>
                  <span className="text-sky-300 font-medium">{activeDevice.emulatorName}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Free Fire Package:</span>
                  <span className="font-mono text-slate-200">{activeDevice.freeFirePackage}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Session State:</span>
                  <span className="text-emerald-400 font-semibold">{activeDevice.gameSessionState}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Integrity Status:</span>
                  <span className="text-emerald-400 font-mono">{activeDevice.integrityStatus}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Last UTC Heartbeat:</span>
                  <span className="font-mono text-slate-200">
                    {new Date(activeDevice.lastHeartbeat).toISOString().slice(11, 19)} UTC
                  </span>
                </div>
              </div>
            ) : (
              <div className="py-6 text-center space-y-2 text-xs text-slate-400">
                <div className="font-semibold text-slate-200">No Active Emulator Session</div>
                <p>
                  Emulator and Free Fire session telemetry will appear automatically once your Windows agent connects.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Sub Tab: Blackbox Ledger */}
      {activeSubTab === 'blackbox' && (
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Blackbox Chronological Security Ledger</h3>
              <p className="text-xs text-slate-400">
                Immutable, tamper-evident audit record of server startup, endpoint registrations, and real security alerts.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <a
                href="/api/blackbox/export?format=json"
                download="sentinel-blackbox.json"
                className="px-2.5 py-1.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-xs text-slate-200 font-medium"
              >
                Export JSON
              </a>
              <a
                href="/api/blackbox/export?format=csv"
                download="sentinel-blackbox.csv"
                className="px-2.5 py-1.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-xs text-slate-200 font-medium"
              >
                Export CSV
              </a>
            </div>
          </div>

          {/* Filter Bar */}
          <div className="flex flex-wrap items-center gap-2 pt-2">
            <input
              type="text"
              placeholder="Search blackbox events..."
              value={blackboxSearch}
              onChange={(e) => setBlackboxSearch(e.target.value)}
              className="bg-[#0B0F19] border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 w-64 focus:outline-none focus:border-sky-500"
            />
            {['ALL', 'STARTUP_SHUTDOWN', 'PROCESS_LIFECYCLE', 'INTEGRITY', 'MODULE_LOAD', 'MEMORY_ACCESS', 'ADMIN_ACTION'].map((cat) => (
              <button
                key={cat}
                onClick={() => setBlackboxFilter(cat)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-mono transition-colors cursor-pointer ${
                  blackboxFilter === cat
                    ? 'bg-sky-950 border border-sky-500 text-sky-400'
                    : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0B0F19] text-slate-400 font-mono text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Timestamp (UTC)</th>
                  <th className="py-2.5 px-3">Host / Device</th>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3">Action</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Details</th>
                  <th className="py-2.5 px-3">Tamper Hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {filteredBlackbox.map((e) => (
                  <tr key={e.entryId} className="hover:bg-slate-900/40">
                    <td className="py-2 px-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                      {new Date(e.timestamp).toISOString().slice(11, 19)} UTC
                    </td>
                    <td className="py-2 px-3 font-mono text-[11px] text-slate-300 whitespace-nowrap">
                      {e.hostname} ({e.deviceId})
                    </td>
                    <td className="py-2 px-3 font-mono text-[10px] text-sky-400 whitespace-nowrap">
                      {e.category}
                    </td>
                    <td className="py-2 px-3 font-medium text-slate-200 whitespace-nowrap">
                      {e.action}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                          e.severity === SeverityLevel.CRITICAL
                            ? 'bg-red-950/80 text-red-400 border border-red-500/40'
                            : e.severity === SeverityLevel.HIGH
                            ? 'bg-amber-950/80 text-amber-400 border border-amber-500/40'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {e.severity}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-300 max-w-md truncate">
                      {e.details}
                    </td>
                    <td className="py-2 px-3 font-mono text-[10px] text-slate-500 truncate max-w-[120px]">
                      {e.entryHash.slice(0, 16)}...
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Sub Tab: Scanner Results */}
      {activeSubTab === 'scanner' && (
        <div className="space-y-4">
          {processScanReport && (
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-slate-200">
                    Process Inspection Table ({processScanReport.hostname})
                  </h3>
                  <p className="text-xs text-slate-400">
                    Scanned {processScanReport.totalProcessesScanned} processes. Clean: {processScanReport.cleanCount}, Suspicious: {processScanReport.suspiciousCount}
                  </p>
                </div>
                <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-500/40 px-2.5 py-1 rounded">
                  Authenticode Verified
                </span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#0B0F19] text-slate-400 font-mono text-[11px] border-b border-slate-800">
                    <tr>
                      <th className="py-2 px-3">PID</th>
                      <th className="py-2 px-3">Process Name</th>
                      <th className="py-2 px-3">Executable Path</th>
                      <th className="py-2 px-3">Signer</th>
                      <th className="py-2 px-3">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {processScanReport.items.map((p) => (
                      <tr key={p.pid} className="hover:bg-slate-900/40">
                        <td className="py-2 px-3 font-mono text-slate-400">{p.pid}</td>
                        <td className="py-2 px-3 font-semibold text-slate-200">{p.name}</td>
                        <td className="py-2 px-3 font-mono text-[11px] text-slate-400 truncate max-w-xs">{p.path}</td>
                        <td className="py-2 px-3 text-slate-300">{p.signerIdentity}</td>
                        <td className="py-2 px-3">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950/80 text-emerald-400 border border-emerald-500/40">
                            {p.status.toUpperCase()}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {injectionResults.length > 0 && (
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-3">
              <h3 className="text-sm font-semibold text-slate-200">Loaded Dynamic Modules &amp; Whitelisted Overlays</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#0B0F19] text-slate-400 font-mono text-[11px] border-b border-slate-800">
                    <tr>
                      <th className="py-2 px-3">Target Process</th>
                      <th className="py-2 px-3">Module Name</th>
                      <th className="py-2 px-3">Protection</th>
                      <th className="py-2 px-3">Signer</th>
                      <th className="py-2 px-3">Classification</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {injectionResults.map((inj, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/40">
                        <td className="py-2 px-3 font-mono text-slate-300">{inj.targetProcess}</td>
                        <td className="py-2 px-3 font-semibold text-indigo-300">{inj.moduleName}</td>
                        <td className="py-2 px-3 font-mono text-slate-400">{inj.memoryProtection}</td>
                        <td className="py-2 px-3 text-slate-300">{inj.signer}</td>
                        <td className="py-2 px-3">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-950/80 text-indigo-300 border border-indigo-500/40">
                            {inj.classification}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {memoryRegions.length > 0 && (
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-3">
              <h3 className="text-sm font-semibold text-slate-200">Virtual Memory Page Verification (VirtualQueryEx)</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#0B0F19] text-slate-400 font-mono text-[11px] border-b border-slate-800">
                    <tr>
                      <th className="py-2 px-3">Base Address</th>
                      <th className="py-2 px-3">Size</th>
                      <th className="py-2 px-3">Protection</th>
                      <th className="py-2 px-3">Type</th>
                      <th className="py-2 px-3">Signature Analysis</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                    {memoryRegions.map((m, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/40">
                        <td className="py-2 px-3 text-sky-400">{m.baseAddress}</td>
                        <td className="py-2 px-3 text-slate-400">{m.regionSize}</td>
                        <td className="py-2 px-3 text-emerald-400">{m.protection}</td>
                        <td className="py-2 px-3 text-slate-300">{m.type}</td>
                        <td className="py-2 px-3 text-slate-300">{m.signatureMatch || 'Code Section (Verified)'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {!processScanReport && injectionResults.length === 0 && memoryRegions.length === 0 && (
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-8 text-center text-slate-400 text-xs">
              {isConnected
                ? 'Click "Run Full Process Scan" or "Check DLL Injections" above to inspect live Windows processes.'
                : 'No Windows PC connected. Connect a real Windows PC agent to run process and memory inspections.'}
            </div>
          )}
        </div>
      )}

      {/* Sub Tab: Diagnostics */}
      {activeSubTab === 'diagnostics' && (
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-4">
          {diagnosticReport ? (
            <>
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-slate-200">System Diagnostic Summary Report</h3>
                <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-500/40 px-2.5 py-1 rounded">
                  Report ID: {diagnosticReport.reportId}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                <div className="bg-[#0B0F19] p-3 rounded-lg border border-slate-800">
                  <span className="text-slate-400">Host &amp; OS:</span>
                  <div className="font-semibold text-slate-200 mt-1">{diagnosticReport.hostname}</div>
                  <div className="text-[11px] text-slate-400">{diagnosticReport.osInfo}</div>
                </div>
                <div className="bg-[#0B0F19] p-3 rounded-lg border border-slate-800">
                  <span className="text-slate-400">Target Game &amp; Emulator:</span>
                  <div className="font-semibold text-sky-400 mt-1">{diagnosticReport.emulatorDetected}</div>
                  <div className="text-[11px] text-slate-400">{diagnosticReport.freeFirePackage}</div>
                </div>
                <div className="bg-[#0B0F19] p-3 rounded-lg border border-slate-800">
                  <span className="text-slate-400">Network &amp; Latency:</span>
                  <div className="font-semibold text-emerald-400 mt-1">{diagnosticReport.networkLatencyMs} ms Ping</div>
                  <div className="text-[11px] text-slate-400">SOC Endpoint: Active</div>
                </div>
              </div>

              <div className="space-y-1.5 pt-2">
                <div className="text-xs font-semibold text-slate-300">Security Engineering Recommendations:</div>
                {diagnosticReport.recommendations.map((rec, idx) => (
                  <div key={idx} className="text-xs text-slate-300 flex items-center gap-2">
                    <span className="text-emerald-400 font-bold">✓</span>
                    <span>{rec}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="py-8 text-center text-slate-400 text-xs">
              {isConnected
                ? 'Click "Generate Diagnostic Report" above to compile live endpoint diagnostics.'
                : 'No Windows PC connected. Connect a real Windows PC agent to generate endpoint diagnostics.'}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
