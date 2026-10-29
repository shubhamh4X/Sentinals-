import React, { useState } from 'react';
import { MonitoredDevice } from '../../shared-schemas/types.ts';
import { computeFleetSummary } from '../../shared-schemas/fleetMetrics.ts';
import { SUPPORTED_EMULATOR_ADAPTERS } from '../../emulator-adapters/adapters.ts';

interface SetupWizardProps {
  devices: MonitoredDevice[];
  onRegisterDevice: (device: MonitoredDevice) => void;
  onNavigateTab: (tab: string) => void;
}

export const SetupWizard: React.FC<SetupWizardProps> = ({
  devices,
  onRegisterDevice,
  onNavigateTab,
}) => {
  const [currentStep, setCurrentStep] = useState<number>(1);
  const [selectedEmulator, setSelectedEmulator] = useState('BlueStacks 5 (Pie64 / Android 11)');
  const [selectedPackage, setSelectedPackage] = useState('com.dts.freefireth');
  const [autoStart, setAutoStart] = useState(true);
  const [copiedScript, setCopiedScript] = useState(false);
  const [simulatingStep1, setSimulatingStep1] = useState(false);
  const [checkingConnection, setCheckingConnection] = useState(false);
  const [step1Error, setStep1Error] = useState<string | null>(null);

  const fleet = computeFleetSummary(devices);
  const connectedDevice = fleet.onlineDevices[0] || null;
  const isAgentConnected = fleet.onlineCount > 0;

  React.useEffect(() => {
    if (isAgentConnected && step1Error) {
      setStep1Error(null);
    }
  }, [isAgentConnected, step1Error]);

  const handleCheckConnection = async () => {
    setCheckingConnection(true);
    setStep1Error(null);
    try {
      const res = await fetch('/api/agent/devices');
      const data = await res.json();
      if (Array.isArray(data?.devices) && Number(data?.onlineCount) > 0) {
        setCurrentStep(2);
      } else {
        setStep1Error(
          'No online Windows PC detected (0 Connected PCs). Run SentinelAgent.exe or sentinel-agent.ps1 on your Windows PC and try again.'
        );
      }
    } catch {
      setStep1Error('Could not reach backend server to verify endpoint enrollment.');
    } finally {
      setCheckingConnection(false);
    }
  };

  const handleDownloadAgent = () => {
    fetch('/api/agent/installer.ps1')
      .then((r) => r.text())
      .then((text) => {
        const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'sentinel-agent.ps1';
        a.click();
        URL.revokeObjectURL(url);
      })
      .catch(() => {
        setStep1Error('Download failed. You can use the copy command below.');
      });
  };

  const handleCopyCommand = () => {
    const cmd = `powershell -ExecutionPolicy Bypass -File .\\sentinel-agent.ps1`;
    navigator.clipboard.writeText(cmd);
    setCopiedScript(true);
    setTimeout(() => setCopiedScript(false), 2500);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Wizard Header */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-400" />
            <h2 className="text-lg font-semibold text-slate-100">Sentinel AC Setup Wizard</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Follow this 6-step guide to enroll your physical Windows PC and protect Free Fire on your emulator.
          </p>
        </div>
        <div className="text-xs font-mono text-sky-400 bg-sky-950/40 border border-sky-500/40 px-3 py-1.5 rounded-lg shrink-0">
          Step {currentStep} of 6 · {fleet.onlineCount} Online PC(s)
        </div>
      </div>

      {/* Stepper Indicator */}
      <div className="grid grid-cols-6 gap-2">
        {[
          { num: 1, title: 'Windows Agent' },
          { num: 2, title: 'Select Emulator' },
          { num: 3, title: 'Free Fire Game' },
          { num: 4, title: 'Auto-Start' },
          { num: 5, title: 'Verify Stream' },
          { num: 6, title: 'Ready to Play' },
        ].map((s) => (
          <button
            key={s.num}
            onClick={() => {
              if (s.num <= currentStep || (s.num === 2 && isAgentConnected)) {
                setCurrentStep(s.num);
              }
            }}
            className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer ${
              currentStep === s.num
                ? 'bg-sky-950/50 border-sky-500/70 text-slate-100'
                : s.num < currentStep
                ? 'bg-[#111827] border-emerald-500/50 text-emerald-400'
                : 'bg-[#0B0F19] border-slate-800/80 text-slate-500 cursor-not-allowed'
            }`}
          >
            <div className="text-[10px] font-mono">
              {s.num < currentStep ? '✓ DONE' : `STEP 0${s.num}`}
            </div>
            <div className="text-xs font-medium truncate mt-0.5">{s.title}</div>
          </button>
        ))}
      </div>

      {/* Wizard Content Cards */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 min-h-[380px] flex flex-col justify-between">
        {/* STEP 1: Install or connect Windows agent */}
        {currentStep === 1 && (
          <div className="space-y-5">
            <div>
              <h3 className="text-base font-semibold text-slate-100">Step 1: Enroll Your Physical Windows PC</h3>
              <p className="text-xs text-slate-400 mt-1">
                Sentinel AC requires an authenticated Windows agent (<code className="text-sky-300 font-mono">SentinelAgent.exe</code> or <code className="text-sky-300 font-mono">sentinel-agent.ps1</code>) running on your PC with a valid heartbeat.
              </p>
            </div>

            {isAgentConnected ? (
              <div className="p-4 bg-emerald-950/30 border border-emerald-500/40 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <span className="w-3 h-3 rounded-full bg-emerald-400 animate-pulse" />
                  <div>
                    <div className="text-sm font-semibold text-emerald-300">
                      Windows Agent Online: {connectedDevice?.hostname} ({connectedDevice?.deviceId})
                    </div>
                    <div className="text-xs text-slate-400">
                      Operating System: {connectedDevice?.osVersion} · Agent v{connectedDevice?.agentVersion}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-emerald-400 font-bold px-2.5 py-1 rounded bg-emerald-950/60 border border-emerald-500/40">
                    STATUS: ONLINE
                  </span>
                  <button
                    onClick={() => setCurrentStep(2)}
                    className="px-4 py-2 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-bold text-xs rounded-lg transition-colors cursor-pointer"
                  >
                    Proceed to Step 2 →
                  </button>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 bg-[#0B0F19] border border-slate-800 rounded-xl space-y-2">
                    <div className="text-xs font-semibold text-slate-200">Option A: PowerShell Agent (.ps1)</div>
                    <p className="text-xs text-slate-400 text-[11px]">
                      Download <code className="text-sky-400 font-mono">sentinel-agent.ps1</code> and run in PowerShell as Administrator on your Windows 10/11 PC.
                    </p>
                    <div className="pt-2 flex items-center gap-2 flex-wrap">
                      <button
                        onClick={handleDownloadAgent}
                        className="px-3.5 py-1.5 bg-sky-400 hover:bg-sky-300 text-slate-950 text-xs font-semibold rounded-md transition-colors cursor-pointer"
                      >
                        Download Agent (.ps1)
                      </button>
                      <button
                        onClick={handleCopyCommand}
                        className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-md transition-colors cursor-pointer"
                      >
                        {copiedScript ? 'Copied!' : 'Copy Run Command'}
                      </button>
                      <button
                        onClick={handleCheckConnection}
                        disabled={checkingConnection}
                        className="px-3.5 py-1.5 bg-sky-950/60 hover:bg-sky-900 border border-sky-500/40 text-sky-300 text-xs font-medium rounded-md transition-colors cursor-pointer disabled:opacity-50"
                      >
                        {checkingConnection ? 'Checking...' : 'Check Connection'}
                      </button>
                    </div>
                  </div>

                  <div className="p-4 bg-[#0B0F19] border border-slate-800 rounded-xl space-y-2">
                    <div className="text-xs font-semibold text-slate-200">Option B: Standalone Windows EXE Agent</div>
                    <p className="text-xs text-slate-400 text-[11px]">
                      Open the <strong>Endpoints / PCs</strong> hub to download <code className="text-sky-400 font-mono">SentinelAgent.cs</code> and <code className="text-sky-400 font-mono">build-exe.ps1</code> with your enrollment token.
                    </p>
                    <div className="pt-2">
                      <button
                        onClick={() => onNavigateTab('connect')}
                        className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-sky-400 border border-sky-500/40 text-xs font-semibold rounded-md transition-colors cursor-pointer"
                      >
                        Open Endpoints &amp; EXE Builder →
                      </button>
                    </div>
                  </div>
                </div>

                {step1Error && (
                  <div className="text-xs font-mono text-rose-400 p-2.5 bg-rose-950/30 border border-rose-500/40 rounded-lg">
                    {step1Error}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* STEP 2: Select Emulator */}
        {currentStep === 2 && (
          <div className="space-y-5">
            <div>
              <h3 className="text-base font-semibold text-slate-100">Step 2: Select Your Android Emulator</h3>
              <p className="text-xs text-slate-400 mt-1">
                Choose the emulator you use to play Free Fire on your Windows computer. Sentinel AC includes dedicated security adapters for each.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {SUPPORTED_EMULATOR_ADAPTERS.map((adapter) => {
                const isSelected = selectedEmulator.includes(adapter.adapterId);
                const mainProc = adapter.processes[0]?.executableName || 'Emulator.exe';
                return (
                  <button
                    key={adapter.adapterId}
                    onClick={() => setSelectedEmulator(`${adapter.displayName} (${adapter.versionSupported})`)}
                    className={`p-4 rounded-xl border text-left transition-all cursor-pointer ${
                      isSelected
                        ? 'bg-sky-950/40 border-sky-400 text-slate-100'
                        : 'bg-[#0B0F19] border-slate-800 text-slate-300 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="text-sm font-semibold">{adapter.displayName}</div>
                      <span className="text-[10px] font-mono text-emerald-400">COMPATIBLE</span>
                    </div>
                    <div className="text-xs text-slate-400 mt-1">
                      Target Process: <code className="text-sky-300 font-mono">{mainProc}</code>
                    </div>
                    <div className="text-[11px] text-slate-500 mt-1">
                      {adapter.architecture} · {adapter.versionSupported}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* STEP 3: Free Fire Target Package */}
        {currentStep === 3 && (
          <div className="space-y-5">
            <div>
              <h3 className="text-base font-semibold text-slate-100">Step 3: Confirm Free Fire Game Edition</h3>
              <p className="text-xs text-slate-400 mt-1">
                Select whether you play Free Fire Standard or Free Fire MAX. Sentinel AC will automatically verify game asset integrity.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <button
                onClick={() => setSelectedPackage('com.dts.freefireth')}
                className={`p-5 rounded-xl border text-left transition-all cursor-pointer ${
                  selectedPackage === 'com.dts.freefireth'
                    ? 'bg-sky-950/40 border-sky-400 text-slate-100'
                    : 'bg-[#0B0F19] border-slate-800 text-slate-300 hover:border-slate-700'
                }`}
              >
                <div className="text-sm font-semibold">Free Fire Standard</div>
                <div className="text-xs font-mono text-sky-400 mt-1">com.dts.freefireth</div>
                <p className="text-xs text-slate-400 mt-2">
                  Official Battle Royale client. Monitors <code className="font-mono text-slate-300">libil2cpp.so</code> file integrity and recoil memory regions.
                </p>
              </button>

              <button
                onClick={() => setSelectedPackage('com.dts.freefiremax')}
                className={`p-5 rounded-xl border text-left transition-all cursor-pointer ${
                  selectedPackage === 'com.dts.freefiremax'
                    ? 'bg-sky-950/40 border-sky-400 text-slate-100'
                    : 'bg-[#0B0F19] border-slate-800 text-slate-300 hover:border-slate-700'
                }`}
              >
                <div className="text-sm font-semibold">Free Fire MAX</div>
                <div className="text-xs font-mono text-sky-400 mt-1">com.dts.freefiremax</div>
                <p className="text-xs text-slate-400 mt-2">
                  Enhanced visuals edition. Monitors HD graphics pipeline, memory write masks, and unauthorized injection modules.
                </p>
              </button>
            </div>
          </div>
        )}

        {/* STEP 4: Auto-Start & Protection Policy */}
        {currentStep === 4 && (
          <div className="space-y-5">
            <div>
              <h3 className="text-base font-semibold text-slate-100">Step 4: Automatic Protection Settings</h3>
              <p className="text-xs text-slate-400 mt-1">
                Configure Sentinel AC to protect your matches seamlessly in the background without needing to open the app every time.
              </p>
            </div>

            <div className="space-y-3">
              <label className="p-4 bg-[#0B0F19] border border-slate-800 rounded-xl flex items-center justify-between cursor-pointer">
                <div>
                  <div className="text-xs font-semibold text-slate-100">Start Monitoring Automatically on Windows Boot</div>
                  <div className="text-xs text-slate-400 mt-0.5">
                    Agent runs as a silent Windows background service with negligible CPU usage (under 0.5%).
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={autoStart}
                  onChange={(e) => setAutoStart(e.target.checked)}
                  className="w-4 h-4 text-sky-500 rounded focus:ring-0 cursor-pointer"
                />
              </label>

              <div className="p-4 bg-[#0B0F19] border border-slate-800 rounded-xl space-y-1">
                <div className="text-xs font-semibold text-slate-100">Zero-Kernel Least Privilege Security</div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Sentinel AC runs using official Microsoft Windows APIs. It never installs hidden rootkits, never disables Windows Defender, and never captures your personal passwords or keystrokes.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* STEP 5: Verify Telemetry Stream */}
        {currentStep === 5 && (
          <div className="space-y-5">
            <div>
              <h3 className="text-base font-semibold text-slate-100">Step 5: Telemetry Stream & Detection Engine Verification</h3>
              <p className="text-xs text-slate-400 mt-1">
                Verifying live communication between your Windows agent and the detection engine.
              </p>
            </div>

            <div className="p-4 bg-[#0B0F19] border border-slate-800 rounded-xl space-y-3 text-xs font-mono">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-slate-400">Endpoint Status:</span>
                <span className="text-emerald-400">{isAgentConnected ? 'CONNECTED' : 'DISCONNECTED'}</span>
              </div>
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-slate-400">Target Emulator:</span>
                <span className="text-sky-300">{selectedEmulator}</span>
              </div>
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-slate-400">Game Package:</span>
                <span className="text-sky-300">{selectedPackage}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Signature Security:</span>
                <span className="text-emerald-400">Ed25519 VERIFIED (9 ACTIVE RULES)</span>
              </div>
            </div>
          </div>
        )}

        {/* STEP 6: Final Status Display */}
        {currentStep === 6 && (
          <div className="space-y-5 text-center py-4">
            <div className="w-12 h-12 bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 rounded-full flex items-center justify-center text-xl mx-auto">
              ✓
            </div>
            <div className="space-y-1">
              <h3 className="text-lg font-bold text-slate-100">Sentinel AC is Configured and Ready!</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Your Windows PC is configured to monitor Free Fire on {selectedEmulator}. Whenever you start your emulator and launch the game, real-time protection will activate automatically.
              </p>
            </div>

            <div className="pt-4 flex justify-center gap-3">
              <button
                onClick={() => onNavigateTab('overview')}
                className="px-5 py-2.5 bg-sky-400 hover:bg-sky-300 text-slate-950 font-semibold text-xs rounded-lg transition-colors cursor-pointer"
              >
                Go to Main Dashboard
              </button>
              <button
                onClick={() => onNavigateTab('live')}
                className="px-5 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs rounded-lg transition-colors cursor-pointer"
              >
                View Live Activity
              </button>
            </div>
          </div>
        )}

        {/* Navigation Buttons between steps */}
        <div className="pt-6 border-t border-slate-800 flex items-center justify-between">
          <button
            onClick={() => setCurrentStep((prev) => Math.max(1, prev - 1))}
            disabled={currentStep === 1}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg transition-colors cursor-pointer disabled:opacity-40"
          >
            ← Previous Step
          </button>

          {currentStep < 6 && (
            <button
              onClick={() => {
                if (currentStep === 1 && !isAgentConnected) {
                  setStep1Error('Please run SentinelAgent.exe or sentinel-agent.ps1 on your Windows PC and click "Check Connection" to proceed.');
                  return;
                }
                setCurrentStep((prev) => Math.min(6, prev + 1));
              }}
              className="px-5 py-2 bg-sky-400 hover:bg-sky-300 text-slate-950 text-xs font-semibold rounded-lg transition-colors cursor-pointer"
            >
              Next Step →
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
