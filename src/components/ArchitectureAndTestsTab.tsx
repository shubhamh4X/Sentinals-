import React, { useState, useEffect } from 'react';
import { UnitTestExecutionReport } from '../../tests/detection_engine.test.ts';

export const ArchitectureAndTestsTab: React.FC = () => {
  const [report, setReport] = useState<UnitTestExecutionReport | null>(null);
  const [isRunningTests, setIsRunningTests] = useState(false);
  const [selectedCodeTab, setSelectedCodeTab] = useState<'cpp' | 'cs' | 'sql'>('cpp');

  const executeTestSuite = async () => {
    setIsRunningTests(true);
    try {
      const res = await fetch('/api/tests/run', { method: 'POST' });
      const data = await res.json();
      setReport(data);
    } catch (err) {
      console.error('Failed to run test suite:', err);
    } finally {
      setIsRunningTests(false);
    }
  };

  useEffect(() => {
    executeTestSuite();
  }, []);

  return (
    <div className="space-y-8">
      {/* Live Unit Test & Performance Benchmark Runner */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Automated Validation Suite & Engine Performance Benchmarks
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Executes unit tests across all detection rules, replay protection, duplicate suppression, Ed25519 signature verification, and 1,000-event throughput latency.
            </p>
          </div>
          <button
            onClick={executeTestSuite}
            disabled={isRunningTests}
            className="px-4 py-2 text-xs font-medium bg-sky-400 hover:bg-sky-300 text-slate-950 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
          >
            {isRunningTests ? 'Running Suite...' : 'Re-Run Test & Benchmark Suite'}
          </button>
        </div>

        {report && (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="p-4 rounded-md bg-[#0B0F19] border border-slate-800">
                <div className="text-xs text-slate-400">Unit & Security Tests</div>
                <div className="text-2xl font-semibold font-mono tabular-nums text-emerald-400 mt-1">
                  {report.passed} / {report.totalTests} Passed
                </div>
                <div className="text-xs font-mono text-slate-400 mt-1">
                  Failed: {report.failed}
                </div>
              </div>

              <div className="p-4 rounded-md bg-[#0B0F19] border border-slate-800">
                <div className="text-xs text-slate-400">Rule Engine Throughput</div>
                <div className="text-2xl font-semibold font-mono tabular-nums text-sky-400 mt-1">
                  {report.benchmarkEventsPerSec.toLocaleString()} evt/s
                </div>
                <div className="text-xs font-mono text-slate-400 mt-1">
                  1,000-Event Synthetic Burst
                </div>
              </div>

              <div className="p-4 rounded-md bg-[#0B0F19] border border-slate-800">
                <div className="text-xs text-slate-400">Avg Evaluation Latency</div>
                <div className="text-2xl font-semibold font-mono tabular-nums text-slate-100 mt-1">
                  {report.avgEvaluationLatencyMs} ms
                </div>
                <div className="text-xs font-mono text-slate-400 mt-1">
                  Per Telemetry Event
                </div>
              </div>

              <div className="p-4 rounded-md bg-[#0B0F19] border border-slate-800">
                <div className="text-xs text-slate-400">Target Agent Overhead</div>
                <div className="text-2xl font-semibold font-mono tabular-nums text-slate-100 mt-1">
                  {report.estimatedAgentCpuOverheadPercent}% CPU
                </div>
                <div className="text-xs font-mono text-slate-400 mt-1">
                  {report.estimatedAgentMemoryMb} MB Working Set
                </div>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-xs text-slate-400">
                    <th className="py-2.5 pr-4 font-medium">Test Case</th>
                    <th className="py-2.5 px-3 font-medium">Module</th>
                    <th className="py-2.5 px-3 font-medium">Result</th>
                    <th className="py-2.5 px-3 font-medium text-right">Latency</th>
                    <th className="py-2.5 pl-3 font-medium">Assertion Output</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70 text-xs">
                  {report.results.map((r) => (
                    <tr key={r.testName} className="hover:bg-slate-900/50">
                      <td className="py-3 pr-4 font-medium text-slate-100">{r.testName}</td>
                      <td className="py-3 px-3 font-mono text-slate-400">{r.category}</td>
                      <td className="py-3 px-3 font-mono">
                        <span className={r.passed ? 'text-emerald-400' : 'text-rose-400'}>
                          {r.passed ? 'PASS' : 'FAIL'}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-right font-mono tabular-nums text-slate-300">
                        {r.durationMs} ms
                      </td>
                      <td className="py-3 pl-3 text-slate-400">{r.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>

      {/* Native Windows Agent & Backend Source Code Explorer */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Monorepo Native Windows Agent & Schema Reference
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Inspect the generated C++20 Windows Service (`windows-agent/src/SentinelAgentService.cpp`), C# Startup Host (`SentinelTrayHost.cs`), and PostgreSQL DDL (`001_initial_schema.sql`).
            </p>
          </div>

          <div className="flex items-center gap-1 p-1 bg-[#0B0F19] border border-slate-800 rounded-lg">
            <button
              onClick={() => setSelectedCodeTab('cpp')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                selectedCodeTab === 'cpp'
                  ? 'bg-slate-800 text-slate-100'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              C++20 Win32 Agent
            </button>
            <button
              onClick={() => setSelectedCodeTab('cs')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                selectedCodeTab === 'cs'
                  ? 'bg-slate-800 text-slate-100'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              C# .NET 8 Service Host
            </button>
            <button
              onClick={() => setSelectedCodeTab('sql')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                selectedCodeTab === 'sql'
                  ? 'bg-slate-800 text-slate-100'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Build & Install Guide
            </button>
          </div>
        </div>

        {selectedCodeTab === 'cpp' && (
          <pre className="p-4 rounded-md bg-[#0B0F19] border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed">
{`// File: windows-agent/src/SentinelAgentService.cpp (Excerpt)
// Uses documented Win32 APIs: CreateToolhelp32Snapshot, WinVerifyTrust, BCrypt (SHA-256),
// EnumWindows (WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST), and CryptProtectData (DPAPI).

static bool ScanForSuspiciousOverlayWindows(const RECT& emulatorRect, uint32_t emulatorPid, uint32_t& outOverlayPid, std::string& outExStyleHex) {
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        if (!IsWindowVisible(hwnd)) return TRUE;
        LONG_PTR exStyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
        bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
        bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;
        bool isTopmost = (exStyle & WS_EX_TOPMOST) != 0;
        if (isLayered && isTransparent && isTopmost) {
            // Flagged for ESP-001 evaluation & Authenticode signer verification
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&ctx));
}`}
          </pre>
        )}

        {selectedCodeTab === 'cs' && (
          <pre className="p-4 rounded-md bg-[#0B0F19] border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed">
{`// File: windows-agent/src/SentinelTrayHost.cs
public sealed class StartupRegistrationManager
{
    private const string RunRegistryPath = @"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    private const string AppRegistryValueName = "SentinelACMonitor";

    public static void SetAutoStart(bool enabled, string executablePath)
    {
        using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunRegistryPath, writable: true);
        if (enabled)
            key?.SetValue(AppRegistryValueName, $"\\"{executablePath}\\" --background-monitor");
        else
            key?.DeleteValue(AppRegistryValueName, throwOnMissingValue: false);
    }
}`}
          </pre>
        )}

        {selectedCodeTab === 'sql' && (
          <pre className="p-4 rounded-md bg-[#0B0F19] border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed">
{`# Windows 10/11 x64 Native Build & Service Registration
cd windows-agent
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release

# Authenticode Sign & Register Service (Elevated PowerShell)
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /n "Sentinel Security Corp" .\\build\\Release\\SentinelAgentService.exe
sc.exe create SentinelACService binPath= "\\"C:\\Program Files\\SentinelAC\\SentinelAgentService.exe\\" --service" start= demand
sc.exe start SentinelACService`}
          </pre>
        )}
      </div>
    </div>
  );
};
