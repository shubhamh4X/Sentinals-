import { MonitoredDevice, MonitoringHealthState } from './types.ts';

export const DEFAULT_HEARTBEAT_TIMEOUT_MS = 90_000;

/**
 * Exhaustive list of confirmed demo, seeded, simulated, and test fixture device IDs and hostnames
 * that must never appear in the production dashboard device registry.
 */
export const CONFIRMED_DEMO_DEVICE_IDS = new Set<string>([
  'win-suvo-pc1',
  'win-gaming-rig-pc2',
  'win-esports-pc3',
  'win-esports-pc4',
  'win-suvo-8rg5',
  'win-suvo-live',
  'win-suvo-local',
  'win-bad-pc',
  'win-esports-pc-01',
  'win-esports-pc-02',
  'win-esports-pc-03',
  'dev-win11-alpha',
  'dev-win10-ldp',
  'dev-win11-memu',
  'dev-win11-gpg',
]);

export const CONFIRMED_DEMO_HOSTNAMES = new Set<string>([
  'SUVO-PC1',
  'ARENA-RIG-PC2',
  'TOURNAMENT-PC3',
  'ESPORTS-RIG-PC4',
  'PLAYER-RIG-ALPHA',
  'DESKTOP-WIN11-WORKSTATION',
  'BAD-PC',
  'ESPORTS-RIG-01',
  'ESPORTS-RIG-02',
  'ESPORTS-RIG-03',
]);

/**
 * Determines whether a device record is a confirmed demo, test fixture, simulated,
 * or un-enrolled synthetic record.
 */
export function isDemoOrFixtureDevice(
  device: Partial<MonitoredDevice> | null | undefined,
  hasValidDeviceToken = true
): boolean {
  if (!device || !device.deviceId) return true;
  if (device.isSimulated === true) return true;

  const idLower = device.deviceId.trim().toLowerCase();
  const hostUpper = (device.hostname || '').trim().toUpperCase();

  if (CONFIRMED_DEMO_DEVICE_IDS.has(idLower)) return true;
  if (CONFIRMED_DEMO_HOSTNAMES.has(hostUpper)) return true;

  if (
    idLower.includes('demo') ||
    idLower.includes('fixture') ||
    idLower.includes('simulated') ||
    idLower.startsWith('dev-win11-') ||
    idLower.startsWith('dev-win10-') ||
    idLower.startsWith('test-') ||
    idLower.startsWith('loadtest-')
  ) {
    return true;
  }

  // A genuinely enrolled device must have an enrolledAt timestamp and an issued device credential token
  if (!device.enrolledAt || !hasValidDeviceToken) {
    return true;
  }

  return false;
}

/**
 * Determines whether a security event or incident record is simulated test data
 * or originates from a confirmed demo / test fixture device.
 */
export function isDemoOrSimulatedEventOrIncident(
  record:
    | {
        deviceId?: string;
        hostname?: string;
        isSimulated?: boolean;
      }
    | null
    | undefined
): boolean {
  if (!record) return true;
  if (record.isSimulated === true) return true;

  const idLower = (record.deviceId || '').trim().toLowerCase();
  const hostUpper = (record.hostname || '').trim().toUpperCase();

  if (!idLower) return true;
  if (CONFIRMED_DEMO_DEVICE_IDS.has(idLower)) return true;
  if (CONFIRMED_DEMO_HOSTNAMES.has(hostUpper)) return true;

  if (
    idLower.includes('demo') ||
    idLower.includes('fixture') ||
    idLower.includes('simulated') ||
    idLower.includes('sandbox') ||
    idLower.startsWith('dev-win11-') ||
    idLower.startsWith('dev-win10-') ||
    idLower.startsWith('test-') ||
    idLower.startsWith('loadtest-')
  ) {
    return true;
  }

  return false;
}

/**
 * Checks whether a device has a valid, non-stale heartbeat within the UTC timeout window.
 * A stored device record alone never means the PC is connected.
 */
export function isDeviceHeartbeatFresh(
  device: Pick<MonitoredDevice, 'lastHeartbeat' | 'status' | 'isSimulated' | 'enrolledAt'>,
  nowUtcMs: number = Date.now(),
  timeoutMs: number = DEFAULT_HEARTBEAT_TIMEOUT_MS
): boolean {
  if (!device || device.isSimulated) return false;
  if (!device.enrolledAt) return false;
  if (device.status === 'revoked' || device.status === 'disconnected') return false;
  if (!device.lastHeartbeat) return false;

  const hbMs = Date.parse(device.lastHeartbeat);
  if (Number.isNaN(hbMs)) return false;

  const elapsedMs = nowUtcMs - hbMs;
  // Allow up to 5 seconds of minor clock skew in the future, and require elapsedMs <= timeoutMs
  return elapsedMs >= -5_000 && elapsedMs <= timeoutMs;
}

/**
 * Deterministically computes one of the 9 explicit tournament monitoring health states.
 * Never marks an uninspectable, sequence-gapped, or integrity-failed PC as 'protected_healthy'.
 */
export function deriveMonitoringHealthState(device: MonitoredDevice): MonitoringHealthState {
  if (device.status === 'revoked') {
    return 'device_revoked';
  }
  if (!device.enrolledAt) {
    return 'enrollment_pending';
  }
  if (
    device.integrityStatus === 'signature_mismatch' ||
    device.integrityStatus === 'tamper_suspected'
  ) {
    return 'agent_integrity_failure';
  }
  if (device.status === 'disconnected') {
    return 'agent_disconnected';
  }
  if ((device.inspectionFailuresCount || 0) >= 3) {
    return 'required_telemetry_unavailable';
  }
  if (
    (device.sequenceGapsDetected || 0) > 0 ||
    (device.inspectionFailuresCount || 0) > 0 ||
    (Array.isArray(device.blindSpotReasons) && device.blindSpotReasons.length > 0) ||
    device.isElevatedAdmin === false
  ) {
    return 'monitoring_degraded';
  }
  if (device.riskScore >= 70 || device.highestSeverity === 'critical') {
    return 'investigation_required';
  }
  if (device.riskScore > 0 || (device.detectedEventsCount || 0) > 0) {
    return 'suspicious_activity_detected';
  }
  return 'protected_healthy';
}

/**
 * Reconciles a device's status based on its revocation state, risk score, blind-spot indicators, and UTC heartbeat age.
 * - Revoked devices remain 'revoked' and are never marked online.
 * - Devices with stale heartbeats (> timeoutMs) or missing heartbeats are marked 'disconnected' (offline).
 * - Devices with fresh heartbeats are 'degraded' if riskScore >= 70 or blind spots/sequence gaps exist, otherwise 'healthy'.
 */
export function reconcileDeviceStatus(
  device: MonitoredDevice,
  nowUtcMs: number = Date.now(),
  timeoutMs: number = DEFAULT_HEARTBEAT_TIMEOUT_MS
): MonitoredDevice {
  if (device.status === 'revoked') {
    const revokedDev: MonitoredDevice = { ...device, status: 'revoked' };
    revokedDev.monitoringHealthState = deriveMonitoringHealthState(revokedDev);
    return revokedDev;
  }

  const fresh = isDeviceHeartbeatFresh(device, nowUtcMs, timeoutMs);
  if (!fresh) {
    const discDev: MonitoredDevice = { ...device, status: 'disconnected' };
    discDev.monitoringHealthState = deriveMonitoringHealthState(discDev);
    return discDev;
  }

  const hasBlindSpotOrTamper =
    device.integrityStatus !== 'verified' ||
    (device.sequenceGapsDetected || 0) > 0 ||
    (device.inspectionFailuresCount || 0) > 0 ||
    device.isElevatedAdmin === false;

  const nextStatus = device.riskScore >= 70 || hasBlindSpotOrTamper ? 'degraded' : 'healthy';
  const reconciled: MonitoredDevice = { ...device, status: nextStatus };
  reconciled.monitoringHealthState = deriveMonitoringHealthState(reconciled);
  return reconciled;
}

export interface FleetSummaryMetrics {
  devices: MonitoredDevice[];
  onlineDevices: MonitoredDevice[];
  offlineDevices: MonitoredDevice[];
  revokedDevices: MonitoredDevice[];
  totalRegistered: number;
  onlineCount: number;
  offlineCount: number;
  revokedCount: number;
  healthyCount: number;
  degradedCount: number;
  healthStateBreakdown: Record<MonitoringHealthState, number>;
  evaluatedAtUtc: string;
  heartbeatTimeoutMs: number;
}

/**
 * Computes authoritative fleet metrics from backend device records.
 * Filters out any demo/test/simulated records, reconciles heartbeat timeouts in UTC,
 * and computes totalRegistered, onlineCount, offlineCount, revokedCount, and 9-state breakdown.
 * Revoked devices are never counted as active connected PCs.
 */
export function computeFleetSummary(
  rawDevices: MonitoredDevice[],
  nowUtcMs: number = Date.now(),
  timeoutMs: number = DEFAULT_HEARTBEAT_TIMEOUT_MS
): FleetSummaryMetrics {
  const legitimateDevices = (rawDevices || [])
    .filter((d) => !isDemoOrFixtureDevice(d, true))
    .map((d) => reconcileDeviceStatus(d, nowUtcMs, timeoutMs));

  const onlineDevices = legitimateDevices.filter(
    (d) => d.status === 'healthy' || d.status === 'degraded'
  );
  const offlineDevices = legitimateDevices.filter((d) => d.status === 'disconnected');
  const revokedDevices = legitimateDevices.filter((d) => d.status === 'revoked');
  const healthyCount = onlineDevices.filter((d) => d.status === 'healthy').length;
  const degradedCount = onlineDevices.filter((d) => d.status === 'degraded').length;

  const healthStateBreakdown: Record<MonitoringHealthState, number> = {
    protected_healthy: 0,
    suspicious_activity_detected: 0,
    monitoring_degraded: 0,
    required_telemetry_unavailable: 0,
    agent_integrity_failure: 0,
    agent_disconnected: 0,
    enrollment_pending: 0,
    device_revoked: 0,
    investigation_required: 0,
  };

  for (const dev of legitimateDevices) {
    const state = dev.monitoringHealthState || deriveMonitoringHealthState(dev);
    healthStateBreakdown[state] = (healthStateBreakdown[state] || 0) + 1;
  }

  return {
    devices: legitimateDevices,
    onlineDevices,
    offlineDevices,
    revokedDevices,
    totalRegistered: legitimateDevices.length,
    onlineCount: onlineDevices.length,
    offlineCount: offlineDevices.length,
    revokedCount: revokedDevices.length,
    healthyCount,
    degradedCount,
    healthStateBreakdown,
    evaluatedAtUtc: new Date(nowUtcMs).toISOString(),
    heartbeatTimeoutMs: timeoutMs,
  };
}

