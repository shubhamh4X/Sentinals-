import {
  AuditLogRecord,
  DetectionRuleRecord,
  IncidentRecord,
  MonitoredDevice,
  SecurityEventRecord,
} from '../../shared-schemas/types.ts';
import { DEFAULT_SIGNED_RULES } from '../../detection-engine/engine.ts';

/**
 * Real-time operational baseline:
 * No pre-populated mock devices, events, incidents, or audit logs.
 * Everything starts clean (empty) and records are created in real time as endpoints connect
 * or live events are ingested.
 */
export function getInitialDemoDevices(_ownerId: string): MonitoredDevice[] {
  return [];
}

export function getInitialDemoEvents(_ownerId: string): SecurityEventRecord[] {
  return [];
}

export function getInitialDemoIncidents(_ownerId: string): IncidentRecord[] {
  return [];
}

export function getInitialDemoAuditLogs(_ownerId: string, _actorEmail: string): AuditLogRecord[] {
  return [];
}

export function getInitialRules(ownerId: string): DetectionRuleRecord[] {
  return DEFAULT_SIGNED_RULES.map((rule) => ({
    ...rule,
    ownerId,
  }));
}
