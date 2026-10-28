export enum UserRole {
  ADMINISTRATOR = 'Administrator',
  SECURITY_ANALYST = 'Security Analyst',
  READ_ONLY_VIEWER = 'Read-Only Viewer',
}

export enum SeverityLevel {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
}

export enum EventClassification {
  INFORMATIONAL = 'informational',
  SUSPICIOUS = 'suspicious',
  STRONGLY_INDICATIVE = 'strongly_indicative',
}

export enum DetectionCategory {
  PROCESS_INTEGRITY = 'Process & Executable Integrity',
  MEMORY_INJECTION = 'Memory & Injection Indicators',
  EMULATOR_INTEGRITY = 'Emulator Integrity',
  ESP_GAMEPLAY = 'ESP & Gameplay Manipulation',
  AGENT_INTEGRITY = 'Agent Self-Integrity',
}

export type IndicatorType =
  | 'NORMAL_EMULATOR_LAUNCH'
  | 'KNOWN_CHEAT_SIGNATURE'
  | 'UNSIGNED_TEMP_EXECUTABLE'
  | 'SUSPICIOUS_PROCESS_ANCESTRY'
  | 'CROSS_PROCESS_VM_WRITE'
  | 'UNBACKED_EXECUTABLE_MEMORY'
  | 'UNEXPECTED_DLL_INJECTION'
  | 'MODIFIED_LIBIL2CPP_ASSET'
  | 'UNAUTHORIZED_ADB_BRIDGE'
  | 'EMULATOR_CONFIG_TAMPER'
  | 'TRANSPARENT_TOPMOST_OVERLAY'
  | 'EXTERNAL_AIMBOT_DRIVER_PIPE'
  | 'AGENT_HEARTBEAT_TIMEOUT';

export interface MonitoredDevice {
  deviceId: string;
  ownerId: string;
  hostname: string;
  osVersion: string;
  agentVersion: string;
  status: 'healthy' | 'degraded' | 'disconnected' | 'revoked';
  emulatorName: string;
  gameSessionState: 'idle' | 'launching' | 'active_match' | 'terminated';
  freeFirePackage: string;
  integrityStatus: 'verified' | 'tamper_suspected' | 'signature_mismatch';
  riskScore: number;
  isSimulated: boolean;
  lastHeartbeat: string;
  cpuOverheadPercent?: number;
  memoryFootprintMb?: number;
  encryptedQueueDepth?: number;
  autoStartEnabled?: boolean;
}

export interface DetectionRuleRecord {
  ruleId: string;
  ownerId: string;
  version: string;
  name: string;
  category: DetectionCategory;
  severity: SeverityLevel;
  classification: EventClassification;
  confidence: number;
  riskScoreContribution: number;
  enabled: boolean;
  detectionSource: string;
  description: string;
  falsePositiveConsiderations: string;
  investigationSteps: string;
  signatureHash: string;
  indicatorTrigger?: IndicatorType;
}

export interface SecurityEventRecord {
  eventId: string;
  ownerId: string;
  deviceId: string;
  hostname: string;
  emulator: string;
  sessionId: string;
  ruleId: string;
  ruleVersion: string;
  category: DetectionCategory;
  severity: SeverityLevel;
  classification: EventClassification;
  confidence: number;
  riskContribution: number;
  processName: string;
  processPath: string;
  sha256: string;
  signerIdentity: string;
  summary: string;
  detectionSource: string;
  isSimulated: boolean;
  eventTimestamp: string;
  metadata?: {
    requestedAccessMask?: string;
    targetProcess?: string;
    windowExStyle?: string;
    memoryProtection?: string;
    parentProcessName?: string;
    falsePositiveNotes?: string;
    recommendedSteps?: string;
  };
}

export interface IncidentRecord {
  incidentId: string;
  ownerId: string;
  title: string;
  deviceId: string;
  hostname: string;
  emulator: string;
  severity: SeverityLevel;
  status: 'open' | 'investigating' | 'confirmed_violation' | 'dismissed_false_positive';
  aggregatedRiskScore: number;
  confidenceScore: number;
  correlatedEventCount: number;
  primaryRuleId: string;
  executablePath: string;
  fileSha256: string;
  digitalSignature: string;
  evidenceSummary: string;
  limitationsNotice: string;
  analystNotes: string;
  recommendedAction: string;
  isSimulated: boolean;
  createdAt?: string;
  updatedAt?: string;
}

export interface AuditLogRecord {
  logId: string;
  ownerId: string;
  actorEmail: string;
  actorRole: UserRole;
  action: string;
  targetType: 'device' | 'incident' | 'rule' | 'session' | 'policy';
  targetId: string;
  details: string;
  timestamp: string;
}

export interface SignedRuleBundle {
  bundleId: string;
  bundleVersion: string;
  issuedAt: string;
  signerKeyId: string;
  ed25519Signature: string;
  payloadSha256: string;
  rules: Omit<DetectionRuleRecord, 'ownerId'>[];
}

export interface RawAgentTelemetry {
  schemaVersion: '1.2.0';
  nonce: string;
  deviceId: string;
  hostname: string;
  emulator: string;
  sessionId: string;
  indicatorType: IndicatorType;
  processName: string;
  processPath: string;
  parentProcessName?: string;
  sha256: string;
  signerIdentity: string;
  requestedAccessMask?: string;
  targetProcess?: string;
  memoryProtection?: string;
  windowExStyle?: string;
  modifiedAssetPath?: string;
  observedTimestamp: string;
  isSimulated: boolean;
}
