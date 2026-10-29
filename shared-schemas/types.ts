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
  | 'SUSPICIOUS_SCRIPT_EXECUTION'
  | 'CROSS_PROCESS_VM_WRITE'
  | 'UNBACKED_EXECUTABLE_MEMORY'
  | 'UNEXPECTED_DLL_INJECTION'
  | 'MODIFIED_LIBIL2CPP_ASSET'
  | 'UNAUTHORIZED_ADB_BRIDGE'
  | 'EMULATOR_CONFIG_TAMPER'
  | 'TRANSPARENT_TOPMOST_OVERLAY'
  | 'EXTERNAL_AIMBOT_DRIVER_PIPE'
  | 'AGENT_HEARTBEAT_TIMEOUT'
  | 'PROCESS_INSPECTION_ACCESS_DENIED'
  | 'TELEMETRY_SEQUENCE_GAP_DETECTED'
  | 'AGENT_BINARY_INTEGRITY_MISMATCH';

export type MonitoringHealthState =
  | 'protected_healthy'
  | 'suspicious_activity_detected'
  | 'monitoring_degraded'
  | 'required_telemetry_unavailable'
  | 'agent_integrity_failure'
  | 'agent_disconnected'
  | 'enrollment_pending'
  | 'device_revoked'
  | 'investigation_required';

export type TelemetryOriginType =
  | 'genuine_telemetry'
  | 'controlled_test'
  | 'load_test_simulation';

export interface MonitoredDevice {
  deviceId: string;
  ownerId: string;
  hostname: string;
  osVersion: string;
  agentVersion: string;
  status: 'healthy' | 'degraded' | 'disconnected' | 'revoked';
  monitoringHealthState?: MonitoringHealthState;
  emulatorName: string;
  gameSessionState: 'idle' | 'launching' | 'active_match' | 'terminated';
  freeFirePackage: string;
  integrityStatus: 'verified' | 'tamper_suspected' | 'signature_mismatch';
  riskScore: number;
  isSimulated: boolean;
  lastHeartbeat: string;
  enrolledAt?: string;
  tokenVersion?: number;
  revokedAt?: string;
  detectedEventsCount?: number;
  highestSeverity?: SeverityLevel | 'none';
  lastEventSummary?: string;
  cpuOverheadPercent?: number;
  memoryFootprintMb?: number;
  encryptedQueueDepth?: number;
  autoStartEnabled?: boolean;
  tournamentId?: string;
  matchId?: string;
  participantId?: string;
  participantTag?: string;
  agentInstallationId?: string;
  lastSequenceNumber?: number;
  sequenceGapsDetected?: number;
  inspectionFailuresCount?: number;
  blindSpotReasons?: string[];
  isElevatedAdmin?: boolean;
}

export interface EnrollmentTokenRecord {
  tokenId: string;
  tokenSecret: string;
  label: string;
  createdBy: string;
  createdAt: string;
  expiresAt: string;
  maxUses: number;
  usedCount: number;
  revoked: boolean;
  tournamentId?: string;
  participantId?: string;
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
  originType?: TelemetryOriginType;
  tournamentId?: string;
  matchId?: string;
  roundId?: string;
  participantId?: string;
  sequenceNumber?: number;
  eventTimestamp: string;
  metadata?: {
    requestedAccessMask?: string;
    targetProcess?: string;
    windowExStyle?: string;
    memoryProtection?: string;
    parentProcessName?: string;
    processPid?: number;
    parentProcessPid?: number;
    commandLine?: string;
    loadedModule?: string;
    memoryAddress?: string;
    falsePositiveNotes?: string;
    recommendedSteps?: string;
    inspectionBlindSpots?: string[];
    sequenceGapCount?: number;
  };
}

export type IncidentReviewState =
  | 'pending_review'
  | 'under_investigation'
  | 'confirmed_violation'
  | 'benign_false_positive'
  | 'appeal_submitted'
  | 'appeal_resolved';

export interface IncidentRecord {
  incidentId: string;
  ownerId: string;
  title: string;
  deviceId: string;
  hostname: string;
  emulator: string;
  severity: SeverityLevel;
  status: 'open' | 'investigating' | 'confirmed_violation' | 'dismissed_false_positive';
  reviewState?: IncidentReviewState;
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
  appealNotes?: string;
  reviewedBy?: string;
  reviewedAt?: string;
  recommendedAction: string;
  isSimulated: boolean;
  originType?: TelemetryOriginType;
  tournamentId?: string;
  matchId?: string;
  participantId?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface AuditLogRecord {
  logId: string;
  ownerId: string;
  actorEmail: string;
  actorRole: UserRole;
  action: string;
  targetType: 'device' | 'incident' | 'rule' | 'session' | 'policy' | 'tournament' | 'participant';
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
  eventId?: string;
  sequenceNumber?: number;
  deviceId: string;
  agentInstallationId?: string;
  tournamentId?: string;
  matchId?: string;
  roundId?: string;
  participantId?: string;
  hostname: string;
  emulator: string;
  sessionId: string;
  indicatorType: IndicatorType;
  processName: string;
  processPath: string;
  processPid?: number;
  parentProcessPid?: number;
  parentProcessName?: string;
  sha256: string;
  signerIdentity: string;
  requestedAccessMask?: string;
  targetProcess?: string;
  memoryProtection?: string;
  windowExStyle?: string;
  modifiedAssetPath?: string;
  commandLine?: string;
  loadedModule?: string;
  memoryAddress?: string;
  memorySize?: string;
  memoryType?: string;
  blindSpotReason?: string;
  observedTimestamp: string;
  isSimulated: boolean;
}

export interface BlackboxEntry {
  entryId: string;
  timestamp: string;
  deviceId: string;
  hostname: string;
  category: 'STARTUP_SHUTDOWN' | 'PROCESS_LIFECYCLE' | 'INTEGRITY' | 'MODULE_LOAD' | 'MEMORY_ACCESS' | 'NETWORK' | 'RULE_UPDATE' | 'ADMIN_ACTION';
  action: string;
  severity: SeverityLevel;
  details: string;
  sourceProcess?: string;
  targetProcess?: string;
  hash?: string;
  entryHash: string;
}

export interface ProcessScanItem {
  pid: number;
  name: string;
  path: string;
  parentPid: number;
  parentName: string;
  sha256: string;
  signerIdentity: string;
  status: 'clean' | 'suspicious' | 'strongly_suspicious' | 'unable_to_verify';
  notes: string;
}

export interface ProcessScanReport {
  scanId: string;
  timestamp: string;
  deviceId: string;
  hostname: string;
  totalProcessesScanned: number;
  cleanCount: number;
  suspiciousCount: number;
  stronglySuspiciousCount: number;
  items: ProcessScanItem[];
}

export interface InjectionDetectionItem {
  targetProcess: string;
  pid: number;
  moduleName: string;
  modulePath: string;
  sha256: string;
  signer: string;
  isWhitelisted: boolean;
  classification: 'legitimate_overlay' | 'suspicious_hook' | 'unauthorized_injection';
  memoryProtection: string;
  notes: string;
}

export interface MemoryScanItem {
  baseAddress: string;
  regionSize: string;
  protection: string;
  state: string;
  type: string;
  status: 'safe' | 'unbacked_executable' | 'tampered_hook';
  signatureMatch?: string;
}

export interface ScreenshotEvidence {
  screenshotId: string;
  timestamp: string;
  deviceId: string;
  hostname: string;
  captureType: 'emulator_window' | 'desktop' | 'game_overlay';
  title: string;
  fileUrl: string;
  associatedEventId?: string;
  sizeBytes: number;
  dimensions: string;
}

export interface DiagnosticReport {
  reportId: string;
  generatedAt: string;
  deviceId: string;
  hostname: string;
  osInfo: string;
  agentVersion: string;
  emulatorDetected: string;
  freeFireInstalled: boolean;
  freeFirePackage: string;
  networkLatencyMs: number;
  activeProcessesCount: number;
  tamperProtectionActive: boolean;
  recommendations: string[];
}

export interface TournamentPolicy {
  requireElevatedAgent: boolean;
  heartbeatTimeoutSeconds: number;
  maxAuthorizedDevicesPerParticipant: number; // Configurable per tournament policy (1, 2, or unlimited = 0)
  allowedEmulators: string[];
  strictRootBlock: boolean;
  strictMemoryRwxBlock: boolean;
  allowMidTournamentDeviceReplacement: boolean;
}

export interface TournamentMatch {
  matchId: string;
  tournamentId: string;
  roundId: string;
  roundNumber: number;
  matchName: string;
  mapName: string;
  status: 'scheduled' | 'live' | 'completed' | 'under_review';
  participantIds: string[];
  startedAt?: string;
  endedAt?: string;
}

export interface TournamentRound {
  roundId: string;
  tournamentId: string;
  roundNumber: number;
  name: string;
  status: 'pending' | 'active' | 'completed';
  matches: TournamentMatch[];
}

export interface DeviceReplacementLog {
  replacementId: string;
  participantId: string;
  tournamentId: string;
  previousDeviceId: string;
  newDeviceId: string;
  reason: string;
  approvedBy: string;
  replacedAt: string;
}

export type ParticipantEligibilityStatus =
  | 'eligible'
  | 'pending_enrollment'
  | 'degraded_telemetry'
  | 'under_investigation'
  | 'disqualified';

export interface TournamentParticipant {
  participantId: string;
  tournamentId: string;
  gamerTag: string;
  teamName: string;
  email?: string;
  registeredAt: string;
  status: 'active' | 'removed' | 'disqualified';
  eligibilityStatus: ParticipantEligibilityStatus;
  monitoringHealthState: MonitoringHealthState;
  authorizedDeviceIds: string[];
  historicalDeviceIds: string[];
  replacementHistory: DeviceReplacementLog[];
  enrollmentTokenSecret?: string;
  notes?: string;
}

export interface TournamentRecord {
  tournamentId: string;
  name: string;
  organizer: string;
  gameTitle: string;
  status: 'draft' | 'registration_open' | 'active' | 'completed' | 'archived';
  createdAt: string;
  updatedAt: string;
  policy: TournamentPolicy;
  enabledRuleIds: string[];
  rounds: TournamentRound[];
  matches: TournamentMatch[];
  participantCount?: number;
}

export type LoadTestProfile =
  | 'small_event'
  | 'medium_event'
  | 'large_event'
  | 'enrollment_burst'
  | 'event_burst'
  | 'backpressure_recovery'
  | 'custom';

export interface LoadTestConfig {
  profile: LoadTestProfile;
  agentCount: number;
  eventsPerAgent: number;
  heartbeatsPerAgent: number;
  duplicateRatePercent: number;
  simulatedOfflineQueueFlushSize: number;
  concurrencyBatchSize: number;
}

export interface LoadTestMetricsResult {
  testRunId: string;
  profile: LoadTestProfile;
  executedAtUtc: string;
  config: LoadTestConfig;
  isolatedFromProduction: boolean;
  productionDevicesAffected: number;
  durationMs: number;
  enrollmentsProcessed: number;
  heartbeatsProcessed: number;
  totalTelemetrySubmitted: number;
  eventsEvaluatedAndStored: number;
  duplicatesSuppressed: number;
  sequenceGapsDetected: number;
  rateLimitedOrRejected: number;
  throughputOpsPerSec: number;
  telemetryEventsPerSec: number;
  latencyP50Ms: number;
  latencyP95Ms: number;
  latencyP99Ms: number;
  latencyMaxMs: number;
  heapUsedMbBefore: number;
  heapUsedMbAfter: number;
  heapDeltaMb: number;
  cpuUserMs: number;
  cpuSystemMs: number;
  reconnectionQueueFlushedCount: number;
  bottleneckAnalysis: string[];
  sizingRecommendations: {
    tier: string;
    recommendedCpuCores: number;
    recommendedRamGb: number;
    databaseGuidance: string;
    websocketGuidance: string;
  };
}


