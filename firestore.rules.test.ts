/**
 * Phase 0: Payload-First Security TDD Test Suite for Sentinel AC Firestore Rules
 * Verifies that all "Dirty Dozen" adversarial payloads are rejected with PERMISSION_DENIED.
 */

export interface AdversarialTestCase {
  id: string;
  name: string;
  collectionPath: string;
  operation: 'get' | 'list' | 'create' | 'update' | 'delete';
  auth: { uid: string; email: string; email_verified: boolean } | null;
  payload?: Record<string, unknown>;
  expectedOutcome: 'PERMISSION_DENIED' | 'ALLOWED';
  pillarVerified: string;
}

export const DIRTY_DOZEN_TEST_CASES: AdversarialTestCase[] = [
  {
    id: 'DD-01',
    name: 'Shadow Field Injection on Incident Creation',
    collectionPath: '/incidents/inc_001',
    operation: 'create',
    auth: { uid: 'user_1', email: 'analyst@sentinel.local', email_verified: true },
    payload: { incidentId: 'inc_001', ownerId: 'user_1', isVerified: true },
    expectedOutcome: 'PERMISSION_DENIED',
    pillarVerified: 'Pillar 2: Strict Keys (hasAll + hasOnly)'
  },
  {
    id: 'DD-02',
    name: 'Unverified Email Spoof of Bootstrapped Admin',
    collectionPath: '/admins/user_spoof',
    operation: 'get',
    auth: { uid: 'user_spoof', email: 'shubhamdas6789@gmail.com', email_verified: false },
    expectedOutcome: 'PERMISSION_DENIED',
    pillarVerified: 'Email Spoofing Guard (email_verified == true)'
  },
  {
    id: 'DD-03',
    name: 'Cross-User PII Scraping on /users/{userId}',
    collectionPath: '/users/victim_uid',
    operation: 'get',
    auth: { uid: 'attacker_uid', email: 'attacker@sentinel.local', email_verified: true },
    expectedOutcome: 'PERMISSION_DENIED',
    pillarVerified: 'Pillar 6: PII Isolation'
  },
  {
    id: 'DD-04',
    name: 'Self-Privilege Escalation in /users/{userId}',
    collectionPath: '/users/attacker_uid',
    operation: 'update',
    auth: { uid: 'attacker_uid', email: 'attacker@sentinel.local', email_verified: true },
    payload: { role: 'Administrator' },
    expectedOutcome: 'PERMISSION_DENIED',
    pillarVerified: 'Pillar 4: Tiered Identity & Role Immutability'
  },
  {
    id: 'DD-05',
    name: 'Identity Spoofing (ownerId Mismatch on Device Registration)',
    collectionPath: '/devices/dev_01',
    operation: 'create',
    auth: { uid: 'attacker_uid', email: 'attacker@sentinel.local', email_verified: true },
    payload: { deviceId: 'dev_01', ownerId: 'other_user_uid' },
    expectedOutcome: 'PERMISSION_DENIED',
    pillarVerified: 'Pillar 2: Identity Integrity (ownerId == request.auth.uid)'
  },
  {
    id: 'DD-06',
    name: 'Value Poisoning on Incident Update (Oversized analystNotes)',
    collectionPath: '/incidents/inc_001',
    operation: 'update',
    auth: { uid: 'user_1', email: 'analyst@sentinel.local', email_verified: true },
    payload: { analystNotes: 'A'.repeat(2500) },
    expectedOutcome: 'PERMISSION_DENIED',
    pillarVerified: 'Pillar 2 & 4.9: Validation Helper in Update Block'
  },
  {
    id: 'DD-07',
    name: 'Tampering with Immutable createdAt Timestamp on Update',
    collectionPath: '/incidents/inc_001',
    operation: 'update',
    auth: { uid: 'user_1', email: 'analyst@sentinel.local', email_verified: true },
    payload: { createdAt: '2020-01-01T00:00:00Z' },
    expectedOutcome: 'PERMISSION_DENIED',
    pillarVerified: 'Pillar 4.12: Immortal Field Rule'
  },
  {
    id: 'DD-08',
    name: 'Forged Client Timestamp on Event Creation',
    collectionPath: '/events/evt_001',
    operation: 'create',
    auth: { uid: 'user_1', email: 'analyst@sentinel.local', email_verified: true },
    payload: { createdAt: '2099-01-01T00:00:00Z' },
    expectedOutcome: 'PERMISSION_DENIED',
    pillarVerified: 'Pillar 4.13: Temporal Integrity (request.time)'
  },
  {
    id: 'DD-09',
    name: 'Modifying or Deleting an Immutable Audit Log Record',
    collectionPath: '/auditLogs/log_001',
    operation: 'update',
    auth: { uid: 'user_1', email: 'shubhamdas6789@gmail.com', email_verified: true },
    payload: { details: 'Modified audit trail' },
    expectedOutcome: 'PERMISSION_DENIED',
    pillarVerified: 'Append-Only Audit Trail Enforcement'
  },
  {
    id: 'DD-10',
    name: 'ID Poisoning Attack with Non-Alphanumeric Characters',
    collectionPath: '/devices/dev$bad!id',
    operation: 'create',
    auth: { uid: 'user_1', email: 'analyst@sentinel.local', email_verified: true },
    payload: { deviceId: 'dev$bad!id' },
    expectedOutcome: 'PERMISSION_DENIED',
    pillarVerified: 'Pillar 3: Path Variable Hardening (isValidId)'
  },
  {
    id: 'DD-11',
    name: 'Unauthorized Blanket List Query on /devices',
    collectionPath: '/devices',
    operation: 'list',
    auth: { uid: 'attacker_uid', email: 'attacker@sentinel.local', email_verified: true },
    expectedOutcome: 'PERMISSION_DENIED',
    pillarVerified: 'Pillar 8: Secure List Queries (Query Enforcer)'
  },
  {
    id: 'DD-12',
    name: 'Rule Update with Invalid Signature Hash Length',
    collectionPath: '/rules/PROC-001',
    operation: 'update',
    auth: { uid: 'user_1', email: 'shubhamdas6789@gmail.com', email_verified: true },
    payload: { signatureHash: 'short' },
    expectedOutcome: 'PERMISSION_DENIED',
    pillarVerified: 'Pillar 2: Cryptographic Signature Boundary Check'
  }
];
