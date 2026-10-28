import {
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocs,
  onSnapshot,
  query,
  serverTimestamp,
  setDoc,
  updateDoc,
  where,
  Unsubscribe,
} from 'firebase/firestore';
import {
  auth,
  db,
  handleFirestoreError,
  OperationType,
} from './firebase.ts';
import {
  AuditLogRecord,
  DetectionRuleRecord,
  IncidentRecord,
  MonitoredDevice,
  SecurityEventRecord,
  UserRole,
} from '../../shared-schemas/types.ts';
import { getInitialRules } from './sentinelData.ts';

function sanitizeId(id: string): string {
  return id.replace(/[^a-zA-Z0-9_\-]/g, '_').slice(0, 128);
}

function truncate(str: string, maxLen: number, minLen = 1): string {
  const clean = (str || '').trim();
  if (clean.length < minLen) {
    return minLen === 0 ? '' : 'N/A';
  }
  return clean.slice(0, maxLen);
}

export async function ensureUserProfileAndCleanWorkspace(
  uid: string,
  email: string,
  displayName: string
): Promise<UserRole> {
  const safeUid = sanitizeId(uid);
  const userPath = `users/${safeUid}`;
  const isBootstrappedAdmin = email === 'shubhamdas6789@gmail.com';
  const assignedRole: UserRole = isBootstrappedAdmin
    ? UserRole.ADMINISTRATOR
    : UserRole.SECURITY_ANALYST;

  try {
    const existingDoc = await getDoc(doc(db, 'users', safeUid));
    if (!existingDoc.exists()) {
      await setDoc(doc(db, 'users', safeUid), {
        uid: safeUid,
        email: truncate(email, 254, 3),
        displayName: truncate(displayName || 'SOC Analyst', 100, 1),
        role: assignedRole,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, userPath);
  }

  // Ensure default detection rules catalog exists so detection engine has active rule specifications
  try {
    const rulesQuery = query(collection(db, 'rules'), where('ownerId', '==', safeUid));
    const snap = await getDocs(rulesQuery);
    if (snap.empty) {
      const defaultRules = getInitialRules(safeUid);
      for (const r of defaultRules) {
        const docId = sanitizeId(`${r.ruleId}_${safeUid.slice(0, 8)}`);
        await setDoc(doc(db, 'rules', docId), {
          ruleId: docId,
          ownerId: safeUid,
          version: truncate(r.version, 32),
          name: truncate(r.name, 160),
          category: r.category,
          severity: r.severity,
          classification: r.classification,
          confidence: Math.min(100, Math.max(0, Number(r.confidence))),
          riskScoreContribution: Math.min(100, Math.max(0, Number(r.riskScoreContribution))),
          enabled: Boolean(r.enabled),
          detectionSource: truncate(r.detectionSource, 120),
          description: truncate(r.description, 1000),
          falsePositiveConsiderations: truncate(r.falsePositiveConsiderations, 1000),
          investigationSteps: truncate(r.investigationSteps, 1000),
          signatureHash: truncate(r.signatureHash, 256, 16),
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
      }
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, 'rules');
  }

  // Purge any previously seeded legacy demo records to enforce clean real-time operational state
  await purgeLegacyDemoRecords(safeUid);

  return assignedRole;
}

export async function purgeLegacyDemoRecords(ownerId: string): Promise<void> {
  const safeOwnerId = sanitizeId(ownerId);
  const collectionsToClean = ['devices', 'events', 'incidents', 'auditLogs'];

  for (const colName of collectionsToClean) {
    try {
      const q = query(collection(db, colName), where('ownerId', '==', safeOwnerId));
      const snap = await getDocs(q);
      for (const docSnap of snap.docs) {
        const data = docSnap.data();
        // If it's a legacy pre-data record, delete it
        if (
          data.isSimulated === true ||
          docSnap.id.includes('demo') ||
          docSnap.id.startsWith('dev-win11-alpha') ||
          docSnap.id.startsWith('dev-win10-ldp') ||
          docSnap.id.startsWith('dev-win11-memu') ||
          docSnap.id.startsWith('dev-win11-gpg')
        ) {
          await deleteDoc(doc(db, colName, docSnap.id)).catch(() => {});
        }
      }
    } catch {
      // Non-blocking cleanup
    }
  }
}

export async function clearAllWorkspaceRecords(ownerId: string): Promise<void> {
  const safeOwnerId = sanitizeId(ownerId);
  const collectionsToClean = ['devices', 'events', 'incidents', 'auditLogs'];

  for (const colName of collectionsToClean) {
    try {
      const q = query(collection(db, colName), where('ownerId', '==', safeOwnerId));
      const snap = await getDocs(q);
      for (const docSnap of snap.docs) {
        await deleteDoc(doc(db, colName, docSnap.id)).catch(() => {});
      }
    } catch (err) {
      console.warn(`Error clearing collection ${colName}:`, err);
    }
  }
}

export async function persistSecurityEventToFirestore(
  ev: SecurityEventRecord
): Promise<void> {
  if (!auth.currentUser) return;
  const safeOwnerId = sanitizeId(auth.currentUser.uid);
  const docId = sanitizeId(ev.eventId);
  try {
    await setDoc(doc(db, 'events', docId), {
      eventId: docId,
      ownerId: safeOwnerId,
      deviceId: sanitizeId(ev.deviceId),
      hostname: truncate(ev.hostname, 120),
      emulator: truncate(ev.emulator, 80),
      sessionId: truncate(ev.sessionId, 128),
      ruleId: truncate(ev.ruleId, 64),
      ruleVersion: truncate(ev.ruleVersion, 32),
      category: ev.category,
      severity: ev.severity,
      classification: ev.classification,
      confidence: Math.min(100, Math.max(0, Number(ev.confidence))),
      riskContribution: Math.min(100, Math.max(0, Number(ev.riskContribution))),
      processName: truncate(ev.processName, 160),
      processPath: truncate(ev.processPath, 512),
      sha256: truncate(ev.sha256, 128),
      signerIdentity: truncate(ev.signerIdentity, 200),
      summary: truncate(ev.summary, 600),
      detectionSource: truncate(ev.detectionSource, 120),
      isSimulated: Boolean(ev.isSimulated),
      eventTimestamp: truncate(ev.eventTimestamp, 64),
      createdAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, `events/${docId}`);
  }
}

export async function persistIncidentToFirestore(
  inc: IncidentRecord,
  isNew: boolean
): Promise<void> {
  if (!auth.currentUser) return;
  const safeOwnerId = sanitizeId(auth.currentUser.uid);
  const docId = sanitizeId(inc.incidentId);
  try {
    if (isNew) {
      await setDoc(doc(db, 'incidents', docId), {
        incidentId: docId,
        ownerId: safeOwnerId,
        title: truncate(inc.title, 240),
        deviceId: sanitizeId(inc.deviceId),
        hostname: truncate(inc.hostname, 120),
        emulator: truncate(inc.emulator, 80),
        severity: inc.severity,
        status: inc.status,
        aggregatedRiskScore: Math.min(100, Math.max(0, Number(inc.aggregatedRiskScore))),
        confidenceScore: Math.min(100, Math.max(0, Number(inc.confidenceScore))),
        correlatedEventCount: Math.max(1, Number(inc.correlatedEventCount) || 1),
        primaryRuleId: truncate(inc.primaryRuleId, 64),
        executablePath: truncate(inc.executablePath, 512),
        fileSha256: truncate(inc.fileSha256, 128),
        digitalSignature: truncate(inc.digitalSignature, 200),
        evidenceSummary: truncate(inc.evidenceSummary, 1500),
        limitationsNotice: truncate(inc.limitationsNotice, 1000),
        analystNotes: truncate(inc.analystNotes, 2000, 0),
        recommendedAction: truncate(inc.recommendedAction, 500),
        isSimulated: Boolean(inc.isSimulated),
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    } else {
      await updateDoc(doc(db, 'incidents', docId), {
        status: inc.status,
        analystNotes: truncate(inc.analystNotes, 2000, 0),
        recommendedAction: truncate(inc.recommendedAction, 500),
        aggregatedRiskScore: Math.min(100, Math.max(0, Number(inc.aggregatedRiskScore))),
        correlatedEventCount: Math.max(1, Number(inc.correlatedEventCount) || 1),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(
      error,
      isNew ? OperationType.CREATE : OperationType.UPDATE,
      `incidents/${docId}`
    );
  }
}

export async function persistRuleUpdateToFirestore(
  rule: DetectionRuleRecord
): Promise<void> {
  if (!auth.currentUser) return;
  const docId = sanitizeId(rule.ruleId);
  try {
    await updateDoc(doc(db, 'rules', docId), {
      enabled: Boolean(rule.enabled),
      severity: rule.severity,
      riskScoreContribution: Math.min(100, Math.max(0, Number(rule.riskScoreContribution))),
      version: truncate(rule.version, 32),
      signatureHash: truncate(rule.signatureHash, 256, 16),
      updatedAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, `rules/${docId}`);
  }
}

export async function persistDeviceUpdateToFirestore(
  device: MonitoredDevice
): Promise<void> {
  if (!auth.currentUser) return;
  const docId = sanitizeId(device.deviceId);
  try {
    await updateDoc(doc(db, 'devices', docId), {
      status: device.status,
      emulatorName: truncate(device.emulatorName, 80),
      gameSessionState: device.gameSessionState,
      freeFirePackage: truncate(device.freeFirePackage, 80),
      integrityStatus: device.integrityStatus,
      riskScore: Math.min(100, Math.max(0, Number(device.riskScore))),
      lastHeartbeat: truncate(device.lastHeartbeat, 64),
      updatedAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, `devices/${docId}`);
  }
}

export async function persistNewDeviceToFirestore(
  device: MonitoredDevice
): Promise<void> {
  if (!auth.currentUser) return;
  const safeOwnerId = sanitizeId(auth.currentUser.uid);
  const docId = sanitizeId(device.deviceId);
  try {
    await setDoc(doc(db, 'devices', docId), {
      deviceId: docId,
      ownerId: safeOwnerId,
      hostname: truncate(device.hostname, 120),
      osVersion: truncate(device.osVersion, 120),
      agentVersion: truncate(device.agentVersion, 40),
      status: device.status,
      emulatorName: truncate(device.emulatorName, 80),
      gameSessionState: device.gameSessionState,
      freeFirePackage: truncate(device.freeFirePackage, 80),
      integrityStatus: device.integrityStatus,
      riskScore: Math.min(100, Math.max(0, Number(device.riskScore) || 0)),
      isSimulated: Boolean(device.isSimulated),
      lastHeartbeat: truncate(device.lastHeartbeat, 64),
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, `devices/${docId}`);
  }
}

export async function appendAuditLogToFirestore(
  log: AuditLogRecord
): Promise<void> {
  if (!auth.currentUser) return;
  const safeOwnerId = sanitizeId(auth.currentUser.uid);
  const docId = sanitizeId(log.logId);
  try {
    await setDoc(doc(db, 'auditLogs', docId), {
      logId: docId,
      ownerId: safeOwnerId,
      actorEmail: truncate(log.actorEmail, 254, 3),
      actorRole: log.actorRole,
      action: truncate(log.action, 120),
      targetType: log.targetType,
      targetId: truncate(log.targetId, 128),
      details: truncate(log.details, 1000),
      createdAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, `auditLogs/${docId}`);
  }
}

export function subscribeToWorkspaceCollections(
  uid: string,
  callbacks: {
    onDevices: (devices: MonitoredDevice[]) => void;
    onRules: (rules: DetectionRuleRecord[]) => void;
    onEvents: (events: SecurityEventRecord[]) => void;
    onIncidents: (incidents: IncidentRecord[]) => void;
    onAuditLogs: (logs: AuditLogRecord[]) => void;
  }
): Unsubscribe[] {
  const safeUid = sanitizeId(uid);

  const unsubDevices = onSnapshot(
    query(collection(db, 'devices'), where('ownerId', '==', safeUid)),
    (snap) => {
      const list = snap.docs.map((d) => d.data() as MonitoredDevice);
      callbacks.onDevices(list);
    },
    (err) => handleFirestoreError(err, OperationType.LIST, 'devices')
  );

  const unsubRules = onSnapshot(
    query(collection(db, 'rules'), where('ownerId', '==', safeUid)),
    (snap) => {
      const list = snap.docs.map((d) => d.data() as DetectionRuleRecord);
      if (list.length > 0) callbacks.onRules(list);
    },
    (err) => handleFirestoreError(err, OperationType.LIST, 'rules')
  );

  const unsubEvents = onSnapshot(
    query(collection(db, 'events'), where('ownerId', '==', safeUid)),
    (snap) => {
      const list = snap.docs
        .map((d) => d.data() as SecurityEventRecord)
        .sort((a, b) => b.eventTimestamp.localeCompare(a.eventTimestamp));
      callbacks.onEvents(list);
    },
    (err) => handleFirestoreError(err, OperationType.LIST, 'events')
  );

  const unsubIncidents = onSnapshot(
    query(collection(db, 'incidents'), where('ownerId', '==', safeUid)),
    (snap) => {
      const list = snap.docs.map((d) => d.data() as IncidentRecord);
      callbacks.onIncidents(list);
    },
    (err) => handleFirestoreError(err, OperationType.LIST, 'incidents')
  );

  const unsubLogs = onSnapshot(
    query(collection(db, 'auditLogs'), where('ownerId', '==', safeUid)),
    (snap) => {
      const list = snap.docs.map((d) => {
        const raw = d.data();
        return {
          ...raw,
          timestamp: raw.timestamp || new Date().toISOString(),
        } as AuditLogRecord;
      });
      callbacks.onAuditLogs(list);
    },
    (err) => handleFirestoreError(err, OperationType.LIST, 'auditLogs')
  );

  return [unsubDevices, unsubRules, unsubEvents, unsubIncidents, unsubLogs];
}
