import { BlackboxEntry, SeverityLevel } from '../../../shared-schemas/types.ts';
import {
  CONFIRMED_DEMO_DEVICE_IDS,
  CONFIRMED_DEMO_HOSTNAMES,
} from '../../../shared-schemas/fleetMetrics.ts';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

export class BlackboxLedgerService {
  private entries: BlackboxEntry[] = [];
  private maxQueueDepth = 10000;
  private prevHash = '0000000000000000000000000000000000000000000000000000000000000000';
  private storageFilePath: string | null = null;

  constructor(storagePath?: string | null) {
    if (storagePath === null) {
      this.storageFilePath = null;
    } else if (typeof storagePath === 'string') {
      this.storageFilePath = storagePath;
    } else {
      this.storageFilePath = path.join(process.cwd(), 'data', 'blackbox-ledger.json');
    }

    if (this.storageFilePath) {
      this.loadFromDisk();
    }

    if (this.entries.length === 0) {
      this.recordSystemEvent(
        'STARTUP_SHUTDOWN',
        'Sentinel AC Server Engine Initialized',
        SeverityLevel.LOW,
        'Sentinel AC central monitoring server initialized and awaiting Windows agent connections.',
        'SYSTEM',
        'SENTINEL-SERVER'
      );
    }
  }

  private loadFromDisk(): void {
    if (!this.storageFilePath) return;
    try {
      if (fs.existsSync(this.storageFilePath)) {
        const raw = fs.readFileSync(this.storageFilePath, 'utf-8');
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed) && parsed.length > 0) {
          const cleanEntries: BlackboxEntry[] = [];
          let runningHash = '0000000000000000000000000000000000000000000000000000000000000000';
          let removedCount = 0;

          for (const e of parsed as BlackboxEntry[]) {
            const devLower = (e.deviceId || '').trim().toLowerCase();
            const hostUpper = (e.hostname || '').trim().toUpperCase();
            const isDemo =
              CONFIRMED_DEMO_DEVICE_IDS.has(devLower) ||
              CONFIRMED_DEMO_HOSTNAMES.has(hostUpper) ||
              devLower.startsWith('win-suvo-') ||
              (e.details || '').includes('Test PC-4 Enrollment');
            if (isDemo) {
              removedCount++;
              continue;
            }
            const payload = `${runningHash}|${e.timestamp}|${e.deviceId}|${e.category}|${e.action}|${e.details}`;
            const entryHash = crypto.createHash('sha256').update(payload).digest('hex');
            runningHash = entryHash;
            cleanEntries.push({ ...e, entryHash });
          }

          this.entries = cleanEntries;
          this.prevHash = runningHash;
          if (removedCount > 0) {
            this.saveToDisk();
          }
        }
      }
    } catch {
      // Fallback cleanly to in-memory ledger
    }
  }

  private saveToDisk(): void {
    if (!this.storageFilePath) return;
    try {
      const dir = path.dirname(this.storageFilePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(this.storageFilePath, JSON.stringify(this.entries, null, 2), 'utf-8');
    } catch {
      // Best-effort local persistence
    }
  }

  public recordSystemEvent(
    category: BlackboxEntry['category'],
    action: string,
    severity: SeverityLevel,
    details: string,
    deviceId: string,
    hostname: string,
    sourceProcess?: string,
    targetProcess?: string,
    hash?: string
  ): BlackboxEntry {
    const timestamp = new Date().toISOString();
    const entryId = `bb-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

    // Privacy protection filter: Scrub any potential sensitive strings
    const sanitizedDetails = this.sanitizePrivacy(details);

    // Compute rolling cryptographic SHA-256 hash for tamper evidence
    const hashPayload = `${this.prevHash}|${timestamp}|${deviceId}|${category}|${action}|${sanitizedDetails}`;
    const entryHash = crypto.createHash('sha256').update(hashPayload).digest('hex');
    this.prevHash = entryHash;

    const entry: BlackboxEntry = {
      entryId,
      timestamp,
      deviceId,
      hostname,
      category,
      action,
      severity,
      details: sanitizedDetails,
      sourceProcess,
      targetProcess,
      hash,
      entryHash,
    };

    this.entries.push(entry);

    // Maintain bounded memory and queue depth
    if (this.entries.length > this.maxQueueDepth) {
      this.entries.shift();
    }

    this.saveToDisk();
    return entry;
  }

  /**
   * For automated testing of tamper-evident verification. Modifies the content of an entry
   * without recalculating the rolling hash chain.
   */
  public tamperEntryForTesting(index: number, newDetails: string): void {
    if (this.entries[index]) {
      this.entries[index] = {
        ...this.entries[index],
        details: newDetails,
      };
    }
  }

  private sanitizePrivacy(text: string): string {
    return text
      .replace(/password\s*[:=]\s*\S+/gi, 'password=[REDACTED]')
      .replace(/token\s*[:=]\s*\S+/gi, 'token=[REDACTED]')
      .replace(/auth\s*[:=]\s*\S+/gi, 'auth=[REDACTED]')
      .replace(/bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, 'Bearer [REDACTED]');
  }

  public getEntries(filter?: {
    category?: string;
    severity?: string;
    search?: string;
    limit?: number;
  }): BlackboxEntry[] {
    let result = [...this.entries];

    if (filter?.category) {
      result = result.filter((e) => e.category === filter.category);
    }
    if (filter?.severity) {
      result = result.filter((e) => e.severity === filter.severity);
    }
    if (filter?.search) {
      const q = filter.search.toLowerCase();
      result = result.filter(
        (e) =>
          e.action.toLowerCase().includes(q) ||
          e.details.toLowerCase().includes(q) ||
          (e.sourceProcess && e.sourceProcess.toLowerCase().includes(q)) ||
          (e.targetProcess && e.targetProcess.toLowerCase().includes(q))
      );
    }

    const limit = filter?.limit || 100;
    return result.slice(-limit).reverse();
  }

  public verifyLedgerIntegrity(): { isValid: boolean; checkedCount: number } {
    let runningHash = '0000000000000000000000000000000000000000000000000000000000000000';
    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i];
      const payload = `${runningHash}|${e.timestamp}|${e.deviceId}|${e.category}|${e.action}|${e.details}`;
      const computed = crypto.createHash('sha256').update(payload).digest('hex');
      if (computed !== e.entryHash) {
        return { isValid: false, checkedCount: i };
      }
      runningHash = computed;
    }
    return { isValid: true, checkedCount: this.entries.length };
  }

  public exportJson(): string {
    return JSON.stringify(
      {
        exportedAt: new Date().toISOString(),
        totalEntries: this.entries.length,
        integrityStatus: this.verifyLedgerIntegrity().isValid ? 'VERIFIED' : 'TAMPER_DETECTED',
        entries: this.entries,
      },
      null,
      2
    );
  }

  public exportCsv(): string {
    const header = 'Timestamp,EntryID,DeviceID,Category,Action,Severity,Details,SourceProcess,TargetProcess,EntryHash\n';
    const rows = this.entries.map((e) =>
      `"${e.timestamp}","${e.entryId}","${e.deviceId}","${e.category}","${e.action}","${e.severity}","${e.details.replace(/"/g, '""')}","${e.sourceProcess || ''}","${e.targetProcess || ''}","${e.entryHash}"`
    );
    return header + rows.join('\n');
  }
}
