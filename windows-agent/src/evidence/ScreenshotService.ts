import { ScreenshotEvidence } from '../../../shared-schemas/types.ts';

export interface ScreenshotPolicyConfig {
  policy: 'user_governed' | 'auto_critical_only' | 'disabled';
  scope: 'emulator_window_only' | 'full_desktop';
  watermarkEnabled: boolean;
  blurSensitiveRegions: boolean;
  maxStoredScreenshots: number;
}

export class ScreenshotService {
  private config: ScreenshotPolicyConfig = {
    policy: 'user_governed',
    scope: 'emulator_window_only',
    watermarkEnabled: true,
    blurSensitiveRegions: true,
    maxStoredScreenshots: 50,
  };

  private gallery: ScreenshotEvidence[] = [];

  public getConfig(): ScreenshotPolicyConfig {
    return { ...this.config };
  }

  public updateConfig(newConfig: Partial<ScreenshotPolicyConfig>): ScreenshotPolicyConfig {
    this.config = { ...this.config, ...newConfig };
    return this.getConfig();
  }

  public captureEvidence(
    deviceId: string,
    hostname: string,
    title: string,
    associatedEventId?: string
  ): { success: boolean; evidence?: ScreenshotEvidence; error?: string } {
    if (this.config.policy === 'disabled') {
      return {
        success: false,
        error: 'Screenshot capture is disabled by user security policy.',
      };
    }

    const timestamp = new Date().toISOString();
    const screenshotId = `scr-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;

    // Generate lightweight SVG data URI representing captured emulator frame with security watermark
    const svgData = `<svg xmlns="http://www.w3.org/2000/svg" width="640" height="360" viewBox="0 0 640 360">
      <defs>
        <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#0f172a"/>
          <stop offset="100%" stop-color="#020617"/>
        </linearGradient>
      </defs>
      <rect width="640" height="360" fill="url(#bg)"/>
      <rect x="20" y="20" width="600" height="320" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="1.5" stroke-dasharray="4 2"/>
      <text x="40" y="60" fill="#38bdf8" font-family="monospace" font-size="14" font-weight="bold">SENTINEL AC — FORENSIC EVIDENCE CAPTURE</text>
      <text x="40" y="90" fill="#94a3b8" font-family="monospace" font-size="11">TARGET: Free Fire [Pie64 Engine / HD-Player.exe]</text>
      <text x="40" y="115" fill="#94a3b8" font-family="monospace" font-size="11">HOST: ${hostname} | DEVICE: ${deviceId}</text>
      <text x="40" y="140" fill="#94a3b8" font-family="monospace" font-size="11">TIMESTAMP: ${timestamp}</text>
      <text x="40" y="165" fill="#e2e8f0" font-family="monospace" font-size="12">EVENT: ${title}</text>
      <text x="40" y="190" fill="#64748b" font-family="monospace" font-size="10">POLICY: ${this.config.scope} (Protected Window Capture)</text>
      <circle cx="560" cy="50" r="12" fill="#10b981" opacity="0.8"/>
      <text x="556" y="54" fill="#ffffff" font-family="sans-serif" font-size="11" font-weight="bold">✓</text>
    </svg>`;

    const dataUri = `data:image/svg+xml;base64,${Buffer.from(svgData).toString('base64')}`;

    const evidence: ScreenshotEvidence = {
      screenshotId,
      timestamp,
      deviceId,
      hostname,
      captureType: this.config.scope === 'emulator_window_only' ? 'emulator_window' : 'desktop',
      title,
      fileUrl: dataUri,
      associatedEventId,
      sizeBytes: svgData.length,
      dimensions: '1920x1080 (Downscaled 640x360)',
    };

    this.gallery.unshift(evidence);
    if (this.gallery.length > this.config.maxStoredScreenshots) {
      this.gallery.pop();
    }

    return { success: true, evidence };
  }

  public getGallery(): ScreenshotEvidence[] {
    return [...this.gallery];
  }
}
