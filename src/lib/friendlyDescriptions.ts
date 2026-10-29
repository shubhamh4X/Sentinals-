import { IndicatorType, SecurityEventRecord } from '../../shared-schemas/types.ts';

export interface FriendlyEventSummary {
  title: string;
  simpleDescription: string;
  suspicionReason: string;
  categoryLabel: string;
  threatLevel: 'Critical' | 'High' | 'Medium' | 'Low';
}

/**
 * Translates complex technical cybersecurity terms into plain, clear language
 * for PC gamers and tournament operators.
 */
export function getFriendlyEventSummary(event: SecurityEventRecord): FriendlyEventSummary {
  const ruleId = event.ruleId;
  const proc = event.processName || 'Unknown program';

  if (ruleId === 'PROC-001' || event.summary?.includes('Cheat Binary')) {
    return {
      title: 'Known Cheat Program Detected',
      simpleDescription: `The program "${proc}" matches the digital signature of a known cheat tool or injector.`,
      suspicionReason: 'Cheat programs hook into emulators to alter player health, recoil, or player visibility.',
      categoryLabel: 'Cheat Program',
      threatLevel: 'Critical',
    };
  }

  if (ruleId === 'PROC-002' || event.summary?.includes('Temp')) {
    return {
      title: 'Unsigned Program in Temporary Folder',
      simpleDescription: `An unverified program was launched from a temporary system folder alongside your emulator.`,
      suspicionReason: 'Legitimate software is rarely launched from hidden temporary directories without a verified digital certificate.',
      categoryLabel: 'Suspicious Program',
      threatLevel: 'High',
    };
  }

  if (ruleId === 'PROC-003' || event.summary?.includes('Ancestry')) {
    return {
      title: 'Suspicious Helper Process',
      simpleDescription: `A command shell or script process was spawned directly by an unauthorized background application.`,
      suspicionReason: 'Automated cheat loaders often use hidden background scripts to start modifications.',
      categoryLabel: 'Process Activity',
      threatLevel: 'Medium',
    };
  }

  if (ruleId === 'MEM-001' || event.summary?.includes('Handle') || event.summary?.includes('VM_WRITE')) {
    return {
      title: 'Unauthorized Game Memory Access',
      simpleDescription: `An outside program opened a direct write handle to emulator memory while Free Fire was running.`,
      suspicionReason: 'Aimbots and speed hacks require write access to emulator process memory to manipulate in-game coordinates.',
      categoryLabel: 'Memory Tampering',
      threatLevel: 'Critical',
    };
  }

  if (ruleId === 'MEM-002' || event.summary?.includes('Unbacked')) {
    return {
      title: 'Hidden Memory Code Injection',
      simpleDescription: `Executable machine code was injected into emulator memory without being backed by a real file on disk.`,
      suspicionReason: 'Hiding executable code inside virtual memory is a standard evasion technique used by private cheats.',
      categoryLabel: 'Memory Injection',
      threatLevel: 'High',
    };
  }

  if (ruleId === 'MEM-003' || event.summary?.includes('DLL Injection')) {
    return {
      title: 'Unexpected Module / DLL Injected',
      simpleDescription: `An unverified dynamic library was injected into the emulator's process space.`,
      suspicionReason: 'Game cheats frequently inject custom DLLs to hijack game rendering or read player positions.',
      categoryLabel: 'DLL Injection',
      threatLevel: 'High',
    };
  }

  if (ruleId === 'EMU-001' || event.summary?.includes('libil2cpp')) {
    return {
      title: 'Modified Free Fire Game Files',
      simpleDescription: `The core game library (libil2cpp.so) has been altered from its official version.`,
      suspicionReason: 'Modifying game code files allows unlimited ammo, zero recoil, or high-damage modifications.',
      categoryLabel: 'Game File Tampering',
      threatLevel: 'Critical',
    };
  }

  if (ruleId === 'EMU-002' || event.summary?.includes('ADB')) {
    return {
      title: 'Debug Bridge Communication Detected',
      simpleDescription: `An unauthorized Android Debug Bridge (ADB) connection was opened to the emulator.`,
      suspicionReason: 'External cheat scripts use debug bridge ports to automate inputs or dump live memory.',
      categoryLabel: 'Emulator Tampering',
      threatLevel: 'Medium',
    };
  }

  if (ruleId === 'ESP-001' || event.summary?.includes('Overlay')) {
    return {
      title: 'Transparent Overlay Detected (Wallhack Risk)',
      simpleDescription: `A transparent, click-through overlay window was detected drawing on top of your emulator.`,
      suspicionReason: 'ESP and Wallhacks draw enemy positions and player boxes on top of the game screen using transparent windows.',
      categoryLabel: 'Overlay / ESP',
      threatLevel: 'Medium',
    };
  }

  if (ruleId === 'AGENT-001' || event.summary?.includes('Heartbeat')) {
    return {
      title: 'Anti-Cheat Agent Heartbeat Interrupted',
      simpleDescription: `The Windows anti-cheat monitoring service stopped sending regular security heartbeats.`,
      suspicionReason: 'The monitoring service may have crashed, been terminated by the user, or been blocked by a firewall.',
      categoryLabel: 'Agent Health',
      threatLevel: 'High',
    };
  }

  // Default fallback
  return {
    title: event.summary?.split(' on ')[0] || 'Security Anomaly Detected',
    simpleDescription: event.summary || 'Unusual activity detected in the emulator environment.',
    suspicionReason: 'Activity deviated from standard Free Fire gameplay baseline.',
    categoryLabel: event.category || 'Security Alert',
    threatLevel:
      event.severity === 'critical'
        ? 'Critical'
        : event.severity === 'high'
        ? 'High'
        : event.severity === 'medium'
        ? 'Medium'
        : 'Low',
  };
}
