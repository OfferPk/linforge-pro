/**
 * LINForge Pro - ISO 21434 / UNECE R155 Automotive Cybersecurity Auditor
 * Standards: ISO 21434:2021, UNECE WP.29 R155, SAE J2602, AUTOSAR SecOC
 * Author: Autonomous Digital Product Factory (Product #165)
 * Version: 1.0.0
 */

class LINSecurityAuditor {
  constructor() {
    this.RULES = [
      {
        id: 'SEC-LIN-001',
        title: 'Unauthenticated Actuator & Sensor Frames (Lack of SecOC)',
        standard: 'ISO 21434 Clause 9 / AUTOSAR SecOC Profile for LIN',
        severity: 'HIGH',
        weight: 15,
        description: 'Standard LIN 2.x/ISO 17987 frames contain no cryptographic MAC or rolling freshness counter, allowing adversaries to inject forged commands into window lifters, steering buttons, or mirrors.',
        remediation: 'Implement truncated CMAC (AES-128 24-bit MAC) and rolling sequence counters on safety-relevant LIN frames or isolate via secure gateways.'
      },
      {
        id: 'SEC-LIN-002',
        title: 'Unrestricted Diagnostic Session Injection (PID 0x3C / UDS 0x10)',
        standard: 'ISO 21434 Clause 10 / UNECE R155 (Vulnerability Management)',
        severity: 'CRITICAL',
        weight: 20,
        description: 'Master diagnostic request frame (PID 0x3C) permits entering extended diagnostic sessions, actuator routine control, and flashing routines without physical token verification.',
        remediation: 'Require seed-key challenge (UDS 0x27 SecurityAccess) before unlocking write services; block diagnostic PID 0x3C transmission from non-master gateway nodes.'
      },
      {
        id: 'SEC-LIN-003',
        title: 'Dynamic NAD Reassignment Exploitation (Command 0xB0/0xB3)',
        standard: 'ISO 17987-3 / SAE J2602-1 Node Configuration',
        severity: 'HIGH',
        weight: 15,
        description: 'Malicious diagnostic frames can execute Assign NAD (0xB0) or Conditional Change NAD (0xB3) to re-index legitimate ECUs, causing permanent denial-of-service.',
        remediation: 'Burn hardcoded static NADs in one-time-programmable (OTP) ECU flash or lock configuration once baseline commissioning is complete.'
      },
      {
        id: 'SEC-LIN-004',
        title: 'Wake-Up Pulse Flooding & Battery Drain Attack',
        standard: 'ISO 17987-4 (Physical Layer & Power Management)',
        severity: 'HIGH',
        weight: 10,
        description: 'Generating repeated 250 microsecond dominant wake-up pulses on the single-wire LIN bus forces all slave nodes to remain awake, discharging the 12V vehicle battery overnight.',
        remediation: 'Implement wake-up rate limiting in the master BCM and monitor bus sleep state transitions.'
      },
      {
        id: 'SEC-LIN-005',
        title: 'Central Gateway Cross-Bus Injection (CAN-to-LIN Routing)',
        standard: 'ISO 21434 Clause 9 / UNECE R155 Gateway Security',
        severity: 'CRITICAL',
        weight: 15,
        description: 'Compromised infotainment or telematics units on high-speed CAN/Ethernet can route arbitrary payloads onto body LIN networks if routing filters lack boundary enforcement.',
        remediation: 'Deploy strict stateful allowlist filtering at the central gateway; prohibit routing diagnostic or unmapped frames between CAN and LIN buses.'
      },
      {
        id: 'SEC-LIN-006',
        title: 'Single-Wire Physical Bus Tampering & Short-Circuit Risk',
        standard: 'ISO 17987-4 (Electrical Physical Layer Specification)',
        severity: 'MEDIUM',
        weight: 5,
        description: 'LIN utilizes a single 12V line without differential signaling, making it vulnerable to accidental chassis shorts or grounding attacks.',
        remediation: 'Utilize transceivers with integrated thermal shutdown, dominant timeout protection (TXD dominant clamp detection), and short-to-battery fault isolation.'
      },
      {
        id: 'SEC-LIN-007',
        title: 'Flawed Parity / Checksum Validation in Slave Nodes',
        standard: 'ISO 17987-2 / SAE J2602 Protocol Conformance',
        severity: 'HIGH',
        weight: 10,
        description: 'Legacy or low-cost microcontrollers failing to verify P0/P1 parity bits or using Classic checksum instead of Enhanced checksum process corrupt data frames.',
        remediation: 'Verify strict parity checking in LIN hardware UART state machine and enforce Enhanced checksum across all unconditional frames (IDs 0..59).'
      },
      {
        id: 'SEC-LIN-008',
        title: 'Unprotected Keyless Entry & Vehicle Immobilizer LIN Sub-Bus',
        standard: 'ISO 21434 / UNECE R155 Anti-Theft Requirements',
        severity: 'MEDIUM',
        weight: 5,
        description: 'Door handle smart antenna nodes transmitting passive entry authorization tokens over unencrypted LIN wires are vulnerable to physical clip-on wiretapping.',
        remediation: 'Enforce asymmetric or symmetric encryption (AES-128 / ChaCha20) over payload bytes for all entry and start authorization signals.'
      },
      {
        id: 'SEC-LIN-009',
        title: 'Master Schedule Table Collision & Jitter Anomaly',
        standard: 'ISO 17987-2 / Time-Deterministic Fieldbus Control',
        severity: 'LOW',
        weight: 3,
        description: 'Rogue slave nodes attempting to initiate header transmissions or failing to release bus lines disrupt master slot timing (10ms/20ms schedule jitter).',
        remediation: 'Validate master-only header generation and enforce hardware TXD dominant timeout circuitry.'
      },
      {
        id: 'SEC-LIN-010',
        title: 'Absence of In-Vehicle Network Intrusion Detection (IVN-IDS)',
        standard: 'ISO 21434 Clause 13 / UNECE R155 Threat Detection',
        severity: 'LOW',
        weight: 2,
        description: 'Vehicles lacking real-time LIN bus monitoring cannot detect abnormal frequency of diagnostic frames or out-of-range sensor values.',
        remediation: 'Integrate lightweight IVN-IDS sensor on body domain controller to monitor frame intervals and payload ranges.'
      }
    ];
  }

  auditConfiguration(config) {
    const findings = [];
    let deduction = 0;

    // 1. SecOC
    if (!config.hasSecOC) {
      findings.push({ ...this.RULES[0], status: 'FAIL', current: 'Plaintext LIN Frames Without Cryptographic MAC' });
      deduction += this.RULES[0].weight;
    } else {
      findings.push({ ...this.RULES[0], status: 'PASS', current: 'AUTOSAR SecOC CMAC Active' });
    }

    // 2. Diag Seed-Key
    if (!config.hasDiagSeedKey) {
      findings.push({ ...this.RULES[1], status: 'FAIL', current: 'Diagnostic PID 0x3C Unlocked / No SecurityAccess' });
      deduction += this.RULES[1].weight;
    } else {
      findings.push({ ...this.RULES[1], status: 'PASS', current: 'UDS 0x27 Seed-Key Interlock Enforced' });
    }

    // 3. Static NAD Lock
    if (config.allowDynamicNAD) {
      findings.push({ ...this.RULES[2], status: 'FAIL', current: 'Dynamic Assign NAD (0xB0) Allowed Over Wire' });
      deduction += this.RULES[2].weight;
    } else {
      findings.push({ ...this.RULES[2], status: 'PASS', current: 'Static Hardcoded NADs in Flash OTP' });
    }

    // 4. Wake-Up Protection
    if (!config.hasWakeupRateLimit) {
      findings.push({ ...this.RULES[3], status: 'FAIL', current: 'No Wake-Up Pulse Rate Limiting' });
      deduction += this.RULES[3].weight;
    } else {
      findings.push({ ...this.RULES[3], status: 'PASS', current: 'Wake-Up Burst Suppressor Active' });
    }

    // 5. Gateway Ingress Filter
    if (!config.hasGatewayFilter) {
      findings.push({ ...this.RULES[4], status: 'FAIL', current: 'Unfiltered CAN-to-LIN Gateway Routing' });
      deduction += this.RULES[4].weight;
    } else {
      findings.push({ ...this.RULES[4], status: 'PASS', current: 'Stateful Central Gateway Allowlist' });
    }

    // 6. Dominant Clamp Protection
    if (!config.hasTransceiverProtection) {
      findings.push({ ...this.RULES[5], status: 'FAIL', current: 'Standard Transceiver Without Clamp Timeout' });
      deduction += this.RULES[5].weight;
    } else {
      findings.push({ ...this.RULES[5], status: 'PASS', current: 'TXD Dominant Clamp & Thermal Shutdown Enabled' });
    }

    // 7. Parity & Enhanced Checksum
    if (!config.hasEnhancedChecksum) {
      findings.push({ ...this.RULES[6], status: 'FAIL', current: 'Classic Checksum / Lenient Parity Accepted' });
      deduction += this.RULES[6].weight;
    } else {
      findings.push({ ...this.RULES[6], status: 'PASS', current: 'Strict Parity & Enhanced Checksum (LIN 2.x)' });
    }

    // 8. Keyless Entry Encryption
    if (config.hasKeylessEntry && !config.hasKeylessCrypto) {
      findings.push({ ...this.RULES[7], status: 'FAIL', current: 'Unencrypted Keyless Entry Over LIN' });
      deduction += this.RULES[7].weight;
    } else {
      findings.push({ ...this.RULES[7], status: 'PASS', current: 'Encrypted Entry Payload / No Smart Nodes on Bus' });
    }

    // 9. Schedule Monitoring
    if (!config.hasScheduleGuard) {
      findings.push({ ...this.RULES[8], status: 'FAIL', current: 'Unmonitored Master Schedule Jitter' });
      deduction += this.RULES[8].weight;
    } else {
      findings.push({ ...this.RULES[8], status: 'PASS', current: 'Master Slot Jitter Bounded (<1.0 ms)' });
    }

    // 10. IVN-IDS
    if (!config.hasIvnIds) {
      findings.push({ ...this.RULES[9], status: 'FAIL', current: 'No In-Vehicle LIN Bus Intrusion Detection' });
      deduction += this.RULES[9].weight;
    } else {
      findings.push({ ...this.RULES[9], status: 'PASS', current: 'IVN-IDS Payload & Frequency Anomaly Engine Active' });
    }

    const score = Math.max(0, 100 - deduction);
    let posture = 'POOR';
    if (score >= 90) posture = 'EXCELLENT';
    else if (score >= 75) posture = 'GOOD';
    else if (score >= 50) posture = 'MODERATE';

    return {
      score,
      posture,
      findings,
      timestamp: new Date().toISOString()
    };
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { LINSecurityAuditor };
}
