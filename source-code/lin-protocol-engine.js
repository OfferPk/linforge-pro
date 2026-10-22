/**
 * LINForge Pro - Automotive Local Interconnect Network Protocol Engine
 * Standards: LIN 2.2A, LIN 2.1, ISO 17987-1:2016, SAE J2602
 * Author: Autonomous Digital Product Factory (Product #165)
 * Version: 1.0.0
 */

class LINEngine {
  constructor() {
    this.SYNC_BYTE = 0x55;

    // Special Frame IDs
    this.FRAME_IDS = {
      DIAG_MASTER_REQ: 0x3C, // 60 (PID 0x3C)
      DIAG_SLAVE_RESP: 0x3D, // 61 (PID 0x7D)
      USER_DEFINED: 0x3E,    // 62 (PID 0xFE)
      RESERVED: 0x3F         // 63 (PID 0xBF)
    };

    // Diagnostic Service IDs (SID)
    this.DIAG_SERVICES = {
      ASSIGN_NAD: 0xB0,
      ASSIGN_FRAME_ID: 0xB1,
      READ_BY_IDENTIFIER: 0xB2,
      CONDITIONAL_CHANGE_NAD: 0xB3,
      DATA_DUMP: 0xB4,
      SAVE_CONFIGURATION: 0xB6,
      ASSIGN_FRAME_ID_RANGE: 0xB7,
      // UDS Services over LIN
      DIAG_SESSION_CONTROL: 0x10,
      ECU_RESET: 0x11,
      READ_DATA_BY_ID: 0x22,
      WRITE_DATA_BY_ID: 0x2E,
      SECURITY_ACCESS: 0x27,
      TESTER_PRESENT: 0x3E
    };

    // Pre-configured automotive LIN ECU profiles
    this.AUTOMOTIVE_PRESETS = {
      DOOR_CONTROL: {
        id: 0x20,
        name: 'DoorControl_Status',
        publisher: 'DoorECU',
        data: [0x12, 0x85, 0x00, 0x4A],
        desc: 'Window Position, Mirror Angle & Door Lock Status'
      },
      HVAC_CLIMATE: {
        id: 0x24,
        name: 'HVAC_FlapActuator',
        publisher: 'ClimateECU',
        data: [0x50, 0x28, 0x01, 0xFF],
        desc: 'Flap Position Setpoint, Blower Speed & Temp Sensor'
      },
      STEERING_SWITCH: {
        id: 0x18,
        name: 'SteeringWheel_Buttons',
        publisher: 'SteeringECU',
        data: [0x04, 0x00, 0x80],
        desc: 'Volume Up/Down, Cruise Control, Voice Button State'
      },
      RAIN_LIGHT_SENSOR: {
        id: 0x22,
        name: 'RainLight_Sensor',
        publisher: 'RLS_Node',
        data: [0xA0, 0x3C],
        desc: 'Wiper Speed Demand, Ambient Solar Lux Intensity'
      }
    };
  }

  // --- Helper Methods ---
  hexToBytes(hex) {
    if (!hex) return new Uint8Array(0);
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
      bytes[i / 2] = parseInt(clean.substr(i, 2), 16);
    }
    return bytes;
  }

  bytesToHex(bytes, sep = ' ') {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(sep);
  }

  // --- Protected Identifier (PID) Calculation ---
  calculatePID(frameId) {
    if (frameId < 0 || frameId > 63) {
      throw new Error(`Frame ID out of range (0..63): ${frameId}`);
    }
    const id0 = (frameId >> 0) & 1;
    const id1 = (frameId >> 1) & 1;
    const id2 = (frameId >> 2) & 1;
    const id3 = (frameId >> 3) & 1;
    const id4 = (frameId >> 4) & 1;
    const id5 = (frameId >> 5) & 1;

    // P0 = ID0 ^ ID1 ^ ID2 ^ ID4
    const p0 = id0 ^ id1 ^ id2 ^ id4;
    // P1 = !(ID1 ^ ID3 ^ ID4 ^ ID5)
    const p1 = (id1 ^ id3 ^ id4 ^ id5) ? 0 : 1;

    return (frameId & 0x3F) | (p0 << 6) | (p1 << 7);
  }

  verifyPID(pid) {
    const frameId = pid & 0x3F;
    const expectedPid = this.calculatePID(frameId);
    const isValid = (pid === expectedPid);
    return {
      frameId,
      expectedPid,
      isValid,
      p0: (pid >> 6) & 1,
      p1: (pid >> 7) & 1
    };
  }

  // --- Checksum Calculation (Classic & Enhanced) ---
  calculateChecksum(dataBytes, pid = null, isEnhanced = true) {
    let acc = 0;

    // Enhanced Checksum includes PID; Diagnostic frames (0x3C, 0x3D) always use Classic
    const frameId = pid !== null ? (pid & 0x3F) : null;
    const forceClassic = (frameId === this.FRAME_IDS.DIAG_MASTER_REQ || frameId === this.FRAME_IDS.DIAG_SLAVE_RESP);

    if (isEnhanced && pid !== null && !forceClassic) {
      acc = pid;
    }

    for (let i = 0; i < dataBytes.length; i++) {
      acc += dataBytes[i];
      if (acc > 255) {
        acc = (acc & 0xFF) + 1; // Carry wrap-around
      }
    }

    return (~acc) & 0xFF;
  }

  verifyChecksum(dataBytes, pid, receivedChecksum, isEnhanced = true) {
    const calc = this.calculateChecksum(dataBytes, pid, isEnhanced);
    return {
      expected: calc,
      received: receivedChecksum,
      isValid: (calc === receivedChecksum),
      mode: (isEnhanced && (pid & 0x3F) !== 0x3C && (pid & 0x3F) !== 0x3D) ? 'ENHANCED (LIN 2.x / ISO 17987)' : 'CLASSIC (LIN 1.3 / Diagnostic)'
    };
  }

  // --- LIN Frame Synthesis ---
  buildFrame(frameId, dataBytes, isEnhanced = true) {
    if (dataBytes.length < 1 || dataBytes.length > 8) {
      throw new Error(`Invalid LIN data length: ${dataBytes.length} bytes (must be 1..8)`);
    }
    const pid = this.calculatePID(frameId);
    const checksum = this.calculateChecksum(dataBytes, pid, isEnhanced);

    // Full frame byte sequence: [Sync (0x55), PID, Data[0..N-1], Checksum]
    const frame = new Uint8Array(2 + dataBytes.length + 1);
    frame[0] = this.SYNC_BYTE;
    frame[1] = pid;
    frame.set(dataBytes, 2);
    frame[2 + dataBytes.length] = checksum;

    return {
      frameId,
      pid,
      dataBytes,
      checksum,
      rawBytes: frame,
      hexString: this.bytesToHex(frame)
    };
  }

  // --- Diagnostic Transport Layer Frame (0x3C / 0x3D) ---
  buildMasterDiagnosticRequest(nad, sid, params = [], padByte = 0xFF) {
    // 8 data bytes: [NAD, PCI, SID, D1, D2, D3, D4, D5]
    const data = new Uint8Array(8);
    data.fill(padByte);

    data[0] = nad;
    const length = 1 + params.length; // SID + parameters
    data[1] = length & 0x0F;          // Single Frame PCI (0x01..0x06)
    data[2] = sid;

    for (let i = 0; i < params.length && (3 + i) < 8; i++) {
      data[3 + i] = params[i];
    }

    return this.buildFrame(this.FRAME_IDS.DIAG_MASTER_REQ, data, false); // Always Classic Checksum
  }

  buildSlaveDiagnosticResponse(nad, rsid, respData = [], padByte = 0xFF) {
    const data = new Uint8Array(8);
    data.fill(padByte);

    data[0] = nad;
    const length = 1 + respData.length;
    data[1] = length & 0x0F;
    data[2] = rsid;

    for (let i = 0; i < respData.length && (3 + i) < 8; i++) {
      data[3 + i] = respData[i];
    }

    return this.buildFrame(this.FRAME_IDS.DIAG_SLAVE_RESP, data, false);
  }

  // --- Comprehensive Dissector ---
  dissect(rawBytes) {
    if (rawBytes.length < 4) {
      throw new Error(`Packet length ${rawBytes.length} is too short for a LIN frame (minimum 4 bytes: Sync + PID + 1 Data + Checksum).`);
    }

    let offset = 0;
    let hasSync = false;

    // Check if frame starts with Sync 0x55
    if (rawBytes[0] === this.SYNC_BYTE) {
      hasSync = true;
      offset = 1;
    }

    const pid = rawBytes[offset++];
    const pidMeta = this.verifyPID(pid);

    if (rawBytes.length <= offset + 1) {
      throw new Error(`Missing data and checksum bytes in LIN frame.`);
    }

    const dataLen = rawBytes.length - offset - 1;
    if (dataLen > 8) {
      throw new Error(`LIN data length ${dataLen} exceeds standard maximum of 8 bytes.`);
    }

    const dataBytes = rawBytes.slice(offset, offset + dataLen);
    const receivedChecksum = rawBytes[rawBytes.length - 1];

    // Determine checksum mode
    const isDiag = (pidMeta.frameId === this.FRAME_IDS.DIAG_MASTER_REQ || pidMeta.frameId === this.FRAME_IDS.DIAG_SLAVE_RESP);
    const checksumAudit = this.verifyChecksum(dataBytes, pid, receivedChecksum, !isDiag);

    const result = {
      protocol: 'LIN (Local Interconnect Network - ISO 17987 / LIN 2.2A)',
      syncByte: hasSync ? `0x${this.SYNC_BYTE.toString(16).toUpperCase()} (Valid Sync)` : 'Omitted / Truncated',
      pid: {
        raw: `0x${pid.toString(16).padStart(2, '0').toUpperCase()}`,
        frameId: pidMeta.frameId,
        frameIdHex: `0x${pidMeta.frameId.toString(16).padStart(2, '0').toUpperCase()}`,
        p0: pidMeta.p0,
        p1: pidMeta.p1,
        isValidParity: pidMeta.isValid
      },
      dataLength: dataLen,
      dataHex: this.bytesToHex(dataBytes),
      checksum: {
        received: `0x${receivedChecksum.toString(16).padStart(2, '0').toUpperCase()}`,
        expected: `0x${checksumAudit.expected.toString(16).padStart(2, '0').toUpperCase()}`,
        isValid: checksumAudit.isValid,
        type: checksumAudit.mode
      },
      classification: this.classifyFrame(pidMeta.frameId, dataBytes)
    };

    return result;
  }

  classifyFrame(frameId, dataBytes) {
    if (frameId === this.FRAME_IDS.DIAG_MASTER_REQ) {
      const nad = dataBytes[0];
      const pci = dataBytes[1];
      const sid = dataBytes[2];
      const sName = Object.keys(this.DIAG_SERVICES).find(k => this.DIAG_SERVICES[k] === sid) || `SID_0x${sid.toString(16).toUpperCase()}`;
      return {
        type: 'DIAGNOSTIC_MASTER_REQUEST',
        nad: `0x${nad.toString(16).padStart(2, '0').toUpperCase()}`,
        pci: `0x${pci.toString(16).padStart(2, '0').toUpperCase()}`,
        service: sName,
        sidHex: `0x${sid.toString(16).padStart(2, '0').toUpperCase()}`,
        payload: this.bytesToHex(dataBytes.slice(3))
      };
    } else if (frameId === this.FRAME_IDS.DIAG_SLAVE_RESP) {
      const nad = dataBytes[0];
      const pci = dataBytes[1];
      const rsid = dataBytes[2];
      const isNegative = (rsid === 0x7F);
      return {
        type: 'DIAGNOSTIC_SLAVE_RESPONSE',
        nad: `0x${nad.toString(16).padStart(2, '0').toUpperCase()}`,
        pci: `0x${pci.toString(16).padStart(2, '0').toUpperCase()}`,
        rsidHex: `0x${rsid.toString(16).padStart(2, '0').toUpperCase()}`,
        isNegativeResponse: isNegative,
        payload: this.bytesToHex(dataBytes.slice(3))
      };
    } else if (frameId >= 0 && frameId <= 59) {
      return {
        type: 'UNCONDITIONAL_SIGNAL_FRAME',
        category: 'Standard Process Data / Signal Frame'
      };
    } else if (frameId === this.FRAME_IDS.USER_DEFINED) {
      return { type: 'USER_DEFINED_FRAME', category: 'OEM Custom Extension' };
    }
    return { type: 'RESERVED_FRAME', category: 'Reserved' };
  }

  // --- Minimal LDF Parser & Validator ---
  parseLDF(ldfContent) {
    const result = {
      protocolVersion: '2.2',
      baudRateKbps: 19.2,
      masterNode: null,
      slaveNodes: [],
      signals: [],
      frames: [],
      scheduleTables: [],
      errors: []
    };

    const lines = ldfContent.split('\n');
    let currentSection = null;

    for (let rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('//')) continue;

      if (line.includes('LIN_protocol_version')) {
        const m = line.match(/"([^"]+)"/);
        if (m) result.protocolVersion = m[1];
      } else if (line.includes('LIN_speed')) {
        const m = line.match(/([0-9.]+)\s*kbps/i);
        if (m) result.baudRateKbps = parseFloat(m[1]);
      } else if (line.startsWith('Nodes {')) {
        currentSection = 'NODES';
      } else if (line.startsWith('Signals {')) {
        currentSection = 'SIGNALS';
      } else if (line.startsWith('Frames {')) {
        currentSection = 'FRAMES';
      } else if (line.startsWith('Schedule_tables {')) {
        currentSection = 'SCHEDULES';
      } else if (line === '}') {
        currentSection = null;
      } else if (currentSection === 'NODES') {
        if (line.startsWith('Master:')) {
          const parts = line.replace('Master:', '').split(',');
          if (parts.length > 0) result.masterNode = parts[0].trim();
        } else if (line.startsWith('Slaves:')) {
          const slaves = line.replace('Slaves:', '').replace(';', '').split(',');
          result.slaveNodes = slaves.map(s => s.trim()).filter(Boolean);
        }
      } else if (currentSection === 'SIGNALS') {
        // e.g. WindowPosition: 8, 0, DriverDoor, BCM;
        const parts = line.replace(';', '').split(':');
        if (parts.length === 2) {
          const sName = parts[0].trim();
          const sProps = parts[1].split(',').map(p => p.trim());
          result.signals.push({
            name: sName,
            sizeBits: parseInt(sProps[0], 10) || 8,
            initValue: sProps[1] || '0',
            publisher: sProps[2] || '',
            subscribers: sProps.slice(3)
          });
        }
      } else if (currentSection === 'FRAMES') {
        // e.g. DoorStatus: 0x20, DriverDoor, 4 {
        const m = line.match(/([a-zA-Z0-9_]+)\s*:\s*(0x[0-9a-fA-F]+|[0-9]+)\s*,\s*([a-zA-Z0-9_]+)\s*,\s*([0-9]+)/);
        if (m) {
          result.frames.push({
            name: m[1],
            id: m[2].startsWith('0x') ? parseInt(m[2], 16) : parseInt(m[2], 10),
            publisher: m[3],
            lengthBytes: parseInt(m[4], 10)
          });
        }
      }
    }

    return result;
  }

  // --- Libpcap 2.4 Exporter ---
  exportPcap(frames) {
    const gh = new Uint8Array(24);
    const gv = new DataView(gh.buffer);
    gv.setUint32(0, 0xa1b2c3d4, false); // Big Endian magic
    gv.setUint16(4, 2, false);          // Major version 2
    gv.setUint16(6, 4, false);          // Minor version 4
    gv.setInt32(8, 0, false);           // Timezone
    gv.setUint32(12, 0, false);         // Sigfigs
    gv.setUint32(16, 65535, false);     // Snaplen
    gv.setUint32(20, 227, false);       // Linktype = 227 (LINKTYPE_CAN_SOCKETCAN)

    const chunks = [gh];
    let timestampSec = 1791244800; // 2026-10-05T00:00:00Z
    let timestampUsec = 100000;

    for (const f of frames) {
      // Synthesize SocketCAN CAN/LIN frame representation (16 bytes)
      // CAN ID (4B) + DLC (1B) + Pad (3B) + Data (8B)
      const canFrame = new Uint8Array(16);
      const cv = new DataView(canFrame.buffer);
      cv.setUint32(0, f.frameId & 0x7FF, false); // Standard 11-bit CAN/LIN ID
      canFrame[4] = f.dataBytes.length;          // Length
      for (let i = 0; i < f.dataBytes.length && i < 8; i++) {
        canFrame[8 + i] = f.dataBytes[i];
      }

      const ph = new Uint8Array(16);
      const pv = new DataView(ph.buffer);
      pv.setUint32(0, timestampSec, false);
      pv.setUint32(4, timestampUsec, false);
      pv.setUint32(8, canFrame.length, false);
      pv.setUint32(12, canFrame.length, false);

      chunks.push(ph);
      chunks.push(canFrame);

      timestampUsec += 10000; // 10ms frame intervals
      if (timestampUsec >= 1000000) {
        timestampSec += 1;
        timestampUsec = 0;
      }
    }

    let totalLen = 0;
    for (const c of chunks) totalLen += c.length;
    const finalPcap = new Uint8Array(totalLen);
    let offset = 0;
    for (const c of chunks) {
      finalPcap.set(c, offset);
      offset += c.length;
    }
    return finalPcap;
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { LINEngine };
}
