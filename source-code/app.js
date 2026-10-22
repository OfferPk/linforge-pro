/**
 * LINForge Pro - Web Application Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  const engine = new LINEngine();
  const auditor = new LINSecurityAuditor();
  const synthesizer = new LINConfigSynthesizer();

  // Presets
  const PRESETS = {
    door_status: engine.buildFrame(0x20, new Uint8Array([0x12, 0x85, 0x00, 0x4A]), true).hexString,
    hvac_flap: engine.buildFrame(0x24, new Uint8Array([0x50, 0x28, 0x01, 0xFF]), true).hexString,
    diag_req: engine.buildMasterDiagnosticRequest(0x01, 0x22, [0xF1, 0x90]).hexString,
    diag_resp: engine.buildSlaveDiagnosticResponse(0x01, 0x62, [0xF1, 0x90, 0x44, 0x31]).hexString,
    steering_sw: engine.buildFrame(0x18, new Uint8Array([0x04, 0x00, 0x80]), true).hexString
  };

  // Tab switching
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabPanels = document.querySelectorAll('.tab-panel');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      tabPanels.forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const target = document.getElementById(btn.getAttribute('data-tab'));
      if (target) target.classList.add('active');
    });
  });

  // Preset selector
  const presetSelector = document.getElementById('preset-selector');
  const hexInput = document.getElementById('hex-input');

  presetSelector.addEventListener('change', () => {
    const val = presetSelector.value;
    if (PRESETS[val]) {
      hexInput.value = PRESETS[val];
      runDissection();
    }
  });

  // Dissector button
  document.getElementById('btn-dissect').addEventListener('click', runDissection);
  document.getElementById('btn-clear-hex').addEventListener('click', () => {
    hexInput.value = '';
    document.getElementById('dissection-output').innerHTML = '<p style="color: var(--text-muted);">Cleared.</p>';
  });

  function runDissection() {
    const hex = hexInput.value.trim();
    if (!hex) return;
    const output = document.getElementById('dissection-output');
    try {
      const bytes = engine.hexToBytes(hex);
      const res = engine.dissect(bytes);

      let html = `
        <div class="tree-node"><span class="tree-key">Protocol:</span> <span class="tree-val">${res.protocol}</span></div>
        <div class="tree-node"><span class="tree-key">Sync Field:</span> <span class="tree-val">${res.syncByte}</span></div>
        <div class="tree-node">
          <span class="tree-key">Protected Identifier (PID):</span> <span class="tree-val">${res.pid.raw}</span><br>
          &nbsp;&nbsp;Frame ID: <span class="tree-val">${res.pid.frameId} (${res.pid.frameIdHex})</span><br>
          &nbsp;&nbsp;Parity Bits: <span class="tree-val">P0=${res.pid.p0}, P1=${res.pid.p1}</span><br>
          &nbsp;&nbsp;Parity Status: <span class="badge ${res.pid.isValidParity ? 'badge-emerald' : 'badge-rose'}">${res.pid.isValidParity ? 'VALID' : 'PARITY ERROR'}</span>
        </div>
        <div class="tree-node">
          <span class="tree-key">Data Payload (${res.dataLength} Bytes):</span><br>
          &nbsp;&nbsp;Hex: <code>${res.dataHex}</code>
        </div>
        <div class="tree-node">
          <span class="tree-key">Checksum Field:</span><br>
          &nbsp;&nbsp;Received: <span class="tree-val">${res.checksum.received}</span> | Expected: <span class="tree-val">${res.checksum.expected}</span><br>
          &nbsp;&nbsp;Type: <span class="tree-val">${res.checksum.type}</span><br>
          &nbsp;&nbsp;Integrity: <span class="badge ${res.checksum.isValid ? 'badge-emerald' : 'badge-rose'}">${res.checksum.isValid ? 'VALID' : 'CHECKSUM MISMATCH'}</span>
        </div>
      `;

      if (res.classification) {
        html += `
          <div class="tree-node">
            <span class="tree-key">Classification:</span> <span class="tree-val" style="color:#38bdf8; font-weight:700;">${res.classification.type}</span>
            ${res.classification.service ? `<br>&nbsp;&nbsp;Service: <strong>${res.classification.service}</strong> (${res.classification.sidHex})` : ''}
            ${res.classification.nad ? `<br>&nbsp;&nbsp;Target NAD: <code>${res.classification.nad}</code>` : ''}
          </div>
        `;
      }

      output.innerHTML = html;
    } catch (e) {
      output.innerHTML = `<p style="color: var(--accent-rose); font-weight:600;">Dissection Error: ${e.message}</p>`;
    }
  }

  // Initial load
  hexInput.value = PRESETS.door_status;
  runDissection();

  // Frame Builder
  document.getElementById('btn-synthesize-frame').addEventListener('click', () => {
    const id = parseInt(document.getElementById('builder-frame-id').value, 10) || 0;
    const isEnhanced = document.getElementById('builder-checksum-mode').value === 'enhanced';
    const dataHex = document.getElementById('builder-data').value;
    const dataBytes = engine.hexToBytes(dataHex);

    const f = engine.buildFrame(id, dataBytes, isEnhanced);
    document.getElementById('frame-hex-output').innerText = f.hexString;

    const pidAudit = engine.verifyPID(f.pid);
    document.getElementById('pid-breakdown').innerHTML = `
      <div><strong>Frame ID:</strong> ${id} (0x${id.toString(16).toUpperCase()})</div>
      <div><strong>Calculated PID:</strong> 0x${f.pid.toString(16).toUpperCase()}</div>
      <div><strong>Parity Bits:</strong> P0 = ${pidAudit.p0}, P1 = ${pidAudit.p1}</div>
      <div><strong>Checksum:</strong> 0x${f.checksum.toString(16).toUpperCase()} (${isEnhanced ? 'Enhanced' : 'Classic'})</div>
    `;
  });

  // Diagnostic Builder
  document.getElementById('btn-build-diag').addEventListener('click', () => {
    const isReq = document.getElementById('diag-type').value === 'req';
    const nad = parseInt(document.getElementById('diag-nad').value, 16) || 0x01;
    const sid = parseInt(document.getElementById('diag-sid').value, 16) || 0x22;
    const params = engine.hexToBytes(document.getElementById('diag-params').value);

    let f;
    if (isReq) {
      f = engine.buildMasterDiagnosticRequest(nad, sid, Array.from(params));
    } else {
      f = engine.buildSlaveDiagnosticResponse(nad, sid, Array.from(params));
    }

    document.getElementById('diag-hex-output').innerText = f.hexString;
    document.getElementById('diag-breakdown').innerHTML = `
      <div><strong>Frame:</strong> ${isReq ? 'Master Request (0x3C)' : 'Slave Response (0x7D)'}</div>
      <div><strong>NAD:</strong> 0x${nad.toString(16).toUpperCase()} | <strong>SID/RSID:</strong> 0x${sid.toString(16).toUpperCase()}</div>
      <div><strong>PCI Length:</strong> ${1 + params.length} bytes (Single Frame)</div>
      <div><strong>Checksum:</strong> 0x${f.checksum.toString(16).toUpperCase()} (Classic Mandatory)</div>
    `;
  });

  // LDF Parser
  document.getElementById('btn-parse-ldf').addEventListener('click', () => {
    const text = document.getElementById('ldf-text').value;
    const ldf = engine.parseLDF(text);

    let html = `
      <div class="tree-node"><span class="tree-key">LIN Protocol:</span> <span class="tree-val">${ldf.protocolVersion} (${ldf.baudRateKbps} kbps)</span></div>
      <div class="tree-node"><span class="tree-key">Master Node:</span> <span class="tree-val">${ldf.masterNode}</span></div>
      <div class="tree-node"><span class="tree-key">Slave Nodes (${ldf.slaveNodes.length}):</span> <span class="tree-val">${ldf.slaveNodes.join(', ')}</span></div>
      <div class="tree-node"><span class="tree-key">Configured Signals (${ldf.signals.length}):</span>
    `;
    ldf.signals.forEach(s => {
      html += `<div style="padding-left:14px;"><strong>${s.name}</strong> (${s.sizeBits} bits, Publisher: ${s.publisher})</div>`;
    });
    html += `</div><div class="tree-node"><span class="tree-key">Configured Frames (${ldf.frames.length}):</span>`;
    ldf.frames.forEach(fr => {
      html += `<div style="padding-left:14px;"><strong>${fr.name}</strong> (ID: 0x${fr.id.toString(16).toUpperCase()}, ${fr.lengthBytes} bytes)</div>`;
    });
    html += `</div>`;

    document.getElementById('ldf-output').innerHTML = html;
  });

  // Initial LDF Parse
  document.getElementById('btn-parse-ldf').click();

  // PCAP Export
  document.getElementById('btn-export-pcap').addEventListener('click', () => {
    const hex = hexInput.value.trim();
    if (!hex) return;
    const bytes = engine.hexToBytes(hex);
    const dissected = engine.dissect(bytes);
    const pcapBytes = engine.exportPcap([{ frameId: dissected.pid.frameId, dataBytes: engine.hexToBytes(dissected.dataHex) }]);
    downloadBlob(pcapBytes, 'lin-bus-capture.pcap');
  });

  function downloadBlob(bytes, filename) {
    const blob = new Blob([bytes], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  // Security Auditor
  function runAudit() {
    const sampleConfig = {
      hasSecOC: false,
      hasDiagSeedKey: false,
      allowDynamicNAD: true,
      hasWakeupRateLimit: true,
      hasGatewayFilter: true,
      hasTransceiverProtection: true,
      hasEnhancedChecksum: true,
      hasKeylessEntry: true,
      hasKeylessCrypto: false,
      hasScheduleGuard: true,
      hasIvnIds: false
    };

    const res = auditor.auditConfiguration(sampleConfig);
    document.getElementById('audit-score').innerText = res.score;
    document.getElementById('audit-posture').innerText = `${res.posture} POSTURE`;

    const tbody = document.getElementById('audit-tbody');
    tbody.innerHTML = res.findings.map(f => `
      <tr>
        <td><code>${f.id}</code></td>
        <td><strong>${f.title}</strong></td>
        <td><small>${f.standard}</small></td>
        <td><span class="badge ${f.severity === 'CRITICAL' ? 'badge-rose' : f.severity === 'HIGH' ? 'badge-amber' : 'badge-blue'}">${f.severity}</span></td>
        <td><span class="badge ${f.status === 'PASS' ? 'badge-emerald' : 'badge-rose'}">${f.status}</span></td>
        <td><small>${f.remediation}</small></td>
      </tr>
    `).join('');
  }

  document.getElementById('btn-run-audit').addEventListener('click', runAudit);
  runAudit();

  // Gateway & IDS
  document.getElementById('gateway-output').innerText = synthesizer.generateGatewayConfig();
  document.getElementById('suricata-output').innerText = synthesizer.generateSuricataRules();
});
