// /opt/foundation-shield/scripts/harvest.js
// Hourly harvester: pull governance events from VPS2 + VPS VRO local logs, POST to FOMCP.
// Runs on VPS Main only (has SSH access to fleet).
'use strict';
const { execSync } = require('child_process');
const http  = require('http');
const fs    = require('fs');

const REMOTE_LOG   = '/var/log/fo-sys/digest.log';
const STATE_FILE   = '/var/log/fo-sys/harvest-state.json';
const SERVERS      = [
  { alias: 'vps2',   name: 'vps2'    },
  { alias: 'vpsvro', name: 'vps-vro' }
];

// Load FOMCP token from .secrets
function loadToken() {
  try {
    const lines = fs.readFileSync('/opt/mcp-server/.secrets', 'utf8').split('\n');
    for (const line of lines) {
      const m = line.match(/^(FOMCP_TOKEN|MCP_API_TOKEN)=(.*)$/);
      if (m) return m[2].replace(/^['"]|['"]$/g, '');
    }
  } catch (_) {}
  return null;
}

// Load harvest state (tracks byte offset per server to avoid re-importing)
function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch { return {}; }
}

function saveState(state) {
  try { fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2)); } catch (_) {}
}

// SSH pull lines from remote log since last offset
function pullRemoteLog(server, offset) {
  try {
    const cmd = `ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no ${server.alias} ` +
                `"tail -c +${offset + 1} ${REMOTE_LOG} 2>/dev/null"`;
    const out = execSync(cmd, { timeout: 30000, encoding: 'utf8' });
    return out;
  } catch { return ''; }
}

// Get remote file size for next offset
function getRemoteSize(server) {
  try {
    const out = execSync(
      `ssh -o ConnectTimeout=10 ${server.alias} "stat -c %s ${REMOTE_LOG} 2>/dev/null || echo 0"`,
      { timeout: 10000, encoding: 'utf8' }
    );
    return parseInt(out.trim()) || 0;
  } catch { return 0; }
}

// Parse NDJSON lines into event objects
function parseEvents(rawText, serverName) {
  const events = [];
  for (const line of rawText.split('\n')) {
    if (!line.trim()) continue;
    try {
      const obj = JSON.parse(line);
      if (obj.level === 'ALERT') {
        events.push({
          server:     serverName,
          check_type: obj.check_type || obj.key?.split('_')[0] || 'unknown',
          severity:   obj.severity   || 'info',
          alert_key:  obj.key        || 'unknown',
          message:    obj.msg        || '',
          source:     'harvest',
          fired_at:   obj.ts         || new Date().toISOString()
        });
      }
    } catch (_) {}
  }
  return events;
}

// POST bulk events to FOMCP
function postBulk(events, token) {
  return new Promise((resolve) => {
    if (!token || !events.length) return resolve(0);
    const body = JSON.stringify({ events });
    const req = http.request({
      hostname: '127.0.0.1',
      port: 4500,
      path: '/api/governance/events/bulk',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Authorization': `Bearer ${token}`
      }
    }, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data).inserted || 0); } catch { resolve(0); }
      });
    });
    req.setTimeout(15000, () => { req.destroy(); resolve(0); });
    req.on('error', () => resolve(0));
    req.write(body);
    req.end();
  });
}

async function main() {
  const token = loadToken();
  if (!token) {
    console.error('[harvest] No FOMCP token found in .secrets');
    process.exit(1);
  }

  const state = loadState();
  let totalImported = 0;

  for (const server of SERVERS) {
    const offset = state[server.name] || 0;
    const newSize = getRemoteSize(server);

    if (newSize <= offset) {
      console.log(`[harvest] ${server.name}: no new data (size=${newSize}, offset=${offset})`);
      continue;
    }

    const raw = pullRemoteLog(server, offset);
    if (!raw.trim()) {
      state[server.name] = newSize;
      continue;
    }

    const events = parseEvents(raw, server.name);
    if (events.length) {
      const imported = await postBulk(events, token);
      totalImported += imported;
      console.log(`[harvest] ${server.name}: ${imported}/${events.length} events imported`);
    }

    state[server.name] = newSize;
  }

  saveState(state);
  console.log(`[harvest] Done. Total imported: ${totalImported}`);
}

main().catch(err => {
  console.error('[harvest] Fatal:', err.message);
  process.exit(1);
});
