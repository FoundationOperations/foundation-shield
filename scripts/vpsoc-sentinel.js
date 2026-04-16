// /opt/foundation-shield/scripts/vpsoc-sentinel.js
// VPSOC dark sentinel — watches VPS Main, VPS2, VPS VRO via SSH heartbeat.
// Uses a SEPARATE Telegram bot token — completely independent alert path.
// Runs ONLY on VPSOC. No FOMCP dependency.
'use strict';
const { execSync } = require('child_process');
const https = require('https');
const fs    = require('fs');

// Load VPSOC-specific credentials from env file
const ENV = (() => {
  const e = {};
  try {
    fs.readFileSync('/etc/fo-sys/env', 'utf8').split('\n').forEach(l => {
      const m = l.match(/^([A-Z_]+)=(.*)$/);
      if (m) e[m[1]] = m[2];
    });
  } catch (_) {}
  return e;
})();

const BOT_TOKEN = process.env.FO_SENTINEL_BOT_TOKEN || ENV.FO_SENTINEL_BOT_TOKEN;
const CHAT_ID   = process.env.FO_SENTINEL_CHAT_ID   || ENV.FO_SENTINEL_CHAT_ID;
const STALE_MINS = 15;

const FLEET = [
  { name: 'vps-main',  alias: 'vpsmain', heartbeatPath: '/var/log/fo-sys/heartbeat.json' },
  { name: 'vps2',      alias: 'vps2',    heartbeatPath: '/var/log/fo-sys/heartbeat.json' },
  { name: 'vps-vro',   alias: 'vpsvro',  heartbeatPath: '/var/log/fo-sys/heartbeat.json' },
];

const COOLDOWN_DIR  = '/tmp/fo-vpsoc-cooldowns';
const COOLDOWN_SECS = 1800;

try { fs.mkdirSync(COOLDOWN_DIR, { recursive: true }); } catch (_) {}

function inCooldown(key) {
  const f = `${COOLDOWN_DIR}/${key.replace(/[^a-z0-9_]/gi, '_')}`;
  try {
    if (!fs.existsSync(f)) return false;
    const last = parseInt(fs.readFileSync(f, 'utf8').trim());
    return !isNaN(last) && (Math.floor(Date.now() / 1000) - last) < COOLDOWN_SECS;
  } catch { return false; }
}

function setCooldown(key) {
  try { fs.writeFileSync(`${COOLDOWN_DIR}/${key.replace(/[^a-z0-9_]/gi, '_')}`, String(Math.floor(Date.now() / 1000))); } catch (_) {}
}

function sendTelegram(message) {
  return new Promise((resolve) => {
    if (!BOT_TOKEN || !CHAT_ID) { console.log('[vpsoc] No bot token configured — would send:', message); return resolve(); }
    const body = JSON.stringify({ chat_id: CHAT_ID, text: message, parse_mode: 'Markdown' });
    const req = https.request({
      hostname: 'api.telegram.org',
      path: `/bot${BOT_TOKEN}/sendMessage`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, res => { res.resume(); res.on('end', resolve); });
    req.setTimeout(10000, () => { req.destroy(); resolve(); });
    req.on('error', () => resolve());
    req.write(body);
    req.end();
  });
}

function readHeartbeat(server) {
  try {
    const out = execSync(
      `ssh -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o BatchMode=yes ${server.alias} "cat ${server.heartbeatPath} 2>/dev/null"`,
      { encoding: 'utf8', timeout: 15000 }
    ).trim();
    return out ? JSON.parse(out) : null;
  } catch { return null; }
}

async function main() {
  let allHealthy = true;

  for (const server of FLEET) {
    const hb = readHeartbeat(server);
    const key = `vpsoc_sentinel_${server.name}`;

    if (!hb) {
      allHealthy = false;
      if (!inCooldown(key)) {
        await sendTelegram(`🔴 *DARK SENTINEL ALERT*\n*${server.name}* is UNREACHABLE\nCannot read heartbeat via SSH — server may be down.\n\n_Sent from VPSOC independent sentinel_`);
        setCooldown(key);
      }
      console.error(`[vpsoc] ${server.name}: UNREACHABLE`);
      continue;
    }

    const ageMins = (Date.now() - new Date(hb.ts).getTime()) / 60000;
    if (ageMins > STALE_MINS) {
      allHealthy = false;
      if (!inCooldown(key)) {
        await sendTelegram(`⏰ *DARK SENTINEL ALERT*\n*${server.name}* heartbeat is STALE — ${Math.round(ageMins)} minutes old\nFoundationShield governance scripts may have stopped.\n\n_Sent from VPSOC independent sentinel_`);
        setCooldown(key);
      }
      console.log(`[vpsoc] ${server.name}: STALE (${Math.round(ageMins)}min)`);
    } else {
      console.log(`[vpsoc] ${server.name}: OK (${Math.round(ageMins * 60)}s ago)`);
    }
  }

  if (allHealthy) {
    console.log('[vpsoc] All fleet servers healthy');
  }
}

main().catch(err => { console.error('[vpsoc-sentinel] fatal:', err.message); process.exit(1); });
