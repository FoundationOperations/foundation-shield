// /opt/foundation-shield/scripts/sentinel-guard.js
// Cross-server heartbeat mesh — every server watches every other server.
// Each server: writes a heartbeat file, checks remote servers via SSH, alerts if silent.
'use strict';
const { execSync } = require('child_process');
const fs   = require('fs');
const path = require('path');
const { alert, info } = require('./alerting.js');

const SERVER_NAME   = process.env.FO_SERVER_NAME || 'vps-main';
const HEARTBEAT_DIR = '/var/log/fo-sys';
const HEARTBEAT_FILE = path.join(HEARTBEAT_DIR, 'heartbeat.json');
const STALE_MINS    = 15;

const FLEET = [
  { name: 'vps-main',  alias: null,     heartbeatPath: '/var/log/fo-sys/heartbeat.json' },
  { name: 'vps2',      alias: 'vps2',   heartbeatPath: '/var/log/fo-sys/heartbeat.json' },
  { name: 'vps-vro',   alias: 'vpsvro', heartbeatPath: '/var/log/fo-sys/heartbeat.json' },
];

function run(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 15000 }).trim(); } catch { return null; }
}

function writeHeartbeat() {
  const data = { server: SERVER_NAME, ts: new Date().toISOString(), pid: process.pid };
  try { fs.writeFileSync(HEARTBEAT_FILE, JSON.stringify(data)); } catch (_) {}
}

function readRemoteHeartbeat(server) {
  if (!server.alias) {
    try { return JSON.parse(fs.readFileSync(server.heartbeatPath, 'utf8')); } catch { return null; }
  }
  const out = run(`ssh -o ConnectTimeout=8 -o StrictHostKeyChecking=no ${server.alias} "cat ${server.heartbeatPath} 2>/dev/null"`);
  if (!out) return null;
  try { return JSON.parse(out); } catch { return null; }
}

async function main() {
  writeHeartbeat();

  for (const server of FLEET) {
    if (server.name === SERVER_NAME) continue;

    const hb = readRemoteHeartbeat(server);
    if (!hb) {
      await alert(`sentinel_unreachable_${server.name}`,
        `🔴 *Sentinel: ${server.name} UNREACHABLE*\nCannot SSH to ${server.name} — server may be down or SSH is blocked.`,
        { check_type: 'sentinel_heartbeat', severity: 'critical', playbook: `ping ${server.alias || server.name} && ssh ${server.alias || server.name} uptime` }
      );
      continue;
    }

    const ageMins = (Date.now() - new Date(hb.ts).getTime()) / 60000;
    if (ageMins > STALE_MINS) {
      await alert(`sentinel_stale_${server.name}`,
        `⏰ *Sentinel: ${server.name} heartbeat stale* — ${Math.round(ageMins)} minutes old\nFoundationShield on ${server.name} may have stopped running.`,
        { check_type: 'sentinel_heartbeat', severity: 'critical', playbook: `ssh ${server.alias || server.name} "systemctl status fo-sysmon.timer && journalctl -u fo-sysmon.service --since '30 minutes ago'"` }
      );
    }
  }

  await info(`sentinel-guard: heartbeat written, ${FLEET.length - 1} peers checked`, { key: 'sentinel_run', check_type: 'heartbeat' });
}

main().catch(err => { console.error('[sentinel-guard] fatal:', err.message); process.exit(1); });
