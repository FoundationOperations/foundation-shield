// /opt/foundation-shield/scripts/pm2-governance.js
// Checks 1-5: Process & Port governance
// Check 1: Dual-daemon port collision   Check 4: Orphaned node processes
// Check 2: Port squatters               Check 5: Dead PM2 apps
// Check 3: Unregistered listeners
'use strict';
const { execSync } = require('child_process');
const fs   = require('fs');
const crypto = require('crypto');
const { alert, info } = require('./alerting.js');
const REGISTRY = require('/home/nodeapp/port-registry.js');

const PLAYBOOKS = {
  collision:    'sudo pm2 list && sudo -u nodeapp pm2 list — identify duplicate, pm2 delete <name> on the nodeapp daemon',
  squatter:     'kill -9 <pid> — verify with ss -tlnp after kill',
  unregistered: 'Add port to /home/nodeapp/port-registry.js if legitimate, else kill -9 <pid>',
  orphan:       'kill -9 <pid> or pm2 start if it should be managed',
  pm2_dead:     'pm2 logs <name> --lines 50 --nostream — fix error then pm2 restart <name>'
};

// Orphan allowlist — cmd substrings that are expected unmanaged node processes
// (Claude CLI child processes, MCP stdio servers, etc.)
const ORPHAN_CMD_ALLOWLIST = [
  'playwright-mcp',       // Claude CLI's playwright MCP server (stdio, managed by Claude)
  '@anthropic-ai',        // Any Anthropic CLI tooling
  'claude-code',          // Claude Code internals
  'npx/@playwright',      // npx-spawned playwright
];

function run(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 10000 }).trim(); } catch { return ''; }
}

function getPm2List(asUser) {
  try {
    const cmd = asUser ? `sudo -u ${asUser} pm2 jlist` : 'pm2 jlist';
    return JSON.parse(execSync(cmd, { encoding: 'utf8', timeout: 10000 }));
  } catch { return []; }
}

function getListeners() {
  const map = new Map();
  try {
    for (const line of run('ss -tlnp').split('\n')) {
      const m = line.match(/:(\d+)\s+[\d*:]+\s+users:\(\("([^"]+)",pid=(\d+)/);
      if (m) map.set(parseInt(m[1]), { proc: m[2], pid: parseInt(m[3]) });
    }
  } catch (_) {}
  return map;
}

function getNodePids() {
  const results = [];
  try {
    const uptimeSecs = parseFloat(fs.readFileSync('/proc/uptime', 'utf8').split(' ')[0]);
    for (const entry of fs.readdirSync('/proc')) {
      if (!/^\d+$/.test(entry)) continue;
      const pid = parseInt(entry);
      try {
        const cmdline = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ').trim();
        if (!cmdline.match(/\bnode\b/i)) continue;
        const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
        const m = stat.match(/^\d+ \(.*?\)(?: \S+){19} (\d+)/);
        if (!m) continue;
        results.push({ pid, cmd: cmdline, uptimeSecs: uptimeSecs - parseInt(m[1]) / 100 });
      } catch (_) {}
    }
  } catch (_) {}
  return results;
}

function buildPortMap(apps, daemon) {
  const map = new Map();
  for (const app of apps) {
    const port = parseInt(app.pm2_env?.env?.PORT ?? app.pm2_env?.PORT ?? NaN);
    if (!isNaN(port)) map.set(port, { name: app.name, daemon, status: app.pm2_env?.status, pid: app.pid });
  }
  return map;
}

function collectPm2Pids(apps) { return new Set(apps.map(a => a.pid).filter(Boolean)); }

function getDockerPids() {
  try {
    const ids = run('docker ps -q').split('\n').filter(Boolean);
    if (!ids.length) return new Set();
    const rootPids = run(`docker inspect --format '{{.State.Pid}}' ${ids.join(' ')}`).split('\n').map(Number).filter(Boolean);
    const children = new Map();
    for (const entry of fs.readdirSync('/proc')) {
      if (!/^\d+$/.test(entry)) continue;
      try {
        const status = fs.readFileSync(`/proc/${entry}/status`, 'utf8');
        const m = status.match(/^PPid:\s+(\d+)/m);
        if (!m) continue;
        const ppid = parseInt(m[1]);
        if (!children.has(ppid)) children.set(ppid, []);
        children.get(ppid).push(parseInt(entry));
      } catch (_) {}
    }
    const all = new Set(rootPids);
    const queue = [...rootPids];
    while (queue.length) {
      const pid = queue.shift();
      for (const child of (children.get(pid) || [])) {
        if (!all.has(child)) { all.add(child); queue.push(child); }
      }
    }
    return all;
  } catch { return new Set(); }
}

function getPm2DaemonPids() {
  const pids = new Set();
  try { run('pgrep -f "PM2 v.*God Daemon"').split('\n').map(Number).filter(Boolean).forEach(p => pids.add(p)); } catch (_) {}
  return pids;
}

// Check 1
async function checkDualDaemonCollision(rootPortMap, nodeappPortMap) {
  for (const [port, rootApp] of rootPortMap) {
    if (rootApp.status !== 'online') continue;
    const nodeApp = nodeappPortMap.get(port);
    if (nodeApp?.status === 'online') {
      await alert(`collision_${port}`,
        `⚠️ *Port collision on ${port}*\nRoot PM2: \`${rootApp.name}\` (pid ${rootApp.pid})\nNodeapp PM2: \`${nodeApp.name}\` (pid ${nodeApp.pid})\nBoth daemons online — EADDRINUSE restart loops imminent.`,
        { check_type: 'pm2_collision', severity: 'critical', playbook: PLAYBOOKS.collision }
      );
    }
  }
}

// Check 2
async function checkPortSquatters(rootPortMap, nodeappPortMap, listeners, allPm2Pids, pm2DaemonPids) {
  const allPm2Ports = new Map([...rootPortMap, ...nodeappPortMap]);
  for (const [port, pm2App] of allPm2Ports) {
    const listener = listeners.get(port);
    if (!listener || pm2DaemonPids.has(listener.pid)) continue;
    if (!allPm2Pids.has(listener.pid)) {
      await alert(`squatter_${port}`,
        `🕵️ *Port squatter on ${port}*\nExpected: \`${pm2App.name}\`\nFound: \`${listener.proc}\` (pid ${listener.pid})\nNot tracked by either PM2 daemon.`,
        { check_type: 'port_squatter', severity: 'critical', playbook: PLAYBOOKS.squatter }
      );
    }
  }
}

// Check 3
const UNREGISTERED_EXCLUDE = new Set([3006]);
async function checkUnregisteredListeners(listeners, registryPorts) {
  for (const [port, listener] of listeners) {
    if (port < 3000 || port > 9090 || UNREGISTERED_EXCLUDE.has(port) || registryPorts.has(port)) continue;
    await alert(`unregistered_${port}`,
      `🔍 *Unregistered port ${port}*\nProcess: \`${listener.proc}\` (pid ${listener.pid})\nNot in /home/nodeapp/port-registry.js — add or investigate.`,
      { check_type: 'unregistered_listener', severity: 'high', playbook: PLAYBOOKS.unregistered }
    );
  }
}

// Check 4
async function checkOrphanedNodeProcesses(allPm2Pids, dockerPids, pm2DaemonPids) {
  for (const { pid, cmd, uptimeSecs } of getNodePids()) {
    if (uptimeSecs < 120 || allPm2Pids.has(pid) || dockerPids.has(pid) || pm2DaemonPids.has(pid)) continue;
    if (ORPHAN_CMD_ALLOWLIST.some(pattern => cmd.includes(pattern))) continue;
    const cmdHash = crypto.createHash('md5').update(cmd).digest('hex').slice(0, 8);
    await alert(`orphan_${cmdHash}`,
      `🧟 *Orphaned node process*\nPID: ${pid} | Uptime: ${Math.round(uptimeSecs / 60)}m\nCmd: \`${cmd.slice(0, 120)}\`\nNot tracked by root or nodeapp PM2.`,
      { check_type: 'orphaned_process', severity: 'high', playbook: PLAYBOOKS.orphan }
    );
  }
}

// Check 5
async function checkDeadPm2Apps(allApps) {
  for (const app of allApps) {
    const status = app.pm2_env?.status;
    if (status === 'errored' || status === 'stopped') {
      await alert(`pm2_dead_${app.name}`,
        `💀 *PM2 app ${status}*\nApp: \`${app.name}\`\nRestarts: ${app.pm2_env?.restart_time ?? 0}\nRun: \`pm2 logs ${app.name} --lines 30\``,
        { check_type: 'pm2_dead', severity: 'critical', playbook: PLAYBOOKS.pm2_dead }
      );
    }
  }
}

async function main() {
  const rootApps    = getPm2List(null);
  const nodeappApps = getPm2List('nodeapp');
  const allApps     = [...rootApps, ...nodeappApps];
  const rootPortMap    = buildPortMap(rootApps, 'root');
  const nodeappPortMap = buildPortMap(nodeappApps, 'nodeapp');
  const listeners     = getListeners();
  const allPm2Pids    = new Set([...collectPm2Pids(rootApps), ...collectPm2Pids(nodeappApps)]);
  const dockerPids    = getDockerPids();
  const pm2DaemonPids = getPm2DaemonPids();
  // Registry ∪ infra ports ∪ any port currently owned by a PM2 app (either daemon).
  // Infra ports don't appear in /home/nodeapp/port-registry.js but are legitimate.
  // PM2-owned ports are already accounted for elsewhere — no need to re-flag them here.
  const registryPorts = new Set(Object.values(REGISTRY));
  registryPorts.add(4500); // FOMCP
  registryPorts.add(9090); // deploy webhook
  for (const port of rootPortMap.keys())    registryPorts.add(port);
  for (const port of nodeappPortMap.keys()) registryPorts.add(port);

  await checkDualDaemonCollision(rootPortMap, nodeappPortMap);
  await checkPortSquatters(rootPortMap, nodeappPortMap, listeners, allPm2Pids, pm2DaemonPids);
  await checkUnregisteredListeners(listeners, registryPorts);
  await checkOrphanedNodeProcesses(allPm2Pids, dockerPids, pm2DaemonPids);
  await checkDeadPm2Apps(allApps);

  await info('pm2-governance run complete', { key: 'pm2_governance_run', check_type: 'heartbeat' });
}

main().catch(err => { console.error('[pm2-governance] fatal:', err.message); process.exit(1); });
