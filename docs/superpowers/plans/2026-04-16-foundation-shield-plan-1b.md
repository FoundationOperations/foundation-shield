# FoundationShield Plan 1B — Core Governance Scripts (Checks 1–31)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the 31 governance checks covering Process/Port, Git/Repo, Resources, Application Health, and Synthetic/Runtime. These run as obfuscated systemd timers on VPS Main first; fleet deployment (VPS2, VPS VRO) is covered in Plan 2A.

**Architecture:** Four scripts, each pulling from the new `alerting.js` (Plan 1A). Scripts install to `/usr/local/lib/fo-sys/` with obfuscated names. Systemd timers replace cron. All scripts accept `--dry-run` flag.

**Prerequisite:** Plan 1A must be complete — `alerting.js` must exist at `/opt/foundation-shield/scripts/alerting.js` and the FOMCP pipeline must be working.

**Tech Stack:** Node 22 CommonJS (matching existing governance scripts), `child_process.execSync`, `/proc` filesystem, `ss`/`systemctl`/`pg`/`pm2` CLI tools.

---

## File Map

**Scripts (install to `/usr/local/lib/fo-sys/`):**
- Create: `/opt/foundation-shield/scripts/pm2-governance.js` — Checks 1–5 (Process & Port)
- Create: `/opt/foundation-shield/scripts/repo-governance.js` — Checks 6–11 (Git & Repo)
- Create: `/opt/foundation-shield/scripts/resource-guard.js` — Checks 12–17 (Resources)
- Create: `/opt/foundation-shield/scripts/app-guard.js` — Checks 18–31 (App Health + Synthetic)

**Systemd units (copy to `/etc/systemd/system/`):**
- Create: `/opt/foundation-shield/systemd/fo-sysmon.service`
- Create: `/opt/foundation-shield/systemd/fo-sysmon.timer`
- Create: `/opt/foundation-shield/systemd/fo-repomon.service`
- Create: `/opt/foundation-shield/systemd/fo-repomon.timer`
- Create: `/opt/foundation-shield/systemd/fo-appmon.service`
- Create: `/opt/foundation-shield/systemd/fo-appmon.timer`

**Port registry reference:**
- Read: `/home/nodeapp/port-registry.js` — required by pm2-governance.js

---

## Task 1: Write `pm2-governance.js` (Checks 1–5)

**Files:**
- Create: `/opt/foundation-shield/scripts/pm2-governance.js`

This is an enhanced version of the existing ops-docs script that uses the new alerting.js.

- [ ] **Step 1: Write the script**

```js
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
  const registryPorts = new Set(Object.values(REGISTRY));

  await checkDualDaemonCollision(rootPortMap, nodeappPortMap);
  await checkPortSquatters(rootPortMap, nodeappPortMap, listeners, allPm2Pids, pm2DaemonPids);
  await checkUnregisteredListeners(listeners, registryPorts);
  await checkOrphanedNodeProcesses(allPm2Pids, dockerPids, pm2DaemonPids);
  await checkDeadPm2Apps(allApps);

  await info('pm2-governance run complete', { key: 'pm2_governance_run', check_type: 'heartbeat' });
}

main().catch(err => { console.error('[pm2-governance] fatal:', err.message); process.exit(1); });
```

- [ ] **Step 2: Dry-run on VPS Main**

```bash
node /opt/foundation-shield/scripts/pm2-governance.js --dry-run 2>&1
```

Expected: Output showing check results (possibly some `[DRY-RUN] ALERT` lines if issues found), ending with `[DRY-RUN]` run complete. No fatal errors.

- [ ] **Step 3: Commit**

```bash
cd /opt/foundation-shield
git add scripts/pm2-governance.js
git commit -m "feat(shield): pm2-governance.js — checks 1-5 with FOMCP alerting"
```

---

## Task 2: Write `repo-governance.js` (Checks 6–11)

**Files:**
- Create: `/opt/foundation-shield/scripts/repo-governance.js`

This is an enhanced version of the ops-docs script using the new alerting.js. Key change: `alert()` now accepts an options object with `check_type`, `severity`, `playbook`.

- [ ] **Step 1: Write the script**

```js
// /opt/foundation-shield/scripts/repo-governance.js
// Checks 6-11: Git & Repo governance
// Check 6: Behind remote    Check 9:  Stale repo
// Check 7: Ahead of remote  Check 10: Staging/prod pair drift
// Check 8: Dirty tree       Check 11: Cross-server drift
'use strict';
const { execSync } = require('child_process');
const { alert, info } = require('./alerting.js');

const REPOS = [
  // VPS Main (local)
  { server: null, path: '/var/www/mac-daddy-portal',       label: 'main:mac-daddy-prod',    pair: 'main:mac-daddy-stage' },
  { server: null, path: '/var/www/mac-daddy-portal-stage', label: 'main:mac-daddy-stage',   pair: 'main:mac-daddy-prod' },
  { server: null, path: '/var/www/foundation-portal',      label: 'main:foundation-portal' },
  { server: null, path: '/opt/mcp-server',                 label: 'main:mcp-server' },
  { server: null, path: '/opt/openclaude',                 label: 'main:openclaude' },
  { server: null, path: '/opt/openclaude-gui',             label: 'main:claudehopper-gui' },
  { server: null, path: '/opt/foundation-shield',          label: 'main:foundation-shield' },
  { server: null, path: '/opt/vps-tools',                  label: 'main:vps-tools' },
  // VPS 2
  { server: 'vps2', path: '/opt/mcp-server',       label: 'vps2:mcp-server' },
  { server: 'vps2', path: '/opt/openclaude',        label: 'vps2:openclaude' },
  { server: 'vps2', path: '/opt/openclaude-gui',    label: 'vps2:claudehopper-gui' },
  { server: 'vps2', path: '/opt/ops-docs',          label: 'vps2:ops-docs' },
  { server: 'vps2', path: '/opt/foundation-shield', label: 'vps2:foundation-shield' },
  // VPS VRO
  { server: 'vpsvro', path: '/var/www/rush-notary-booking', label: 'vro:rush-notary' },
  { server: 'vpsvro', path: '/var/www/vro-spider',          label: 'vro:vro-spider' },
];

const STALE_DAYS = 30;

function run(cmd, cwd) {
  try { return execSync(cmd, { cwd, timeout: 30000, encoding: 'utf8' }).trim(); } catch { return null; }
}

function sshRun(server, cmd) {
  try {
    return execSync(
      `ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no ${server} ${JSON.stringify(cmd)}`,
      { timeout: 15000, encoding: 'utf8' }
    ).trim();
  } catch { return null; }
}

function gitCmd(server, dir, cmd) {
  return server ? sshRun(server, `cd ${dir} && ${cmd}`) : run(cmd, dir);
}

function getRepoState(repo) {
  const { server, path: dir, label } = repo;
  const state = { label, path: dir, server: server || 'local', ok: true, issues: [] };

  const head = gitCmd(server, dir, 'git rev-parse --short HEAD 2>/dev/null');
  if (!head) { state.ok = false; state.issues.push('repo unreachable'); state.commitHash = 'N/A'; return state; }
  state.commitHash = head;
  state.branch = gitCmd(server, dir, 'git branch --show-current 2>/dev/null') || 'detached';

  gitCmd(server, dir, 'git fetch origin --quiet 2>/dev/null');

  const defaultBranch = gitCmd(server, dir, 'git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null');
  const trackingRef = defaultBranch ? defaultBranch.replace('refs/remotes/', '') : `origin/${state.branch}`;
  const counts = gitCmd(server, dir, `git rev-list --left-right --count HEAD...${trackingRef} 2>/dev/null`);
  [state.ahead, state.behind] = counts ? counts.split(/\s+/).map(Number) : [0, 0];

  const statusOut = gitCmd(server, dir, 'git status --porcelain 2>/dev/null') || '';
  const lines = statusOut ? statusOut.split('\n').filter(Boolean) : [];
  state.modified  = lines.filter(l => /^ M|^M /.test(l)).length;
  state.untracked = lines.filter(l => l.startsWith('??')).length;
  state.staged    = lines.filter(l => /^[MADRC]/.test(l)).length;
  state.dirty     = lines.length > 0;

  const dateStr = gitCmd(server, dir, 'git log -1 --format=%aI 2>/dev/null');
  state.lastCommitDate = dateStr ? new Date(dateStr) : null;
  state.lastCommitAge  = state.lastCommitDate ? Math.floor((Date.now() - state.lastCommitDate.getTime()) / 86400000) : null;

  return state;
}

// Check 6
async function checkBehind(state) {
  if (state.behind > 0) {
    state.ok = false; state.issues.push(`${state.behind} unpulled`);
    await alert(`repo_behind_${state.label}`,
      `📥 *${state.label}* is ${state.behind} commit(s) behind remote\nPath: \`${state.path}\` on ${state.server}\nBranch: ${state.branch}\nFix: \`git pull\``,
      { check_type: 'repo_behind', severity: 'high', playbook: `cd ${state.path} && git pull` }
    );
  }
}

// Check 7
async function checkAhead(state) {
  if (state.ahead > 0) {
    state.ok = false; state.issues.push(`${state.ahead} unpushed`);
    await alert(`repo_ahead_${state.label}`,
      `📤 *${state.label}* has ${state.ahead} unpushed commit(s)\nPath: \`${state.path}\` on ${state.server}\nBranch: ${state.branch}`,
      { check_type: 'repo_ahead', severity: 'medium', playbook: `cd ${state.path} && git push` }
    );
  }
}

// Check 8
async function checkDirty(state) {
  if (state.dirty) {
    state.ok = false;
    const parts = [];
    if (state.modified)  parts.push(`${state.modified} modified`);
    if (state.untracked) parts.push(`${state.untracked} untracked`);
    if (state.staged)    parts.push(`${state.staged} staged`);
    const summary = parts.join(', ');
    state.issues.push(summary);
    await alert(`repo_dirty_${state.label}`,
      `🔧 *${state.label}* has uncommitted changes (${summary})\nPath: \`${state.path}\` on ${state.server}`,
      { check_type: 'repo_dirty', severity: 'medium', playbook: `cd ${state.path} && git status` }
    );
  }
}

// Check 9
async function checkStale(state) {
  if (state.lastCommitAge !== null && state.lastCommitAge > STALE_DAYS) {
    state.issues.push(`stale ${state.lastCommitAge}d`);
    await alert(`repo_stale_${state.label}`,
      `🕸️ *${state.label}* — no commits in ${state.lastCommitAge} days\nPath: \`${state.path}\` on ${state.server}\nLast: ${state.lastCommitDate.toISOString().slice(0, 10)}`,
      { check_type: 'repo_stale', severity: 'info' }
    );
  }
}

// Check 10
async function checkPairDrift(states) {
  const pairs = new Map();
  for (const s of states) {
    const repo = REPOS.find(r => r.label === s.label);
    if (!repo?.pair) continue;
    const key = [s.label, repo.pair].sort().join(' <> ');
    if (!pairs.has(key)) pairs.set(key, []);
    pairs.get(key).push(s);
  }
  for (const [key, [a, b]] of pairs) {
    if (!b || a.commitHash === b.commitHash) continue;
    await alert(`repo_pair_drift_${key}`,
      `⚡ *Staging/Prod drift:* ${key}\n${a.label}: \`${a.commitHash}\` | ${b.label}: \`${b.commitHash}\`\nDeploy to prod or reset staging.`,
      { check_type: 'repo_pair_drift', severity: 'high', playbook: 'Sync via deploy pipeline' }
    );
  }
}

// Check 11
async function checkCrossServerDrift(states) {
  const groups = new Map();
  for (const s of states) {
    const name = s.label.split(':').slice(1).join(':');
    if (!groups.has(name)) groups.set(name, []);
    groups.get(name).push(s);
  }
  for (const [name, members] of groups) {
    if (members.length < 2) continue;
    const hashes = [...new Set(members.map(m => m.commitHash))];
    if (hashes.length > 1) {
      const detail = members.map(m => `${m.label}: \`${m.commitHash}\``).join('\n');
      await alert(`repo_xserver_drift_${name}`,
        `🌐 *Cross-server drift:* ${name} differs\n${detail}`,
        { check_type: 'repo_xserver_drift', severity: 'high', playbook: 'Deploy same commit to all servers' }
      );
    }
  }
}

async function main() {
  const states = [];
  let healthy = 0, issues = 0;

  const byServer = new Map();
  for (const repo of REPOS) {
    const key = repo.server || 'local';
    if (!byServer.has(key)) byServer.set(key, []);
    byServer.get(key).push(repo);
  }

  for (const [serverKey, repos] of byServer) {
    console.log(`[${new Date().toISOString()}] Scanning ${serverKey} (${repos.length} repos)...`);
    for (const repo of repos) {
      const state = getRepoState(repo);
      states.push(state);
      if (state.issues.includes('repo unreachable')) { issues++; continue; }
      await checkBehind(state);
      await checkAhead(state);
      await checkDirty(state);
      await checkStale(state);
      state.ok && state.issues.length === 0 ? healthy++ : issues++;
    }
  }

  await checkPairDrift(states);
  await checkCrossServerDrift(states);

  await info(`repo-governance: ${healthy} healthy, ${issues} issues (${states.length} repos)`, { key: 'repo_governance_run', check_type: 'heartbeat' });
}

main().catch(err => { console.error('[repo-governance] fatal:', err.message); process.exit(1); });
```

- [ ] **Step 2: Dry-run test**

```bash
node /opt/foundation-shield/scripts/repo-governance.js --dry-run 2>&1 | head -30
```

Expected: Scanning output per server, no fatal errors.

- [ ] **Step 3: Commit**

```bash
cd /opt/foundation-shield
git add scripts/repo-governance.js
git commit -m "feat(shield): repo-governance.js — checks 6-11 with FOMCP alerting"
```

---

## Task 3: Write `resource-guard.js` (Checks 12–17)

**Files:**
- Create: `/opt/foundation-shield/scripts/resource-guard.js`

- [ ] **Step 1: Write the script**

```js
// /opt/foundation-shield/scripts/resource-guard.js
// Checks 12-17: Resource governance
// Check 12: Disk usage (>80% warn, >90% crit)   Check 15: Swap usage (>50%)
// Check 13: Inode exhaustion (>80%)              Check 16: CPU load > nproc
// Check 14: RAM pressure (>85%)                  Check 17: OOM events
'use strict';
const { execSync } = require('child_process');
const fs = require('fs');
const { alert, info } = require('./alerting.js');

function run(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 10000 }).trim(); } catch { return ''; }
}

// Check 12: Disk usage
async function checkDisk() {
  const lines = run('df -h --output=target,pcent,avail').split('\n').slice(1);
  for (const line of lines) {
    const m = line.match(/^(\S+)\s+(\d+)%\s+(\S+)/);
    if (!m) continue;
    const [, mount, pctStr, avail] = m;
    const pct = parseInt(pctStr);
    if (pct >= 90) {
      await alert(`disk_crit_${mount.replace(/\//g, '_') || 'root'}`,
        `💾 *Disk critical on ${mount}* — ${pct}% used (${avail} free)\nFix: \`df -h && ncdu ${mount}\``,
        { check_type: 'disk_usage', severity: 'critical', playbook: `ncdu ${mount} — find and remove large files` }
      );
    } else if (pct >= 80) {
      await alert(`disk_warn_${mount.replace(/\//g, '_') || 'root'}`,
        `💾 *Disk warning on ${mount}* — ${pct}% used (${avail} free)`,
        { check_type: 'disk_usage', severity: 'high', playbook: `ncdu ${mount}` }
      );
    }
  }
}

// Check 13: Inode exhaustion
async function checkInodes() {
  const lines = run('df -i --output=target,ipcent').split('\n').slice(1);
  for (const line of lines) {
    const m = line.match(/^(\S+)\s+(\d+)%/);
    if (!m) continue;
    const [, mount, pctStr] = m;
    const pct = parseInt(pctStr);
    if (pct >= 80) {
      await alert(`inodes_${mount.replace(/\//g, '_') || 'root'}`,
        `📁 *Inode exhaustion on ${mount}* — ${pct}% inodes used\nFix: \`find ${mount} -xdev -type f | wc -l\` to find file bloat`,
        { check_type: 'inode_exhaustion', severity: 'critical', playbook: `find ${mount} -xdev -type f | sort | uniq -c | sort -rn | head -20` }
      );
    }
  }
}

// Check 14: RAM pressure
async function checkRam() {
  const meminfo = fs.readFileSync('/proc/meminfo', 'utf8');
  const get = key => parseInt(meminfo.match(new RegExp(`^${key}:\\s+(\\d+)`, 'm'))?.[1] || 0);
  const total = get('MemTotal');
  const avail = get('MemAvailable');
  if (!total) return;
  const usedPct = Math.round((total - avail) / total * 100);
  if (usedPct >= 85) {
    const usedMb = Math.round((total - avail) / 1024);
    const totalMb = Math.round(total / 1024);
    await alert('ram_pressure',
      `🧠 *RAM pressure* — ${usedPct}% used (${usedMb}MB / ${totalMb}MB)\nFix: \`ps aux --sort=-%mem | head -15\``,
      { check_type: 'ram_pressure', severity: 'high', playbook: 'ps aux --sort=-%mem | head -15 — identify top consumers' }
    );
  }
}

// Check 15: Swap usage
async function checkSwap() {
  const meminfo = fs.readFileSync('/proc/meminfo', 'utf8');
  const get = key => parseInt(meminfo.match(new RegExp(`^${key}:\\s+(\\d+)`, 'm'))?.[1] || 0);
  const swapTotal = get('SwapTotal');
  const swapFree  = get('SwapFree');
  if (!swapTotal) return;
  const usedPct = Math.round((swapTotal - swapFree) / swapTotal * 100);
  if (usedPct >= 50) {
    await alert('swap_high',
      `💤 *Swap usage high* — ${usedPct}% used\nSwap use indicates RAM pressure. Fix: \`free -h && sudo swapon --show\``,
      { check_type: 'swap_usage', severity: 'high', playbook: 'free -h — check RAM consumers, consider restart of heavy services' }
    );
  }
}

// Check 16: CPU load > nproc
async function checkCpuLoad() {
  const nproc = parseInt(run('nproc')) || 1;
  const uptime = fs.readFileSync('/proc/loadavg', 'utf8').split(' ');
  const load5 = parseFloat(uptime[1]); // 5-minute load average
  if (load5 > nproc) {
    await alert('cpu_load_high',
      `⚡ *CPU load high* — 5min avg ${load5.toFixed(2)} (${nproc} cores)\nFix: \`btop\` or \`ps aux --sort=-%cpu | head -15\``,
      { check_type: 'cpu_load', severity: 'high', playbook: 'btop — identify CPU consumers' }
    );
  }
}

// Check 17: OOM events
async function checkOom() {
  try {
    // Scan dmesg for OOM kills in the last 10 minutes
    const output = run('dmesg -T --since "10 minutes ago" 2>/dev/null || journalctl -k --since "10 minutes ago" 2>/dev/null');
    const oomLines = output.split('\n').filter(l => l.includes('Out of memory') || l.includes('Killed process'));
    if (oomLines.length > 0) {
      const summary = oomLines.slice(0, 3).join('\n');
      await alert('oom_event',
        `💥 *OOM killer fired* — ${oomLines.length} event(s) in last 10min\n\`\`\`\n${summary}\n\`\`\``,
        { check_type: 'oom_event', severity: 'critical', playbook: 'journalctl -k --since "1 hour ago" | grep -i oom — identify victim processes' }
      );
    }
  } catch (_) {}
}

async function main() {
  await checkDisk();
  await checkInodes();
  await checkRam();
  await checkSwap();
  await checkCpuLoad();
  await checkOom();
  await info('resource-guard run complete', { key: 'resource_guard_run', check_type: 'heartbeat' });
}

main().catch(err => { console.error('[resource-guard] fatal:', err.message); process.exit(1); });
```

- [ ] **Step 2: Dry-run test**

```bash
node /opt/foundation-shield/scripts/resource-guard.js --dry-run 2>&1
```

Expected: No fatal errors. May show `[DRY-RUN]` alerts if disk/RAM thresholds are met.

- [ ] **Step 3: Commit**

```bash
cd /opt/foundation-shield
git add scripts/resource-guard.js
git commit -m "feat(shield): resource-guard.js — checks 12-17 (disk, inodes, RAM, swap, CPU, OOM)"
```

---

## Task 4: Write `app-guard.js` (Checks 18–31)

**Files:**
- Create: `/opt/foundation-shield/scripts/app-guard.js`

- [ ] **Step 1: Write the script**

```js
// /opt/foundation-shield/scripts/app-guard.js
// Checks 18-31: Application Health + Synthetic & Runtime
// 18: SSL expiry          23: Service dependencies    28: Deploy fingerprint drift
// 19: Fail2ban/SSH        24: FD exhaustion           29: Nginx 5xx spike
// 20: Docker health       25: Egress listeners        30: PG connection pool
// 21: PM2 memory          26: Endpoint probing        31: PM2 log error rate
// 22: PM2 restart storm   27: Watchdog heartbeat
'use strict';
const { execSync } = require('child_process');
const https = require('https');
const http  = require('http');
const fs    = require('fs');
const { alert, info } = require('./alerting.js');

function run(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 15000 }).trim(); } catch { return ''; }
}

// Endpoints to probe (Check 26)
const ENDPOINTS = [
  { url: 'http://127.0.0.1:3000/health', name: 'mac-daddy-prod',  warnMs: 2000, critMs: 5000 },
  { url: 'http://127.0.0.1:3001/health', name: 'mac-daddy-stage', warnMs: 2000, critMs: 5000 },
  { url: 'http://127.0.0.1:4500/healthz', name: 'mcp-server',     warnMs: 1000, critMs: 3000 },
];

// Check 18: SSL cert expiry
async function checkSsl() {
  const domains = ['server.foundationoperations.com', 'mcp.foundationoperations.com'];
  for (const domain of domains) {
    try {
      const out = run(`echo | openssl s_client -servername ${domain} -connect ${domain}:443 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null`);
      const m = out.match(/notAfter=(.*)/);
      if (!m) continue;
      const expiry = new Date(m[1]);
      const days = Math.round((expiry - Date.now()) / 86400000);
      if (days < 7) {
        await alert(`ssl_expiry_crit_${domain}`, `🔐 *SSL cert expiring in ${days}d* — ${domain}\nExpiry: ${m[1]}`,
          { check_type: 'ssl_expiry', severity: 'critical', playbook: 'Renew cert via Cloudflare or certbot' });
      } else if (days < 30) {
        await alert(`ssl_expiry_warn_${domain}`, `🔐 *SSL cert expiring in ${days}d* — ${domain}`,
          { check_type: 'ssl_expiry', severity: 'high', playbook: 'Renew cert before expiry' });
      }
    } catch (_) {}
  }
}

// Check 19: Fail2ban + SSH brute force
async function checkFail2ban() {
  const status = run('systemctl is-active fail2ban 2>/dev/null');
  if (status !== 'active') {
    await alert('fail2ban_down', `🛡️ *Fail2ban is not active* — status: ${status || 'unknown'}`,
      { check_type: 'fail2ban', severity: 'high', playbook: 'sudo systemctl start fail2ban' });
    return;
  }
  // Check SSH fail rate in last hour
  try {
    const fails = run("journalctl -u ssh --since '1 hour ago' 2>/dev/null | grep -c 'Failed password' || echo 0");
    const count = parseInt(fails) || 0;
    if (count > 100) {
      await alert('ssh_bruteforce', `🔒 *SSH brute force spike* — ${count} failed logins in last hour`,
        { check_type: 'ssh_bruteforce', severity: 'high', playbook: 'fail2ban-client status sshd — check banned IPs' });
    }
  } catch (_) {}
}

// Check 20: Docker health
async function checkDocker() {
  try {
    const out = run("docker ps -a --format '{{.Names}}\t{{.Status}}' 2>/dev/null");
    for (const line of out.split('\n').filter(Boolean)) {
      const [name, status] = line.split('\t');
      if (!status) continue;
      if (status.includes('unhealthy')) {
        await alert(`docker_unhealthy_${name}`, `🐳 *Docker container unhealthy*: ${name}\nStatus: ${status}`,
          { check_type: 'docker_health', severity: 'high', playbook: `docker logs ${name} --tail 50` });
      } else if (status.startsWith('Exited')) {
        await alert(`docker_exited_${name}`, `🐳 *Docker container exited*: ${name}\nStatus: ${status}`,
          { check_type: 'docker_exit', severity: 'high', playbook: `docker logs ${name} --tail 50 && docker start ${name}` });
      }
    }
  } catch (_) {}
}

// Check 21: PM2 memory >512MB
async function checkPm2Memory() {
  try {
    const apps = JSON.parse(execSync('pm2 jlist', { encoding: 'utf8', timeout: 10000 }));
    for (const app of apps) {
      const memBytes = app.monit?.memory || 0;
      const memMb = Math.round(memBytes / 1024 / 1024);
      if (memMb > 512) {
        await alert(`pm2_mem_${app.name}`, `🧠 *PM2 app high memory*: ${app.name} — ${memMb}MB\nFix: \`pm2 restart ${app.name}\``,
          { check_type: 'pm2_memory', severity: 'medium', playbook: `pm2 logs ${app.name} --lines 20 — check for memory leak then pm2 restart ${app.name}` });
      }
    }
  } catch (_) {}
}

// Check 22: PM2 restart storm (>5 restarts in 5min)
async function checkRestartStorm() {
  try {
    const apps = JSON.parse(execSync('pm2 jlist', { encoding: 'utf8', timeout: 10000 }));
    for (const app of apps) {
      const restarts = app.pm2_env?.restart_time || 0;
      const uptimeMs = app.pm2_env?.pm_uptime || Date.now();
      const uptimeSecs = (Date.now() - uptimeMs) / 1000;
      // Restart storm: >5 restarts AND uptime <5min (restarted recently multiple times)
      if (restarts > 5 && uptimeSecs < 300) {
        await alert(`restart_storm_${app.name}`,
          `🔄 *PM2 restart storm*: ${app.name}\nRestarts: ${restarts} | Uptime: ${Math.round(uptimeSecs)}s\nFix: \`pm2 logs ${app.name} --lines 50\``,
          { check_type: 'restart_storm', severity: 'critical', playbook: `pm2 logs ${app.name} --lines 50 --nostream` });
      }
    }
  } catch (_) {}
}

// Check 23: Service dependencies
async function checkServiceDeps() {
  const services = [
    { name: 'postgresql', check: 'pg_isready -q && echo ok', critical: true },
    { name: 'nginx',      check: 'nginx -t 2>&1 | grep -q "ok" && echo ok', critical: true },
    { name: 'docker',     check: 'docker info -f "{{.ServerVersion}}" 2>/dev/null', critical: false },
  ];
  for (const svc of services) {
    const result = run(svc.check);
    if (!result) {
      await alert(`service_dep_${svc.name}`, `🔧 *Service down*: ${svc.name}\nFix: \`sudo systemctl status ${svc.name}\``,
        { check_type: 'service_dependency', severity: svc.critical ? 'critical' : 'high', playbook: `sudo systemctl restart ${svc.name}` });
    }
  }
}

// Check 24: FD exhaustion (>80% of ulimit)
async function checkFdExhaustion() {
  try {
    const apps = JSON.parse(execSync('pm2 jlist', { encoding: 'utf8', timeout: 10000 }));
    for (const app of apps) {
      const pid = app.pid;
      if (!pid) continue;
      const fdCount = run(`ls /proc/${pid}/fd 2>/dev/null | wc -l`);
      const limit   = run(`cat /proc/${pid}/limits 2>/dev/null | awk '/Max open files/{print $4}'`);
      const count = parseInt(fdCount) || 0;
      const max   = parseInt(limit)   || 1024;
      const pct   = Math.round(count / max * 100);
      if (pct >= 80) {
        await alert(`fd_exhaust_${app.name}`,
          `📂 *FD exhaustion*: ${app.name} — ${count}/${max} (${pct}%)\nFix: \`lsof -p ${pid} | wc -l\``,
          { check_type: 'fd_exhaustion', severity: 'high', playbook: `lsof -p ${pid} | sort | uniq -c | sort -rn | head -20` });
      }
    }
  } catch (_) {}
}

// Check 25: Unexpected egress (listeners outside port registry)
async function checkEgress() {
  const REGISTRY = require('/home/nodeapp/port-registry.js');
  const registryPorts = new Set(Object.values(REGISTRY));
  registryPorts.add(4500); // FOMCP
  registryPorts.add(9090); // deploy webhook
  const lines = run('ss -tlnp').split('\n');
  for (const line of lines) {
    const m = line.match(/:(\d+)\s+[\d*:]+\s+users:\(\("([^"]+)",pid=(\d+)/);
    if (!m) continue;
    const port = parseInt(m[1]);
    if (port < 3000 || port > 9100 || registryPorts.has(port)) continue;
    await alert(`egress_${port}`, `🌐 *Unexpected listener on port ${port}*\nProcess: \`${m[2]}\` (pid ${m[3]})\nInvestigate: \`lsof -i :${port}\``,
      { check_type: 'unexpected_egress', severity: 'high', playbook: `lsof -i :${port} — identify and kill if unauthorized` });
  }
}

// Check 26: Endpoint probing
function probe(url) {
  return new Promise((resolve) => {
    const start = Date.now();
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, (res) => {
      res.resume();
      res.on('end', () => resolve({ ok: res.statusCode < 500, ms: Date.now() - start, status: res.statusCode }));
    });
    req.setTimeout(10000, () => { req.destroy(); resolve({ ok: false, ms: 10000, status: 0 }); });
    req.on('error', () => resolve({ ok: false, ms: Date.now() - start, status: 0 }));
  });
}

async function checkEndpoints() {
  for (const ep of ENDPOINTS) {
    const result = await probe(ep.url);
    if (!result.ok) {
      await alert(`endpoint_down_${ep.name}`,
        `🔴 *Endpoint down*: ${ep.name}\nURL: \`${ep.url}\`\nStatus: ${result.status} (${result.ms}ms)`,
        { check_type: 'endpoint_probe', severity: 'critical', playbook: `sudo pm2 logs ${ep.name} --lines 30` });
    } else if (result.ms >= ep.critMs) {
      await alert(`endpoint_slow_crit_${ep.name}`,
        `🐢 *Endpoint critically slow*: ${ep.name} — ${result.ms}ms (>${ep.critMs}ms threshold)`,
        { check_type: 'endpoint_slow', severity: 'critical', playbook: `sudo pm2 logs ${ep.name} --lines 30` });
    } else if (result.ms >= ep.warnMs) {
      await alert(`endpoint_slow_warn_${ep.name}`,
        `🐢 *Endpoint slow*: ${ep.name} — ${result.ms}ms`,
        { check_type: 'endpoint_slow', severity: 'medium' });
    }
  }
}

// Check 27: Watchdog heartbeat — verify governance scripts ran recently
async function checkWatchdog() {
  const LOG = '/var/log/fo-sys/digest.log';
  try {
    const stat = fs.statSync(LOG);
    const ageMins = (Date.now() - stat.mtimeMs) / 60000;
    if (ageMins > 15) {
      await alert('watchdog_stale',
        `⏰ *Governance watchdog stale* — last write ${Math.round(ageMins)} minutes ago\nExpected activity every 5 minutes.`,
        { check_type: 'watchdog_heartbeat', severity: 'critical', playbook: 'systemctl status fo-sysmon.timer && journalctl -u fo-sysmon.service --since "30 minutes ago"' });
    }
  } catch { /* log doesn't exist yet — skip */ }
}

// Check 28: Deploy fingerprint drift (built files vs git hash)
async function checkDeployFingerprint() {
  const apps = [
    { path: '/var/www/mac-daddy-portal',       builtFile: 'public/app.js',    label: 'mac-daddy-prod' },
    { path: '/var/www/mac-daddy-portal-stage', builtFile: 'public/app.js',    label: 'mac-daddy-stage' },
  ];
  for (const app of apps) {
    try {
      const gitHash    = run(`git -C ${app.path} rev-parse --short HEAD 2>/dev/null`);
      const builtMtime = fs.statSync(`${app.path}/${app.builtFile}`).mtimeMs;
      const gitMtime   = new Date(run(`git -C ${app.path} log -1 --format=%aI HEAD 2>/dev/null`)).getTime();
      // If built file is older than last commit by more than 60 seconds, it's not rebuilt
      if (gitMtime - builtMtime > 60000) {
        await alert(`deploy_fingerprint_${app.label}`,
          `🏗️ *Deploy fingerprint drift*: ${app.label}\nBuilt file is older than last commit (${gitHash}) — may need a rebuild.\nFix: \`cd ${app.path} && npm run build\``,
          { check_type: 'deploy_fingerprint', severity: 'high', playbook: `cd ${app.path} && npm run build` });
      }
    } catch (_) {}
  }
}

// Check 29: Nginx 5xx spike (last 5 minutes)
async function checkNginx5xx() {
  try {
    const logFile = '/var/log/nginx/access.log';
    // Count 5xx responses in last 5 minutes using awk on timestamps
    const count = run(`awk -v d="$(date -d '5 minutes ago' '+%d/%b/%Y:%H:%M')" '$0 ~ d && $9 ~ /^5/' ${logFile} 2>/dev/null | wc -l`);
    const n = parseInt(count) || 0;
    if (n >= 10) {
      await alert('nginx_5xx_spike',
        `🚨 *Nginx 5xx spike* — ${n} errors in last 5 minutes\nFix: \`tail -50 /var/log/nginx/error.log\``,
        { check_type: 'nginx_5xx', severity: 'critical', playbook: 'tail -100 /var/log/nginx/error.log | grep crit' });
    }
  } catch (_) {}
}

// Check 30: PostgreSQL connection pool exhaustion
async function checkPgPool() {
  try {
    const out = run(`sudo -u postgres psql -t -c "SELECT count(*), (SELECT setting::int FROM pg_settings WHERE name='max_connections') FROM pg_stat_activity;" 2>/dev/null`);
    const m = out.match(/(\d+)\s*\|\s*(\d+)/);
    if (!m) return;
    const [, current, max] = m.map(Number);
    const pct = Math.round(current / max * 100);
    if (pct >= 80) {
      await alert('pg_pool_high',
        `🐘 *PostgreSQL connections high* — ${current}/${max} (${pct}%)\nFix: \`sudo -u postgres psql -c "SELECT pid,usename,application_name,state FROM pg_stat_activity ORDER BY state;"\``,
        { check_type: 'pg_pool', severity: 'high', playbook: 'SELECT pid, pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = \'idle\' AND query_start < now() - interval \'10 minutes\';' });
    }
  } catch (_) {}
}

// Check 31: PM2 log error rate spike
async function checkPm2ErrorRate() {
  try {
    const apps = JSON.parse(execSync('pm2 jlist', { encoding: 'utf8', timeout: 10000 }));
    for (const app of apps) {
      const logPath = app.pm2_env?.pm_err_log_path;
      if (!logPath) continue;
      try {
        const stat = fs.statSync(logPath);
        if ((Date.now() - stat.mtimeMs) > 300000) continue; // log unchanged in 5min
        // Count ERROR lines written in last 5 minutes
        const recentErrors = run(`tail -500 ${logPath} 2>/dev/null | grep -c -i 'error\\|exception\\|fatal' || echo 0`);
        const count = parseInt(recentErrors) || 0;
        if (count >= 20) {
          await alert(`pm2_error_rate_${app.name}`,
            `📋 *PM2 error spike*: ${app.name} — ${count} errors in recent log\nFix: \`pm2 logs ${app.name} --lines 50 --nostream\``,
            { check_type: 'pm2_error_rate', severity: 'high', playbook: `pm2 logs ${app.name} --lines 100 --nostream` });
        }
      } catch (_) {}
    }
  } catch (_) {}
}

async function main() {
  await checkSsl();
  await checkFail2ban();
  await checkDocker();
  await checkPm2Memory();
  await checkRestartStorm();
  await checkServiceDeps();
  await checkFdExhaustion();
  await checkEgress();
  await checkEndpoints();
  await checkWatchdog();
  await checkDeployFingerprint();
  await checkNginx5xx();
  await checkPgPool();
  await checkPm2ErrorRate();
  await info('app-guard run complete', { key: 'app_guard_run', check_type: 'heartbeat' });
}

main().catch(err => { console.error('[app-guard] fatal:', err.message); process.exit(1); });
```

- [ ] **Step 2: Dry-run test**

```bash
node /opt/foundation-shield/scripts/app-guard.js --dry-run 2>&1 | head -30
```

Expected: Check results printed, no fatal errors.

- [ ] **Step 3: Commit**

```bash
cd /opt/foundation-shield
git add scripts/app-guard.js
git commit -m "feat(shield): app-guard.js — checks 18-31 (app health + synthetic + runtime)"
```

---

## Task 5: Write Systemd Unit Files

**Files:**
- Create: `/opt/foundation-shield/systemd/fo-sysmon.service`
- Create: `/opt/foundation-shield/systemd/fo-sysmon.timer`
- Create: `/opt/foundation-shield/systemd/fo-repomon.service`
- Create: `/opt/foundation-shield/systemd/fo-repomon.timer`
- Create: `/opt/foundation-shield/systemd/fo-appmon.service`
- Create: `/opt/foundation-shield/systemd/fo-appmon.timer`

- [ ] **Step 1: Write all six unit files**

`/opt/foundation-shield/systemd/fo-sysmon.service`:
```ini
[Unit]
Description=Foundation System Monitor
After=network.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/node /usr/local/lib/fo-sys/pm2-governance.js
WorkingDirectory=/usr/local/lib/fo-sys
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fo-sysmon
Restart=no
EnvironmentFile=-/etc/fo-sys/env
```

`/opt/foundation-shield/systemd/fo-sysmon.timer`:
```ini
[Unit]
Description=Foundation System Monitor — every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
```

`/opt/foundation-shield/systemd/fo-repomon.service`:
```ini
[Unit]
Description=Foundation Repo Monitor
After=network.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/node /usr/local/lib/fo-sys/repo-governance.js
WorkingDirectory=/usr/local/lib/fo-sys
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fo-repomon
Restart=no
EnvironmentFile=-/etc/fo-sys/env
```

`/opt/foundation-shield/systemd/fo-repomon.timer`:
```ini
[Unit]
Description=Foundation Repo Monitor — hourly

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
AccuracySec=5min
Persistent=true

[Install]
WantedBy=timers.target
```

`/opt/foundation-shield/systemd/fo-appmon.service`:
```ini
[Unit]
Description=Foundation App Monitor
After=network.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/node /usr/local/lib/fo-sys/app-guard.js
WorkingDirectory=/usr/local/lib/fo-sys
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fo-appmon
Restart=no
EnvironmentFile=-/etc/fo-sys/env
```

`/opt/foundation-shield/systemd/fo-appmon.timer`:
```ini
[Unit]
Description=Foundation App Monitor — every 5 minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
```

- [ ] **Step 2: Commit the unit files**

```bash
cd /opt/foundation-shield
git add systemd/
git commit -m "feat(shield): systemd unit files for fo-sysmon, fo-repomon, fo-appmon timers"
```

---

## Task 6: Install and Enable on VPS Main

- [ ] **Step 1: Create install directories**

```bash
sudo mkdir -p /usr/local/lib/fo-sys /etc/fo-sys /var/log/fo-sys
sudo chown root:root /usr/local/lib/fo-sys /etc/fo-sys
sudo chown root:root /var/log/fo-sys
```

- [ ] **Step 2: Copy scripts to install path**

```bash
sudo cp /opt/foundation-shield/scripts/alerting.js    /usr/local/lib/fo-sys/
sudo cp /opt/foundation-shield/scripts/pm2-governance.js /usr/local/lib/fo-sys/
sudo cp /opt/foundation-shield/scripts/repo-governance.js /usr/local/lib/fo-sys/
sudo cp /opt/foundation-shield/scripts/resource-guard.js  /usr/local/lib/fo-sys/
sudo cp /opt/foundation-shield/scripts/app-guard.js       /usr/local/lib/fo-sys/
```

- [ ] **Step 3: Create environment config**

```bash
sudo tee /etc/fo-sys/env > /dev/null <<'EOF'
FO_SERVER_NAME=vps-main
FOMCP_URL=http://127.0.0.1:4500
SECRETS_PATH=/opt/mcp-server/.secrets
EOF
```

- [ ] **Step 4: Copy and enable systemd units**

```bash
sudo cp /opt/foundation-shield/systemd/*.service /etc/systemd/system/
sudo cp /opt/foundation-shield/systemd/*.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fo-sysmon.timer fo-repomon.timer fo-appmon.timer
```

- [ ] **Step 5: Verify timers are active**

```bash
systemctl list-timers fo-sysmon.timer fo-repomon.timer fo-appmon.timer
```

Expected: All three timers listed with `NEXT` dates in the future.

- [ ] **Step 6: Manually trigger a one-shot run and check output**

```bash
sudo systemctl start fo-sysmon.service
sudo journalctl -u fo-sysmon.service --since "1 minute ago" --no-pager
```

Expected: Journal output showing pm2-governance run, no fatal errors.

- [ ] **Step 7: Verify events appear in governance.db**

```bash
FOMCP_TOKEN=$(grep -E 'FOMCP_TOKEN|MCP_API_TOKEN' /opt/mcp-server/.secrets | head -1 | cut -d= -f2 | tr -d "'\"")
curl -s "http://127.0.0.1:4500/api/governance/status?server=vps-main" \
  -H "Authorization: Bearer $FOMCP_TOKEN"
```

Expected: JSON with event counts (total >= 1 from the heartbeat info event)

- [ ] **Step 8: Apply `chattr +a` to log file (append-only hardening)**

```bash
# Create the log file if it doesn't exist yet, then lock it append-only
sudo touch /var/log/fo-sys/digest.log
sudo chattr +a /var/log/fo-sys/digest.log
lsattr /var/log/fo-sys/digest.log
```

Expected: `----ia------------ /var/log/fo-sys/digest.log` (the `a` flag should be set)

- [ ] **Step 9: Push to foundation-shield GitHub**

```bash
cd /opt/foundation-shield
git push origin main
```

---

## Definition of Done

- [ ] `pm2-governance.js` runs checks 1–5 without errors, fires `alert()` with proper severity/check_type
- [ ] `repo-governance.js` runs checks 6–11 across fleet repos
- [ ] `resource-guard.js` runs checks 12–17 using `/proc` + system commands
- [ ] `app-guard.js` runs checks 14–31 covering app health, synthetic, runtime
- [ ] All four scripts dry-run cleanly: `node <script> --dry-run`
- [ ] Systemd timers `fo-sysmon`, `fo-repomon`, `fo-appmon` enabled and active on VPS Main
- [ ] Events appear in `governance.db` after a manual timer start
- [ ] Digest log at `/var/log/fo-sys/digest.log` is `chattr +a` locked
