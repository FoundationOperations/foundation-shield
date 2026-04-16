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
