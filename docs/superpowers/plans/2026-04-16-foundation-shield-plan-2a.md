# FoundationShield Plan 2A — Security, Deception, Intel Scripts (Checks 32–57) + Fleet Deployment

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the remaining 26 governance checks across Security Hardening, 2026 Threat Checks, Deception & Intrusion Detection, Advanced Intelligence, and Observability Polish — then deploy the full governance stack to VPS2 and VPS VRO.

**Prerequisite:** Plans 1A and 1B complete. Scripts installed and running on VPS Main. FOMCP pipeline active.

**Tech Stack:** Node 22 CommonJS, `child_process.execSync`, auditd, `ss`, `pg_stat_statements`, system commands.

---

## File Map

**Scripts (create in `/opt/foundation-shield/scripts/`):**
- Create: `security-guard.js` — Checks 32–44 (Security Hardening + 2026 Threats)
- Create: `deception-guard.js` — Checks 45–48 (Canary, Honey, auditd, systemd)
- Create: `intel-guard.js` — Checks 49–57 (Advanced Intelligence + Observability)
- Create: `sentinel-guard.js` — Cross-server heartbeat mesh

**Systemd units (add to `/opt/foundation-shield/systemd/`):**
- Create: `fo-secmon.service` + `fo-secmon.timer` (15min)
- Create: `fo-sentinel.service` + `fo-sentinel.timer` (15min)

**Fleet deployment scripts:**
- Create: `deploy/install.sh` — idempotent install script for any server
- Create: `deploy/uninstall.sh` — clean removal

---

## Task 1: Write `security-guard.js` (Checks 32–44)

**Files:**
- Create: `/opt/foundation-shield/scripts/security-guard.js`

- [ ] **Step 1: Write the script**

```js
// /opt/foundation-shield/scripts/security-guard.js
// Checks 32-44: Security Hardening + 2026 Threat Checks
// 32: Secrets exposure     37: Cryptominer detection    42: Deploy pipeline integrity
// 33: NPM audit CVE        38: Filesystem integrity     43: Threat intel outbound
// 34: Uptime Kuma sync     39: SUID/SGID detection      44: NTP clock drift
// 35: Config integrity     40: Unauthorized SSH keys
// 36: npm lockfile         41: IPv6 firewall gap
'use strict';
const { execSync } = require('child_process');
const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const { alert, info } = require('./alerting.js');

function run(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 20000 }).trim(); } catch { return ''; }
}

// ── Check 32: Secrets file exposure (world-readable .env, .secrets, *.pem) ──
async function checkSecretsExposure() {
  const paths = ['/var/www', '/opt', '/root', '/home'];
  for (const searchPath of paths) {
    try {
      const out = run(
        `find ${searchPath} -maxdepth 4 -type f \\( -name '.env' -o -name '.secrets' -o -name '*.pem' -o -name '*.key' \\) -perm /o+r 2>/dev/null | head -10`
      );
      if (out) {
        for (const file of out.split('\n').filter(Boolean)) {
          await alert(`secrets_exposed_${crypto.createHash('md5').update(file).digest('hex').slice(0,8)}`,
            `🔑 *Secrets file world-readable*: \`${file}\`\nFix: \`chmod 600 ${file}\``,
            { check_type: 'secrets_exposure', severity: 'critical', playbook: `chmod 600 ${file}` }
          );
        }
      }
    } catch (_) {}
  }
}

// ── Check 33: NPM audit CVE (weekly — check timestamp guard) ──
async function checkNpmAudit() {
  const STATE = '/var/log/fo-sys/npm-audit-last.txt';
  try {
    const lastRun = fs.existsSync(STATE) ? parseInt(fs.readFileSync(STATE, 'utf8')) : 0;
    if (Date.now() - lastRun < 6 * 24 * 60 * 60 * 1000) return; // weekly only
    const apps = ['/var/www/mac-daddy-portal', '/var/www/mac-daddy-portal-stage', '/opt/mcp-server'];
    for (const appPath of apps) {
      if (!fs.existsSync(`${appPath}/package.json`)) continue;
      const out = run(`cd ${appPath} && npm audit --json 2>/dev/null`);
      try {
        const report = JSON.parse(out);
        const vulns = report.metadata?.vulnerabilities || {};
        const critCount = (vulns.critical || 0) + (vulns.high || 0);
        if (critCount > 0) {
          await alert(`npm_audit_${path.basename(appPath)}`,
            `🔒 *NPM audit: ${critCount} critical/high CVEs* in ${appPath}\nCritical: ${vulns.critical || 0} | High: ${vulns.high || 0}\nFix: \`cd ${appPath} && npm audit fix\``,
            { check_type: 'npm_audit', severity: 'high', playbook: `cd ${appPath} && npm audit fix` }
          );
        }
      } catch (_) {}
    }
    fs.writeFileSync(STATE, String(Date.now()));
  } catch (_) {}
}

// ── Check 34: Uptime Kuma sync ──
async function checkUptimeKuma() {
  try {
    const out = run(`curl -s --max-time 5 'http://127.0.0.1:3010/api/status-page/heartbeat/all' 2>/dev/null`);
    if (!out) return;
    const data = JSON.parse(out);
    for (const [slug, hb] of Object.entries(data.heartbeatList || {})) {
      const last = hb[hb.length - 1];
      if (last && last.status === 0) {
        await alert(`kuma_down_${slug}`,
          `📊 *Uptime Kuma monitor DOWN*: ${slug}\nMessage: ${last.msg || 'no message'}`,
          { check_type: 'uptime_kuma', severity: 'high' }
        );
      }
    }
  } catch (_) {}
}

// ── Check 35: Config integrity (nginx, cron.d, deploy scripts checksum) ──
async function checkConfigIntegrity() {
  const STATE_FILE = '/var/log/fo-sys/config-checksums.json';
  const WATCH = [
    '/etc/nginx/nginx.conf',
    '/etc/nginx/sites-enabled/',
    '/etc/cron.d/',
    '/root/scripts/deploy.sh',
    '/opt/foundation-shield/scripts/alerting.js',
  ];

  let stored = {};
  try { stored = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch (_) {}

  const current = {};
  for (const watchPath of WATCH) {
    try {
      if (fs.statSync(watchPath).isDirectory()) {
        const files = fs.readdirSync(watchPath).map(f => path.join(watchPath, f));
        for (const f of files) {
          const hash = crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex').slice(0, 16);
          current[f] = hash;
        }
      } else {
        const hash = crypto.createHash('sha256').update(fs.readFileSync(watchPath)).digest('hex').slice(0, 16);
        current[watchPath] = hash;
      }
    } catch (_) {}
  }

  for (const [file, hash] of Object.entries(current)) {
    if (stored[file] && stored[file] !== hash) {
      await alert(`config_changed_${crypto.createHash('md5').update(file).digest('hex').slice(0,8)}`,
        `⚙️ *Config changed*: \`${file}\`\nPrevious hash: ${stored[file]}\nCurrent hash: ${hash}\nInvestigate: \`git diff ${file}\``,
        { check_type: 'config_integrity', severity: 'high', playbook: `git diff ${file}` }
      );
    }
  }

  // Always update stored checksums
  try { fs.writeFileSync(STATE_FILE, JSON.stringify(current, null, 2)); } catch (_) {}
}

// ── Check 36: npm lockfile integrity ──
async function checkLockfileIntegrity() {
  const apps = ['/var/www/mac-daddy-portal', '/opt/mcp-server'];
  for (const appPath of apps) {
    try {
      const lockFile = `${appPath}/package-lock.json`;
      if (!fs.existsSync(lockFile)) continue;
      const out = run(`cd ${appPath} && npm ci --dry-run 2>&1 | grep -i 'invalid\\|missing\\|tampered' | head -5`);
      if (out) {
        await alert(`lockfile_integrity_${path.basename(appPath)}`,
          `🔐 *npm lockfile integrity issue*: ${appPath}\n\`\`\`\n${out.slice(0, 300)}\n\`\`\``,
          { check_type: 'lockfile_integrity', severity: 'critical', playbook: `cd ${appPath} && npm ci` }
        );
      }
    } catch (_) {}
  }
}

// ── Check 37: Cryptominer detection ──
async function checkCryptominer() {
  // Stratum mining ports
  const MINER_PORTS = [3333, 4444, 14444, 45700, 9999];
  for (const port of MINER_PORTS) {
    const conns = run(`ss -tnp 2>/dev/null | grep ':${port}\\b' | head -5`);
    if (conns) {
      await alert(`cryptominer_port_${port}`,
        `⛏️ *Cryptominer connection detected!* Port ${port} (stratum)\n\`\`\`\n${conns}\n\`\`\`\nKill immediately and audit system.`,
        { check_type: 'cryptominer', severity: 'critical', playbook: 'netstat -tnp | grep ESTABLISHED — kill miner process, audit /tmp /var/tmp for binaries' }
      );
    }
  }

  // Non-PM2 processes with sustained high CPU (>80%) for longer than 5min
  try {
    const nproc = parseInt(run('nproc')) || 1;
    const out = run(`ps aux --sort=-%cpu --no-headers 2>/dev/null | head -5`);
    for (const line of out.split('\n').filter(Boolean)) {
      const parts = line.trim().split(/\s+/);
      const pid = parseInt(parts[1]);
      const cpu = parseFloat(parts[2]);
      const cmd = parts.slice(10).join(' ');
      if (cpu > 80 && !cmd.includes('node') && !cmd.includes('postgres') && !cmd.includes('nginx')) {
        const uptimeSecs = (() => {
          try {
            const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
            const m = stat.match(/^\d+ \(.*?\)(?: \S+){19} (\d+)/);
            const sysUptime = parseFloat(fs.readFileSync('/proc/uptime', 'utf8').split(' ')[0]);
            return m ? sysUptime - parseInt(m[1]) / 100 : 0;
          } catch { return 0; }
        })();
        if (uptimeSecs > 300) {
          await alert(`cryptominer_cpu_${pid}`,
            `⛏️ *Suspicious high-CPU process*\nPID: ${pid} | CPU: ${cpu}% | Uptime: ${Math.round(uptimeSecs / 60)}min\nCmd: \`${cmd.slice(0, 120)}\``,
            { check_type: 'cryptominer', severity: 'critical', playbook: `kill -9 ${pid} && ls -la /proc/${pid}/exe 2>/dev/null` }
          );
        }
      }
    }
  } catch (_) {}
}

// ── Check 38: Filesystem integrity on critical paths ──
async function checkFilesystemIntegrity() {
  const STATE_FILE = '/var/log/fo-sys/fs-hashes.json';
  const CRITICAL_FILES = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/sudoers',
    '/root/.ssh/authorized_keys',
    '/home/nodeapp/.ssh/authorized_keys',
    '/etc/nginx/nginx.conf',
  ];

  let stored = {};
  try { stored = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch (_) {}

  const current = {};
  for (const f of CRITICAL_FILES) {
    try {
      const content = fs.readFileSync(f);
      current[f] = crypto.createHash('sha256').update(content).digest('hex');
    } catch (_) { current[f] = 'missing'; }
  }

  for (const [f, hash] of Object.entries(current)) {
    if (stored[f] && stored[f] !== hash) {
      await alert(`fs_integrity_${crypto.createHash('md5').update(f).digest('hex').slice(0,8)}`,
        `🚨 *Critical file changed*: \`${f}\`\nThis could indicate system compromise.\nPrevious: ${stored[f].slice(0, 16)}\nCurrent: ${hash.slice(0, 16)}`,
        { check_type: 'fs_integrity', severity: 'critical', playbook: `diff <(echo ${stored[f]}) <(sha256sum ${f}) — investigate immediately` }
      );
    }
  }

  try { fs.writeFileSync(STATE_FILE, JSON.stringify(current, null, 2)); } catch (_) {}
}

// ── Check 39: New SUID/SGID binary detection ──
async function checkSuid() {
  const STATE_FILE = '/var/log/fo-sys/suid-baseline.txt';
  const current = run('find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | sort');

  if (fs.existsSync(STATE_FILE)) {
    const stored = fs.readFileSync(STATE_FILE, 'utf8').trim();
    const storedSet = new Set(stored.split('\n').filter(Boolean));
    const currentSet = new Set(current.split('\n').filter(Boolean));
    for (const binary of currentSet) {
      if (!storedSet.has(binary)) {
        await alert(`suid_new_${crypto.createHash('md5').update(binary).digest('hex').slice(0,8)}`,
          `🚨 *New SUID/SGID binary detected*: \`${binary}\`\nThis is a serious security concern — investigate immediately.`,
          { check_type: 'suid_detection', severity: 'critical', playbook: `ls -la ${binary} && sha256sum ${binary} && strings ${binary} | head -20` }
        );
      }
    }
  }

  try { fs.writeFileSync(STATE_FILE, current); } catch (_) {}
}

// ── Check 40: Unauthorized SSH key addition ──
async function checkSshKeys() {
  const STATE_FILE = '/var/log/fo-sys/ssh-keys.json';
  const AUTH_KEY_FILES = [
    '/root/.ssh/authorized_keys',
    '/home/nodeapp/.ssh/authorized_keys',
  ];

  let stored = {};
  try { stored = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch (_) {}

  const current = {};
  for (const f of AUTH_KEY_FILES) {
    try { current[f] = crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex'); } catch { current[f] = 'missing'; }
  }

  for (const [f, hash] of Object.entries(current)) {
    if (stored[f] && stored[f] !== hash) {
      await alert(`ssh_key_change_${crypto.createHash('md5').update(f).digest('hex').slice(0,8)}`,
        `🔑 *SSH authorized_keys changed*: \`${f}\`\nThis may indicate unauthorized access.\nDiff: \`diff <stored> <current>\``,
        { check_type: 'ssh_key_change', severity: 'critical', playbook: `cat ${f} — review all keys and remove unauthorized ones` }
      );
    }
  }

  try { fs.writeFileSync(STATE_FILE, JSON.stringify(current, null, 2)); } catch (_) {}
}

// ── Check 41: IPv6 firewall gap ──
async function checkIpv6Gap() {
  try {
    const ipv6Active = run("cat /proc/net/if_inet6 2>/dev/null | grep -v '^$' | wc -l");
    if (parseInt(ipv6Active) === 0) return; // IPv6 not active
    const ip6tables = run('ip6tables -L INPUT --line-numbers 2>/dev/null | grep -v "^$\\|^Chain\\|^num\\|^target" | wc -l');
    if (parseInt(ip6tables) === 0) {
      await alert('ipv6_firewall_gap',
        `🌐 *IPv6 active but no ip6tables rules*\nIPv6 interfaces exist but ip6tables INPUT chain is empty — traffic bypasses firewall.\nFix: Configure ip6tables or disable IPv6.`,
        { check_type: 'ipv6_gap', severity: 'high', playbook: 'ip6tables -A INPUT -j DROP — or: sysctl -w net.ipv6.conf.all.disable_ipv6=1' }
      );
    }
  } catch (_) {}
}

// ── Check 42: Deploy pipeline integrity ──
async function checkDeployIntegrity() {
  const PIPELINE_FILES = [
    '/root/scripts/deploy.sh',
  ];
  const STATE_FILE = '/var/log/fo-sys/deploy-hashes.json';

  let stored = {};
  try { stored = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch (_) {}

  const current = {};
  for (const f of PIPELINE_FILES) {
    try { current[f] = crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex'); } catch { current[f] = 'missing'; }
  }

  for (const [f, hash] of Object.entries(current)) {
    if (stored[f] && stored[f] !== hash) {
      await alert(`deploy_integrity_${crypto.createHash('md5').update(f).digest('hex').slice(0,8)}`,
        `🏗️ *Deploy pipeline script changed*: \`${f}\`\nUnexpected change to deploy infrastructure — investigate before next deploy.`,
        { check_type: 'deploy_integrity', severity: 'high', playbook: `git -C $(dirname ${f}) log --oneline -5` }
      );
    }
  }

  try { fs.writeFileSync(STATE_FILE, JSON.stringify(current, null, 2)); } catch (_) {}
}

// ── Check 43: Threat intel outbound connections ──
async function checkThreatIntel() {
  // Load known-bad IPs from governance.db via FOMCP endpoint
  // For now: pull from local cached blocklist (updated weekly by a separate job)
  const BLOCKLIST = '/var/log/fo-sys/threat-intel-ips.txt';
  if (!fs.existsSync(BLOCKLIST)) return;

  const badIps = new Set(fs.readFileSync(BLOCKLIST, 'utf8').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#')));
  if (!badIps.size) return;

  const conns = run('ss -tnp state established 2>/dev/null');
  for (const line of conns.split('\n').filter(Boolean)) {
    const m = line.match(/(\d+\.\d+\.\d+\.\d+):(\d+)\s+users/);
    if (!m) continue;
    const [, ip] = m;
    if (badIps.has(ip)) {
      await alert(`threat_intel_conn_${ip.replace(/\./g, '_')}`,
        `🚨 *Active connection to threat intel IP*: ${ip}\nThis IP is in the C2/malware blocklist.\nKill: \`ss -K dst ${ip}\``,
        { check_type: 'threat_intel', severity: 'critical', playbook: `ss -K dst ${ip} && netstat -tnp | grep ${ip}` }
      );
    }
  }
}

// ── Check 44: NTP clock drift ──
async function checkNtpDrift() {
  try {
    const out = run('timedatectl show --property=NTPSynchronized,TimeUSec 2>/dev/null');
    const synced = out.includes('NTPSynchronized=yes');
    if (!synced) {
      await alert('ntp_unsynchronized',
        `🕐 *NTP not synchronized*\nSystem clock may be drifting — this affects log correlation and JWT validity.\nFix: \`timedatectl set-ntp true\``,
        { check_type: 'ntp_drift', severity: 'high', playbook: 'timedatectl set-ntp true && systemctl restart systemd-timesyncd' }
      );
      return;
    }
    // Check actual offset with chronyc if available
    const chrony = run('chronyc tracking 2>/dev/null | grep "System time"');
    const m = chrony.match(/System time\s*:\s*([\d.]+) seconds/);
    if (m) {
      const offsetSecs = parseFloat(m[1]);
      if (offsetSecs > 60) {
        await alert('ntp_drift_large',
          `🕐 *NTP drift excessive* — ${offsetSecs.toFixed(1)}s offset from NTP server\nFix: \`chronyc makestep\``,
          { check_type: 'ntp_drift', severity: 'high', playbook: 'chronyc makestep' }
        );
      }
    }
  } catch (_) {}
}

async function main() {
  await checkSecretsExposure();
  await checkNpmAudit();
  await checkUptimeKuma();
  await checkConfigIntegrity();
  await checkLockfileIntegrity();
  await checkCryptominer();
  await checkFilesystemIntegrity();
  await checkSuid();
  await checkSshKeys();
  await checkIpv6Gap();
  await checkDeployIntegrity();
  await checkThreatIntel();
  await checkNtpDrift();
  await info('security-guard run complete', { key: 'security_guard_run', check_type: 'heartbeat' });
}

main().catch(err => { console.error('[security-guard] fatal:', err.message); process.exit(1); });
```

- [ ] **Step 2: Dry-run test**

```bash
node /opt/foundation-shield/scripts/security-guard.js --dry-run 2>&1 | head -30
```

Expected: No fatal errors. Checks run silently or produce dry-run output.

- [ ] **Step 3: Commit**

```bash
cd /opt/foundation-shield
git add scripts/security-guard.js
git commit -m "feat(shield): security-guard.js — checks 32-44 (hardening + 2026 threats)"
```

---

## Task 2: Write `deception-guard.js` (Checks 45–48)

**Files:**
- Create: `/opt/foundation-shield/scripts/deception-guard.js`
- Create: `/opt/foundation-shield/scripts/honey-listener.js` (long-running honeypot HTTP listener)

- [ ] **Step 1: Write `deception-guard.js`**

```js
// /opt/foundation-shield/scripts/deception-guard.js
// Checks 45-48: Deception & Intrusion Detection
// 45: Canary file tripwires   47: auditd trail review
// 46: Honey credentials       48: New systemd service detection
'use strict';
const { execSync } = require('child_process');
const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const { alert, info } = require('./alerting.js');

function run(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 15000 }).trim(); } catch { return ''; }
}

// ── Check 45: Canary files ──
// Canary files are planted at startup and their mtimes/presence monitored each run.
// Any access (atime change) or modification/deletion triggers an alert.
const CANARY_DIR  = '/var/log/fo-sys/.canaries';
const CANARY_STATE = '/var/log/fo-sys/canary-state.json';
const CANARY_LOCATIONS = [
  { dir: '/tmp',          name: '.systemd-private-cache', content: 'DECOY' },
  { dir: '/var/www',     name: '.git-credentials',       content: 'github_pat_DECOY_11AAAAAAAAAAAA' },
  { dir: '/root',         name: '.aws-credentials.bak',  content: '[default]\naws_access_key_id=AKIADECOY00000000000\n' },
  { dir: '/var/backups', name: 'db-backup-2026.sql.gz',  content: 'DECOY-BACKUP' },
];

async function checkCanaries() {
  // Plant canaries if missing
  try { fs.mkdirSync(CANARY_DIR, { recursive: true }); } catch (_) {}

  let state = {};
  try { state = JSON.parse(fs.readFileSync(CANARY_STATE, 'utf8')); } catch (_) {}

  for (const canary of CANARY_LOCATIONS) {
    const filePath = path.join(canary.dir, canary.name);
    const key = filePath;

    // Plant if missing
    if (!fs.existsSync(filePath)) {
      try { fs.writeFileSync(filePath, canary.content, { mode: 0o644 }); } catch (_) {}
      // Only alert if it was previously tracked (disappearance = access+deletion)
      if (state[key]) {
        await alert(`canary_deleted_${crypto.createHash('md5').update(key).digest('hex').slice(0,8)}`,
          `🎣 *Canary file DELETED*: \`${filePath}\`\nSomeone deleted a planted decoy file — this indicates active intrusion.`,
          { check_type: 'canary_touch', severity: 'critical', playbook: 'Incident response: check auditd logs, bash_history, /var/log/auth.log immediately' }
        );
        state[key] = null;
        continue;
      }
    }

    try {
      const stat = fs.statSync(filePath);
      const storedMtime = state[key]?.mtime || null;
      const currentMtime = stat.mtimeMs;

      if (storedMtime && currentMtime !== storedMtime) {
        await alert(`canary_modified_${crypto.createHash('md5').update(key).digest('hex').slice(0,8)}`,
          `🎣 *Canary file MODIFIED*: \`${filePath}\`\nA planted decoy file was modified — indicates active intrusion or ransomware activity.`,
          { check_type: 'canary_touch', severity: 'critical', playbook: 'Incident response immediately — check auditd, bash_history, auth.log' }
        );
      }

      state[key] = { mtime: currentMtime };
    } catch (_) {}
  }

  try { fs.writeFileSync(CANARY_STATE, JSON.stringify(state, null, 2)); } catch (_) {}
}

// ── Check 46: Honey credentials ──
// Check if honey-listener.js is running and if its log shows any hits
async function checkHoneyCredentials() {
  const HONEY_LOG = '/var/log/fo-sys/honey-hits.log';
  if (!fs.existsSync(HONEY_LOG)) return;

  try {
    const stat = fs.statSync(HONEY_LOG);
    const STATE_FILE = '/var/log/fo-sys/honey-state.json';
    let state = { lastSize: 0 };
    try { state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch (_) {}

    if (stat.size > state.lastSize) {
      // New hits since last check
      const fd = fs.openSync(HONEY_LOG, 'r');
      const buf = Buffer.alloc(stat.size - state.lastSize);
      fs.readSync(fd, buf, 0, buf.length, state.lastSize);
      fs.closeSync(fd);
      const newLines = buf.toString('utf8').split('\n').filter(Boolean);

      for (const line of newLines) {
        try {
          const hit = JSON.parse(line);
          await alert(`honey_hit_${Date.now()}`,
            `🍯 *Honey credential used!*\nTime: ${hit.ts}\nIP: ${hit.ip} | Path: ${hit.path}\nCredential: ${hit.credential || 'unknown'}\nThis is an active attacker probing for credentials.`,
            { check_type: 'honey_credential', severity: 'critical', playbook: `Block IP: iptables -A INPUT -s ${hit.ip} -j DROP && fail2ban-client set sshd banip ${hit.ip}` }
          );
        } catch (_) {}
      }

      state.lastSize = stat.size;
      try { fs.writeFileSync(STATE_FILE, JSON.stringify(state)); } catch (_) {}
    }
  } catch (_) {}
}

// ── Check 47: auditd trail review ──
async function checkAuditd() {
  // Check auditd is running
  const status = run('systemctl is-active auditd 2>/dev/null');
  if (status !== 'active') {
    await alert('auditd_down',
      `🔍 *auditd is not running* — kernel audit trail inactive\nFix: \`sudo systemctl start auditd\``,
      { check_type: 'auditd', severity: 'high', playbook: 'sudo systemctl enable --now auditd' }
    );
    return;
  }

  // Check for recent high-severity audit events (su, sudo to root, passwd changes)
  try {
    const recentEvents = run('ausearch -ts recent -m USER_CMD,USER_AUTH -i 2>/dev/null | tail -20');
    const suspicious = recentEvents.split('\n').filter(l =>
      l.includes('cmd=') && (l.includes('su root') || l.includes('passwd') || l.includes('visudo'))
    );
    if (suspicious.length > 0) {
      await alert('auditd_suspicious_cmd',
        `🔍 *Suspicious audit event*\n\`\`\`\n${suspicious.slice(0, 3).join('\n')}\n\`\`\`\nReview full log: \`ausearch -ts today -m USER_CMD\``,
        { check_type: 'auditd_event', severity: 'high', playbook: 'ausearch -ts today -m USER_CMD -i | grep -v nodeapp' }
      );
    }
  } catch (_) {}
}

// ── Check 48: New systemd service detection ──
async function checkNewSystemdServices() {
  const STATE_FILE = '/var/log/fo-sys/systemd-services.txt';
  const SYSTEM_DIRS = ['/etc/systemd/system', '/lib/systemd/system'];
  const KNOWN_PREFIXES = ['fo-', 'nginx', 'postgresql', 'docker', 'ssh', 'cron', 'fail2ban',
    'systemd-', 'multi-user', 'network', 'ntp', 'rsync', 'ufw', 'pm2', 'n8n', 'uptime-kuma'];

  let known = new Set();
  try { known = new Set(fs.readFileSync(STATE_FILE, 'utf8').split('\n').filter(Boolean)); } catch (_) {}

  const current = new Set();
  for (const dir of SYSTEM_DIRS) {
    try {
      const files = fs.readdirSync(dir).filter(f => f.endsWith('.service'));
      files.forEach(f => current.add(`${dir}/${f}`));
    } catch (_) {}
  }

  for (const svc of current) {
    if (known.has(svc)) continue;
    const svcName = path.basename(svc);
    const isKnown = KNOWN_PREFIXES.some(p => svcName.startsWith(p));
    if (!isKnown && known.size > 0) { // only alert if we have a baseline
      await alert(`new_systemd_svc_${crypto.createHash('md5').update(svc).digest('hex').slice(0,8)}`,
        `⚙️ *New systemd service detected*: \`${svc}\`\nUnknown service unit appeared — investigate before rebooting.\nView: \`systemctl cat ${svcName}\``,
        { check_type: 'new_systemd_service', severity: 'critical', playbook: `systemctl cat ${svcName} && systemctl status ${svcName}` }
      );
    }
  }

  try { fs.writeFileSync(STATE_FILE, [...current].join('\n')); } catch (_) {}
}

async function main() {
  await checkCanaries();
  await checkHoneyCredentials();
  await checkAuditd();
  await checkNewSystemdServices();
  await info('deception-guard run complete', { key: 'deception_guard_run', check_type: 'heartbeat' });
}

main().catch(err => { console.error('[deception-guard] fatal:', err.message); process.exit(1); });
```

- [ ] **Step 2: Write `honey-listener.js`** (long-running decoy HTTP listener)

```js
// /opt/foundation-shield/scripts/honey-listener.js
// Runs on a non-registered port (7474) as a honeypot.
// Logs any connection attempt to /var/log/fo-sys/honey-hits.log
// Any request = attacker probing for credentials.
'use strict';
const http = require('http');
const fs   = require('fs');

const PORT     = parseInt(process.env.HONEY_PORT || '7474');
const LOG_FILE = '/var/log/fo-sys/honey-hits.log';

const HONEY_CREDS = {
  api_key:       'sk-HONEY-DECOY-NOT-REAL-KEY-0000000000000000000000000000000000000000',
  db_url:        'postgresql://admin:HONEY_PASSWORD_DECOY@localhost:5432/production',
  telegram_token: '0000000000:HONEYDECOY_TOKEN_NOTREAL_AAAAAAAAAAAAA',
};

function logHit(ip, path, method, body, credential) {
  const entry = JSON.stringify({ ts: new Date().toISOString(), ip, path, method, body: body?.slice(0, 200), credential }) + '\n';
  try { fs.appendFileSync(LOG_FILE, entry); } catch (_) {}
}

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', d => body += d.toString().slice(0, 500));
  req.on('end', () => {
    const ip = req.socket.remoteAddress;
    // Identify which honey credential was used (if any)
    let credential = null;
    for (const [name, value] of Object.entries(HONEY_CREDS)) {
      if (body.includes(value) || (req.headers.authorization || '').includes(value)) {
        credential = name;
        break;
      }
    }
    logHit(ip, req.url, req.method, body, credential);
    // Respond slowly to waste attacker time
    setTimeout(() => {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
    }, 2000);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[honey-listener] Decoy HTTP listener on :${PORT}`);
});

server.on('error', err => console.error('[honey-listener] error:', err.message));
```

- [ ] **Step 3: Commit**

```bash
cd /opt/foundation-shield
git add scripts/deception-guard.js scripts/honey-listener.js
git commit -m "feat(shield): deception-guard.js + honey-listener.js — checks 45-48"
```

---

## Task 3: Write `intel-guard.js` (Checks 49–57)

**Files:**
- Create: `/opt/foundation-shield/scripts/intel-guard.js`

- [ ] **Step 1: Write the script**

```js
// /opt/foundation-shield/scripts/intel-guard.js
// Checks 49-57: Advanced Intelligence + Observability Polish
// 49: Process masquerade   53: AI cost anomaly        57: Self-monitoring
// 50: Backup integrity     54: Statistical baseline
// 51: Log forwarding       55: Response time trend
// 52: Slow PG queries      56: Dependency staleness
'use strict';
const { execSync } = require('child_process');
const fs   = require('fs');
const http = require('http');
const { alert, info } = require('./alerting.js');

function run(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 15000 }).trim(); } catch { return ''; }
}

// ── Check 49: Process masquerade detection ──
async function checkProcessMasquerade() {
  // Real kernel threads: comm starts with '[', mapped to ring 0, no /proc/pid/exe link
  // Masquerade: a process with name like 'kworker' or 'sshd' that HAS an exe link to /tmp or /var/tmp
  try {
    const pids = fs.readdirSync('/proc').filter(d => /^\d+$/.test(d));
    for (const pidStr of pids) {
      const pid = parseInt(pidStr);
      try {
        const comm = fs.readFileSync(`/proc/${pid}/comm`, 'utf8').trim();
        const suspiciousNames = ['kworker', 'kthread', 'sshd', 'systemd', 'bash', 'sh', 'cron'];
        if (!suspiciousNames.some(n => comm.includes(n))) continue;

        let exePath = null;
        try { exePath = fs.readlinkSync(`/proc/${pid}/exe`); } catch { continue; } // real kernel threads have no exe

        // If exe points to /tmp, /var/tmp, /dev/shm — definite masquerade
        if (exePath && (exePath.startsWith('/tmp/') || exePath.startsWith('/var/tmp/') || exePath.startsWith('/dev/shm/'))) {
          await alert(`masquerade_${pid}`,
            `🎭 *Process masquerade detected!*\nPID: ${pid} | Comm: ${comm}\nExe: \`${exePath}\`\nA process is impersonating a system process from a temp directory.`,
            { check_type: 'process_masquerade', severity: 'critical', playbook: `kill -9 ${pid} && sha256sum ${exePath} && ls -la ${exePath}` }
          );
        }
      } catch (_) {}
    }
  } catch (_) {}
}

// ── Check 50: Backup integrity ──
async function checkBackupIntegrity() {
  const BACKUP_DIRS = ['/var/backups', '/root/backups'];
  const STATE_FILE  = '/var/log/fo-sys/backup-state.json';

  let state = {};
  try { state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch (_) {}

  let found = false;
  for (const dir of BACKUP_DIRS) {
    if (!fs.existsSync(dir)) continue;
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.sql') || f.endsWith('.gz') || f.endsWith('.dump'));
    if (files.length === 0) continue;
    found = true;

    for (const file of files) {
      const filePath = `${dir}/${file}`;
      try {
        const stat = fs.statSync(filePath);
        const ageDays = (Date.now() - stat.mtimeMs) / 86400000;
        if (ageDays > 2) {
          await alert(`backup_stale_${file}`,
            `💾 *Backup stale* — ${file}\nLast modified: ${Math.round(ageDays)} days ago\nExpected: daily backup rotation`,
            { check_type: 'backup_integrity', severity: 'high', playbook: 'Trigger manual backup: pg_dump macdaddyportal > /var/backups/macdaddyportal-$(date +%Y%m%d).sql' }
          );
        }
      } catch (_) {}
    }
  }

  if (!found) {
    await alert('backup_missing',
      `💾 *No backups found* in /var/backups or /root/backups\nDatabase backups appear to be missing — configure automated pg_dump.`,
      { check_type: 'backup_integrity', severity: 'high', playbook: 'Set up daily pg_dump cron: 0 3 * * * pg_dump macdaddyportal | gzip > /var/backups/macdaddy-$(date +%Y%m%d).sql.gz' }
    );
  }
}

// ── Check 51: Log forwarding health ──
async function checkLogForwarding() {
  const DIGEST_LOG = '/var/log/fo-sys/digest.log';
  try {
    const stat = fs.statSync(DIGEST_LOG);
    const ageMins = (Date.now() - stat.mtimeMs) / 60000;
    if (ageMins > 10) {
      await alert('log_forwarding_stale',
        `📋 *Governance digest log stale* — last write ${Math.round(ageMins)}min ago\nGovernance scripts may not be running. Check: \`systemctl status fo-sysmon.timer\``,
        { check_type: 'log_forwarding', severity: 'high', playbook: 'systemctl status fo-sysmon.timer fo-appmon.timer && journalctl -u fo-sysmon.service --since "30 minutes ago"' }
      );
    }
    // Verify log is growing (not truncated by attacker — should be chattr +a)
    const lsattr = run(`lsattr ${DIGEST_LOG} 2>/dev/null`);
    if (!lsattr.includes('a')) {
      await alert('log_append_only_missing',
        `📋 *Governance log not append-only* — \`chattr +a\` missing on \`${DIGEST_LOG}\`\nLog could be truncated by attacker. Fix: \`chattr +a ${DIGEST_LOG}\``,
        { check_type: 'log_hardening', severity: 'high', playbook: `chattr +a ${DIGEST_LOG}` }
      );
    }
  } catch (_) {}
}

// ── Check 52: PostgreSQL slow queries ──
async function checkSlowQueries() {
  try {
    const out = run(`sudo -u postgres psql -t -c "SELECT query, calls, mean_exec_time::int FROM pg_stat_statements WHERE mean_exec_time > 1000 ORDER BY mean_exec_time DESC LIMIT 5;" 2>/dev/null`);
    if (out && out.trim() && !out.includes('relation "pg_stat_statements" does not exist')) {
      const lines = out.split('\n').filter(l => l.trim() && l.includes('|'));
      if (lines.length > 0) {
        await alert('pg_slow_queries',
          `🐘 *PostgreSQL slow queries detected*\n\`\`\`\n${lines.slice(0, 3).join('\n')}\n\`\`\`\nAvg >1000ms — consider adding indexes or query optimization.`,
          { check_type: 'slow_queries', severity: 'medium', playbook: 'EXPLAIN ANALYZE <slow_query> — identify missing indexes' }
        );
      }
    }
  } catch (_) {}
}

// ── Check 53: AI/API cost anomaly ──
async function checkAiCostAnomaly() {
  // Compare today's FOMCP tool call count to 7-day baseline
  // Pull from FOMCP stats endpoint
  return new Promise((resolve) => {
    const FOMCP_TOKEN = (() => {
      try {
        const lines = fs.readFileSync('/opt/mcp-server/.secrets', 'utf8').split('\n');
        for (const l of lines) { const m = l.match(/^(FOMCP_TOKEN|MCP_API_TOKEN)=(.+)$/); if (m) return m[2].replace(/^['"]|['"]$/g, ''); }
      } catch { return null; }
    })();
    if (!FOMCP_TOKEN) return resolve();

    const req = http.get({
      hostname: '127.0.0.1',
      port: 4500,
      path: '/stats',
      headers: { Authorization: `Bearer ${FOMCP_TOKEN}` }
    }, async (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', async () => {
        try {
          const stats = JSON.parse(data);
          const totalCalls = stats?.overview?.totalCalls || 0;
          // Simple threshold: if >500 calls today, flag for review
          // (A proper baseline comparison is implemented in Plan 3B)
          if (totalCalls > 500) {
            await alert('ai_cost_anomaly',
              `💰 *High AI tool call volume* — ${totalCalls} calls tracked\nReview: \`curl http://127.0.0.1:4500/stats\``,
              { check_type: 'ai_cost_anomaly', severity: 'high', playbook: 'Review /stats endpoint for unusual patterns' }
            );
          }
        } catch (_) {}
        resolve();
      });
    });
    req.on('error', () => resolve());
    req.setTimeout(5000, () => { req.destroy(); resolve(); });
  });
}

// ── Check 54: Statistical baseline anomaly ──
async function checkBaselineAnomaly() {
  // Compare current resource metrics to 7-day rolling baseline stored in governance.db
  // Baseline data is populated by the agent (Plan 3A). Skip if no baseline yet.
  const STATE_FILE = '/var/log/fo-sys/baseline-metrics.json';
  try {
    if (!fs.existsSync(STATE_FILE)) return;
    const baseline = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));

    // Current metrics
    const meminfo = fs.readFileSync('/proc/meminfo', 'utf8');
    const get = key => parseInt(meminfo.match(new RegExp(`^${key}:\\s+(\\d+)`, 'm'))?.[1] || 0);
    const ramUsedPct = Math.round((get('MemTotal') - get('MemAvailable')) / get('MemTotal') * 100);
    const load5 = parseFloat(fs.readFileSync('/proc/loadavg', 'utf8').split(' ')[1]);

    const metrics = { ram_pct: ramUsedPct, cpu_load5: load5 };
    for (const [metric, current] of Object.entries(metrics)) {
      const b = baseline[metric];
      if (!b || !b.avg || !b.stddev) continue;
      const zscore = Math.abs((current - b.avg) / b.stddev);
      if (zscore > 2) {
        await alert(`baseline_anomaly_${metric}`,
          `📊 *Statistical anomaly*: ${metric}\nCurrent: ${current} | Baseline avg: ${b.avg.toFixed(1)} | σ: ${b.stddev.toFixed(1)}\nZ-score: ${zscore.toFixed(1)} (>2σ threshold)`,
          { check_type: 'baseline_anomaly', severity: 'high' }
        );
      }
    }
  } catch (_) {}
}

// ── Check 55: HTTP response time trend ──
async function checkResponseTimeTrend() {
  // Lightweight: check if endpoint response time is consistently >2x 7-day avg
  // Full trend analysis done by governance agent in Plan 3A. This is a quick sanity check.
  const STATE_FILE = '/var/log/fo-sys/response-times.json';
  const ENDPOINT   = 'http://127.0.0.1:3000/health';
  const start = Date.now();

  await new Promise(resolve => {
    const req = http.get(ENDPOINT, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve);
    req.setTimeout(5000, () => { req.destroy(); resolve(); });
  });

  const currentMs = Date.now() - start;
  let history = [];
  try { history = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch (_) {}
  history.push({ ts: Date.now(), ms: currentMs });
  history = history.slice(-50); // keep last 50 samples

  if (history.length >= 10) {
    const avg = history.slice(0, -1).reduce((s, h) => s + h.ms, 0) / (history.length - 1);
    if (currentMs > avg * 2 && currentMs > 2000) {
      await alert('response_time_degraded',
        `⏱️ *Response time degraded*: mac-daddy-prod\nCurrent: ${currentMs}ms | Avg: ${Math.round(avg)}ms (2x threshold exceeded)`,
        { check_type: 'response_time_trend', severity: 'medium' }
      );
    }
  }

  try { fs.writeFileSync(STATE_FILE, JSON.stringify(history)); } catch (_) {}
}

// ── Check 56: Dependency staleness (weekly) ──
async function checkDependencyStaleness() {
  const STATE = '/var/log/fo-sys/dep-staleness-last.txt';
  try {
    const lastRun = fs.existsSync(STATE) ? parseInt(fs.readFileSync(STATE, 'utf8')) : 0;
    if (Date.now() - lastRun < 6 * 24 * 60 * 60 * 1000) return;
    const out = run('cd /var/www/mac-daddy-portal && npm outdated --json 2>/dev/null');
    if (out) {
      const outdated = JSON.parse(out);
      const majorBehind = Object.entries(outdated).filter(([, v]) => {
        const curr = v.current?.split('.')[0];
        const latest = v.latest?.split('.')[0];
        return curr && latest && parseInt(latest) > parseInt(curr);
      });
      if (majorBehind.length > 0) {
        await alert('dependency_staleness',
          `📦 *${majorBehind.length} major version(s) behind*: mac-daddy-portal\nPackages: ${majorBehind.map(([name]) => name).join(', ')}\nRun: \`npm outdated\` for full report`,
          { check_type: 'dependency_staleness', severity: 'info' }
        );
      }
    }
    fs.writeFileSync(STATE, String(Date.now()));
  } catch (_) {}
}

// ── Check 57: FoundationShield self-monitoring ──
async function checkSelfMonitoring() {
  const DIGEST_LOG = '/var/log/fo-sys/digest.log';
  const issues = [];

  // Last run time
  try {
    const stat = fs.statSync(DIGEST_LOG);
    const ageMins = (Date.now() - stat.mtimeMs) / 60000;
    if (ageMins > 15) issues.push(`digest log stale (${Math.round(ageMins)}min)`);
  } catch { issues.push('digest log missing'); }

  // Timer status
  const timerStatus = run('systemctl is-active fo-sysmon.timer fo-repomon.timer fo-appmon.timer fo-secmon.timer 2>/dev/null');
  const inactiveTimers = timerStatus.split('\n').filter(l => l !== 'active');
  if (inactiveTimers.length > 0) issues.push(`inactive timers: ${inactiveTimers.length}`);

  if (issues.length > 0) {
    await alert('shield_self_monitor',
      `🛡️ *FoundationShield self-check issues*\n${issues.map(i => `• ${i}`).join('\n')}\nCheck: \`systemctl list-timers fo-*\``,
      { check_type: 'self_monitoring', severity: 'high', playbook: 'systemctl list-timers fo-* && journalctl -u fo-sysmon.service --since "1 hour ago"' }
    );
  } else {
    await info('FoundationShield self-check: all systems nominal', { key: 'shield_healthy', check_type: 'self_monitoring' });
  }
}

async function main() {
  await checkProcessMasquerade();
  await checkBackupIntegrity();
  await checkLogForwarding();
  await checkSlowQueries();
  await checkAiCostAnomaly();
  await checkBaselineAnomaly();
  await checkResponseTimeTrend();
  await checkDependencyStaleness();
  await checkSelfMonitoring();
  await info('intel-guard run complete', { key: 'intel_guard_run', check_type: 'heartbeat' });
}

main().catch(err => { console.error('[intel-guard] fatal:', err.message); process.exit(1); });
```

- [ ] **Step 2: Dry-run test**

```bash
node /opt/foundation-shield/scripts/intel-guard.js --dry-run 2>&1 | head -30
```

Expected: No fatal errors.

- [ ] **Step 3: Commit**

```bash
cd /opt/foundation-shield
git add scripts/intel-guard.js
git commit -m "feat(shield): intel-guard.js — checks 49-57 (advanced intelligence + observability)"
```

---

## Task 4: Write `sentinel-guard.js` (Cross-Server Heartbeat)

**Files:**
- Create: `/opt/foundation-shield/scripts/sentinel-guard.js`

- [ ] **Step 1: Write the script**

```js
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

// Write own heartbeat
function writeHeartbeat() {
  const data = { server: SERVER_NAME, ts: new Date().toISOString(), pid: process.pid };
  try { fs.writeFileSync(HEARTBEAT_FILE, JSON.stringify(data)); } catch (_) {}
}

// Read remote heartbeat via SSH
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
    if (server.name === SERVER_NAME) continue; // don't watch ourselves

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
```

- [ ] **Step 2: Commit**

```bash
cd /opt/foundation-shield
git add scripts/sentinel-guard.js
git commit -m "feat(shield): sentinel-guard.js — cross-server heartbeat mesh"
```

---

## Task 5: Additional Systemd Units + Install Script

- [ ] **Step 1: Write `fo-secmon` units**

`/opt/foundation-shield/systemd/fo-secmon.service`:
```ini
[Unit]
Description=Foundation Security Monitor
After=network.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/node /usr/local/lib/fo-sys/security-guard.js
WorkingDirectory=/usr/local/lib/fo-sys
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fo-secmon
Restart=no
EnvironmentFile=-/etc/fo-sys/env
```

`/opt/foundation-shield/systemd/fo-secmon.timer`:
```ini
[Unit]
Description=Foundation Security Monitor — every 15 minutes

[Timer]
OnBootSec=4min
OnUnitActiveSec=15min
AccuracySec=1min
Persistent=true

[Install]
WantedBy=timers.target
```

`/opt/foundation-shield/systemd/fo-sentinel.service`:
```ini
[Unit]
Description=Foundation Sentinel Heartbeat
After=network.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/node /usr/local/lib/fo-sys/sentinel-guard.js
WorkingDirectory=/usr/local/lib/fo-sys
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fo-sentinel
Restart=no
EnvironmentFile=-/etc/fo-sys/env
```

`/opt/foundation-shield/systemd/fo-sentinel.timer`:
```ini
[Unit]
Description=Foundation Sentinel — every 15 minutes

[Timer]
OnBootSec=6min
OnUnitActiveSec=15min
AccuracySec=1min
Persistent=true

[Install]
WantedBy=timers.target
```

- [ ] **Step 2: Write `deploy/install.sh`** (idempotent install for any server)

```bash
#!/bin/bash
# /opt/foundation-shield/deploy/install.sh
# Idempotent install script for FoundationShield on any fleet server.
# Usage: sudo bash install.sh [server-name]
# Example: sudo bash install.sh vps2
set -euo pipefail

SERVER_NAME="${1:-$(hostname -s)}"
INSTALL_DIR="/usr/local/lib/fo-sys"
CONFIG_DIR="/etc/fo-sys"
LOG_DIR="/var/log/fo-sys"
SCRIPTS_SRC="$(dirname "$0")/../scripts"
UNITS_SRC="$(dirname "$0")/../systemd"

echo "[install] Installing FoundationShield on ${SERVER_NAME}..."

# Create directories
mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}" "${LOG_DIR}"

# Copy scripts
for script in alerting.js pm2-governance.js repo-governance.js resource-guard.js \
              app-guard.js security-guard.js deception-guard.js intel-guard.js \
              sentinel-guard.js honey-listener.js harvest.js; do
  if [ -f "${SCRIPTS_SRC}/${script}" ]; then
    cp "${SCRIPTS_SRC}/${script}" "${INSTALL_DIR}/"
    echo "[install] Installed: ${script}"
  fi
done

# Write env config
cat > "${CONFIG_DIR}/env" <<EOF
FO_SERVER_NAME=${SERVER_NAME}
FOMCP_URL=http://127.0.0.1:4500
SECRETS_PATH=/opt/mcp-server/.secrets
EOF

# Create log file and lock append-only
touch "${LOG_DIR}/digest.log"
chattr +a "${LOG_DIR}/digest.log" 2>/dev/null || echo "[install] Warning: chattr +a failed (may need kernel support)"

# Install systemd units
for unit in fo-sysmon fo-repomon fo-appmon fo-secmon fo-sentinel; do
  if [ -f "${UNITS_SRC}/${unit}.service" ]; then
    cp "${UNITS_SRC}/${unit}.service" /etc/systemd/system/
    cp "${UNITS_SRC}/${unit}.timer"   /etc/systemd/system/
    echo "[install] Installed unit: ${unit}"
  fi
done

systemctl daemon-reload

# Enable and start timers
systemctl enable --now fo-sysmon.timer fo-repomon.timer fo-appmon.timer fo-secmon.timer fo-sentinel.timer

echo "[install] FoundationShield installed and active on ${SERVER_NAME}"
echo "[install] Verify with: systemctl list-timers fo-*"
```

```bash
chmod +x /opt/foundation-shield/deploy/install.sh
```

- [ ] **Step 3: Commit**

```bash
cd /opt/foundation-shield
git add systemd/fo-secmon.* systemd/fo-sentinel.* deploy/install.sh
git commit -m "feat(shield): fo-secmon + fo-sentinel systemd units + idempotent install.sh"
```

---

## Task 6: Deploy to VPS2 and VPS VRO

- [ ] **Step 1: Clone the foundation-shield repo on VPS2**

```bash
ssh vps2 "sudo git clone https://github.com/FoundationOperations/foundation-shield.git /opt/foundation-shield && sudo chown -R nodeapp:nodeapp /opt/foundation-shield"
```

- [ ] **Step 2: Run install script on VPS2**

```bash
ssh vps2 "sudo bash /opt/foundation-shield/deploy/install.sh vps2"
```

- [ ] **Step 3: Verify timers active on VPS2**

```bash
ssh vps2 "systemctl list-timers fo-*"
```

Expected: All 5 timers listed with upcoming NEXT times.

- [ ] **Step 4: Trigger a manual run on VPS2 and verify**

```bash
ssh vps2 "sudo systemctl start fo-sysmon.service && sudo journalctl -u fo-sysmon.service --since '1 minute ago' --no-pager"
```

Expected: pm2-governance run output, no fatal errors.

- [ ] **Step 5: Clone and install on VPS VRO**

```bash
ssh vpsvro "sudo git clone https://github.com/FoundationOperations/foundation-shield.git /opt/foundation-shield && sudo chown -R nodeapp:nodeapp /opt/foundation-shield"
ssh vpsvro "sudo bash /opt/foundation-shield/deploy/install.sh vps-vro"
ssh vpsvro "systemctl list-timers fo-*"
```

- [ ] **Step 6: Verify sentinel heartbeat mesh from VPS Main**

```bash
sudo systemctl start fo-sentinel.service
sudo journalctl -u fo-sentinel.service --since "1 minute ago" --no-pager
```

Expected: Output showing VPS2 and VPS VRO heartbeats being read and both reporting fresh timestamps.

- [ ] **Step 7: Push all changes**

```bash
cd /opt/foundation-shield
git push origin main
```

---

## Definition of Done

- [ ] `security-guard.js` runs checks 32–44 cleanly in `--dry-run` mode
- [ ] `deception-guard.js` plants canary files and checks honey listener log
- [ ] `intel-guard.js` runs checks 49–57 cleanly
- [ ] `sentinel-guard.js` writes heartbeat and reads remote servers
- [ ] `fo-secmon.timer` + `fo-sentinel.timer` active on VPS Main
- [ ] FoundationShield installed and all 5 timers running on VPS2
- [ ] FoundationShield installed and all 5 timers running on VPS VRO
- [ ] Sentinel heartbeat from VPS Main reports both VPS2 + VPS VRO as healthy
- [ ] Events from VPS2/VPS VRO appearing in `governance.db` after harvest run
