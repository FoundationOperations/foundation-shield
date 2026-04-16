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
    if (parseInt(ipv6Active) === 0) return;
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
  const PIPELINE_FILES = ['/root/scripts/deploy.sh'];
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
