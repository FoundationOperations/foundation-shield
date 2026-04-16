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
const CANARY_DIR  = '/var/log/fo-sys/.canaries';
const CANARY_STATE = '/var/log/fo-sys/canary-state.json';
const CANARY_LOCATIONS = [
  { dir: '/tmp',          name: '.systemd-private-cache', content: 'DECOY' },
  { dir: '/var/www',     name: '.git-credentials',       content: 'github_pat_DECOY_11AAAAAAAAAAAA' },
  { dir: '/root',         name: '.aws-credentials.bak',  content: '[default]\naws_access_key_id=AKIADECOY00000000000\n' },
  { dir: '/var/backups', name: 'db-backup-2026.sql.gz',  content: 'DECOY-BACKUP' },
];

async function checkCanaries() {
  try { fs.mkdirSync(CANARY_DIR, { recursive: true }); } catch (_) {}

  let state = {};
  try { state = JSON.parse(fs.readFileSync(CANARY_STATE, 'utf8')); } catch (_) {}

  for (const canary of CANARY_LOCATIONS) {
    const filePath = path.join(canary.dir, canary.name);
    const key = filePath;

    if (!fs.existsSync(filePath)) {
      try { fs.writeFileSync(filePath, canary.content, { mode: 0o644 }); } catch (_) {}
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
async function checkHoneyCredentials() {
  const HONEY_LOG = '/var/log/fo-sys/honey-hits.log';
  if (!fs.existsSync(HONEY_LOG)) return;

  try {
    const stat = fs.statSync(HONEY_LOG);
    const STATE_FILE = '/var/log/fo-sys/honey-state.json';
    let state = { lastSize: 0 };
    try { state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch (_) {}

    if (stat.size > state.lastSize) {
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
  const status = run('systemctl is-active auditd 2>/dev/null');
  if (status !== 'active') {
    await alert('auditd_down',
      `🔍 *auditd is not running* — kernel audit trail inactive\nFix: \`sudo systemctl start auditd\``,
      { check_type: 'auditd', severity: 'high', playbook: 'sudo systemctl enable --now auditd' }
    );
    return;
  }

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
    if (!isKnown && known.size > 0) {
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
