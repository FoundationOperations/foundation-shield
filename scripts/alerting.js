// /opt/foundation-shield/scripts/alerting.js
// Drop-in replacement for ops-docs alerting.js with FOMCP push + local log fallback.
// Critical/high events push immediately to FOMCP. All events go to local append-only log.
'use strict';
const https = require('https');
const http  = require('http');
const fs    = require('fs');
const path  = require('path');

// ── Config ────────────────────────────────────────────────────────────────────
const LOG_DIR       = '/var/log/fo-sys';
const DIGEST_LOG    = path.join(LOG_DIR, 'digest.log');
const COOLDOWN_DIR  = '/tmp/fo-sys-cooldowns';
const COOLDOWN_SECS = 1800; // 30 minutes per alert key
const FOMCP_URL     = process.env.FOMCP_URL || 'http://127.0.0.1:4500';

// Server identity — set via env or fallback detection
const SERVER_NAME = process.env.FO_SERVER_NAME || (() => {
  try { return require('child_process').execSync('hostname', { encoding: 'utf8' }).trim(); } catch { return 'unknown'; }
})();

// ── Vault / Credentials ───────────────────────────────────────────────────────
function loadVault() {
  const secretsPath = process.env.SECRETS_PATH || '/opt/mcp-server/.secrets';
  const vault = {};
  try {
    const lines = fs.readFileSync(secretsPath, 'utf8').split('\n');
    for (const line of lines) {
      const m = line.match(/^([A-Z_]+)=(.*)$/);
      if (m) vault[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
    }
  } catch (_) {}
  return vault;
}

const _vault = loadVault();
const TELEGRAM_TOKEN = process.env.TELEGRAM_BOT_TOKEN || _vault.TELEGRAM_BOT_TOKEN || _vault.FOUNDATION_SHIELD_BOT_TOKEN;
const TELEGRAM_CHAT  = process.env.TELEGRAM_CHAT_ID   || _vault.TELEGRAM_CHAT_ID   || _vault.FOUNDATION_SHIELD_CHAT_ID;
const FOMCP_TOKEN    = process.env.FOMCP_TOKEN         || _vault.FOMCP_TOKEN        || _vault.MCP_API_TOKEN;

const DRY_RUN = process.argv.includes('--dry-run');

// ── Directory Setup ───────────────────────────────────────────────────────────
try { fs.mkdirSync(LOG_DIR,      { recursive: true }); } catch (_) {}
try { fs.mkdirSync(COOLDOWN_DIR, { recursive: true }); } catch (_) {}

// ── Cooldown ──────────────────────────────────────────────────────────────────
function cooldownFile(key) {
  return path.join(COOLDOWN_DIR, key.replace(/[^a-z0-9_]/gi, '_').slice(0, 64));
}

function inCooldown(key) {
  try {
    if (!fs.existsSync(cooldownFile(key))) return false;
    const last = parseInt(fs.readFileSync(cooldownFile(key), 'utf8').trim(), 10);
    return !isNaN(last) && (Math.floor(Date.now() / 1000) - last) < COOLDOWN_SECS;
  } catch { return false; }
}

function setCooldown(key) {
  try { fs.writeFileSync(cooldownFile(key), String(Math.floor(Date.now() / 1000))); } catch (_) {}
}

// ── Local Digest Log ──────────────────────────────────────────────────────────
function appendDigest(level, key, message, extra = {}) {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    key,
    server: SERVER_NAME,
    msg: message,
    ...extra
  }) + '\n';
  try { fs.appendFileSync(DIGEST_LOG, line); } catch (_) {}
}

// ── FOMCP Push ────────────────────────────────────────────────────────────────
function pushToFomcp(event) {
  return new Promise((resolve) => {
    if (!FOMCP_TOKEN) return resolve(false);
    const body = JSON.stringify(event);
    const options = {
      hostname: '127.0.0.1',
      port: 4500,
      path: '/api/governance/events',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Authorization': `Bearer ${FOMCP_TOKEN}`
      }
    };
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => resolve(res.statusCode === 200));
    });
    req.setTimeout(5000, () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.write(body);
    req.end();
  });
}

// ── Telegram ──────────────────────────────────────────────────────────────────
function sendTelegram(message) {
  return new Promise((resolve) => {
    if (!TELEGRAM_TOKEN || !TELEGRAM_CHAT) return resolve(false);
    const body = JSON.stringify({ chat_id: TELEGRAM_CHAT, text: message, parse_mode: 'Markdown' });
    const req = https.request({
      hostname: 'api.telegram.org',
      path: `/bot${TELEGRAM_TOKEN}/sendMessage`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode === 200));
    });
    req.setTimeout(10000, () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.write(body);
    req.end();
  });
}

// ── Public API ────────────────────────────────────────────────────────────────

/** deriveSeverity: best-effort severity from key prefix if not specified */
function deriveSeverity(key) {
  if (/^(collision|squatter|pm2_dead|disk_crit|oom|canary|honey|suid|ssh_key|masquerade|crypto)/.test(key)) return 'critical';
  if (/^(disk_warn|repo_behind|ssl|fail2ban|docker|restart_storm|fd_exhaust|fs_integrity|threat_intel)/.test(key)) return 'high';
  if (/^(repo_ahead|repo_dirty|pm2_mem|pg_pool|slow_query)/.test(key)) return 'medium';
  return 'info';
}

/**
 * Fire an alert.
 * @param {string} key         - Dedup key (e.g. 'disk_/var_vps-main')
 * @param {string} message     - Human-readable alert message (Telegram Markdown OK)
 * @param {object} opts        - { check_type, severity, raw_data, playbook }
 */
async function alert(key, message, opts = {}) {
  const severity   = opts.severity   || deriveSeverity(key);
  const check_type = opts.check_type || key.split('_')[0];

  appendDigest('ALERT', key, message, { severity, check_type });

  if (DRY_RUN) {
    console.log(`[DRY-RUN] ALERT [${severity}] ${key}:\n${message}\n`);
    return;
  }

  // Push to FOMCP (all severities — non-blocking, fire-and-forget)
  pushToFomcp({
    server:     SERVER_NAME,
    check_type,
    severity,
    alert_key:  key,
    message,
    raw_data:   opts.raw_data   || null,
    playbook:   opts.playbook   || null,
    source:     'push'
  }).catch(() => {}); // never throw — alerting must not crash governance scripts

  // Telegram: critical + high get immediate Telegram; others are harvest-only
  if (['critical', 'high'].includes(severity) && !inCooldown(key)) {
    await sendTelegram(`🚨 *FoundationShield Alert*\n*Server:* ${SERVER_NAME}\n\n${message}`);
    setCooldown(key);
  }
}

/** Log an informational event (no Telegram). Always goes to digest + FOMCP. */
async function info(message, opts = {}) {
  appendDigest('INFO', opts.key || 'info', message, opts);
  if (!DRY_RUN && opts.key) {
    pushToFomcp({
      server:     SERVER_NAME,
      check_type: opts.check_type || 'info',
      severity:   'info',
      alert_key:  opts.key,
      message,
      source:     'push'
    }).catch(() => {});
  }
}

module.exports = { alert, info };
