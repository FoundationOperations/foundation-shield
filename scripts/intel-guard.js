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
  try {
    const pids = fs.readdirSync('/proc').filter(d => /^\d+$/.test(d));
    for (const pidStr of pids) {
      const pid = parseInt(pidStr);
      try {
        const comm = fs.readFileSync(`/proc/${pid}/comm`, 'utf8').trim();
        const suspiciousNames = ['kworker', 'kthread', 'sshd', 'systemd', 'bash', 'sh', 'cron'];
        if (!suspiciousNames.some(n => comm.includes(n))) continue;

        let exePath = null;
        try { exePath = fs.readlinkSync(`/proc/${pid}/exe`); } catch { continue; }

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
  return new Promise((resolve) => {
    const FOMCP_TOKEN = (() => {
      try {
        const lines = fs.readFileSync('/opt/mcp-server/.secrets', 'utf8').split('\n');
        for (const l of lines) { const m = l.match(/^(FOMCP_TOKEN|MCP_API_TOKEN|MCP_ADMIN_TOKEN)=(.+)$/); if (m) return m[2].replace(/^['"]|['"]$/g, ''); }
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
  const STATE_FILE = '/var/log/fo-sys/baseline-metrics.json';
  try {
    if (!fs.existsSync(STATE_FILE)) return;
    const baseline = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));

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
  history = history.slice(-50);

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

  try {
    const stat = fs.statSync(DIGEST_LOG);
    const ageMins = (Date.now() - stat.mtimeMs) / 60000;
    if (ageMins > 15) issues.push(`digest log stale (${Math.round(ageMins)}min)`);
  } catch { issues.push('digest log missing'); }

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
