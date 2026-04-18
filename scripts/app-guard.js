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

// Check 22: PM2 restart storm — use unstable_restarts (recent crash counter that
// PM2 resets once an app stays up). Previously used cumulative restart_time which
// meant any app with >5 lifetime restarts would flag on every normal restart.
async function checkRestartStorm() {
  try {
    const apps = JSON.parse(execSync('pm2 jlist', { encoding: 'utf8', timeout: 10000 }));
    for (const app of apps) {
      const unstable   = app.pm2_env?.unstable_restarts || 0;
      const uptimeMs   = app.pm2_env?.pm_uptime || Date.now();
      const uptimeSecs = (Date.now() - uptimeMs) / 1000;
      // Only alert if PM2 is actively crash-looping this app (unstable > 5) AND
      // current uptime is under 5 min (i.e. still in the storm, not recovered).
      if (unstable > 5 && uptimeSecs < 300) {
        const totalRestarts = app.pm2_env?.restart_time || 0;
        await alert(`restart_storm_${app.name}`,
          `🔄 *PM2 restart storm*: ${app.name}\nUnstable restarts: ${unstable} | Uptime: ${Math.round(uptimeSecs)}s | Lifetime restarts: ${totalRestarts}\nFix: \`pm2 logs ${app.name} --lines 50\``,
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

// Check 25: Unexpected egress — REMOVED (duplicate of pm2-governance.js checkUnregisteredListeners).
// Both read ss -tlnp against the same /home/nodeapp/port-registry.js and fired
// independently for every finding, doubling the event volume. pm2-governance.js
// owns this check now. Intentionally kept as no-op stub for signature parity.
async function checkEgress() { /* superseded by pm2-governance.js checkUnregisteredListeners */ }

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
    // Skip silently if the app isn't deployed on this server — prevents every 5min
    // scan from flagging "stage" on servers that only host prod, etc.
    if (!fs.existsSync(app.path)) continue;
    if (!fs.existsSync(`${app.path}/${app.builtFile}`)) continue;
    try {
      const gitHash    = run(`git -C ${app.path} rev-parse --short HEAD 2>/dev/null`);
      const builtMtime = fs.statSync(`${app.path}/${app.builtFile}`).mtimeMs;
      const gitMtime   = new Date(run(`git -C ${app.path} log -1 --format=%aI HEAD 2>/dev/null`)).getTime();
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
    // Skip silently if nginx isn't logging here — not every server runs nginx.
    if (!fs.existsSync(logFile)) return;
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
        if ((Date.now() - stat.mtimeMs) > 300000) continue;
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
