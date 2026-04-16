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
  const lines = run('df -i').split('\n').slice(1);
  for (const line of lines) {
    const m = line.match(/^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)%\s+(\S+)/);
    if (!m) continue;
    const [, , , , , pctStr, mount] = m;
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
