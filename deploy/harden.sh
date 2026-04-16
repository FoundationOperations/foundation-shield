#!/bin/bash
# /opt/foundation-shield/deploy/harden.sh
# Apply stealth hardening layer to FoundationShield installation.
# Run ONCE after install — re-run after any legitimate script update.
# Usage: sudo bash harden.sh
set -euo pipefail

INSTALL_DIR="/usr/local/lib/fo-sys"
LOG_DIR="/var/log/fo-sys"

echo "[harden] Applying FoundationShield hardening..."

# ── Layer 2A: chattr +i on all scripts (immutable) ──
for script in alerting.js pm2-governance.js repo-governance.js resource-guard.js \
              app-guard.js security-guard.js deception-guard.js intel-guard.js \
              sentinel-guard.js honey-listener.js harvest.js; do
  if [ -f "${INSTALL_DIR}/${script}" ]; then
    chattr +i "${INSTALL_DIR}/${script}" 2>/dev/null && echo "[harden] +i: ${script}" || echo "[harden] Warning: chattr +i failed for ${script}"
  fi
done

# ── Layer 2B: chattr +a on log files (append-only WORM) ──
for logfile in digest.log honey-hits.log; do
  touch "${LOG_DIR}/${logfile}" 2>/dev/null || true
  chattr +a "${LOG_DIR}/${logfile}" 2>/dev/null && echo "[harden] +a: ${logfile}" || echo "[harden] Warning: chattr +a failed for ${logfile}"
done

# ── Layer 2C: Update systemd units to Restart=always ──
for unit in fo-sysmon fo-repomon fo-appmon fo-secmon fo-sentinel; do
  UNIT_FILE="/etc/systemd/system/${unit}.service"
  if [ -f "${UNIT_FILE}" ]; then
    if ! grep -q "^Restart=always" "${UNIT_FILE}"; then
      sed -i '/^\[Service\]/a Restart=always\nRestartSec=10' "${UNIT_FILE}"
      echo "[harden] Restart=always: ${unit}.service"
    fi
  fi
done

systemctl daemon-reload

# ── Layer 2D: Record script hashes for self-verification ──
HASH_FILE="/etc/fo-sys/script-hashes.json"
echo "{" > "${HASH_FILE}.tmp"
first=1
for script in alerting.js pm2-governance.js repo-governance.js resource-guard.js \
              app-guard.js security-guard.js deception-guard.js intel-guard.js \
              sentinel-guard.js; do
  if [ -f "${INSTALL_DIR}/${script}" ]; then
    hash=$(sha256sum "${INSTALL_DIR}/${script}" | cut -d' ' -f1)
    [ $first -eq 0 ] && echo "," >> "${HASH_FILE}.tmp"
    echo -n "  \"${script}\": \"${hash}\"" >> "${HASH_FILE}.tmp"
    first=0
  fi
done
echo "" >> "${HASH_FILE}.tmp"
echo "}" >> "${HASH_FILE}.tmp"
mv "${HASH_FILE}.tmp" "${HASH_FILE}"
chmod 644 "${HASH_FILE}"
echo "[harden] Script hashes recorded to ${HASH_FILE}"

echo ""
echo "[harden] Hardening complete."
echo ""
echo "To update a script legitimately:"
echo "  1. sudo chattr -i /usr/local/lib/fo-sys/<script>"
echo "  2. sudo cp /opt/foundation-shield/scripts/<script> /usr/local/lib/fo-sys/"
echo "  3. sudo bash /opt/foundation-shield/deploy/harden.sh"
echo ""
echo "Script attributes:"
lsattr "${INSTALL_DIR}"/*.js 2>/dev/null | head -10
echo ""
echo "Log attributes:"
lsattr "${LOG_DIR}"/*.log 2>/dev/null
