#!/bin/bash
# /opt/foundation-shield/deploy/install.sh
# Idempotent install script for FoundationShield on any fleet server.
# Usage: sudo bash install.sh [server-name]
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
