#!/bin/bash
# /opt/foundation-shield/deploy/install-vpsoc.sh
# Install ONLY the dark sentinel on VPSOC. No PM2, no FOMCP, no governance scripts.
# Usage: sudo bash install-vpsoc.sh
set -euo pipefail

INSTALL_DIR="/usr/local/lib/fo-sys"
CONFIG_DIR="/etc/fo-sys"
SCRIPTS_SRC="$(dirname "$0")/../scripts"
UNITS_SRC="$(dirname "$0")/../systemd"

echo "[vpsoc-install] Installing VPSOC Dark Sentinel..."

mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}"

# Only copy the sentinel script — nothing else
cp "${SCRIPTS_SRC}/vpsoc-sentinel.js" "${INSTALL_DIR}/"

cat > "${CONFIG_DIR}/env" <<'ENVEOF'
# VPSOC Dark Sentinel env — configure FO_SENTINEL_BOT_TOKEN and FO_SENTINEL_CHAT_ID here
FO_SERVER_NAME=vpsoc
# FO_SENTINEL_BOT_TOKEN=<your-dark-sentinel-bot-token>
# FO_SENTINEL_CHAT_ID=<your-dark-sentinel-chat-id>
ENVEOF

echo "[vpsoc-install] Edit /etc/fo-sys/env to add FO_SENTINEL_BOT_TOKEN and FO_SENTINEL_CHAT_ID"

# Install and enable systemd units
cp "${UNITS_SRC}/fo-vpsoc.service" /etc/systemd/system/
cp "${UNITS_SRC}/fo-vpsoc.timer"   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now fo-vpsoc.timer

echo "[vpsoc-install] VPSOC Dark Sentinel active. Verify: systemctl list-timers fo-vpsoc.timer"
