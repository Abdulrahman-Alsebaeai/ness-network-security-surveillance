#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_NAME="$(id -un)"
echo "[NESS] Installing native WSL/Linux cyber-range engine (no Docker)..."
if ! command -v sudo >/dev/null 2>&1; then echo "sudo is required"; exit 1; fi
sudo apt-get update
sudo apt-get install -y iproute2 iputils-ping python3 procps
sudo install -d -m 755 /opt/ness-lab /var/lib/ness-lab /run/ness-lab
sudo install -m 755 "$HERE/ness-labctl" /usr/local/sbin/ness-labctl
sudo install -m 755 "$HERE/ness_lab_sensor.py" /opt/ness-lab/ness_lab_sensor.py
sudo install -m 755 "$HERE/ness_lab_web.py" /opt/ness-lab/ness_lab_web.py
sudo install -m 755 "$HERE/ness_lab_db.py" /opt/ness-lab/ness_lab_db.py
sudo install -m 755 "$HERE/read_events.py" /opt/ness-lab/read_events.py
printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/ness-labctl *\n' "$USER_NAME" | sudo tee /etc/sudoers.d/ness-lab >/dev/null
sudo chmod 440 /etc/sudoers.d/ness-lab
sudo visudo -cf /etc/sudoers.d/ness-lab >/dev/null
sudo -n /usr/local/sbin/ness-labctl stop >/dev/null 2>&1 || true
echo "[NESS] Installation complete. NESS can now start/stop the isolated lab from the web interface."
