#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# Update and install required packages
apt-get update -y
apt-get install -y xfce4 xfce4-goodies x11vnc xvfb python3 python3-pip git curl jq golang wget gnupg2

# Install Google Chrome
echo "[INFO] Installing Google Chrome..."
wget -q -O /tmp/google-chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
dpkg -i /tmp/google-chrome.deb || apt-get install -fy -y
rm -f /tmp/google-chrome.deb

# Clone noVNC if not exists
if [ ! -d "${HOME}/noVNC" ]; then
  git clone https://github.com/novnc/noVNC.git "${HOME}/noVNC"
fi
chmod +x "${HOME}/noVNC/utils/novnc_proxy"

# Kill previous sessions
pkill -f "Xvfb :0" || true
pkill -f "startxfce4" || true
pkill -f "x11vnc -display :0" || true
pkill -f "novnc_proxy" || true

# Start Xvfb
echo "[INFO] Starting Xvfb..."
Xvfb :0 -screen 0 1024x768x24 >/var/log/xvfb.log 2>&1 &
sleep 1

# Start XFCE
echo "[INFO] Starting XFCE..."
DISPLAY=:0 startxfce4 >/var/log/xfce4.log 2>&1 &
sleep 2

# Start x11vnc
echo "[INFO] Starting x11vnc on :0 -> 5900..."
x11vnc -display :0 -nopw -forever -shared -rfbport 5900 -o /var/log/x11vnc.log >/dev/null 2>&1 &
sleep 1

# Start noVNC
echo "[INFO] Starting noVNC..."
cd "${HOME}/noVNC"
./utils/novnc_proxy --vnc localhost:5900 --listen 6080 >/var/log/novnc.log 2>&1 &
sleep 1

# Start cloudflared in background and extract URL
echo "[INFO] Starting Cloudflare Tunnel..."
cloudflared tunnel --url http://localhost:6080 --no-autoupdate 2>&1 | while read -r line; do
    echo "$line"
    if [[ "$line" =~ https://[a-zA-Z0-9.-]+\.trycloudflare\.com ]]; then
        URL=$(echo "$line" | grep -oP 'https://[a-zA-Z0-9.-]+\.trycloudflare\.com')
        echo "[INFO] Your noVNC web URL: $URL/vnc.html"
    fi
done
