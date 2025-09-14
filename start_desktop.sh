#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y xfce4 xfce4-goodies x11vnc xvfb python3 python3-pip git curl jq golang

if [ ! -d "${HOME}/noVNC" ]; then
  git clone https://github.com/novnc/noVNC.git "${HOME}/noVNC"
fi
chmod +x "${HOME}/noVNC/utils/novnc_proxy"

pkill -f "Xvfb :0" || true
pkill -f "startxfce4" || true
pkill -f "x11vnc -display :0" || true
pkill -f "novnc_proxy" || true

echo "[INFO] Starting Xvfb..."
Xvfb :0 -screen 0 1024x768x24 >/var/log/xvfb.log 2>&1 &
sleep 1

echo "[INFO] Starting XFCE..."
DISPLAY=:0 startxfce4 >/var/log/xfce4.log 2>&1 &
sleep 2

echo "[INFO] Starting x11vnc on :0 -> 5900..."
x11vnc -display :0 -nopw -forever -shared -rfbport 5900 -o /var/log/x11vnc.log >/dev/null 2>&1 &
sleep 1

echo "[INFO] Starting noVNC..."
cd "${HOME}/noVNC"
./utils/novnc_proxy --vnc localhost:5900 --listen 6080 >/var/log/novnc.log 2>&1 &
sleep 1

echo "[INFO] Starting Cloudflare Tunnel..."
URL=$(cloudflared tunnel --url http://localhost:6080 --no-autoupdate 2>&1 | grep -oP 'https://[a-zA-Z0-9.-]+\.trycloudflare\.com' | head -n1)

if [ -n "$URL" ]; then
  echo "[INFO] Your noVNC web URL: $URL/vnc.html"
else
  echo "[ERROR] Could not extract Cloudflare Tunnel URL."
fi
