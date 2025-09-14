#!/bin/bash
set -euo pipefail

# Usage: ./start_desktop.sh jwt_secret
JWT_SECRET="${1:-mysecret123}"

echo "[INFO] JWT_SECRET=${JWT_SECRET}"

# --- Install packages ---
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y xfce4 xfce4-goodies x11vnc xvfb python3 python3-pip git curl jq golang

# --- Install noVNC ---
if [ ! -d "${HOME}/noVNC" ]; then
  git clone https://github.com/novnc/noVNC.git "${HOME}/noVNC"
fi
chmod +x "${HOME}/noVNC/utils/novnc_proxy"

# --- Kill prior instances ---
pkill -f "Xvfb :0" || true
pkill -f "startxfce4" || true
pkill -f "x11vnc -display :0" || true
pkill -f "novnc_proxy" || true
pkill -f "auth_proxy" || true

# --- Start headless desktop ---
echo "[INFO] Starting Xvfb..."
Xvfb :0 -screen 0 1024x768x24 >/var/log/xvfb.log 2>&1 &
sleep 1

echo "[INFO] Starting XFCE..."
DISPLAY=:0 startxfce4 >/var/log/xfce4.log 2>&1 &
sleep 2

echo "[INFO] Starting x11vnc on :0 -> 5900..."
x11vnc -display :0 -nopw -forever -shared -rfbport 5900 -o /var/log/x11vnc.log >/dev/null 2>&1 &
sleep 1

# --- Start noVNC ---
echo "[INFO] Starting noVNC..."
cd "${HOME}/noVNC"
./utils/novnc_proxy --vnc localhost:5900 --listen 6080 >/var/log/novnc.log 2>&1 &
sleep 1

# --- Build auth_proxy ---
AUTH_PROXY_GO="${HOME}/auth_proxy.go"

cd $HOME
# --- Run auth proxy ---
./auth_proxy --secret "$JWT_SECRET" --listen ":8080" --upstream "http://127.0.0.1:6080" >/var/log/auth_proxy.log 2>&1 &
sleep 2

# --- Generate JWT valid 15 hours ---
JWT=$(python3 - <<PY
import time, hmac, hashlib, base64, json
secret=b"$JWT_SECRET"
header=json.dumps({"alg":"HS256","typ":"JWT"}).encode()
payload=json.dumps({"sub":"amit","exp":int(time.time())+54000}).encode()
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=') 
msg=b'.'.join([b64u(header),b64u(payload)])
sig=hmac.new(secret,msg,hashlib.sha256).digest()
print((msg+b'.'+b64u(sig)).decode())
PY
)

echo ""
echo "=============================="
echo "Your JWT token (valid 15 hours):"
echo "$JWT"
echo "Use it in browser:"
echo "https://<your-cloudflared-url>/index.html?token=$JWT"
echo "=============================="
echo ""

# --- Start cloudflared ---
cloudflared tunnel --url http://localhost:8080 --no-autoupdate
