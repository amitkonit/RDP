#!/bin/bash
set -euo pipefail

# Usage:
#   ./start_desktop.sh            -> defaults: myuser / mypassword / mytoken
#   ./start_desktop.sh user pass token

USER_NAME="${1:-myuser}"
USER_PASS="${2:-mypassword}"
PROXY_TOKEN="${3:-mytoken}"

echo "[INFO] USER_NAME=${USER_NAME}"
echo "[INFO] USER_PASS=${USER_PASS}"
echo "[INFO] PROXY_TOKEN=${PROXY_TOKEN}"

# --- Packages (Debian/Ubuntu) ---
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  xfce4 xfce4-goodies x11vnc xvfb python3 python3-pip git curl jq

# Install noVNC
if [ ! -d "${HOME}/noVNC" ]; then
  git clone https://github.com/novnc/noVNC.git "${HOME}/noVNC"
fi

# Install cloudflared (binary)
if ! command -v cloudflared &> /dev/null; then
  echo "[INFO] Installing cloudflared..."
  curl -L -o /usr/local/bin/cloudflared \
    "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
  chmod +x /usr/local/bin/cloudflared
fi

# Install python libs
pip3 install --no-warn-script-location --upgrade pip
pip3 install flask requests

# Kill any prior instances that may conflict
pkill -f "Xvfb :0" || true
pkill -f "startxfce4" || true
pkill -f "x11vnc -display :0" || true
pkill -f "novnc_proxy" || true
pkill -f "auth_proxy.py" || true

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
chmod +x ./utils/novnc_proxy || true
./utils/novnc_proxy --vnc localhost:5900 --listen 6080 >/var/log/novnc.log 2>&1 &

sleep 1

# --- Write a robust token+basic-auth proxy (Flask) ---
PROXY_FILE="${HOME}/auth_proxy.py"
cat > "${PROXY_FILE}" <<EOF
from flask import Flask, request, Response, redirect
import requests, os, logging
from functools import wraps

# --- inserted by start script ---
USERNAME = "${USER_NAME}"
PASSWORD = "${USER_PASS}"
TOKEN = "${PROXY_TOKEN}"
TARGET = "http://localhost:6080"
# -----------------------------------

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

def check_basic_auth():
    auth = request.authorization
    return auth and auth.username == USERNAME and auth.password == PASSWORD

def check_token():
    # token via query param or header X-Auth-Token
    t = request.args.get('token') or request.headers.get('X-Auth-Token')
    return bool(t) and t == TOKEN

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if check_token() or check_basic_auth():
            # authorized
            return f(*args, **kwargs)
        # not authorized
        return Response('Authentication required', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})
    return decorated

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
@requires_auth
def proxy(path):
    # redirect bare root -> /index.html preserving query string
    if path == '':
        qs = request.query_string.decode()
        url = '/index.html' + (('?' + qs) if qs else '')
        app.logger.info("Redirecting / -> %s", url)
        return redirect(url)

    # build target URL and forward query params
    url = f"{TARGET}/{path}"
    params = request.args.to_dict(flat=True)

    # forward most headers except hop-by-hop, host, and encoding
    headers = {}
    for h, v in request.headers.items():
        if h.lower() in ('host','connection','content-length','transfer-encoding','accept-encoding'):
            continue
        headers[h] = v
    # set Host to origin's host so static server sees expected host
    headers['Host'] = '127.0.0.1:6080'

    app.logger.info("Proxying %s -> %s (params=%s)", request.path, url, params)

    try:
        resp = requests.request(
            method=request.method,
            url=url,
            params=params,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=True,
            timeout=30
        )
    except Exception as e:
        app.logger.exception("Error connecting to target: %s", e)
        return Response("Upstream unreachable", status=502)

    excluded = ('content-encoding','transfer-encoding','connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','upgrade')
    response_headers = [(name, value) for (name, value) in resp.headers.items() if name.lower() not in excluded]

    return Response(resp.iter_content(chunk_size=8192), resp.status_code, response_headers)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
EOF

chmod +x "${PROXY_FILE}"

# --- Start auth proxy ---
echo "[INFO] Starting auth proxy on http://0.0.0.0:8080 ..."
python3 "${PROXY_FILE}" >/var/log/auth_proxy.log 2>&1 &

sleep 1

# --- Start cloudflared (foreground so you see the URL) ---
echo "[INFO] Starting cloudflared tunnel (you'll see the assigned trycloudflare URL here)..."
cloudflared tunnel --url http://localhost:8080 --no-autoupdate
