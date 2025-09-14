#!/bin/bash
set -e

USER_NAME=${1:-myuser}
USER_PASS=${2:-mypassword}

echo "Using username: $USER_NAME"
echo "Using password: $USER_PASS"

apt-get update -y
apt-get install -y xfce4 xfce4-goodies x11vnc xvfb python3 python3-pip git curl jq
if [ ! -d "$HOME/noVNC" ]; then
  git clone https://github.com/novnc/noVNC.git $HOME/noVNC
fi
if ! command -v cloudflared &> /dev/null; then
  curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
    -o /usr/local/bin/cloudflared
  chmod +x /usr/local/bin/cloudflared
fi

pip3 install flask requests
Xvfb :0 -screen 0 1024x768x24 &
DISPLAY=:0 startxfce4 &
x11vnc -display :0 -nopw -forever -rfbport 5900 &
cd $HOME/noVNC
./utils/novnc_proxy --vnc localhost:5900 --listen 6080 &

cat > $HOME/auth_proxy.py <<EOF
from flask import Flask, request, Response
import requests
from functools import wraps

USERNAME = "$USER_NAME"
PASSWORD = "$USER_PASS"
TARGET = "http://localhost:6080"

app = Flask(__name__)

def check_auth(u, p):
    return u == USERNAME and p == PASSWORD

def authenticate():
    return Response(
        'Login required', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
@requires_auth
def proxy(path):
    resp = requests.request(
        method=request.method,
        url=f"{TARGET}/{path}",
        headers={k: v for k, v in request.headers if k.lower() != 'host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False,
        stream=True
    )
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_headers]
    return Response(resp.content, resp.status_code, headers)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080)
EOF

python3 $HOME/auth_proxy.py &
cloudflared tunnel --url http://localhost:8080 --no-autoupdate
