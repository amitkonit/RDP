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
cat > "${AUTH_PROXY_GO}" <<EOF
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

func mustBase64URLDecode(s string) ([]byte, error) {
	if l := len(s) % 4; l != 0 {
		s += strings.Repeat("=", 4-l)
	}
	return base64.URLEncoding.DecodeString(s)
}

type claims map[string]interface{}

func verifyHS256(token string, secret []byte) (claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token parts != 3")
	}
	payloadRaw, err := mustBase64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload decode: %v", err)
	}
	var cl claims
	if err := json.Unmarshal(payloadRaw, &cl); err != nil {
		return nil, fmt.Errorf("invalid payload json: %v", err)
	}
	sigRaw, err := mustBase64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("sig decode: %v", err)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, sigRaw) {
		return nil, fmt.Errorf("invalid signature")
	}

	// check exp if present
	if expv, ok := cl["exp"]; ok {
		switch t := expv.(type) {
		case float64:
			if int64(t) < time.Now().Unix() {
				return nil, fmt.Errorf("token expired")
			}
		case json.Number:
			n, _ := t.Int64()
			if n < time.Now().Unix() {
				return nil, fmt.Errorf("token expired")
			}
		}
	}

	return cl, nil
}

func main() {
	var listen string
	var upstream string
	var secretStr string
	flag.StringVar(&listen, "listen", ":8080", "listen address")
	flag.StringVar(&upstream, "upstream", "http://127.0.0.1:6080", "upstream target (noVNC)")
	flag.StringVar(&secretStr, "secret", "", "HMAC secret for HS256 JWT (required)")
	flag.Parse()
	if secretStr == "" {
		log.Fatal("secret is required. e.g. --secret \"mysecret\"")
	}
	secret := []byte(secretStr)
	upURL, err := url.Parse(upstream)
	if err != nil {
		log.Fatalf("invalid upstream: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upURL)
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = upURL.Host
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// get token from query or header
		token := r.URL.Query().Get("token")
		if token == "" {
			token = r.Header.Get("X-Auth-Token")
		}
		if token == "" {
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
				token = strings.TrimSpace(auth[7:])
			}
		}

		if token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="noVNC"`)
			http.Error(w, "token required", http.StatusUnauthorized)
			log.Printf("unauthorized: no token for %s %s", r.RemoteAddr, r.URL.Path)
			return
		}

		_, err := verifyHS256(token, secret)
		if err != nil {
			http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
			log.Printf("invalid token for %s %s: %v", r.RemoteAddr, r.URL.Path, err)
			return
		}

		// remove token from query before forwarding
		q := r.URL.Query()
		q.Del("token")
		r.URL.RawQuery = q.Encode()

		proxy.ServeHTTP(w, r)
	})

	log.Printf("auth proxy listening on %s -> upstream %s", listen, upstream)
	log.Fatal(http.ListenAndServe(listen, nil))
}
EOF

cd $HOME
go build -o auth_proxy auth_proxy.go

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
