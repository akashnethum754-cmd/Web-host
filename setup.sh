#!/usr/bin/env bash
# HostX installer for Ubuntu/Debian VPS.
# Usage (run inside the hostx folder, as root):
#   BASE_DOMAIN=host.example.com bash setup.sh
#
# Before running, in your DNS add:
#   A   host.example.com     -> VPS IP
#   A   *.host.example.com   -> VPS IP
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Run as root (sudo)."; exit 1; }
: "${BASE_DOMAIN:?Set BASE_DOMAIN, e.g. BASE_DOMAIN=host.example.com bash setup.sh}"

APP=/opt/hostx
SERVER_IP="${SERVER_IP:-$(curl -4 -fsS https://ifconfig.me)}"
SRC="$(cd "$(dirname "$0")" && pwd)"

echo "==> Installing Node.js 20 + Caddy"
apt-get update -y
apt-get install -y curl gpg debian-keyring debian-archive-keyring apt-transport-https
command -v node >/dev/null || { curl -fsSL https://deb.nodesource.com/setup_20.x | bash -; apt-get install -y nodejs; }
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y && apt-get install -y caddy
fi

echo "==> Installing app to $APP"
mkdir -p "$APP"
[ "$SRC" = "$APP" ] || cp -r "$SRC/server.js" "$SRC/public" "$APP/"
cd "$APP"
[ -f package.json ] || npm init -y >/dev/null
npm install --omit=dev express multer adm-zip bcryptjs jsonwebtoken cookie-parser

echo "==> Creating service"
cat > /etc/systemd/system/hostx.service <<EOF
[Unit]
Description=HostX hosting platform
After=network.target

[Service]
WorkingDirectory=$APP
Environment=BASE_DOMAIN=$BASE_DOMAIN
Environment=172.104.166.177
Environment=PORT=3000
ExecStart=$(command -v node) server.js
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

echo "==> Configuring Caddy (automatic HTTPS for subdomains + custom domains)"
cat > /etc/caddy/Caddyfile <<EOF
{
	on_demand_tls {
		ask http://172.104.166.177/_caddy/check
	}
}

https:// {
	tls {
		on_demand
	}
	request_body {
		max_size 120MB
	}
	reverse_proxy 127.0.0.1:3000
}

http:// {
	redir https://{host}{uri} permanent
}
EOF

systemctl daemon-reload
systemctl enable --now hostx
systemctl restart caddy

command -v ufw >/dev/null && ufw allow 80,443/tcp || true
echo
echo "Done. Open https://$BASE_DOMAIN and create your account."
echo "Users point their domain with an A record to: $SERVER_IP"
