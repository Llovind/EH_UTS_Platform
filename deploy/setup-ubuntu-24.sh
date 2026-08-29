#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${APP_DIR:-/opt/mbc-las-week4-portal}"
APP_USER="${APP_USER:-mbc-ctf}"
NODE_MAJOR="${NODE_MAJOR:-22}"
WG_HELPER_PATH="${WG_HELPER_PATH:-/usr/local/sbin/mbc-las-wg-peer}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (or through sudo)." >&2
  exit 1
fi
[[ "${APP_USER}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { echo "Invalid APP_USER" >&2; exit 1; }
[[ "${WG_HELPER_PATH}" == "/usr/local/sbin/mbc-las-wg-peer" ]] || { echo "WG_HELPER_PATH must match the checked-in helper template" >&2; exit 1; }

apt-get update
apt-get install -y ca-certificates curl git build-essential wireguard ufw
if ! command -v node >/dev/null 2>&1 || ! node -e 'const [major, minor] = process.versions.node.split(".").map(Number); process.exit(major > 22 || (major === 22 && minor >= 5) ? 0 : 1)'; then
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -
  apt-get install -y nodejs
fi

id -u "${APP_USER}" >/dev/null 2>&1 || useradd --system --home "${APP_DIR}" --shell /usr/sbin/nologin "${APP_USER}"
install -d -o "${APP_USER}" -g "${APP_USER}" -m 0750 "${APP_DIR}"

if [[ ! -d "${APP_DIR}/.git" ]]; then
  echo "Clone the repository into ${APP_DIR}, then run this script again." >&2
  exit 1
fi
cd "${APP_DIR}"
npm ci --omit=dev
install -d -o "${APP_USER}" -g "${APP_USER}" -m 0700 data

if [[ -f deploy/mbc-las-wg-peer.example && -f deploy/mbc-las-wg-peer.sudoers.example ]]; then
  install -o root -g root -m 0750 deploy/mbc-las-wg-peer.example "${WG_HELPER_PATH}"
  install -o root -g root -m 0440 deploy/mbc-las-wg-peer.sudoers.example /etc/sudoers.d/mbc-las-wg-peer
  sed -i "s/^mbc-portal /${APP_USER} /" /etc/sudoers.d/mbc-las-wg-peer
  visudo -cf /etc/sudoers.d/mbc-las-wg-peer
else
  echo "WireGuard helper templates are missing from the checkout." >&2
  exit 1
fi
if [[ ! -f .env ]]; then
  install -o "${APP_USER}" -g "${APP_USER}" -m 0600 .env.example .env
  echo "Edit ${APP_DIR}/.env with real secrets, then run this script again." >&2
  exit 0
fi

cat >/etc/systemd/system/mbc-las-week4.service <<EOF
[Unit]
Description=MBC LAS Week 4 mini CTF portal
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
Environment=NODE_ENV=production
ExecStart=/usr/bin/node ${APP_DIR}/server.mjs
Restart=on-failure
RestartSec=4
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${APP_DIR}/data
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable mbc-las-week4.service
systemctl restart mbc-las-week4.service

ufw allow 51820/udp comment 'WireGuard hub'
ufw allow 80/tcp comment 'HTTP ACME redirect'
ufw allow 443/tcp comment 'HTTPS portal'
ufw --force enable
echo "Portal service configured. Keep admin access on WireGuard; do not open target service ports in UFW."
