#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" != 0 ] || [ "$(uname -s)" != Linux ]; then
  echo 'Запустите sudo bash /opt/fortis/deploy/install-services.sh на Linux с systemd' >&2
  exit 1
fi
fortis_root="$(cd "$(dirname "$0")/.." && pwd)"
if [ "$fortis_root" != /opt/fortis ]; then
  echo 'Для этих служб установите исходники в /opt/fortis' >&2
  exit 1
fi
if ! id fortis >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /var/lib/fortis --shell /usr/sbin/nologin fortis
fi
# Source and interpreter remain immutable to the HTTP application's account.
chown -R root:root /opt/fortis
chmod -R go-w /opt/fortis
install -d -o fortis -g fortis -m 0700 /var/lib/fortis
# Migrate only the fixed application data directory; never dereference symlinks.
chown -hR fortis:fortis /var/lib/fortis
install -d -o root -g root -m 0700 /var/lib/fortis-network /etc/wireguard
install -d -o root -g root -m 0755 /etc/fortis /etc/netplan
if [ ! -e /etc/fortis/fortis.env ]; then
  cat > /etc/fortis/fortis.env <<'ENV'
DATA_DIR=/var/lib/fortis
DATABASE_URL=sqlite:////var/lib/fortis/fortis.db
CA_DIR=/var/lib/fortis/ca
DOCS_DIR=/var/lib/fortis/docs
UPLOADS_DIR=/var/lib/fortis/uploads
NETWORK_HELPER_SOCKET=/run/fortis-network.sock
PUBLIC_ORIGIN=http://127.0.0.1:8088
ALLOWED_HOSTS=localhost,127.0.0.1,::1
ENV
elif ! grep -q '^NETWORK_HELPER_SOCKET=' /etc/fortis/fortis.env; then
  printf '\nNETWORK_HELPER_SOCKET=/run/fortis-network.sock\n' >> /etc/fortis/fortis.env
fi
chmod 0600 /etc/fortis/fortis.env
install -m 0644 "$fortis_root/deploy/fortis-network.service" /etc/systemd/system/fortis-network.service
install -m 0644 "$fortis_root/deploy/fortis.service" /etc/systemd/system/fortis.service
systemctl daemon-reload
systemctl enable fortis-network fortis
systemctl restart fortis-network
systemctl restart fortis
systemctl --no-pager status fortis-network fortis
