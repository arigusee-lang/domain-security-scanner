#!/bin/bash
# One-time VM setup for the Domain Security Scanner on a GCE e2-micro.
# SQLite + Redis run co-located on this same host (no Docker).
# Run as root:  curl -fsSL <raw setup-vm.sh> | sudo bash
#           or: sudo bash deploy/setup-vm.sh
set -euo pipefail

APP_DIR=/opt/dn-sec
REPO=https://github.com/arigusee-lang/domain-security-scanner.git

echo "=== Domain Security Scanner — VM setup ==="

# 0. Swap — e2-micro has only 1 GB RAM, not enough for `vite build` + Node.
#    A 2 GB swapfile prevents OOM kills during build and under load.
if [ ! -f /swapfile ]; then
  echo ">>> Creating 2 GB swapfile"
  fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# 1. System deps: Node 20, git, and Redis (co-located).
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs git redis-server

# 2. Redis — bound to localhost by default; enable + start.
systemctl enable redis-server
systemctl restart redis-server

# 3. Dedicated service user.
useradd --system --create-home --shell /bin/bash dn-sec || true

# 4. Clone (or fast-forward) the repo.
if [ ! -d "$APP_DIR/.git" ]; then
  git clone "$REPO" "$APP_DIR"
else
  git -C "$APP_DIR" fetch origin && git -C "$APP_DIR" reset --hard origin/main
fi
chown -R dn-sec:dn-sec "$APP_DIR"

# 5. SQLite data directory.
mkdir -p "$APP_DIR/data"
chown dn-sec:dn-sec "$APP_DIR/data"

# 6. Install deps + build the frontend.
#    PDF export is disabled on this deployment, so skip the Chromium download
#    (~150 MB) that puppeteer would otherwise fetch on install.
cd "$APP_DIR"
sudo -u dn-sec env PUPPETEER_SKIP_DOWNLOAD=true npm ci --legacy-peer-deps
sudo -u dn-sec npm run build

# 7. systemd service.
cp "$APP_DIR/deploy/dn-sec.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable dn-sec

echo ""
echo "=== Base setup complete ==="
echo "Next:"
echo "  1. Put the production env file at $APP_DIR/.env (chown dn-sec, chmod 600)"
echo "  2. Start:   sudo systemctl restart dn-sec"
echo "  3. Status:  sudo systemctl status dn-sec"
echo "  4. Logs:    sudo journalctl -u dn-sec -f"
echo "  5. Point Cloudflare A record for dn-sec.com at this VM's external IP (proxied),"
echo "     and set SSL/TLS mode to 'Flexible'."
