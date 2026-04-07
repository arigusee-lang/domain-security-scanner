#!/bin/bash
# One-time VM setup script for GCE e2-micro
# Run as root: sudo bash deploy/setup-vm.sh
set -e

echo "=== Setting up DN-Sec on GCE VM ==="

# 1. Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs git

# 2. Create app user
useradd --system --create-home --shell /bin/bash dn-sec || true

# 3. Clone repo (or set up for pull-based deploy)
if [ ! -d /opt/dn-sec ]; then
  git clone https://github.com/YOUR_USERNAME/security.txt.git /opt/dn-sec
  chown -R dn-sec:dn-sec /opt/dn-sec
fi

# 4. Create data directory for SQLite
mkdir -p /opt/dn-sec/data
chown dn-sec:dn-sec /opt/dn-sec/data

# 5. Create .env file (fill in secrets manually after setup)
if [ ! -f /opt/dn-sec/.env ]; then
  cat > /opt/dn-sec/.env << 'EOF'
# Production secrets — fill these in manually
NODE_ENV=production
PORT=8080
DB_DIR=/opt/dn-sec/data
APP_URL=https://dn-sec.com

GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=https://dn-sec.com/api/auth/google/callback

GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GITHUB_REDIRECT_URI=https://dn-sec.com/api/auth/github/callback

RESEND_API_KEY=
FROM_EMAIL=notifications@dn-sec.com

CRON_SECRET=
EOF
  chown dn-sec:dn-sec /opt/dn-sec/.env
  chmod 600 /opt/dn-sec/.env
  echo ">>> IMPORTANT: Edit /opt/dn-sec/.env and fill in your secrets!"
fi

# 6. Install dependencies and build
cd /opt/dn-sec
sudo -u dn-sec npm ci --legacy-peer-deps
sudo -u dn-sec npm run build

# 7. Install systemd service
cp /opt/dn-sec/deploy/dn-sec.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable dn-sec
systemctl start dn-sec

# 8. Set up daily SQLite backup to GCS (optional)
cat > /etc/cron.d/dn-sec-backup << 'CRON'
# Backup SQLite to GCS every 6 hours
0 */6 * * * dn-sec gsutil cp /opt/dn-sec/data/app.db gs://YOUR_BUCKET/backups/app-$(date +\%Y\%m\%d-\%H\%M).db 2>/dev/null || true
CRON

echo ""
echo "=== Setup complete ==="
echo "1. Edit /opt/dn-sec/.env with your secrets"
echo "2. Point Cloudflare DNS A record to this VM's IP"
echo "3. In Cloudflare, set SSL mode to 'Flexible' (Cloudflare handles SSL)"
echo "4. Restart: sudo systemctl restart dn-sec"
echo "5. Check: sudo systemctl status dn-sec"
echo "6. Logs: sudo journalctl -u dn-sec -f"
