#!/bin/bash
# Set up cron job for scheduled scans on the VM
# Run as root: sudo bash deploy/setup-cron.sh
set -e

# Read CRON_SECRET from .env
CRON_SECRET=$(grep CRON_SECRET /opt/dn-sec/.env | cut -d= -f2)

if [ -z "$CRON_SECRET" ]; then
  echo "ERROR: CRON_SECRET not set in /opt/dn-sec/.env"
  exit 1
fi

# Trigger scheduled scans every 15 minutes
cat > /etc/cron.d/dn-sec-scheduler << EOF
*/15 * * * * dn-sec curl -sf -X POST http://localhost:8080/api/cron/run-scheduled -H "Authorization: Bearer ${CRON_SECRET}" > /dev/null 2>&1
EOF

echo "Cron job installed. Scheduled scans will run every 15 minutes."
echo "Check: cat /etc/cron.d/dn-sec-scheduler"
