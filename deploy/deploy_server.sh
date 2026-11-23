#!/usr/bin/env bash
# Deploy the control plane on this server (needs sudo for systemd).
# Safe to re-run. Backs up the database before migrating.
set -euo pipefail
cd "$(dirname "$0")/../control-plane"
set -a; . ./.env; set +a

stamp=$(date +%Y%m%d-%H%M%S)
mkdir -p /data/clavium-backups
docker exec clavium-db pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB" > "/data/clavium-backups/clavium-$stamp.dump"
echo "database backed up to /data/clavium-backups/clavium-$stamp.dump"

.venv/bin/pip install -q -r requirements.txt
.venv/bin/python manage.py migrate --noinput
.venv/bin/python manage.py createcachetable
.venv/bin/python manage.py collectstatic --noinput -v0

# Threaded workers: sync clients hold a long-poll open for up to 25 s,
# which would otherwise occupy a whole worker each.
unit=/etc/systemd/system/clavium-control.service
if ! grep -q "worker-class gthread" "$unit"; then
  sudo sed -i 's#--workers 2 --timeout 120#--worker-class gthread --workers 2 --threads 32 --timeout 120#' "$unit"
  sudo systemctl daemon-reload
fi
sudo systemctl restart clavium-control
sleep 3
systemctl is-active clavium-control
curl -fsS https://clavium-api.172-169-233-189.sslip.io/api/health/ && echo
