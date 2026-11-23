#!/usr/bin/env bash
# One-time go-live on this server (uses sudo). Safe to re-run.
#  1. control plane: DB backup, migrations, threaded workers, restart
#  2. web app + download page published to /srv/clavium/site
#  3. Caddy site clavium.172-169-233-189.sslip.io added and reloaded
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
export PATH=/data/flutter/bin:/data/jdk17/bin:$PATH:/data/cargo-home/bin PUB_CACHE=/data/pub-cache

"$here/deploy_server.sh"

sudo mkdir -p /srv/clavium
sudo chown "$(id -un)":"$(id -gn)" /srv/clavium
"$here/publish_site.sh"

if ! grep -q "clavium.172-169-233-189.sslip.io {" /etc/caddy/Caddyfile; then
  sudo cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.$(date +%s)"
  { echo; cat "$here/Caddyfile.clavium-site"; } | sudo tee -a /etc/caddy/Caddyfile >/dev/null
fi
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl reload caddy
sleep 5
curl -fsS -o /dev/null -w "web app: %{http_code}\n" https://clavium.172-169-233-189.sslip.io/
curl -fsS -o /dev/null -w "download page: %{http_code}\n" https://clavium.172-169-233-189.sslip.io/download/
curl -fsS -o /dev/null -w "console: %{http_code}\n" https://clavium-api.172-169-233-189.sslip.io/console/login/
