#!/usr/bin/env bash
# Publish the Clavium web app (PWA) and the download page, with a copy of
# the latest Android build re-signed with the Clavium release key.
#
#   SITE_DIR   where Caddy serves the site from (default /srv/clavium/site)
#   KEY_ENV    release keystore settings (default ~/.clavium-release/keystore.env)
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
site="${SITE_DIR:-/srv/clavium/site}"
key_env="${KEY_ENV:-$HOME/.clavium-release/keystore.env}"
gh_api="https://api.github.com/repos/enricoshilisia/clavium/releases/tags"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# 1. The PWA, built against the production control plane.
(cd "$repo/mobile" && ./tool/build_web.sh >/dev/null)

# 2. Release assets.
asset_url() { # tag, filename regex
  curl -fsS "$gh_api/$1" | python3 -c "import sys,json,re
for a in json.load(sys.stdin)['assets']:
    if re.search(sys.argv[1], a['name']): print(a['browser_download_url']); break" "$2"
}
exe=$(asset_url desktop-latest '\.exe$')
msi=$(asset_url desktop-latest '\.msi$')
apk=$(asset_url android-latest '\.apk$')
[ -n "$exe" ] && [ -n "$apk" ] || { echo "release assets not found yet (CI still running?)"; exit 1; }

# 3. Re-sign the APK with the release key (v2/v3 signatures; the APK is
#    already zip-aligned by the build).
. "$key_env"
curl -fsSL -o "$work/ci.apk" "$apk"
java -jar /data/android-sdk/build-tools/35.0.0/lib/apksigner.jar sign \
  --ks "$KEYSTORE" --ks-pass "pass:$KEYSTORE_PASSWORD" --ks-key-alias "$KEY_ALIAS" \
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true \
  --out "$work/clavium.apk" "$work/ci.apk"
java -jar /data/android-sdk/build-tools/35.0.0/lib/apksigner.jar verify "$work/clavium.apk"
cert=$(java -jar /data/android-sdk/build-tools/35.0.0/lib/apksigner.jar verify --print-certs "$work/clavium.apk" \
  | grep "SHA-256 digest" | head -1 | awk '{print $NF}')

# 4. Assemble and swap in atomically.
stage="$work/site"
cp -r "$repo/mobile/build/web" "$stage"
mkdir -p "$stage/download"
cp "$work/clavium.apk" "$stage/download/clavium.apk"
sed -e "s#{{WINDOWS_EXE}}#$exe#" -e "s#{{WINDOWS_MSI}}#${msi:-$exe}#" -e "s#{{APK_CERT}}#$cert#" \
    -e "s#{{UPDATED}}#$(date -u '+%Y-%m-%d %H:%M UTC')#" \
    "$repo/deploy/site/download.html" > "$stage/download/index.html"
mkdir -p "$site"
rsync -a --delete "$stage/" "$site.new/"
rm -rf "$site.old"; [ -d "$site" ] && mv "$site" "$site.old"; mv "$site.new" "$site"
echo "published to $site"
