#!/usr/bin/env bash
# Build the Clavium PWA: the Rust core as WebAssembly, then the Flutter web
# app around it. Output: mobile/build/web (static files, serve over HTTPS).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
root="$(cd "$here/.." && pwd)"
target_dir="$(cd "$root" && cargo metadata --format-version 1 --no-deps | python3 -c 'import sys,json;print(json.load(sys.stdin)["target_directory"])')"

(cd "$root" && cargo build -p clavium-wasm --release --target wasm32-unknown-unknown)
rm -rf "$here/web/core"
wasm-bindgen --target web --no-typescript --out-dir "$here/web/core" \
  "$target_dir/wasm32-unknown-unknown/release/clavium_wasm.wasm"

cd "$here"
flutter build web --release --pwa-strategy=none "$@"
python3 "$here/tool/write_sw.py" "$here/build/web"
echo "PWA built in $here/build/web"
