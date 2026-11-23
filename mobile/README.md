# Clavium mobile and web app (Flutter)

One Flutter codebase for Android, iOS and the browser (PWA). It replaces the
Expo authenticator in `authenticator/`: authenticator codes now live inside
the encrypted vault, so they sync and back up with everything else.

## How it fits together

```
Flutter UI (lib/ui)            screens only
AppState / SyncService         lock state, account, HTTP to the control plane
lib/core/native.dart           one call: Core.call(cmd, args) -> JSON
        |                                   |
  bridge_io.dart (dart:ffi)          bridge_web.dart (js_interop)
        |                                   |
  bindings/ffi  (libclavium_ffi)     bindings/wasm (clavium_wasm.wasm)
        \___________ bindings/api (JSON commands) ___________/
                              |
                     security-core (Rust)
```

Every security decision (encryption, key slots, auto-categorisation, sync
merging, password health) is made in Rust. Dart never sees a key.

## Develop and test (Linux host)

```bash
cargo build -p clavium-ffi --release            # host build of the core
export CLAVIUM_FFI_PATH=<cargo target dir>/release/libclavium_ffi.so
cd mobile
flutter analyze
flutter test                                     # real Rust core through FFI
```

`test/live_server_test.dart` runs against a real control plane when
`CLAVIUM_LIVE_SERVER` is set. Point it at a throwaway instance, never
production: it creates an account.

## Build

- **Android:** `.github/workflows/build-mobile.yml` (cargo-ndk, then
  `flutter build apk/appbundle`). Google's NDK only runs on x86-64 hosts,
  so Android builds happen in CI. Release signing uses the
  `CLAVIUM_ANDROID_*` repository secrets; without them the APK is
  debug-signed and must not be distributed.
- **Web (PWA):** `tool/build_web.sh` → `build/web/`. Serve over HTTPS. The
  service worker (`tool/write_sw.py`) precaches the app shell so it opens
  offline.
- **iOS:** needs a Mac. Build `clavium-ffi` as a static library for
  `aarch64-apple-ios` (+ simulator), link it into the Runner target; the
  Dart side already loads it with `DynamicLibrary.process()`.

## Security notes

- Android: `FLAG_SECURE` (no screenshots or recent-apps preview), backups
  and device transfer disabled, biometric prompt via `local_auth`.
- Biometric unlock adds a key slot whose secret lives in the platform
  keystore; removing it from Settings removes the slot.
- Clipboard copies clear after 30 seconds.
- The app locks after the chosen time in the background; reloading the
  PWA always locks.
