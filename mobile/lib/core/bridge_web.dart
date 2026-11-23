// WebAssembly core. web/clavium_core.js loads the wasm-bindgen module and
// exposes `globalThis.claviumInvoke(json) -> json` before Flutter starts.
import 'dart:js_interop';

@JS('claviumInvoke')
external JSString _invoke(JSString request);

String invoke(String request) => _invoke(request.toJS).toDart;

/// No threads to move Argon2 onto in the browser; give the UI one frame to
/// show its progress indicator first.
Future<String> invokeSlow(String request) async {
  await Future<void>.delayed(const Duration(milliseconds: 32));
  return invoke(request);
}
