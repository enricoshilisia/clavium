// The only bridge to the Rust security core. Every security decision
// (crypto, categorisation, merging sync changes) happens in Rust; Dart
// only moves bytes and draws screens. On phones and desktop the core is a
// native library (FFI); in the browser it is the same code as WebAssembly.
import 'dart:convert';

import 'bridge_io.dart' if (dart.library.js_interop) 'bridge_web.dart' as bridge;

class CoreException implements Exception {
  CoreException(this.message);
  final String message;
  @override
  String toString() => message;
}

dynamic _decode(String response) {
  final decoded = jsonDecode(response) as Map<String, dynamic>;
  if (decoded.containsKey('error')) throw CoreException(decoded['error'] as String);
  return decoded['ok'];
}

String _request(String cmd, Map<String, dynamic> args) => jsonEncode({'cmd': cmd, 'args': args});

/// Commands that run Argon2 (most of a second). Natively they run on a
/// background isolate so the UI never freezes.
const _slowCommands = {'create', 'open', 'open_from_keyring', 'change_master_password'};

class Core {
  static dynamic call(String cmd, [Map<String, dynamic> args = const {}]) =>
      _decode(bridge.invoke(_request(cmd, args)));

  static Future<dynamic> run(String cmd, [Map<String, dynamic> args = const {}]) async {
    final req = _request(cmd, args);
    if (_slowCommands.contains(cmd)) return _decode(await bridge.invokeSlow(req));
    return _decode(bridge.invoke(req));
  }
}
