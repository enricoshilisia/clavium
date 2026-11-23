// Native core over dart:ffi.
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart';

typedef _InvokeC = Pointer<Utf8> Function(Pointer<Utf8>);
typedef _FreeC = Void Function(Pointer<Utf8>);
typedef _FreeDart = void Function(Pointer<Utf8>);

DynamicLibrary _open() {
  final override = Platform.environment['CLAVIUM_FFI_PATH'];
  if (override != null && override.isNotEmpty) return DynamicLibrary.open(override);
  if (Platform.isIOS || Platform.isMacOS) return DynamicLibrary.process();
  if (Platform.isWindows) return DynamicLibrary.open('clavium_ffi.dll');
  return DynamicLibrary.open('libclavium_ffi.so');
}

class _Bindings {
  _Bindings() {
    final lib = _open();
    invoke = lib.lookupFunction<_InvokeC, _InvokeC>('clavium_invoke');
    free = lib.lookupFunction<_FreeC, _FreeDart>('clavium_free');
  }
  late final _InvokeC invoke;
  late final _FreeDart free;
}

_Bindings? _bindings;

String invoke(String request) {
  final b = _bindings ??= _Bindings();
  final req = request.toNativeUtf8();
  try {
    final res = b.invoke(req);
    try {
      return res.toDartString();
    } finally {
      b.free(res);
    }
  } finally {
    malloc.free(req);
  }
}

/// The Rust session is process-wide, so work done on another isolate is
/// visible to this one.
Future<String> invokeSlow(String request) => Isolate.run(() => invoke(request));
