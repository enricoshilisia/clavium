// Where things live on the device:
// - the sealed vault (ciphertext) in the app's private files, or browser
//   storage for the PWA;
// - the device token and biometric unlock secret in the platform keystore.
import 'dart:convert';
import 'dart:math';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'api_client.dart';
import 'blob_store.dart';

abstract class KeyValueStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

class SecureStore implements KeyValueStore {
  static const _s = FlutterSecureStorage(
    iOptions: IOSOptions(accessibility: KeychainAccessibility.unlocked_this_device),
  );
  @override
  Future<String?> read(String key) => _s.read(key: key);
  @override
  Future<void> write(String key, String value) => _s.write(key: key, value: value);
  @override
  Future<void> delete(String key) => _s.delete(key: key);
}

class MemoryStore implements KeyValueStore {
  final Map<String, String> data = {};
  @override
  Future<String?> read(String key) async => data[key];
  @override
  Future<void> write(String key, String value) async => data[key] = value;
  @override
  Future<void> delete(String key) async => data.remove(key);
}

class DeviceStorage {
  DeviceStorage({KeyValueStore? secure, BlobStore? blobs})
      : secure = secure ?? SecureStore(),
        blobs = blobs ?? defaultBlobStore();

  final KeyValueStore secure;
  final BlobStore blobs;

  static const _vault = 'vault.clavium';
  static const _prefs = 'prefs.json';

  // Every write goes through this chain, so two overlapping saves (a sync
  // finishing while the person edits) can never interleave.
  Future<void> _writes = Future.value();

  Future<T> _serial<T>(Future<T> Function() op) {
    final next = _writes.then((_) => op());
    _writes = next.then((_) {}, onError: (_) {});
    return next;
  }

  Future<bool> vaultExists() async => await blobs.read(_vault) != null;

  /// The sealed vault, base64. Stored as base64 text so the same format
  /// works in files and in browser storage.
  Future<String> readVault() async {
    final v = await blobs.read(_vault);
    if (v == null) throw StateError('no vault on this device');
    return v;
  }

  Future<void> writeVault(String sealedB64) => _serial(() => blobs.write(_vault, sealedB64));

  Future<void> deleteVault() => _serial(() => blobs.delete(_vault));

  // Non-secret preferences (auto-lock seconds, keyring revision).
  Future<Map<String, dynamic>> prefs() async {
    final raw = await blobs.read(_prefs);
    if (raw == null) return {};
    try {
      return jsonDecode(raw) as Map<String, dynamic>;
    } catch (_) {
      return {};
    }
  }

  Future<void> setPref(String key, Object? value) => _serial(() async {
        final p = await prefs();
        if (value == null) {
          p.remove(key);
        } else {
          p[key] = value;
        }
        await blobs.write(_prefs, jsonEncode(p));
      });

  Future<String> clientDeviceId() async {
    var id = await secure.read('client_device_id');
    if (id == null) {
      final r = Random.secure();
      id = List.generate(16, (_) => r.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
      await secure.write('client_device_id', id);
    }
    return id;
  }

  Future<AccountSession?> loadSession() async {
    final raw = await secure.read('account_session');
    if (raw == null) return null;
    final m = jsonDecode(raw) as Map<String, dynamic>;
    return AccountSession(
      server: m['server'] as String,
      token: m['token'] as String,
      email: m['email'] as String,
      deviceId: m['device_id'] as String,
    );
  }

  Future<void> saveSession(AccountSession? s) async {
    if (s == null) {
      await secure.delete('account_session');
      return;
    }
    await secure.write(
      'account_session',
      jsonEncode({'server': s.server, 'token': s.token, 'email': s.email, 'device_id': s.deviceId}),
    );
  }
}
