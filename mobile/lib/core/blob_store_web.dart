import 'package:web/web.dart' as web;

import 'blob_store.dart';

/// localStorage holds ciphertext only (the sealed vault) and non-secret
/// preferences. A single setItem is atomic.
class LocalStorageBlobStore implements BlobStore {
  static const _prefix = 'clavium.';
  @override
  Future<String?> read(String name) async => web.window.localStorage.getItem('$_prefix$name');
  @override
  Future<void> write(String name, String value) async => web.window.localStorage.setItem('$_prefix$name', value);
  @override
  Future<void> delete(String name) async => web.window.localStorage.removeItem('$_prefix$name');
}

BlobStore defaultBlobStore() => LocalStorageBlobStore();
