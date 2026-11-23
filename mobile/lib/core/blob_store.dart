// Small named blobs (the sealed vault, preferences). Files on phones and
// desktop, localStorage in the browser.
export 'blob_store_io.dart' if (dart.library.js_interop) 'blob_store_web.dart';

abstract class BlobStore {
  Future<String?> read(String name);

  /// Must be atomic: a crash mid-write never leaves a half-written blob.
  Future<void> write(String name, String value);
  Future<void> delete(String name);
}
