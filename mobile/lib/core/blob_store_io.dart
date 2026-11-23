import 'dart:io';

import 'package:path_provider/path_provider.dart';

import 'blob_store.dart';

class DirectoryBlobStore implements BlobStore {
  DirectoryBlobStore([Future<Directory> Function()? dir]) : _dir = dir ?? getApplicationDocumentsDirectory;
  final Future<Directory> Function() _dir;
  int _seq = 0;

  Future<File> _file(String name) async => File('${(await _dir()).path}/$name');

  @override
  Future<String?> read(String name) async {
    final f = await _file(name);
    return await f.exists() ? f.readAsString() : null;
  }

  @override
  Future<void> write(String name, String value) async {
    final f = await _file(name);
    final tmp = File('${f.path}.${_seq++}.tmp');
    await tmp.writeAsString(value, flush: true);
    await tmp.rename(f.path);
  }

  @override
  Future<void> delete(String name) async {
    final f = await _file(name);
    if (await f.exists()) await f.delete();
  }
}

BlobStore defaultBlobStore() => DirectoryBlobStore();
