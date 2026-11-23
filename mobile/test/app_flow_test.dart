// End-to-end over the real Rust core (through FFI) and a fake server.
// Run with CLAVIUM_FFI_PATH pointing at a host build of libclavium_ffi.
import 'dart:convert';
import 'dart:io';

import 'package:clavium/core/api_client.dart';
import 'package:clavium/core/app_state.dart';
import 'package:clavium/core/native.dart';
import 'package:clavium/core/blob_store_io.dart';
import 'package:clavium/core/storage.dart';
import 'package:flutter_test/flutter_test.dart';

import 'fake_server.dart';

class FakeBiometrics implements BiometricPrompt {
  bool allow = true;
  @override
  Future<bool> available() async => true;
  @override
  Future<bool> authenticate(String reason) async => allow;
}

const master = 'correct horse battery staple';
const server = 'https://fake.invalid';

AppState device(FakeControlPlane cp, Directory dir, MemoryStore secure, [FakeBiometrics? bio]) => AppState(
      storage: DeviceStorage(secure: secure, blobs: DirectoryBlobStore(() async => dir)),
      api: ApiClient(client: cp.client),
      biometrics: bio ?? FakeBiometrics(),
      liveSync: false,
    );

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('clavium_test'));
  tearDown(() => tmp.deleteSync(recursive: true));

  test('core answers through FFI', () {
    expect((Core.call('version') as Map)['api'], 1);
    expect(() => Core.call('nope'), throwsA(isA<CoreException>()));
  });

  test('create, add with auto-category, lock, unlock', () async {
    final cp = FakeControlPlane();
    final a = device(cp, tmp, MemoryStore());
    await a.init();
    expect(a.phase, Phase.onboarding);
    await a.createVault(master);
    expect(a.phase, Phase.unlocked);

    await a.addRecord({'title': 'KCB', 'url': 'https://ke.kcbgroup.com', 'username': 'me', 'password': 'p'});
    await a.addRecord({'kind': 'card', 'title': 'Visa', 'fields': {'number': '4111 1111 1111 1111'}});
    await a.addRecord({'title': 'Office Wi-Fi', 'kind': 'wifi', 'fields': {'ssid': 'HQ'}, 'password': 'x'});
    expect(a.records.length, 3);
    expect(a.categories.firstWhere((c) => c.slug == 'banking').count, 2);

    a.setCategoryFilter('banking');
    expect(a.records.map((r) => r.title).toSet(), {'KCB', 'Visa'});
    expect(a.records.firstWhere((r) => r.title == 'Visa').fields['brand'], 'visa');
    a.setCategoryFilter(null);

    a.lock();
    expect(a.phase, Phase.locked);
    await expectLater(a.unlock('wrong password!'), throwsA(isA<CoreException>()));
    await a.unlock(master);
    expect(a.records.length, 3);

    // The file on disk is v3 and opaque.
    final bytes = base64Decode(File('${tmp.path}/vault.clavium').readAsStringSync());
    expect(bytes[4], 3);
    expect(utf8.decode(bytes, allowMalformed: true).contains('kcbgroup'), isFalse);
  });

  test('biometric unlock and recovery key', () async {
    final bio = FakeBiometrics();
    final a = device(FakeControlPlane(), tmp, MemoryStore(), bio);
    await a.init();
    await a.createVault(master);
    await a.addRecord({'title': 'GitHub', 'password': 'gh'});
    await a.enableBiometrics();
    final rk = await a.createRecoveryKey();
    expect(a.slots().length, 3);

    a.lock();
    bio.allow = false;
    expect(await a.unlockWithBiometrics(), isFalse);
    bio.allow = true;
    expect(await a.unlockWithBiometrics(), isTrue);
    expect(a.records.single.title, 'GitHub');

    a.lock();
    await a.unlockWithRecoveryKey(rk.toLowerCase());
    expect(a.phase, Phase.unlocked);

    await a.disableBiometrics();
    expect(a.slots().length, 2);
  });

  test('two devices sync through the server, including a conflict', () async {
    final cp = FakeControlPlane();
    final dirA = Directory('${tmp.path}/a')..createSync();
    final dirB = Directory('${tmp.path}/b')..createSync();
    final secA = MemoryStore(), secB = MemoryStore();

    // Device A: create, sign up, sync.
    final a = device(cp, dirA, secA);
    await a.init();
    await a.createVault(master);
    final gh = await a.addRecord({'title': 'GitHub', 'url': 'github.com', 'password': 'one'});
    await a.register(server, 'me@example.com', 'account password 1');
    await a.signIn(server, 'me@example.com', 'account password 1');
    expect(a.syncError, isNull);
    expect(cp.items['me@example.com']!.length, 1);
    // The server holds ciphertext only.
    expect(jsonEncode(cp.items).contains('GitHub'), isFalse);
    a.lock();

    // Device B: restore from the account.
    final b = device(cp, dirB, secB);
    await b.init();
    await b.restoreFromAccount(server, 'me@example.com', 'account password 1', master);
    expect(b.records.single.title, 'GitHub');
    expect(b.records.single.category, 'development');
    // B edits the password and syncs.
    final input = b.records.single.toInput()..['password'] = 'from-b';
    await b.updateRecord(gh.id, input);
    await b.syncNow();
    b.lock();

    // A comes back while offline and edits the same record.
    cp.offline = true;
    await a.unlock(master);
    final inA = a.get(gh.id)!.toInput()..['password'] = 'from-a';
    await a.updateRecord(gh.id, inA);
    await a.syncNow();
    expect(a.syncError, isNotNull, reason: 'offline sync reports an error, does not lose data');
    cp.offline = false;
    await a.syncNow();
    expect(a.syncError, isNull);
    final passwords = a.records.map((r) => r.password).toSet();
    expect(passwords, containsAll(['from-a', 'from-b']), reason: 'neither edit is lost');
    final copy = a.records.firstWhere((r) => r.title.contains('conflict copy'));
    expect(a.get(gh.id)!.password, 'from-a', reason: 'the newer edit keeps the record');

    // A resolves by deleting the copy; B converges after syncing.
    await a.deleteRecord(copy.id);
    await a.syncNow();
    a.lock();
    await b.unlock(master);
    await b.syncNow();
    expect(b.records.length, 1);
    expect(b.records.single.password, 'from-a');
    expect(cp.items['me@example.com']!.length, 2, reason: 'the deleted copy remains as a tombstone');
  });

  test('restore with the wrong master password fails cleanly', () async {
    final cp = FakeControlPlane();
    final a = device(cp, tmp, MemoryStore());
    await a.init();
    await a.createVault(master);
    await a.register(server, 'x@example.com', 'account password 1');
    await a.signIn(server, 'x@example.com', 'account password 1');
    a.lock();
    final dirB = Directory('${tmp.path}/b')..createSync();
    final b = device(cp, dirB, MemoryStore());
    await b.init();
    await expectLater(
      b.restoreFromAccount(server, 'x@example.com', 'account password 1', 'not the master password'),
      throwsA(isA<CoreException>()),
    );
    expect(b.phase, Phase.onboarding);
  });
}
