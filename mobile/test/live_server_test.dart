// Against a real control plane. Skipped unless CLAVIUM_LIVE_SERVER is set,
// e.g. CLAVIUM_LIVE_SERVER=http://127.0.0.1:8299 (a throwaway instance).
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:clavium/core/api_client.dart';
import 'package:clavium/core/app_state.dart';
import 'package:clavium/core/blob_store_io.dart';
import 'package:clavium/core/storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

import 'app_flow_test.dart' show FakeBiometrics;

void main() {
  final server = Platform.environment['CLAVIUM_LIVE_SERVER'];
  final skip = server == null ? 'set CLAVIUM_LIVE_SERVER to run' : null;
  const master = 'correct horse battery staple';
  final email = 'e2e-${Random().nextInt(1 << 32)}@example.com';
  const accountPw = 'e2e account password 1';

  AppState dev(Directory d) => AppState(
        storage: DeviceStorage(secure: MemoryStore(), blobs: DirectoryBlobStore(() async => d)),
        api: ApiClient(),
        biometrics: FakeBiometrics(),
        liveSync: false,
      );

  test('two devices, real server: sync, conflict, keyring update, long-poll', () async {
    final tmp = Directory.systemTemp.createTempSync('clavium_live');
    addTearDown(() => tmp.deleteSync(recursive: true));
    final dA = Directory('${tmp.path}/a')..createSync();
    final dB = Directory('${tmp.path}/b')..createSync();

    final a = dev(dA);
    await a.init();
    await a.createVault(master);
    final rec = await a.addRecord({'title': 'NCBA', 'url': 'https://ncbagroup.com', 'password': 'v1'});
    await a.register(server!, email, accountPw);
    await a.signIn(server, email, accountPw);
    expect(a.syncError, isNull, reason: a.syncError);
    a.lock();

    final b = dev(dB);
    await b.init();
    await b.restoreFromAccount(server, email, accountPw, master);
    expect(b.records.single.title, 'NCBA');
    expect(b.records.single.category, 'banking');
    await b.updateRecord(rec.id, b.records.single.toInput()..['password'] = 'from-b');
    await b.syncNow();
    expect(b.syncError, isNull, reason: b.syncError);
    // B adds a recovery key: the keyring changes and is published.
    await b.createRecoveryKey();
    await b.syncNow();
    expect(b.syncError, isNull, reason: b.syncError);
    final ring = await b.api.getKeyring(b.session!);
    expect((ring!['header']['slots'] as List).length, 2);
    expect(ring['revision'], 2);
    b.lock();

    // A was "offline" in between and edits the same record before syncing.
    a.session = null; // no auto-sync on unlock
    await a.unlock(master);
    await a.updateRecord(rec.id, a.get(rec.id)!.toInput()..['password'] = 'from-a');
    a.session = await a.storage.loadSession();
    await a.syncNow();
    expect(a.syncError, isNull, reason: a.syncError);
    expect(a.records.map((r) => r.password).toSet(), containsAll(['from-a', 'from-b']));
    // A did not change its keyring, so it is told, not overwritten.
    expect(a.syncNotice, isNotNull);

    // Long-poll: a waiting pull returns as soon as something is pushed.
    final s = a.session!;
    final counter = (await a.api.getKeyring(s))!['counter'] as int;
    final sw = Stopwatch()..start();
    final waiting = a.api.pull(s, counter, wait: true);
    await Future<void>.delayed(const Duration(seconds: 2));
    await a.syncNow(); // nothing pending: push something new
    await a.addRecord({'title': 'Trigger', 'password': 'x'});
    await a.syncNow();
    final page = await waiting;
    sw.stop();
    expect((page['items'] as List).isNotEmpty, isTrue);
    expect(sw.elapsed.inSeconds, lessThan(10), reason: 'long-poll should wake on the push, not time out');

    // Organization policy reaches the app after a sync.
    final org = jsonDecode((await http.post(Uri.parse('$server/api/orgs/'),
            headers: {'Authorization': 'Bearer ${s.token}', 'Content-Type': 'application/json'},
            body: jsonEncode({'name': 'E2E Org'})))
        .body) as Map<String, dynamic>;
    final put = await http.put(Uri.parse('$server/api/orgs/${org['id']}/policy/'),
        headers: {'Authorization': 'Bearer ${s.token}', 'Content-Type': 'application/json'},
        body: jsonEncode({'min_master_password_length': 40, 'max_auto_lock_minutes': 2, 'require_recovery_key': true}));
    expect(put.statusCode, 200, reason: put.body);
    await a.setAutoLock(900);
    await a.syncNow();
    expect(a.policy['min_master_password_length'], 40);
    expect(a.effectiveAutoLockSeconds, 120, reason: 'org caps auto-lock at 2 minutes');
    expect(a.policyNotices.length, 2, reason: a.policyNotices.join(' | '));
    await a.createRecoveryKey();
    expect(a.policyNotices.length, 1);

    // The server holds nothing readable.
    final raw = await a.api.pull(s, 0);
    expect(jsonEncode(raw).contains('NCBA'), isFalse);
    expect(jsonEncode(raw).contains('from-a'), isFalse);
  }, skip: skip, timeout: const Timeout(Duration(minutes: 2)));

  test('QR sign-in: a signed-in phone approves a new device', () async {
    final tmp = Directory.systemTemp.createTempSync('clavium_qr');
    addTearDown(() => tmp.deleteSync(recursive: true));
    final phone = dev(Directory('${tmp.path}/p')..createSync());
    final laptop = dev(Directory('${tmp.path}/l')..createSync());
    final qrEmail = 'qr-${Random().nextInt(1 << 32)}@example.com';

    await phone.init();
    await phone.createVault(master);
    await phone.addRecord({'title': 'Co-op Bank', 'url': 'co-opbank.co.ke', 'password': 'coop-pass'});
    await phone.register(server!, qrEmail, accountPw);
    await phone.signIn(server, qrEmail, accountPw);
    expect(phone.syncError, isNull, reason: phone.syncError);

    await laptop.init();
    final link = await laptop.startLink(server);
    expect(link.qr, startsWith('clavium://link?'));
    final waiting = laptop.waitForLink(link);

    // The phone scans the QR (the same string) and approves.
    final inspected = await phone.inspectLink(link.qr);
    expect(inspected.code, link.code, reason: 'both screens show the same code');
    await phone.approveLink(inspected);

    expect(await waiting, isTrue);
    expect(laptop.phase, Phase.unlocked);
    expect(laptop.session!.email, qrEmail);
    expect(laptop.records.single.title, 'Co-op Bank');
    expect(laptop.records.single.password, 'coop-pass');

    // The laptop's own file still needs the master password after locking.
    laptop.lock();
    await expectLater(laptop.unlock('wrong master password'), throwsA(anything));
    await laptop.unlock(master);
    expect(laptop.records.single.title, 'Co-op Bank');

    // A used QR cannot be approved again.
    await expectLater(phone.inspectLink(link.qr), throwsA(anything));
  }, skip: skip, timeout: const Timeout(Duration(minutes: 2)));
}
