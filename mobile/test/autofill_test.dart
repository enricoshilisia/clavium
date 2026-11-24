// The "Fill from Clavium" screen with the real core and a fake Android side.
import 'dart:io';

import 'package:clavium/core/api_client.dart';
import 'package:clavium/core/app_state.dart';
import 'package:clavium/core/blob_store_io.dart';
import 'package:clavium/core/native.dart';
import 'package:clavium/core/storage.dart';
import 'package:clavium/ui/autofill_screen.dart';
import 'package:clavium/ui/theme.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

import 'app_flow_test.dart' show FakeBiometrics;

const master = 'correct horse battery staple';
const channel = MethodChannel('clavium/autofill-test');

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late Directory dir;
  late DeviceStorage storage;

  AppState newApp() => AppState(storage: storage, api: ApiClient(), biometrics: FakeBiometrics(), liveSync: false);

  setUp(() async {
    dir = Directory.systemTemp.createTempSync('clavium_autofill');
    storage = DeviceStorage(secure: MemoryStore(), blobs: DirectoryBlobStore(() async => dir));
    final a = newApp();
    await a.init();
    await a.createVault(master);
    await a.addRecord({'title': 'Equity', 'username': 'jane', 'password': 'Eq-pass-1', 'url': 'https://equitybank.co.ke'});
    await a.addRecord({'title': 'KCB', 'username': 'jane.k', 'password': 'Kc-pass-2', 'url': 'https://kcbgroup.com'});
    a.lock();
  });
  tearDown(() => dir.deleteSync(recursive: true));

  Future<List<MethodCall>> run(WidgetTester tester, Map<String, Object?> request, Future<void> Function() steps) async {
    final calls = <MethodCall>[];
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return call.method == 'request' ? request : null;
    });
    await tester.pumpWidget(MaterialApp(theme: claviumTheme(), home: AutofillScreen(app: newApp(), channel: channel)));
    // Start-up reads the vault file for real: give it real time.
    for (var i = 0; i < 40 && find.byType(CircularProgressIndicator).evaluate().isNotEmpty; i++) {
      await tester.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 100)));
      await tester.pump();
    }
    await tester.pumpAndSettle();
    await steps();
    return calls;
  }

  Future<void> unlock(WidgetTester tester) async {
    await tester.enterText(find.byKey(const Key('autofill-master')), master);
    await tester.runAsync(() async {
      await tester.tap(find.byKey(const Key('autofill-unlock')));
      await Future<void>.delayed(const Duration(seconds: 2));
    });
    await tester.pumpAndSettle();
  }

  testWidgets('a website login is offered first and filled; the vault is locked again', (tester) async {
    final calls = await run(tester, {'webDomain': 'online.equitybank.co.ke', 'package': 'com.android.chrome'}, () async {
      await unlock(tester);
      expect(find.text('FOR THIS SITE'), findsOneWidget);
      await tester.runAsync(() async {
        await tester.tap(find.text('Equity').first);
        await Future<void>.delayed(const Duration(milliseconds: 300));
      });
      await tester.pumpAndSettle();
    });
    final fill = calls.firstWhere((c) => c.method == 'fill');
    expect(fill.arguments, {'username': 'jane', 'password': 'Eq-pass-1'});
    expect(Core.call('is_unlocked'), isFalse, reason: 'this screen unlocked it, so it locks it again');
  });

  testWidgets('a fake site is refused', (tester) async {
    final calls = await run(tester, {'webDomain': 'equity-bank-login.top'}, () async {
      await unlock(tester);
      expect(find.textContaining('will not fill'), findsOneWidget);
      expect(find.text('Equity'), findsNothing);
    });
    expect(calls.where((c) => c.method == 'fill'), isEmpty);
    Core.call('lock');
  });

  testWidgets('an app is suggested by name and remembered after the first fill', (tester) async {
    await run(tester, {'package': 'com.kcb.mobilebanking.android'}, () async {
      await unlock(tester);
      expect(find.text('MIGHT BE FOR THIS APP'), findsOneWidget);
      await tester.runAsync(() async {
        await tester.tap(find.text('KCB').first);
        await Future<void>.delayed(const Duration(milliseconds: 500));
      });
      await tester.pumpAndSettle();
    });
    // Real file access must run outside the test's fake clock.
    final c = await tester.runAsync(() async {
      final again = newApp();
      await again.init();
      await again.unlock(master);
      final out = Core.call('autofill_candidates', {'package': 'com.kcb.mobilebanking.android'}) as Map;
      again.lock();
      return out;
    });
    expect(((c!['matches'] as List).single as Map)['title'], 'KCB');
  });
}
