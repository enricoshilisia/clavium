// Drives the real screens over the real Rust core.
import 'dart:io';

import 'package:clavium/core/api_client.dart';
import 'package:clavium/core/app_state.dart';
import 'package:clavium/core/blob_store_io.dart';
import 'package:clavium/core/storage.dart';
import 'package:clavium/main.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

import 'app_flow_test.dart' show FakeBiometrics;
import 'fake_server.dart';

Future<void> settle(WidgetTester t) async {
  for (var i = 0; i < 5; i++) {
    await t.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 60)));
    await t.pump(const Duration(milliseconds: 200));
  }
}

void main() {
  testWidgets('onboarding -> create -> add a bank login -> categorised and searchable', (t) async {
    await t.binding.setSurfaceSize(const Size(420, 900));
    final tmp = Directory.systemTemp.createTempSync('clavium_ui');
    addTearDown(() => tmp.deleteSync(recursive: true));
    final app = AppState(
      storage: DeviceStorage(secure: MemoryStore(), blobs: DirectoryBlobStore(() async => tmp)),
      api: ApiClient(client: FakeControlPlane().client),
      biometrics: FakeBiometrics(),
      liveSync: false,
    );
    await t.runAsync(app.init);
    await t.pumpWidget(ClaviumApp(app: app));
    await settle(t);

    expect(find.text('Create a new vault'), findsOneWidget);
    await t.tap(find.byKey(const Key('create-vault')));
    await settle(t);
    await t.enterText(find.byKey(const Key('master-password')), 'correct horse battery staple');
    await t.enterText(find.byKey(const Key('master-password-confirm')), 'correct horse battery staple');
    await t.tap(find.byKey(const Key('create-submit')));
    await t.runAsync(() => Future<void>.delayed(const Duration(seconds: 2)));
    await settle(t);
    expect(find.text('Vault'), findsWidgets);
    expect(find.textContaining('Nothing here yet'), findsOneWidget);

    await t.tap(find.byKey(const Key('add-record')));
    await settle(t);
    await t.tap(find.text('Login'));
    await settle(t);
    await t.enterText(find.byKey(const Key('field-title')), 'Equity Bank');
    await t.enterText(find.byKey(const Key('field-username')), 'enrico');
    await t.enterText(find.byKey(const Key('field-url')), 'equitybank.co.ke');
    await t.tap(find.byKey(const Key('save-record')));
    await settle(t);
    await settle(t); // let the editor's exit animation finish

    expect(find.text('Equity Bank'), findsOneWidget);
    expect(find.text('Banking & mobile money · 1'), findsOneWidget);

    await t.enterText(find.byKey(const Key('search')), 'zzz');
    await settle(t);
    expect(find.text('No matches.'), findsOneWidget);
    await t.enterText(find.byKey(const Key('search')), 'equity');
    await settle(t);
    expect(find.text('Equity Bank'), findsOneWidget);

    // Lock from the app bar.
    await t.tap(find.byTooltip('Lock'));
    await settle(t);
    expect(find.text('Vault locked'), findsOneWidget);
  });
}
