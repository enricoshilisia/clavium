// Breach check with a fake Have I Been Pwned: only 5-character prefixes are
// requested, and matching happens on the device.
import 'dart:io';

import 'package:clavium/core/api_client.dart';
import 'package:clavium/core/app_state.dart';
import 'package:clavium/core/blob_store_io.dart';
import 'package:clavium/core/storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

import 'app_flow_test.dart' show FakeBiometrics;

void main() {
  test('weak password is flagged, strong one is not, only prefixes are sent', () async {
    final asked = <String>[];
    final client = MockClient((req) async {
      expect(req.url.host, 'api.pwnedpasswords.com');
      expect(req.headers['Add-Padding'], 'true');
      final prefix = req.url.pathSegments.last;
      asked.add(prefix);
      // SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
      final body = prefix == '5BAA6'
          ? 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:10434004\r\n'
          : 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2\r\n';
      return http.Response(body, 200);
    });
    final dir = Directory.systemTemp.createTempSync('clavium_breach');
    addTearDown(() => dir.deleteSync(recursive: true));
    final app = AppState(
      storage: DeviceStorage(secure: MemoryStore(), blobs: DirectoryBlobStore(() async => dir)),
      api: ApiClient(client: client),
      biometrics: FakeBiometrics(),
      liveSync: false,
    );
    await app.init();
    await app.createVault('correct horse battery staple');
    final weak = await app.addRecord({'title': 'Old router', 'password': 'password'});
    await app.addRecord({'title': 'Bank', 'password': 'uY7#kq!2Lp9@vZ4m'});
    await app.checkBreaches();
    expect(asked.length, 2);
    expect(asked.every((p) => p.length == 5), isTrue);
    expect(app.breachHits.map((h) => h['title']), ['Old router']);
    expect(app.breachFor(weak.id)!['count'], 10434004);
    expect((app.health()['breached'] as List).length, 1);
    app.lock();
    expect(app.breachHits, isEmpty);
  });
}
