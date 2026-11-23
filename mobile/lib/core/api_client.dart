// The Clavium control plane. Everything sent here is either account
// credentials (the account password, never the master password) or
// ciphertext the server cannot read.
import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

const defaultServer = 'https://clavium-api.172-169-233-189.sslip.io';

class ApiException implements Exception {
  ApiException(this.status, this.message, [this.body]);
  final int status;
  final String message;
  final Map<String, dynamic>? body;
  @override
  String toString() => message;
}

class AccountSession {
  AccountSession({required this.server, required this.token, required this.email, required this.deviceId});
  final String server;
  final String token;
  final String email;
  final String deviceId;
}

class ApiClient {
  ApiClient({http.Client? client}) : _http = client ?? http.Client();
  final http.Client _http;

  Future<dynamic> _send(
    String method,
    String server,
    String path, {
    String? token,
    Object? body,
    Duration timeout = const Duration(seconds: 20),
  }) async {
    final uri = Uri.parse('$server$path');
    final headers = {
      'Content-Type': 'application/json',
      if (token != null) 'Authorization': 'Bearer $token',
    };
    final req = http.Request(method, uri)..headers.addAll(headers);
    if (body != null) req.body = jsonEncode(body);
    http.Response res;
    try {
      res = await http.Response.fromStream(await _http.send(req).timeout(timeout));
    } on TimeoutException {
      throw ApiException(0, 'The server did not answer in time.');
    } catch (_) {
      throw ApiException(0, 'Could not reach the server. Check your connection.');
    }
    Map<String, dynamic>? decoded;
    if (res.body.isNotEmpty) {
      try {
        final d = jsonDecode(res.body);
        if (d is Map<String, dynamic>) decoded = d;
        if (res.statusCode < 300) return d;
      } catch (_) {}
    }
    if (res.statusCode >= 300) {
      String msg = decoded?['detail']?.toString() ?? 'Request failed (HTTP ${res.statusCode})';
      if (res.statusCode == 429) msg = 'Too many attempts. Wait a minute and try again.';
      if (res.statusCode == 401) msg = 'This device was signed out. Sign in again.';
      if (decoded != null && decoded['detail'] == null && res.statusCode == 400) {
        msg = decoded.values.expand((v) => v is List ? v : [v]).join(' ');
      }
      throw ApiException(res.statusCode, msg, decoded);
    }
    return null;
  }

  Future<void> register(String server, String email, String password) =>
      _send('POST', server, '/api/accounts/register/', body: {'email': email, 'password': password});

  Future<AccountSession> signIn(String server, String email, String password,
      {required String clientDeviceId, required String deviceName, required String platform}) async {
    final d = await _send('POST', server, '/api/accounts/devices/register/', body: {
      'email': email,
      'password': password,
      'client_device_id': clientDeviceId,
      'name': deviceName,
      'platform': platform,
    }) as Map<String, dynamic>;
    return AccountSession(
      server: server,
      token: d['token'] as String,
      email: (d['account'] as Map)['email'] as String,
      deviceId: d['device_id'].toString(),
    );
  }

  Future<void> signOut(AccountSession s) =>
      _send('POST', s.server, '/api/accounts/devices/${s.deviceId}/revoke/', token: s.token);

  Future<Map<String, dynamic>?> getKeyring(AccountSession s) async {
    try {
      return await _send('GET', s.server, '/api/sync/keyring/', token: s.token) as Map<String, dynamic>;
    } on ApiException catch (e) {
      if (e.status == 404) return null;
      rethrow;
    }
  }

  Future<Map<String, dynamic>> putKeyring(AccountSession s, String vaultId, Map<String, dynamic> header, int baseRevision) async =>
      await _send('PUT', s.server, '/api/sync/keyring/',
          token: s.token,
          body: {'vault_id': vaultId, 'header': header, 'base_revision': baseRevision}) as Map<String, dynamic>;

  Future<Map<String, dynamic>> pull(AccountSession s, int since, {bool wait = false}) async =>
      await _send('GET', s.server, '/api/sync/items/?since=$since${wait ? '&wait=1' : ''}',
          token: s.token, timeout: Duration(seconds: wait ? 40 : 20)) as Map<String, dynamic>;

  Future<Map<String, dynamic>> push(AccountSession s, String vaultId, List<dynamic> items) async =>
      await _send('POST', s.server, '/api/sync/items/',
          token: s.token, body: {'vault_id': vaultId, 'items': items}) as Map<String, dynamic>;

  Future<void> resetSync(AccountSession s, String accountPassword) =>
      _send('POST', s.server, '/api/sync/reset/', token: s.token, body: {'password': accountPassword});
}
