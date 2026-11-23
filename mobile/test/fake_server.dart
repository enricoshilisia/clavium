// An in-memory control plane with the same accept/refuse rules as the
// Django sync app, for tests that must not touch a network.
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

class FakeControlPlane {
  final accounts = <String, String>{}; // email -> password
  final tokens = <String, String>{}; // token -> email
  final keyrings = <String, Map<String, dynamic>>{}; // email -> {vault_id, header, revision}
  final items = <String, Map<String, Map<String, dynamic>>>{}; // email -> id -> item
  final counters = <String, int>{};
  int _n = 0;
  bool offline = false;

  http.Response _json(Object body, [int status = 200]) =>
      http.Response(jsonEncode(body), status, headers: {'content-type': 'application/json'});

  MockClient get client => MockClient((req) async {
        if (offline) throw const SocketException('offline');
        final path = req.url.path;
        final body = req.body.isEmpty ? <String, dynamic>{} : jsonDecode(req.body) as Map<String, dynamic>;
        if (path == '/api/accounts/register/') {
          if (accounts.containsKey(body['email'])) return _json({'detail': 'exists'}, 400);
          accounts[body['email'] as String] = body['password'] as String;
          return _json({'email': body['email']}, 201);
        }
        if (path == '/api/accounts/devices/register/') {
          if (accounts[body['email']] != body['password']) return _json({'detail': 'invalid credentials'}, 400);
          final t = 'tok${_n++}';
          tokens[t] = body['email'] as String;
          return _json({'token': t, 'device_id': 'dev$_n', 'account': {'email': body['email']}});
        }
        final auth = req.headers['Authorization']?.replaceFirst('Bearer ', '');
        final email = tokens[auth];
        if (email == null) return _json({'detail': 'unauthorized'}, 401);
        if (path.endsWith('/revoke/')) {
          tokens.remove(auth);
          return http.Response('', 204);
        }
        if (path == '/api/sync/keyring/') {
          final kr = keyrings[email];
          if (req.method == 'GET') return kr == null ? _json({'detail': 'none'}, 404) : _json({...kr, 'counter': counters[email] ?? 0});
          if (kr == null) {
            if (body['base_revision'] != 0) return _json({'detail': 'conflict'}, 409);
            keyrings[email] = {'vault_id': body['vault_id'], 'header': body['header'], 'revision': 1};
          } else {
            if (kr['vault_id'] != body['vault_id'] || kr['revision'] != body['base_revision']) {
              return _json({'detail': 'conflict', 'current': kr}, 409);
            }
            kr['header'] = body['header'];
            kr['revision'] = (kr['revision'] as int) + 1;
          }
          return _json(keyrings[email]!);
        }
        if (path == '/api/sync/items/') {
          final store = items.putIfAbsent(email, () => {});
          if (req.method == 'GET') {
            final since = int.parse(req.url.queryParameters['since'] ?? '0');
            final list = store.values.where((i) => (i['revision'] as int) > since).toList()
              ..sort((a, b) => (a['revision'] as int).compareTo(b['revision'] as int));
            final c = counters[email] ?? 0;
            return _json({'items': list, 'cursor': c > since ? c : since, 'has_more': false});
          }
          final results = [];
          for (final it in (body['items'] as List).cast<Map<String, dynamic>>()) {
            final current = (store[it['id']]?['revision'] as int?) ?? 0;
            if (current != it['revision']) {
              results.add({'id': it['id'], 'status': 'conflict', 'revision': current});
              continue;
            }
            final rev = (counters[email] ?? 0) + 1;
            counters[email] = rev;
            store[it['id'] as String] = {...it, 'revision': rev};
            results.add({'id': it['id'], 'status': 'accepted', 'revision': rev});
          }
          return _json({'results': results, 'counter': counters[email] ?? 0});
        }
        return _json({'detail': 'not found'}, 404);
      });
}
