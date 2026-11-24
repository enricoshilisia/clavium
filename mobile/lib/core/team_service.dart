// Team vaults on the phone and web app. HTTP happens here; every key and
// every bit of encryption happens in the Rust core (team_* commands), the
// same code the desktop app runs.

import 'models.dart';
import 'api_client.dart';
import 'native.dart';
import 'storage.dart';

class TeamInfo {
  TeamInfo(this.raw);
  final Map<String, dynamic> raw;
  String get id => raw['id'] as String;
  String get name => raw['name'] as String;
  String get orgName => (raw['organization'] as Map)['name'] as String;
  String? get role => raw['role'] as String?;
  bool get canManage => raw['can_manage'] == true;
  int get keyVersion => raw['key_version'] as int;
  bool get needsRotation => raw['needs_rotation'] == true;
  Object? get wrappedKey => raw['wrapped_key'];
  bool get hasKey => wrappedKey != null && role != null;
  bool get canWrite => hasKey && (role == 'manager' || role == 'editor');
}

const roleLabels = {'manager': 'Manager', 'editor': 'Can edit', 'viewer': 'Can view'};

class TeamService {
  TeamService(this.api, this.storage, this.persistPersonal);
  final ApiClient api;
  final DeviceStorage storage;

  /// Saves the personal vault when a team command changed it (pinned keys).
  final Future<void> Function(dynamic result) persistPersonal;

  String? _readyFor;
  String? accountId;

  /// Warnings: a member's key changed and needs checking by a person.
  final List<Map<String, String>> keyWarnings = [];

  String _cacheKey(String id) => 'team_cache_$id';

  Future<dynamic> _core(String cmd, Map<String, dynamic> args) async {
    final out = Core.call(cmd, args);
    if (out is Map) {
      final cache = out['cache'];
      final id = (args['team_id'] ?? out['team_id']) as String?;
      if (cache is String && id != null) await storage.blobs.write(_cacheKey(id), cache);
      if (out['saved'] != null) await persistPersonal(out);
    }
    return out;
  }

  void forget() {
    _readyFor = null;
    accountId = null;
  }

  Future<void> ensureKey(AccountSession s) async {
    if (_readyFor == s.token && accountId != null) return;
    final me = await api.call(s, 'GET', '/api/accounts/me/') as Map<String, dynamic>;
    accountId = me['id'] as String;
    Object? stored;
    try {
      stored = await api.call(s, 'GET', '/api/teams/key/');
    } on ApiException catch (e) {
      if (e.status != 404) rethrow;
    }
    final out = await _core('team_account_key', {'account_id': accountId, 'stored': stored}) as Map;
    if (out['status'] == 'created') await api.call(s, 'PUT', '/api/teams/key/', body: out['stored']);
    _readyFor = s.token;
  }

  /// Every team vault this person can see; opens those they hold a key for.
  Future<List<TeamInfo>> list(AccountSession s) async {
    await ensureKey(s);
    final out = await api.call(s, 'GET', '/api/teams/') as Map<String, dynamic>;
    final teams = (out['teams'] as List).map((t) => TeamInfo(t as Map<String, dynamic>)).toList();
    for (final t in teams) {
      if (!t.hasKey) continue;
      await _core('team_open', {
        'team_id': t.id,
        'key_version': t.keyVersion,
        'wrapped_key': t.wrappedKey,
        'role': t.role,
        'cache': await storage.blobs.read(_cacheKey(t.id)),
      });
    }
    return teams;
  }

  List<VaultRecord> records(String teamId, {String query = ''}) =>
      (Core.call('team_list', {'team_id': teamId, 'query': query}) as List).map((r) => VaultRecord(r as Map<String, dynamic>)).toList();

  VaultRecord? get(String teamId, String id) {
    try {
      return VaultRecord(Core.call('team_get', {'team_id': teamId, 'id': id}) as Map<String, dynamic>);
    } on CoreException {
      return null;
    }
  }

  Future<VaultRecord> add(String teamId, Map<String, dynamic> input) async =>
      VaultRecord((await _core('team_add', {'team_id': teamId, 'record': input}) as Map)['record'] as Map<String, dynamic>);

  Future<VaultRecord> update(String teamId, String id, Map<String, dynamic> input) async =>
      VaultRecord((await _core('team_update', {'team_id': teamId, 'id': id, 'record': input}) as Map)['record'] as Map<String, dynamic>);

  Future<void> delete(String teamId, String id) => _core('team_delete', {'team_id': teamId, 'id': id});

  /// Push local changes, pull everyone else's. Returns how many arrived.
  Future<int> sync(AccountSession s, TeamInfo t) async {
    if (!t.hasKey) return 0;
    final st = Core.call('team_sync_state', {'team_id': t.id}) as Map;
    final pending = (st['pending'] as List);
    if (pending.isNotEmpty) {
      try {
        final res = await api.call(s, 'POST', '/api/teams/${t.id}/items/', body: {'key_version': st['key_version'], 'items': pending}) as Map;
        final byId = {for (final i in pending) (i as Map)['id']: i};
        final accepted = [
          for (final r in res['results'] as List)
            if (r['status'] == 'ok') {'item': byId[r['id']], 'revision': r['revision']}
        ];
        if (accepted.isNotEmpty) await _core('team_mark_pushed', {'team_id': t.id, 'accepted': accepted});
      } on ApiException catch (e) {
        if (e.status != 409) rethrow; // key replaced meanwhile; next list fetches it
      }
    }
    var cursor = st['cursor'] as int;
    var arrived = 0;
    while (true) {
      final page = await api.call(s, 'GET', '/api/teams/${t.id}/items/?since=$cursor') as Map;
      if (page['key_version'] != st['key_version']) break;
      final items = page['items'] as List;
      if (items.isNotEmpty || page['cursor'] != cursor) {
        await _core('team_apply_pull', {'team_id': t.id, 'items': items, 'cursor': page['cursor']});
        arrived += items.length;
      }
      cursor = page['cursor'] as int;
      if (page['has_more'] != true) break;
    }
    if (t.role == 'manager') await _managerDuties(s, t);
    return arrived;
  }

  Future<Object?> _wrapFor(TeamInfo t, Map m, {bool forRotation = false}) async {
    try {
      final w = await _core('team_wrap_for', {
        'team_id': t.id,
        'account_id': m['account_id'],
        'public_key': m['public_key'],
        'for_rotation': forRotation,
      }) as Map;
      return w['wrapped_key'];
    } on CoreException catch (e) {
      if (!e.message.startsWith('key_changed')) rethrow;
      final fp = Core.call('team_fingerprint', {'public_key': m['public_key']}) as String;
      if (!keyWarnings.any((k) => k['account_id'] == m['account_id'] && k['public_key'] == m['public_key'])) {
        keyWarnings.add({'team': t.name, 'email': m['email'] as String, 'account_id': m['account_id'] as String, 'public_key': m['public_key'] as String, 'fingerprint': fp});
      }
      return null;
    }
  }

  /// Seal keys for pending people; replace the key after someone left.
  Future<void> _managerDuties(AccountSession s, TeamInfo t) async {
    if (t.needsRotation) return rotate(s, t);
    final view = await members(s, t.id);
    final grants = [];
    for (final m in view['members'] as List) {
      if (m['has_key'] == true || m['public_key'] == null) continue;
      final w = await _wrapFor(t, m as Map);
      if (w != null) grants.add({'account_id': m['account_id'], 'public_key': m['public_key'], 'wrapped_key': w});
    }
    if (grants.isNotEmpty) {
      await api.call(s, 'POST', '/api/teams/${t.id}/grants/', body: {'key_version': t.keyVersion, 'grants': grants});
    }
  }

  Future<void> rotate(AccountSession s, TeamInfo t) async {
    final prep = Core.call('team_rotate_prepare', {'team_id': t.id}) as Map;
    try {
      final view = await members(s, t.id);
      final grants = [];
      for (final m in view['members'] as List) {
        if (m['public_key'] == null) continue;
        final w = await _wrapFor(t, m as Map, forRotation: true);
        if (w != null) grants.add({'account_id': m['account_id'], 'public_key': m['public_key'], 'wrapped_key': w});
      }
      await api.call(s, 'POST', '/api/teams/${t.id}/rotate/', body: {'key_version': prep['key_version'], 'items': prep['items'], 'grants': grants});
    } catch (_) {
      Core.call('team_rotate_cancel', {'team_id': t.id});
      rethrow;
    }
    await _core('team_rotate_commit', {'team_id': t.id});
    var cursor = 0;
    while (true) {
      final page = await api.call(s, 'GET', '/api/teams/${t.id}/items/?since=$cursor') as Map;
      await _core('team_apply_pull', {'team_id': t.id, 'items': page['items'], 'cursor': page['cursor']});
      cursor = page['cursor'] as int;
      if (page['has_more'] != true) break;
    }
  }

  /// Create a team vault in an organization this person administers.
  Future<TeamInfo> create(AccountSession s, String organizationId, String name) async {
    await ensureKey(s);
    final made = await _core('team_create', {}) as Map;
    try {
      return TeamInfo(await api.call(s, 'POST', '/api/teams/', body: {
        'id': made['team_id'],
        'organization_id': organizationId,
        'name': name,
        'wrapped_key': made['wrapped_key'],
      }) as Map<String, dynamic>);
    } catch (_) {
      Core.call('team_close', {'team_id': made['team_id']});
      await storage.blobs.delete(_cacheKey(made['team_id'] as String));
      rethrow;
    }
  }

  /// Add someone; seal the key for them at once if they have a key pair.
  Future<void> addMember(AccountSession s, TeamInfo t, Map person, String role) async {
    final body = <String, dynamic>{'account_id': person['account_id'], 'role': role};
    if (person['public_key'] != null && t.hasKey) {
      final w = await _wrapFor(t, person);
      if (w != null) body.addAll({'public_key': person['public_key'], 'wrapped_key': w, 'key_version': t.keyVersion});
    }
    await api.call(s, 'POST', '/api/teams/${t.id}/members/', body: body);
  }

  Future<Map<String, dynamic>> members(AccountSession s, String teamId) async =>
      await api.call(s, 'GET', '/api/teams/$teamId/members/') as Map<String, dynamic>;

  String fingerprint(String publicKey) => Core.call('team_fingerprint', {'public_key': publicKey}) as String;

  Future<void> leave(AccountSession s, String teamId) async {
    await api.call(s, 'DELETE', '/api/teams/$teamId/members/$accountId/');
    Core.call('team_close', {'team_id': teamId});
    await storage.blobs.delete(_cacheKey(teamId));
  }
}
