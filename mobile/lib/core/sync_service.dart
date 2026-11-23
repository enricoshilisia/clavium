// Per-record sync against the control plane. Dart moves ciphertext;
// the Rust core decrypts, merges and decides what to push.
import 'dart:convert';

import 'api_client.dart';
import 'native.dart';
import 'storage.dart';

class SyncException implements Exception {
  SyncException(this.message);
  final String message;
  @override
  String toString() => message;
}

class SyncOutcome {
  SyncOutcome({this.pulled = 0, this.pushed = 0, this.conflicts = 0, this.notice});
  int pulled;
  int pushed;
  int conflicts;

  /// Something the person should know but that did not stop the sync.
  String? notice;
}

/// JSON with object keys sorted, so a header stored in Postgres (which
/// reorders keys) compares equal to the one the core produced.
String canonicalJson(Object? v) {
  Object? norm(Object? x) {
    if (x is Map) {
      final keys = x.keys.map((k) => k.toString()).toList()..sort();
      return {for (final k in keys) k: norm(x[k])};
    }
    if (x is List) return x.map(norm).toList();
    return x;
  }

  return jsonEncode(norm(v));
}

class SyncService {
  SyncService(this.api, this.storage);
  final ApiClient api;
  final DeviceStorage storage;

  Future<void> _persist(dynamic result) async {
    final saved = (result as Map)['saved'] as String?;
    if (saved != null) await storage.writeVault(saved);
  }

  /// Pull every change since the vault's cursor. Returns records changed.
  Future<int> pull(AccountSession s, {bool wait = false}) async {
    var changed = 0;
    while (true) {
      final cursor = (Core.call('sync_state') as Map)['cursor'] as int;
      final page = await api.pull(s, cursor, wait: wait);
      wait = false;
      final items = page['items'] as List;
      final newCursor = page['cursor'] as int;
      if (items.isEmpty && newCursor == cursor) return changed;
      final out = Core.call('sync_apply_pull', {'items': items, 'cursor': newCursor}) as Map;
      await _persist(out);
      final report = out['report'] as Map;
      changed += (report['added'] as int) + (report['updated'] as int) + (report['deleted'] as int) + (report['conflicts'] as int);
      if (page['has_more'] != true) return changed;
    }
  }

  Future<String?> _syncKeyring(AccountSession s, Map state) async {
    final prefs = await storage.prefs();
    final knownRev = prefs['keyring_revision'] as int?;
    final vaultId = state['vault_id'] as String;
    final local = Map<String, dynamic>.from(state['header'] as Map);
    final remote = await api.getKeyring(s);
    if (remote == null) {
      final r = await api.putKeyring(s, vaultId, local, 0);
      await storage.setPref('keyring_revision', r['revision']);
      return null;
    }
    if (remote['vault_id'] != vaultId) {
      throw SyncException(
        'This account already syncs a different vault. Restore that vault on this device, '
        'or reset sync from a device that holds the vault you want to keep.',
      );
    }
    if (canonicalJson(remote['header']) == canonicalJson(local)) {
      await storage.setPref('keyring_revision', remote['revision']);
      return null;
    }
    if (knownRev == remote['revision']) {
      // We changed our unlock methods (password, biometrics, recovery key)
      // since the last sync: publish them so new devices see them.
      try {
        final r = await api.putKeyring(s, vaultId, local, knownRev!);
        await storage.setPref('keyring_revision', r['revision']);
        return null;
      } on ApiException catch (e) {
        if (e.status != 409) rethrow;
      }
    }
    // Someone changed unlock methods on another device. Never adopt a
    // header from the server into the local file: this device keeps
    // opening with what it had.
    return 'Your master password or unlock methods were changed on another device. '
        'This device still unlocks the old way until you sign out and restore again.';
  }

  Future<SyncOutcome> syncNow(AccountSession s) async {
    final outcome = SyncOutcome();
    final state = Core.call('sync_state') as Map;
    outcome.notice = await _syncKeyring(s, state);

    outcome.pulled += await pull(s);
    for (var attempt = 0; attempt < 3; attempt++) {
      final st = Core.call('sync_state') as Map;
      final pending = (st['pending'] as List).cast<Map<String, dynamic>>();
      if (pending.isEmpty) break;
      var hadConflict = false;
      for (var i = 0; i < pending.length; i += 500) {
        final chunk = pending.sublist(i, i + 500 > pending.length ? pending.length : i + 500);
        final byId = {for (final p in chunk) p['id'] as String: p};
        final res = await api.push(s, st['vault_id'] as String, chunk);
        final accepted = <Map<String, dynamic>>[];
        for (final r in (res['results'] as List).cast<Map<String, dynamic>>()) {
          if (r['status'] == 'accepted') {
            accepted.add({'item': byId[r['id']], 'revision': r['revision']});
          } else if (r['status'] == 'conflict') {
            hadConflict = true;
          }
        }
        if (accepted.isNotEmpty) {
          await _persist(Core.call('sync_mark_pushed', {'accepted': accepted}));
          outcome.pushed += accepted.length;
        }
      }
      if (!hadConflict) break;
      outcome.conflicts++;
      outcome.pulled += await pull(s);
    }
    return outcome;
  }
}
