// App-wide state: lock status, the visible records, account and sync.
import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:flutter/foundation.dart';

import 'api_client.dart';
import 'models.dart';
import 'native.dart';
import 'storage.dart';
import 'sync_service.dart';

enum Phase { loading, onboarding, locked, unlocked }

/// Biometric prompt, abstracted so tests do not need a fingerprint.
abstract class BiometricPrompt {
  Future<bool> available();
  Future<bool> authenticate(String reason);
}

class AppState extends ChangeNotifier {
  AppState({required this.storage, required this.api, required this.biometrics, this.liveSync = true})
      : sync = SyncService(api, storage);

  final DeviceStorage storage;
  final ApiClient api;
  final BiometricPrompt biometrics;
  final SyncService sync;
  final bool liveSync;

  Phase phase = Phase.loading;
  List<VaultRecord> records = [];
  List<CategoryInfo> categories = [];
  List<String> folders = [];

  String query = '';
  String? categoryFilter;
  String? folderFilter;
  bool favoritesOnly = false;

  AccountSession? session;
  bool syncing = false;
  DateTime? lastSync;
  String? syncError;
  String? syncNotice;

  int autoLockSeconds = 60;
  bool biometricEnabled = false;
  DateTime? _backgroundedAt;
  bool _liveLoopRunning = false;
  Timer? _syncDebounce;

  // ---------- startup ----------

  Future<void> init() async {
    session = await storage.loadSession();
    final prefs = await storage.prefs();
    autoLockSeconds = (prefs['auto_lock_seconds'] as int?) ?? 60;
    biometricEnabled = await storage.secure.read('biometric_secret') != null;
    phase = await storage.vaultExists() ? Phase.locked : Phase.onboarding;
    notifyListeners();
  }

  Future<void> _persist(dynamic result) async {
    final saved = (result as Map?)?['saved'] as String?;
    if (saved != null) await storage.writeVault(saved);
  }

  // ---------- lock / unlock ----------

  Future<void> createVault(String masterPassword) async {
    final res = await Core.run('create', {'master_password': masterPassword});
    await _persist(res);
    await _afterUnlock();
  }

  Future<void> unlock(String masterPassword) async {
    final file = await storage.readVault();
    final res = await Core.run('open', {'file': file, 'master_password': masterPassword});
    // A v1 file opened here is upgraded; write the v3 form back at once.
    await _persist(res);
    await _afterUnlock();
  }

  Future<void> unlockWithRecoveryKey(String key) async {
    final file = await storage.readVault();
    await _persist(await Core.run('open_with_recovery_key', {'file': file, 'recovery_key': key}));
    await _afterUnlock();
  }

  Future<bool> unlockWithBiometrics() async {
    if (!biometricEnabled) return false;
    if (!await biometrics.authenticate('Unlock your Clavium vault')) return false;
    final secret = await storage.secure.read('biometric_secret');
    if (secret == null) return false;
    final file = await storage.readVault();
    await _persist(await Core.run('open_with_prf', {
      'file': file,
      'credential_id': await _biometricCredentialId(),
      'prf_output': secret,
    }));
    await _afterUnlock();
    return true;
  }

  Future<void> _afterUnlock() async {
    phase = Phase.unlocked;
    refresh();
    if (session != null) {
      unawaited(syncNow());
      if (liveSync) unawaited(_liveLoop());
    }
  }

  void lock() {
    _syncDebounce?.cancel();
    Core.call('lock');
    records = [];
    categories = [];
    folders = [];
    phase = Phase.locked;
    notifyListeners();
  }

  /// Called from the app lifecycle observer.
  void onBackgrounded() => _backgroundedAt = DateTime.now();

  void onResumed() {
    final at = _backgroundedAt;
    _backgroundedAt = null;
    if (phase == Phase.unlocked && at != null && autoLockSeconds >= 0 &&
        DateTime.now().difference(at).inSeconds >= autoLockSeconds) {
      lock();
    } else if (phase == Phase.unlocked && session != null) {
      unawaited(syncNow());
    }
  }

  Future<void> setAutoLock(int seconds) async {
    autoLockSeconds = seconds;
    await storage.setPref('auto_lock_seconds', seconds);
    notifyListeners();
  }

  // ---------- records ----------

  void refresh() {
    if (phase != Phase.unlocked) return;
    final list = Core.call('list', {
      'query': query,
      'category': categoryFilter,
      'folder': folderFilter,
      'favorites_only': favoritesOnly,
    }) as List;
    records = list.map((r) => VaultRecord(r as Map<String, dynamic>)).toList();
    categories = (Core.call('categories') as List)
        .map((c) => CategoryInfo(c['slug'] as String, c['label'] as String, c['count'] as int))
        .toList();
    folders = (Core.call('folders') as List).cast<String>();
    notifyListeners();
  }

  void setQuery(String q) {
    query = q;
    refresh();
  }

  void setCategoryFilter(String? c) {
    categoryFilter = c;
    refresh();
  }

  void setFolderFilter(String? f) {
    folderFilter = f;
    refresh();
  }

  void setFavoritesOnly(bool v) {
    favoritesOnly = v;
    refresh();
  }

  List<VaultRecord> totpRecords() => (Core.call('list', {'with_totp_only': true}) as List)
      .map((r) => VaultRecord(r as Map<String, dynamic>))
      .toList();

  VaultRecord? get(String id) {
    try {
      return VaultRecord(Core.call('get', {'id': id}) as Map<String, dynamic>);
    } on CoreException {
      return null;
    }
  }

  Future<VaultRecord> addRecord(Map<String, dynamic> input) async {
    final res = Core.call('add', {'record': input}) as Map;
    await _persist(res);
    _changed();
    return VaultRecord(res['record'] as Map<String, dynamic>);
  }

  Future<VaultRecord> updateRecord(String id, Map<String, dynamic> input) async {
    final res = Core.call('update', {'id': id, 'record': input}) as Map;
    await _persist(res);
    _changed();
    return VaultRecord(res['record'] as Map<String, dynamic>);
  }

  Future<void> toggleFavorite(String id) async {
    await _persist(Core.call('toggle_favorite', {'id': id}));
    _changed();
  }

  Future<void> deleteRecord(String id) async {
    await _persist(Core.call('delete', {'id': id}));
    _changed();
  }

  Future<void> setCategory(String id, String? category, {bool learn = true}) async {
    await _persist(Core.call('set_category', {'id': id, 'category': category, 'learn': learn}));
    _changed();
  }

  Future<void> createFolder(String name) async {
    await _persist(Core.call('create_folder', {'name': name}));
    _changed();
  }

  void _changed() {
    refresh();
    if (session != null) {
      _syncDebounce?.cancel();
      _syncDebounce = Timer(const Duration(seconds: 2), () => unawaited(syncNow()));
    }
  }

  Map<String, dynamic> health() => Map<String, dynamic>.from(Core.call('health') as Map);

  // ---------- account ----------

  String get _platform => kIsWeb ? 'web' : defaultTargetPlatform.name;
  String get _deviceName => kIsWeb
      ? 'Clavium Web'
      : 'Clavium ${defaultTargetPlatform.name[0].toUpperCase()}${defaultTargetPlatform.name.substring(1)}';

  Future<void> register(String server, String email, String accountPassword) =>
      api.register(server, email, accountPassword);

  Future<void> signIn(String server, String email, String accountPassword) async {
    final s = await api.signIn(server, email, accountPassword,
        clientDeviceId: await storage.clientDeviceId(), deviceName: _deviceName, platform: _platform);
    session = s;
    await storage.saveSession(s);
    notifyListeners();
    if (phase == Phase.unlocked) {
      await syncNow();
      if (liveSync) unawaited(_liveLoop());
    }
  }

  Future<void> signOut() async {
    final s = session;
    session = null;
    await storage.saveSession(null);
    await storage.setPref('keyring_revision', null);
    notifyListeners();
    if (s != null) {
      try {
        await api.signOut(s);
      } catch (_) {
        // Offline: the local session is gone either way.
      }
    }
  }

  /// A new device: sign in, fetch the keyring, unlock it with the master
  /// password, then pull every record.
  Future<void> restoreFromAccount(String server, String email, String accountPassword, String masterPassword) async {
    final s = await api.signIn(server, email, accountPassword,
        clientDeviceId: await storage.clientDeviceId(), deviceName: _deviceName, platform: _platform);
    final ring = await api.getKeyring(s);
    if (ring == null) {
      throw SyncException('This account has no synced vault yet. Create a vault instead, then turn on sync.');
    }
    final res = await Core.run('open_from_keyring', {'header': ring['header'], 'master_password': masterPassword});
    session = s;
    await storage.saveSession(s);
    await storage.setPref('keyring_revision', ring['revision']);
    await _persist(res);
    await sync.pull(s);
    await _afterUnlock();
  }

  Future<void>? _inFlight;
  bool _again = false;

  /// Sync now. If a sync is already running, this waits for it and then
  /// runs once more, so a change made mid-sync is never left unpushed.
  Future<void> syncNow() {
    if (_inFlight != null) {
      _again = true;
      return _inFlight!;
    }
    final f = _syncLoop();
    _inFlight = f;
    return f.whenComplete(() => _inFlight = null);
  }

  Future<void> _syncLoop() async {
    do {
      _again = false;
      await _syncOnce();
    } while (_again);
  }

  Future<void> _syncOnce() async {
    final s = session;
    if (s == null || phase != Phase.unlocked) return;
    syncing = true;
    syncError = null;
    notifyListeners();
    try {
      final out = await sync.syncNow(s);
      syncNotice = out.notice;
      lastSync = DateTime.now();
      if (out.pulled > 0) refresh();
    } on ApiException catch (e) {
      syncError = e.message;
      if (e.status == 401) {
        session = null;
        await storage.saveSession(null);
      }
    } on SyncException catch (e) {
      syncError = e.message;
    } on CoreException catch (e) {
      syncError = e.message;
    } finally {
      syncing = false;
      notifyListeners();
    }
  }

  /// Long-poll the server while unlocked and signed in, so a change made
  /// on another device shows up here within a second or two.
  Future<void> _liveLoop() async {
    if (_liveLoopRunning) return;
    _liveLoopRunning = true;
    try {
      // The first sync creates the account's keyring if needed; only then
      // can the long-poll succeed.
      if (_inFlight != null) await _inFlight;
      while (phase == Phase.unlocked && session != null) {
        try {
          final changed = await sync.pull(session!, wait: true);
          if (changed > 0 && phase == Phase.unlocked) {
            lastSync = DateTime.now();
            refresh();
          }
        } catch (_) {
          await Future<void>.delayed(const Duration(seconds: 5));
        }
      }
    } finally {
      _liveLoopRunning = false;
    }
  }

  // ---------- unlock methods ----------

  Future<String> _biometricCredentialId() async => 'device:${await storage.clientDeviceId()}';

  Future<void> enableBiometrics() async {
    if (!await biometrics.available()) {
      throw CoreException('This device has no fingerprint, face or screen-lock unlock set up.');
    }
    if (!await biometrics.authenticate('Turn on biometric unlock')) return;
    final r = Random.secure();
    final secret = base64Encode(List<int>.generate(32, (_) => r.nextInt(256)));
    final res = Core.call('add_prf_slot', {
      'credential_id': await _biometricCredentialId(),
      'prf_salt': base64Encode(utf8.encode('device-biometric')),
      'prf_output': secret,
      'label': _deviceName,
    }) as Map;
    await _persist(res);
    await storage.secure.write('biometric_secret', secret);
    await storage.secure.write('biometric_slot', res['slot_id'] as String);
    biometricEnabled = true;
    notifyListeners();
    unawaited(syncNow());
  }

  Future<void> disableBiometrics() async {
    final slot = await storage.secure.read('biometric_slot');
    if (slot != null && phase == Phase.unlocked) {
      try {
        await _persist(Core.call('remove_slot', {'slot_id': slot}));
      } on CoreException {
        // Slot already gone.
      }
    }
    await storage.secure.delete('biometric_secret');
    await storage.secure.delete('biometric_slot');
    biometricEnabled = false;
    notifyListeners();
    unawaited(syncNow());
  }

  Future<void> changeMasterPassword(String newPassword) async {
    await _persist(await Core.run('change_master_password', {'new_password': newPassword}));
    unawaited(syncNow());
  }

  Future<String> createRecoveryKey() async {
    final res = Core.call('add_recovery_key') as Map;
    await _persist(res);
    unawaited(syncNow());
    return res['recovery_key'] as String;
  }

  List<Map<String, dynamic>> slots() => (Core.call('slots') as List).cast<Map<String, dynamic>>();

  /// Erase the vault from this device (not from the server).
  Future<void> eraseThisDevice() async {
    Core.call('lock');
    await storage.deleteVault();
    await storage.secure.delete('biometric_secret');
    await storage.secure.delete('biometric_slot');
    await storage.setPref('keyring_revision', null);
    biometricEnabled = false;
    records = [];
    phase = Phase.onboarding;
    notifyListeners();
  }
}
