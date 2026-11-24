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
import 'team_service.dart';

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

  /// Effective organization policy (strictest across the person's orgs),
  /// refreshed after each sync. Empty when not in any organization.
  Map<String, dynamic> policy = {};
  int? _unlockPasswordLength;
  DateTime? _lastHealthReport;
  bool biometricEnabled = false;
  DateTime? _backgroundedAt;
  bool _liveLoopRunning = false;
  Timer? _syncDebounce;

  // ---------- team vaults ----------
  late final TeamService teams = TeamService(api, storage, _persist);
  List<TeamInfo> teamList = [];
  String? activeTeamId;
  String? teamError;
  Timer? _teamTimer;
  bool _teamSyncing = false;

  TeamInfo? get activeTeam => activeTeamId == null ? null : teamList.where((t) => t.id == activeTeamId).firstOrNull;

  /// True when what is on screen can be changed (personal vault, or a team
  /// vault where this person is a manager or editor).
  bool get canEdit => activeTeam == null || activeTeam!.canWrite;

  void selectTeam(String? id) {
    activeTeamId = id;
    refresh();
  }

  Future<void> syncTeams() async {
    final s = session;
    if (s == null || phase != Phase.unlocked || _teamSyncing) return;
    _teamSyncing = true;
    try {
      final list = await teams.list(s);
      for (final t in list) {
        if (t.hasKey) await teams.sync(s, t);
      }
      teamList = list;
      if (activeTeamId != null && activeTeam == null) activeTeamId = null;
      teamError = null;
    } on ApiException catch (e) {
      teamError = e.message;
    } on CoreException catch (e) {
      teamError = e.message;
    } finally {
      _teamSyncing = false;
      if (phase == Phase.unlocked) refresh();
    }
  }

  void _startTeamTimer() {
    _teamTimer?.cancel();
    if (!liveSync) return;
    _teamTimer = Timer.periodic(const Duration(seconds: 20), (_) => unawaited(syncTeams()));
  }

  void _resetTeams() {
    _teamTimer?.cancel();
    _teamTimer = null;
    teams.forget();
    teamList = [];
    activeTeamId = null;
    teamError = null;
  }

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
    _unlockPasswordLength = masterPassword.length;
    final res = await Core.run('create', {'master_password': masterPassword});
    await _persist(res);
    await _afterUnlock();
  }

  Future<void> unlock(String masterPassword) async {
    _unlockPasswordLength = masterPassword.length;
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
      _startTeamTimer();
    }
  }

  void lock() {
    _syncDebounce?.cancel();
    _resetTeams();
    _unlockPasswordLength = null;
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
    if (phase == Phase.unlocked && at != null && DateTime.now().difference(at).inSeconds >= effectiveAutoLockSeconds) {
      lock();
    } else if (phase == Phase.unlocked && session != null) {
      unawaited(syncNow());
    }
  }

  /// The person's auto-lock choice, capped by organization policy.
  int get effectiveAutoLockSeconds {
    final maxMin = (policy['max_auto_lock_minutes'] as int?) ?? 0;
    return maxMin > 0 && autoLockSeconds > maxMin * 60 ? maxMin * 60 : autoLockSeconds;
  }

  /// Things the organization asks for that this vault does not meet yet.
  List<String> get policyNotices {
    final out = <String>[];
    final min = (policy['min_master_password_length'] as int?) ?? 0;
    final orgs = ((policy['organizations'] as List?) ?? const []).join(', ');
    if (_unlockPasswordLength != null && _unlockPasswordLength! < min) {
      out.add('$orgs requires a master password of at least $min characters. Change it in Settings.');
    }
    if (policy['require_recovery_key'] == true && phase == Phase.unlocked && !slots().any((s) => s['kind'] == 'recovery')) {
      out.add('$orgs asks you to create a recovery key. Do it in Settings.');
    }
    return out;
  }

  bool get exportAllowed => policy['allow_export'] != false;

  Future<void> _afterSync(AccountSession s) async {
    try {
      policy = await api.getPolicy(s);
    } catch (_) {
      // Keep the last known policy when offline.
    }
    final now = DateTime.now();
    if (_lastHealthReport == null || now.difference(_lastHealthReport!).inMinutes >= 30) {
      try {
        final h = health();
        final reused = (h['reused'] as List).fold<int>(0, (n, g) => n + (g as List).length);
        await api.reportHealth(s, {
          'score': h['score'],
          'total': h['with_password'],
          'weak': (h['weak'] as List).length,
          'reused': reused,
          'old': (h['old'] as List).length,
          'without_totp': (h['without_totp'] as List).length,
          'has_recovery_key': slots().any((x) => x['kind'] == 'recovery'),
        });
        _lastHealthReport = now;
      } catch (_) {}
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
    final team = activeTeam;
    if (team != null) {
      records = team.hasKey ? teams.records(team.id, query: query) : [];
      notifyListeners();
      return;
    }
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
    if (activeTeam != null) return teams.get(activeTeam!.id, id);
    try {
      return VaultRecord(Core.call('get', {'id': id}) as Map<String, dynamic>);
    } on CoreException {
      return null;
    }
  }

  Future<VaultRecord> addRecord(Map<String, dynamic> input) async {
    if (activeTeam != null) {
      final r = await teams.add(activeTeam!.id, input);
      _teamChanged();
      return r;
    }
    final res = Core.call('add', {'record': input}) as Map;
    await _persist(res);
    _changed();
    return VaultRecord(res['record'] as Map<String, dynamic>);
  }

  Future<VaultRecord> updateRecord(String id, Map<String, dynamic> input) async {
    if (activeTeam != null) {
      final r = await teams.update(activeTeam!.id, id, input);
      _teamChanged();
      return r;
    }
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
    if (activeTeam != null) {
      await teams.delete(activeTeam!.id, id);
      _teamChanged();
      return;
    }
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

  void _teamChanged() {
    refresh();
    _syncDebounce?.cancel();
    _syncDebounce = Timer(const Duration(seconds: 2), () => unawaited(syncTeams()));
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
      _startTeamTimer();
    }
  }

  Future<void> signOut() async {
    final s = session;
    session = null;
    _resetTeams();
    await storage.saveSession(null);
    await storage.setPref('keyring_revision', null);
    refresh();
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
      await _afterSync(s);
      await syncTeams();
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

  // ---------- QR device linking ----------

  static bool _sameServer(String a, String b) =>
      a.trim().replaceAll(RegExp(r'/+$'), '').toLowerCase() == b.trim().replaceAll(RegExp(r'/+$'), '').toLowerCase();

  /// New device: start a link and return what the QR code shows. Call
  /// [waitForLink] next.
  Future<LinkStart> startLink(String server) async {
    final qr = Core.call('link_begin') as Map;
    final res = await api.linkStart(server, {
      'public_key': qr['public_key'],
      'client_device_id': await storage.clientDeviceId(),
      'name': _deviceName,
      'platform': _platform,
    });
    final uri = Uri(scheme: 'clavium', host: 'link', queryParameters: {
      'v': '1',
      'id': res['id'] as String,
      'k': qr['public_key'] as String,
      'x': qr['link_secret'] as String,
      // Left out for the default server: a shorter link is a sparser QR
      // code, which phone cameras read faster.
      if (!_sameServer(server, defaultServer)) 's': server,
    }).toString();
    return LinkStart(server: server, id: res['id'] as String, pollToken: res['poll_token'] as String, qr: uri, code: qr['code'] as String);
  }

  /// New device: wait for the phone to approve, then open the vault.
  /// Returns false if the link expired or was declined.
  Future<bool> waitForLink(LinkStart link, {bool Function()? cancelled}) async {
    final deadline = DateTime.now().add(const Duration(minutes: 2, seconds: 10));
    while (DateTime.now().isBefore(deadline)) {
      if (cancelled?.call() ?? false) return false;
      final r = await api.linkPoll(link.server, link.id, link.pollToken);
      switch (r['status']) {
        case 'approved':
          final token = r['token'] as String;
          final ring = await api.getKeyringWithToken(link.server, token);
          if (ring == null) throw SyncException('Your account has no synced vault yet.');
          final opened = Core.call('link_finish', {'envelope': r['envelope'], 'header': ring['header']});
          final s = AccountSession(
            server: link.server,
            token: token,
            email: (r['account'] as Map)['email'] as String,
            deviceId: r['device_id'] as String,
          );
          session = s;
          await storage.saveSession(s);
          await storage.setPref('keyring_revision', ring['revision']);
          await _persist(opened);
          // Every record must decrypt with the linked key; a wrong key
          // fails here, before anything is shown.
          await sync.pull(s);
          await _afterUnlock();
          return true;
        case 'pending':
          continue;
        default:
          Core.call('link_cancel');
          return false;
      }
    }
    Core.call('link_cancel');
    return false;
  }

  /// Approving phone: check a scanned QR and return what to show the
  /// person before they approve.
  Future<LinkInspection> inspectLink(String scanned) async {
    final s = session;
    if (s == null) throw CoreException('Sign in on this device first (Settings, Turn on sync).');
    final uri = Uri.tryParse(scanned);
    final q = uri?.queryParameters ?? const {};
    if (uri == null || uri.scheme != 'clavium' || uri.host != 'link' || q['id'] == null || q['k'] == null || q['x'] == null) {
      throw CoreException('That is not a Clavium sign-in QR code.');
    }
    final target = q['s'] ?? defaultServer;
    if (!_sameServer(target, s.server)) {
      throw CoreException('That device is signing in to a different Clavium server ($target).');
    }
    final info = await api.linkInfo(s, q['id']!);
    if (info['public_key'] != q['k']) throw CoreException('This QR code does not match its sign-in request.');
    final code = Core.call('link_code', {'public_key': q['k'], 'link_secret': q['x']}) as String;
    return LinkInspection(
      id: q['id']!,
      publicKey: q['k']!,
      linkSecret: q['x']!,
      deviceName: info['name'] as String,
      platform: info['platform'] as String? ?? '',
      ip: info['requester_ip'] as String? ?? '',
      code: code,
    );
  }

  Future<void> approveLink(LinkInspection l) async {
    final s = session!;
    if (await biometrics.available() && !await biometrics.authenticate('Approve signing in ${l.deviceName}')) {
      throw CoreException('Not approved.');
    }
    final env = Core.call('link_approve', {'public_key': l.publicKey, 'link_secret': l.linkSecret}) as Map;
    await api.linkApprove(s, l.id, l.publicKey, Map<String, dynamic>.from(env));
  }

  Future<void> denyLink(LinkInspection l) async {
    final s = session;
    if (s != null) await api.linkDeny(s, l.id);
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
    final min = (policy['min_master_password_length'] as int?) ?? 10;
    if (newPassword.length < min) {
      throw CoreException('Your organization requires at least $min characters.');
    }
    _unlockPasswordLength = newPassword.length;
    await _persist(await Core.run('change_master_password', {'new_password': newPassword}));
    unawaited(syncNow());
  }

  Future<String> createRecoveryKey() async {
    final res = Core.call('add_recovery_key') as Map;
    await _persist(res);
    _lastHealthReport = null;
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

class LinkStart {
  LinkStart({required this.server, required this.id, required this.pollToken, required this.qr, required this.code});
  final String server;
  final String id;
  final String pollToken;
  final String qr;
  final String code;
}

class LinkInspection {
  LinkInspection({
    required this.id,
    required this.publicKey,
    required this.linkSecret,
    required this.deviceName,
    required this.platform,
    required this.ip,
    required this.code,
  });
  final String id;
  final String publicKey;
  final String linkSecret;
  final String deviceName;
  final String platform;
  final String ip;
  final String code;
}
