import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import '../core/app_state.dart';
import '../core/native.dart';
import 'share_screens.dart' show VerdictCard;
import 'theme.dart';
import 'widgets.dart';

const _channel = MethodChannel('clavium/autofill');

/// Opened by Android when someone picks "Fill from Clavium" in another app
/// or a browser: unlock, pick a login, hand it back to be filled.
class AutofillApp extends StatelessWidget {
  const AutofillApp({super.key, required this.app});
  final AppState app;

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'Clavium',
        debugShowCheckedModeBanner: false,
        theme: claviumTheme(),
        home: AutofillScreen(app: app),
      );
}

class AutofillScreen extends StatefulWidget {
  const AutofillScreen({super.key, required this.app, this.channel = _channel});
  final AppState app;
  final MethodChannel channel;
  @override
  State<AutofillScreen> createState() => _AutofillScreenState();
}

class _AutofillScreenState extends State<AutofillScreen> {
  Map<String, dynamic> request = {};
  Map<String, dynamic>? candidates;
  bool ready = false;
  bool adopted = false;
  bool busy = false;
  bool remember = true;
  String query = '';
  String? error;
  final master = TextEditingController();

  AppState get app => widget.app;
  String? get domain => (request['webDomain'] as String?)?.isNotEmpty == true ? request['webDomain'] as String : null;
  String? get package => request['package'] as String?;

  @override
  void initState() {
    super.initState();
    _start();
  }

  Future<void> _start() async {
    try {
      request = Map<String, dynamic>.from(await widget.channel.invokeMethod('request') as Map);
    } catch (_) {}
    await app.init();
    app.session = null; // no syncing from this small screen
    adopted = app.adoptUnlockedCore();
    if (adopted) _load();
    setState(() => ready = true);
    if (!adopted && app.biometricEnabled) _biometric();
  }

  void _load() {
    setState(() => candidates = Map<String, dynamic>.from(Core.call('autofill_candidates', {'web_domain': domain, 'package': package}) as Map));
  }

  Future<void> _unlock() async {
    setState(() {
      busy = true;
      error = null;
    });
    try {
      await app.unlock(master.text);
      app.session = null;
      _load();
    } catch (e) {
      setState(() => error = e is CoreException ? 'Wrong master password.' : e.toString());
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> _biometric() async {
    try {
      if (await app.unlockWithBiometrics()) {
        app.session = null;
        _load();
      }
    } catch (_) {}
  }

  Future<void> _pick(Map row, {required bool matched}) async {
    final teamId = row['team_id'];
    try {
      if (domain == null && package != null && !matched && teamId == null && remember) {
        final out = Core.call('autofill_remember', {'id': row['id'], 'package': package}) as Map;
        await app.storage.writeVault(out['saved'] as String);
      }
      final cred = Core.call('autofill_get', {'id': row['id'], 'team_id': teamId}) as Map;
      await widget.channel.invokeMethod('fill', {'username': cred['username'], 'password': cred['password']});
    } catch (e) {
      if (mounted) showError(context, e);
      return;
    }
    _finish();
  }

  void _finish() {
    // Leave the vault as we found it: lock only if this screen unlocked it.
    if (!adopted && app.phase == Phase.unlocked) app.lock();
  }

  Future<void> _cancel() async {
    _finish();
    try {
      await widget.channel.invokeMethod('cancel');
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    final target = domain ?? package ?? 'this app';
    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) {
        if (!didPop) _cancel();
      },
      child: Scaffold(
        appBar: AppBar(
          leading: IconButton(icon: const Icon(Icons.close), tooltip: 'Cancel', onPressed: _cancel),
          title: Text('Fill $target', overflow: TextOverflow.ellipsis),
        ),
        body: !ready
            ? const Center(child: CircularProgressIndicator())
            : candidates == null
                ? _unlockView()
                : _pickView(),
      ),
    );
  }

  Widget _unlockView() => ListView(padding: const EdgeInsets.all(24), children: [
        const Icon(Icons.lock_outline, size: 48, color: ClvColors.gold500),
        const SizedBox(height: 12),
        const Text('Unlock Clavium to fill this login', textAlign: TextAlign.center, style: TextStyle(fontSize: 18)),
        const SizedBox(height: 20),
        TextField(
          key: const Key('autofill-master'),
          controller: master,
          obscureText: true,
          autofocus: !app.biometricEnabled,
          decoration: const InputDecoration(labelText: 'Master password'),
          onSubmitted: (_) => _unlock(),
        ),
        if (error != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(error!, style: const TextStyle(color: ClvColors.danger))),
        const SizedBox(height: 12),
        FilledButton(key: const Key('autofill-unlock'), onPressed: busy ? null : _unlock, child: Text(busy ? 'Unlocking…' : 'Unlock')),
        if (app.biometricEnabled)
          TextButton.icon(onPressed: _biometric, icon: const Icon(Icons.fingerprint), label: const Text('Use fingerprint or face')),
      ]);

  Widget _pickView() {
    final c = candidates!;
    final verdict = c['verdict'] is Map ? Map<String, dynamic>.from(c['verdict'] as Map) : null;
    final dangerous = verdict?['verdict'] == 'dangerous';
    final matches = (c['matches'] as List).cast<Map>();
    final suggestions = (c['suggestions'] as List).cast<Map>();
    final q = query.toLowerCase();
    final all = (c['all'] as List)
        .cast<Map>()
        .where((r) => q.isEmpty || '${r['title']} ${r['username']} ${r['url']}'.toLowerCase().contains(q))
        .toList();

    Widget tile(Map r, {required bool matched}) => ListTile(
          leading: const CircleAvatar(backgroundColor: ClvColors.navy700, child: Icon(Icons.key, size: 18, color: ClvColors.blue300)),
          title: Text(r['title'] as String),
          subtitle: Text([r['username'], if ((r['reason'] as String).isNotEmpty) r['reason'], if (r['team_id'] != null) 'team vault'].where((x) => (x as String).isNotEmpty).join(' · ')),
          onTap: () => _pick(r, matched: matched),
        );

    if (dangerous) {
      return ListView(padding: const EdgeInsets.all(20), children: [
        VerdictCard(check: verdict!),
        const SizedBox(height: 16),
        const Text('Clavium will not fill passwords on this page. Close it and go to the real site yourself.'),
        const SizedBox(height: 16),
        FilledButton(onPressed: _cancel, child: const Text('Close')),
      ]);
    }
    return ListView(children: [
      if (verdict?['verdict'] == 'suspicious') Padding(padding: const EdgeInsets.all(16), child: VerdictCard(check: verdict!)),
      if (matches.isNotEmpty) ...[
        const _Heading('For this site'),
        for (final r in matches) tile(r, matched: true),
      ],
      if (suggestions.isNotEmpty) ...[
        const _Heading('Might be for this app'),
        for (final r in suggestions) tile(r, matched: false),
      ],
      const _Heading('All logins'),
      Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16),
        child: TextField(
          key: const Key('autofill-search'),
          decoration: const InputDecoration(prefixIcon: Icon(Icons.search), hintText: 'Search'),
          onChanged: (v) => setState(() => query = v),
        ),
      ),
      if (domain == null && package != null)
        CheckboxListTile(
          value: remember,
          onChanged: (v) => setState(() => remember = v ?? true),
          title: const Text('Remember my choice for this app'),
        ),
      for (final r in all.take(80)) tile(r, matched: false),
      const SizedBox(height: 24),
    ]);
  }
}

class _Heading extends StatelessWidget {
  const _Heading(this.text);
  final String text;
  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
        child: Text(text.toUpperCase(), style: const TextStyle(color: ClvColors.textDim, fontSize: 12, letterSpacing: 0.6)),
      );
}
