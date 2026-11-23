import 'package:material_ui/material_ui.dart';

import '../core/api_client.dart';
import '../core/app_state.dart';
import 'health_screen.dart';
import 'theme.dart';
import 'widgets.dart';

class SettingsTab extends StatelessWidget {
  const SettingsTab({super.key, required this.app});
  final AppState app;

  @override
  Widget build(BuildContext context) {
    final s = app.session;
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(children: [
        const _Header('Account and sync'),
        if (s == null)
          ListTile(
            leading: const Icon(Icons.cloud_outlined),
            title: const Text('Turn on sync'),
            subtitle: const Text('Sign in to keep this vault in step across your devices, encrypted end to end'),
            onTap: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => SignInScreen(app: app))),
          )
        else ...[
          ListTile(
            leading: const Icon(Icons.account_circle_outlined),
            title: Text(s.email),
            subtitle: Text(app.syncError ??
                (app.lastSync == null ? 'Not synced yet' : 'Last synced ${TimeOfDay.fromDateTime(app.lastSync!).format(context)}')),
            trailing: IconButton(icon: const Icon(Icons.sync), onPressed: app.syncing ? null : app.syncNow),
          ),
          ListTile(
            leading: const Icon(Icons.logout),
            title: const Text('Sign out on this device'),
            subtitle: const Text('Your vault stays on this device; it stops syncing'),
            onTap: app.signOut,
          ),
        ],
        const _Header('Security'),
        ListTile(
          leading: const Icon(Icons.health_and_safety_outlined, color: ClvColors.gold500),
          title: const Text('Password health'),
          subtitle: const Text('Weak, reused and old passwords'),
          onTap: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => HealthScreen(app: app))),
        ),
        SwitchListTile(
          secondary: const Icon(Icons.fingerprint),
          title: const Text('Unlock with biometrics'),
          subtitle: const Text('Fingerprint, face or your phone\'s screen lock'),
          value: app.biometricEnabled,
          onChanged: (v) async {
            try {
              v ? await app.enableBiometrics() : await app.disableBiometrics();
            } catch (e) {
              if (context.mounted) showError(context, e);
            }
          },
        ),
        ListTile(
          leading: const Icon(Icons.timer_outlined),
          title: const Text('Lock after leaving the app'),
          subtitle: ((app.policy['max_auto_lock_minutes'] as int?) ?? 0) > 0
              ? Text('Your organization allows at most ${app.policy['max_auto_lock_minutes']} min')
              : null,
          trailing: DropdownButton<int>(
            value: const [0, 60, 300, 900].contains(app.effectiveAutoLockSeconds) ? app.effectiveAutoLockSeconds : 60,
            underline: const SizedBox(),
            items: const [
              DropdownMenuItem(value: 0, child: Text('Immediately')),
              DropdownMenuItem(value: 60, child: Text('1 minute')),
              DropdownMenuItem(value: 300, child: Text('5 minutes')),
              DropdownMenuItem(value: 900, child: Text('15 minutes')),
            ],
            onChanged: (v) => app.setAutoLock(v ?? 60),
          ),
        ),
        ListTile(
          leading: const Icon(Icons.password),
          title: const Text('Change master password'),
          onTap: () => _changePassword(context),
        ),
        ListTile(
          leading: const Icon(Icons.key_outlined),
          title: const Text('Create a recovery key'),
          subtitle: const Text('Opens your vault if you forget the master password'),
          onTap: () => _recoveryKey(context),
        ),
        ListTile(
          leading: const Icon(Icons.vpn_key_outlined),
          title: const Text('Unlock methods'),
          subtitle: Text('${app.slots().length} active'),
          onTap: () => _slots(context),
        ),
        const _Header('This device'),
        ListTile(
          leading: const Icon(Icons.delete_forever_outlined, color: ClvColors.danger),
          title: const Text('Remove vault from this device'),
          subtitle: Text(s == null ? 'Without sync, this deletes your only copy' : 'Your synced copy stays on your account'),
          onTap: () => _erase(context),
        ),
      ]),
    );
  }

  Future<void> _changePassword(BuildContext context) async {
    final a = TextEditingController(), b = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        title: const Text('New master password'),
        content: Column(mainAxisSize: MainAxisSize.min, children: [
          TextField(controller: a, obscureText: true, decoration: const InputDecoration(labelText: 'New password')),
          const SizedBox(height: 8),
          TextField(controller: b, obscureText: true, decoration: const InputDecoration(labelText: 'Again')),
        ]),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('Change')),
        ],
      ),
    );
    if (ok != true || !context.mounted) return;
    if (a.text != b.text) return showError(context, 'The two passwords do not match.');
    try {
      await app.changeMasterPassword(a.text);
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Master password changed.')));
      }
    } catch (e) {
      if (context.mounted) showError(context, e);
    }
  }

  Future<void> _recoveryKey(BuildContext context) async {
    try {
      final key = await app.createRecoveryKey();
      if (!context.mounted) return;
      await showDialog<void>(
        context: context,
        barrierDismissible: false,
        builder: (c) => AlertDialog(
          title: const Text('Your recovery key'),
          content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text('Write this down and keep it somewhere safe. It is shown only once.'),
            const SizedBox(height: 16),
            SelectableText(key, style: const TextStyle(fontFamily: 'monospace', fontSize: 16, color: ClvColors.gold400)),
          ]),
          actions: [FilledButton(onPressed: () => Navigator.pop(c), child: const Text('I have saved it'))],
        ),
      );
    } catch (e) {
      if (context.mounted) showError(context, e);
    }
  }

  Future<void> _slots(BuildContext context) async {
    final slots = app.slots();
    await showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (_) => SafeArea(
        child: ListView(shrinkWrap: true, children: [
          for (final s in slots)
            ListTile(
              leading: Icon(switch (s['kind']) {
                'password' => Icons.password,
                'prf' => Icons.fingerprint,
                _ => Icons.key_outlined,
              }),
              title: Text((s['label'] as String?)?.isNotEmpty == true ? s['label'] as String : s['kind'] as String),
              subtitle: Text('Added ${(s['created_at'] as String).substring(0, 10)}'),
            ),
        ]),
      ),
    );
  }

  Future<void> _erase(BuildContext context) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        title: const Text('Remove the vault from this device?'),
        content: Text(app.session == null
            ? 'You are not syncing. This permanently deletes every item in this vault.'
            : 'Unsynced changes made on this device will be lost.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
          FilledButton(style: FilledButton.styleFrom(backgroundColor: ClvColors.danger), onPressed: () => Navigator.pop(c, true), child: const Text('Remove')),
        ],
      ),
    );
    if (ok == true) await app.eraseThisDevice();
  }
}

class _Header extends StatelessWidget {
  const _Header(this.text);
  final String text;
  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 24, 16, 8),
        child: Text(text.toUpperCase(), style: const TextStyle(fontSize: 12, letterSpacing: 1.2, color: ClvColors.textDim)),
      );
}

class SignInScreen extends StatefulWidget {
  const SignInScreen({super.key, required this.app});
  final AppState app;
  @override
  State<SignInScreen> createState() => _SignInScreenState();
}

class _SignInScreenState extends State<SignInScreen> {
  final server = TextEditingController(text: defaultServer);
  final email = TextEditingController();
  final pw = TextEditingController();
  bool creating = false;
  bool busy = false;

  Future<void> submit() async {
    setState(() => busy = true);
    try {
      if (creating) await widget.app.register(server.text.trim(), email.text.trim(), pw.text);
      await widget.app.signIn(server.text.trim(), email.text.trim(), pw.text);
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (mounted) showError(context, e);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(creating ? 'Create account' : 'Sign in')),
      body: ListView(padding: const EdgeInsets.all(24), children: [
        const Text(
          'Your account password only signs you in. It is not your master password, and the server '
          'never receives your master password or anything it could decrypt your vault with.',
          style: TextStyle(color: ClvColors.textDim),
        ),
        const SizedBox(height: 24),
        TextField(controller: email, keyboardType: TextInputType.emailAddress, decoration: const InputDecoration(labelText: 'Email')),
        const SizedBox(height: 12),
        TextField(controller: pw, obscureText: true, decoration: const InputDecoration(labelText: 'Account password')),
        const SizedBox(height: 12),
        TextField(controller: server, decoration: const InputDecoration(labelText: 'Server')),
        const SizedBox(height: 24),
        FilledButton(onPressed: busy ? null : submit, child: Text(creating ? 'Create account and sync' : 'Sign in and sync')),
        TextButton(
          onPressed: () => setState(() => creating = !creating),
          child: Text(creating ? 'I already have an account' : 'Create an account'),
        ),
      ]),
    );
  }
}
