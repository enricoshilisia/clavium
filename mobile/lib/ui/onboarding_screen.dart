import 'package:material_ui/material_ui.dart';

import '../core/api_client.dart';
import '../core/app_state.dart';
import '../core/native.dart';
import 'theme.dart';
import 'widgets.dart';

class OnboardingScreen extends StatelessWidget {
  const OnboardingScreen({super.key, required this.app});
  final AppState app;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: ListView(padding: const EdgeInsets.all(24), children: [
          const SizedBox(height: 40),
          const Icon(Icons.shield_outlined, size: 64, color: ClvColors.gold500),
          const SizedBox(height: 16),
          Text('Clavium', textAlign: TextAlign.center, style: Theme.of(context).textTheme.headlineMedium),
          const SizedBox(height: 8),
          const Text(
            'Passwords, cards, bank details and authenticator codes, encrypted on this device. '
            'Only you hold the key.',
            textAlign: TextAlign.center,
            style: TextStyle(color: ClvColors.textDim),
          ),
          const SizedBox(height: 40),
          FilledButton.icon(
            key: const Key('create-vault'),
            icon: const Icon(Icons.add),
            label: const Text('Create a new vault'),
            onPressed: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => CreateVaultScreen(app: app))),
          ),
          const SizedBox(height: 12),
          OutlinedButton.icon(
            key: const Key('restore-vault'),
            icon: const Icon(Icons.cloud_download_outlined),
            label: const Text('I already use Clavium'),
            onPressed: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => RestoreScreen(app: app))),
          ),
        ]),
      ),
    );
  }
}

class CreateVaultScreen extends StatefulWidget {
  const CreateVaultScreen({super.key, required this.app});
  final AppState app;
  @override
  State<CreateVaultScreen> createState() => _CreateVaultScreenState();
}

class _CreateVaultScreenState extends State<CreateVaultScreen> {
  final pw = TextEditingController();
  final confirm = TextEditingController();
  bool busy = false;
  double bits = 0;

  Future<void> submit() async {
    if (pw.text.length < 10) return showError(context, 'Use at least 10 characters.');
    if (pw.text != confirm.text) return showError(context, 'The two passwords do not match.');
    setState(() => busy = true);
    try {
      await widget.app.createVault(pw.text);
      if (mounted) Navigator.of(context).popUntil((r) => r.isFirst);
    } catch (e) {
      if (mounted) showError(context, e);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Create your vault')),
      body: ListView(padding: const EdgeInsets.all(24), children: [
        const Text(
          'Choose a master password. It encrypts your vault on this device and is never sent anywhere. '
          'If you forget it, nobody can recover your vault unless you create a recovery key in Settings.',
          style: TextStyle(color: ClvColors.textDim),
        ),
        const SizedBox(height: 24),
        TextField(
          key: const Key('master-password'),
          controller: pw,
          obscureText: true,
          decoration: const InputDecoration(labelText: 'Master password'),
          onChanged: (v) => setState(() => bits = ((Core.call('password_strength', {'password': v}) as Map)['bits'] as num).toDouble()),
        ),
        const SizedBox(height: 8),
        PasswordStrengthBar(bits: bits),
        const SizedBox(height: 16),
        TextField(
          key: const Key('master-password-confirm'),
          controller: confirm,
          obscureText: true,
          decoration: const InputDecoration(labelText: 'Type it again'),
          onSubmitted: (_) => submit(),
        ),
        const SizedBox(height: 24),
        FilledButton(
          key: const Key('create-submit'),
          onPressed: busy ? null : submit,
          child: busy ? const SizedBox(height: 18, width: 18, child: CircularProgressIndicator(strokeWidth: 2)) : const Text('Create vault'),
        ),
      ]),
    );
  }
}

class RestoreScreen extends StatefulWidget {
  const RestoreScreen({super.key, required this.app});
  final AppState app;
  @override
  State<RestoreScreen> createState() => _RestoreScreenState();
}

class _RestoreScreenState extends State<RestoreScreen> {
  final server = TextEditingController(text: defaultServer);
  final email = TextEditingController();
  final accountPw = TextEditingController();
  final masterPw = TextEditingController();
  bool busy = false;
  bool showServer = false;

  Future<void> submit() async {
    setState(() => busy = true);
    try {
      await widget.app.restoreFromAccount(server.text.trim(), email.text.trim(), accountPw.text, masterPw.text);
      if (mounted) Navigator.of(context).popUntil((r) => r.isFirst);
    } catch (e) {
      if (mounted) showError(context, e);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Restore your vault')),
      body: ListView(padding: const EdgeInsets.all(24), children: [
        const Text(
          'Sign in to your Clavium account, then unlock with your master password. '
          'Your records download encrypted and are decrypted only on this phone.',
          style: TextStyle(color: ClvColors.textDim),
        ),
        const SizedBox(height: 24),
        TextField(controller: email, keyboardType: TextInputType.emailAddress, decoration: const InputDecoration(labelText: 'Account email')),
        const SizedBox(height: 12),
        TextField(controller: accountPw, obscureText: true, decoration: const InputDecoration(labelText: 'Account password')),
        const SizedBox(height: 12),
        TextField(controller: masterPw, obscureText: true, decoration: const InputDecoration(labelText: 'Master password')),
        const SizedBox(height: 8),
        TextButton(
          onPressed: () => setState(() => showServer = !showServer),
          child: Text(showServer ? 'Hide server' : 'Company server (self-hosted)?'),
        ),
        if (showServer) TextField(controller: server, decoration: const InputDecoration(labelText: 'Server address')),
        const SizedBox(height: 24),
        FilledButton(
          onPressed: busy ? null : submit,
          child: busy ? const SizedBox(height: 18, width: 18, child: CircularProgressIndicator(strokeWidth: 2)) : const Text('Restore'),
        ),
      ]),
    );
  }
}
