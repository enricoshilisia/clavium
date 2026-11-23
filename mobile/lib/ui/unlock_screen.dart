import 'package:material_ui/material_ui.dart';

import '../core/app_state.dart';
import 'theme.dart';
import 'widgets.dart';

class UnlockScreen extends StatefulWidget {
  const UnlockScreen({super.key, required this.app});
  final AppState app;
  @override
  State<UnlockScreen> createState() => _UnlockScreenState();
}

class _UnlockScreenState extends State<UnlockScreen> {
  final pw = TextEditingController();
  bool busy = false;
  bool recovery = false;

  @override
  void initState() {
    super.initState();
    if (widget.app.biometricEnabled) {
      WidgetsBinding.instance.addPostFrameCallback((_) => biometric());
    }
  }

  Future<void> _run(Future<void> Function() f) async {
    setState(() => busy = true);
    try {
      await f();
    } catch (e) {
      if (mounted) showError(context, e);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> submit() => _run(() async {
        if (recovery) {
          await widget.app.unlockWithRecoveryKey(pw.text);
        } else {
          await widget.app.unlock(pw.text);
        }
        pw.clear();
      });

  Future<void> biometric() => _run(() async {
        await widget.app.unlockWithBiometrics();
      });

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: ListView(shrinkWrap: true, padding: const EdgeInsets.all(24), children: [
              const Icon(Icons.lock_outline, size: 56, color: ClvColors.gold500),
              const SizedBox(height: 16),
              Text('Vault locked', textAlign: TextAlign.center, style: Theme.of(context).textTheme.headlineSmall),
              const SizedBox(height: 24),
              TextField(
                key: const Key('unlock-password'),
                controller: pw,
                obscureText: !recovery,
                autofocus: !widget.app.biometricEnabled,
                decoration: InputDecoration(labelText: recovery ? 'Recovery key' : 'Master password'),
                onSubmitted: (_) => submit(),
              ),
              const SizedBox(height: 16),
              FilledButton(
                key: const Key('unlock-submit'),
                onPressed: busy ? null : submit,
                child: busy
                    ? const SizedBox(height: 18, width: 18, child: CircularProgressIndicator(strokeWidth: 2))
                    : const Text('Unlock'),
              ),
              if (widget.app.biometricEnabled) ...[
                const SizedBox(height: 12),
                OutlinedButton.icon(
                  icon: const Icon(Icons.fingerprint),
                  label: const Text('Unlock with biometrics'),
                  onPressed: busy ? null : biometric,
                ),
              ],
              const SizedBox(height: 12),
              TextButton(
                onPressed: () => setState(() {
                  recovery = !recovery;
                  pw.clear();
                }),
                child: Text(recovery ? 'Use master password' : 'Forgot it? Use a recovery key'),
              ),
            ]),
          ),
        ),
      ),
    );
  }
}
