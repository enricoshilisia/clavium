import 'package:material_ui/material_ui.dart';

import '../core/app_state.dart';
import '../core/native.dart';
import 'link_screens.dart';
import 'record_edit_screen.dart';
import 'scan_screen.dart';
import 'theme.dart';
import 'totp_view.dart';
import 'widgets.dart';

/// The authenticator: every record with a TOTP secret, live codes. Codes
/// live inside the encrypted vault, so they sync and back up with it.
class CodesTab extends StatelessWidget {
  const CodesTab({super.key, required this.app});
  final AppState app;

  Future<void> _scan(BuildContext context) async {
    final uri = await Navigator.of(context).push<String>(MaterialPageRoute(
        builder: (_) => ScanScreen(
              accept: (v) => v.startsWith('otpauth://') || v.startsWith('clavium://link'),
              hint: 'Scan a 2FA setup code or a Clavium sign-in code',
              rejectMessage: 'That QR code is not a 2FA setup code or a Clavium sign-in code.',
            )));
    if (uri == null || !context.mounted) return;
    if (uri.startsWith('clavium://link')) return scanAndApproveLink(context, app, scanned: uri);
    try {
      final p = Core.call('parse_otpauth', {'uri': uri}) as Map;
      final issuer = (p['issuer'] as String).isNotEmpty ? p['issuer'] as String : p['account'] as String;
      await Navigator.of(context).push(MaterialPageRoute(
        builder: (_) => RecordEditScreen(
          app: app,
          kind: 'login',
          prefill: {'title': issuer, 'username': p['account'], 'totp_secret': uri},
        ),
      ));
    } catch (e) {
      if (context.mounted) showError(context, e);
    }
  }

  @override
  Widget build(BuildContext context) {
    final list = app.totpRecords();
    return Scaffold(
      appBar: AppBar(title: const Text('Authenticator')),
      floatingActionButton: FloatingActionButton.extended(
        backgroundColor: ClvColors.gold500,
        foregroundColor: ClvColors.navy950,
        icon: const Icon(Icons.qr_code_scanner),
        label: const Text('Scan'),
        onPressed: () => _scan(context),
      ),
      body: list.isEmpty
          ? const Center(
              child: Padding(
                padding: EdgeInsets.all(32),
                child: Text(
                  'Scan the QR code a website shows when you turn on two-factor authentication, '
                  'or paste the secret into any login.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: ClvColors.textDim),
                ),
              ),
            )
          : ListView.separated(
              itemCount: list.length,
              separatorBuilder: (_, _) => const Divider(height: 1),
              itemBuilder: (context, i) => ListTile(
                title: Text(list[i].title),
                subtitle: Text(list[i].username, style: const TextStyle(color: ClvColors.textDim)),
                trailing: TotpView(secret: list[i].totpSecret!),
              ),
            ),
    );
  }
}
