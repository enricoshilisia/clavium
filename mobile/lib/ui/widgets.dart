import 'dart:async';

import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import 'theme.dart';

IconData kindIcon(String kind) => switch (kind) {
      'bank_account' => Icons.account_balance,
      'card' => Icons.credit_card,
      'identity' => Icons.badge_outlined,
      'secure_note' => Icons.sticky_note_2_outlined,
      'wifi' => Icons.wifi,
      'ssh_key' => Icons.terminal,
      'api_key' => Icons.vpn_key_outlined,
      'server' => Icons.dns_outlined,
      'database' => Icons.storage,
      'software_license' => Icons.verified_outlined,
      'passkey' => Icons.fingerprint,
      _ => Icons.language,
    };

IconData categoryIcon(String slug) => switch (slug) {
      'banking' => Icons.account_balance,
      'finance' => Icons.payments_outlined,
      'email' => Icons.mail_outline,
      'social' => Icons.forum_outlined,
      'work' => Icons.work_outline,
      'development' => Icons.code,
      'cloud' => Icons.cloud_outlined,
      'infrastructure' => Icons.dns_outlined,
      'network' => Icons.wifi,
      'shopping' => Icons.shopping_bag_outlined,
      'entertainment' => Icons.movie_outlined,
      'government' => Icons.account_balance_outlined,
      'travel' => Icons.flight_outlined,
      'utilities' => Icons.bolt_outlined,
      'health' => Icons.favorite_outline,
      'education' => Icons.school_outlined,
      'personal' => Icons.person_outline,
      'software' => Icons.apps_outlined,
      'uncategorized' => Icons.help_outline,
      _ => Icons.folder_outlined,
    };

Timer? _clipboardTimer;

/// Copy a value and clear the clipboard after 30 seconds, unless the
/// person copied something else in the meantime.
Future<void> copySecret(BuildContext context, String value, String what) async {
  await Clipboard.setData(ClipboardData(text: value));
  _clipboardTimer?.cancel();
  _clipboardTimer = Timer(const Duration(seconds: 30), () async {
    final current = await Clipboard.getData(Clipboard.kTextPlain);
    if (current?.text == value) await Clipboard.setData(const ClipboardData(text: ''));
  });
  if (context.mounted) {
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text('$what copied. Clipboard clears in 30 seconds.')));
  }
}

void showError(BuildContext context, Object e) {
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(content: Text(e.toString()), backgroundColor: ClvColors.danger));
}

/// A labelled read-only value with copy (and reveal, for secrets).
class FieldTile extends StatefulWidget {
  const FieldTile({super.key, required this.label, required this.value, this.secret = false, this.monospace = false});
  final String label;
  final String value;
  final bool secret;
  final bool monospace;

  @override
  State<FieldTile> createState() => _FieldTileState();
}

class _FieldTileState extends State<FieldTile> {
  bool revealed = false;

  @override
  Widget build(BuildContext context) {
    final shown = widget.secret && !revealed ? '•' * widget.value.length.clamp(8, 16) : widget.value;
    return ListTile(
      title: Text(widget.label, style: const TextStyle(fontSize: 12, color: ClvColors.textDim)),
      subtitle: Text(
        shown,
        style: TextStyle(
          fontSize: 16,
          color: ClvColors.text,
          fontFamily: widget.monospace || (widget.secret && revealed) ? 'monospace' : null,
        ),
      ),
      trailing: Row(mainAxisSize: MainAxisSize.min, children: [
        if (widget.secret)
          IconButton(
            tooltip: revealed ? 'Hide' : 'Show',
            icon: Icon(revealed ? Icons.visibility_off : Icons.visibility),
            onPressed: () => setState(() => revealed = !revealed),
          ),
        IconButton(
          tooltip: 'Copy',
          icon: const Icon(Icons.copy),
          onPressed: () => copySecret(context, widget.value, widget.label),
        ),
      ]),
    );
  }
}

class PasswordStrengthBar extends StatelessWidget {
  const PasswordStrengthBar({super.key, required this.bits});
  final double bits;

  @override
  Widget build(BuildContext context) {
    final p = (bits / 100).clamp(0.0, 1.0);
    final color = bits < 50 ? ClvColors.danger : (bits < 75 ? ClvColors.gold500 : ClvColors.success);
    final label = bits < 50 ? 'Weak' : (bits < 75 ? 'Good' : 'Strong');
    return Row(children: [
      Expanded(child: LinearProgressIndicator(value: p, color: color, backgroundColor: ClvColors.navy700)),
      const SizedBox(width: 8),
      Text(label, style: TextStyle(color: color, fontSize: 12)),
    ]);
  }
}
