import 'package:material_ui/material_ui.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../core/api_client.dart';
import '../core/app_state.dart';
import 'scan_screen.dart';
import 'theme.dart';
import 'widgets.dart';

/// New device: show a QR code for a phone that is already signed in.
class ShowLinkQrScreen extends StatefulWidget {
  const ShowLinkQrScreen({super.key, required this.app});
  final AppState app;
  @override
  State<ShowLinkQrScreen> createState() => _ShowLinkQrScreenState();
}

class _ShowLinkQrScreenState extends State<ShowLinkQrScreen> {
  final server = TextEditingController(text: defaultServer);
  LinkStart? link;
  String? status;
  bool closed = false;
  bool showServer = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _start());
  }

  @override
  void dispose() {
    closed = true;
    super.dispose();
  }

  Future<void> _start() async {
    setState(() {
      link = null;
      status = null;
    });
    try {
      final l = await widget.app.startLink(server.text.trim());
      if (!mounted) return;
      setState(() => link = l);
      final ok = await widget.app.waitForLink(l, cancelled: () => closed);
      if (!mounted) return;
      if (ok) {
        Navigator.of(context).popUntil((r) => r.isFirst);
      } else {
        setState(() => status = 'The code expired or was declined.');
      }
    } catch (e) {
      if (mounted) setState(() => status = e.toString());
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Sign in with QR code')),
      body: ListView(padding: const EdgeInsets.all(24), children: [
        const Text(
          'On your phone, open Clavium, go to Settings and choose "Sign in another device", then scan this code.',
          style: TextStyle(color: ClvColors.textDim),
        ),
        const SizedBox(height: 24),
        Center(
          child: link == null
              ? (status == null ? const Padding(padding: EdgeInsets.all(80), child: CircularProgressIndicator()) : const SizedBox())
              : Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(16)),
                  child: QrImageView(
                    key: const Key('link-qr'),
                    data: link!.qr,
                    size: 240,
                    backgroundColor: Colors.white,
                    errorCorrectionLevel: QrErrorCorrectLevel.M,
                  ),
                ),
        ),
        if (link != null) ...[
          const SizedBox(height: 16),
          Text('Your phone should show', textAlign: TextAlign.center, style: const TextStyle(color: ClvColors.textDim)),
          Text(link!.code, key: const Key('link-code'), textAlign: TextAlign.center,
              style: const TextStyle(fontSize: 28, letterSpacing: 4, fontFamily: 'monospace', color: ClvColors.gold400)),
          const SizedBox(height: 8),
          const Text('Waiting for approval…', textAlign: TextAlign.center, style: TextStyle(color: ClvColors.textDim)),
        ],
        if (status != null) ...[
          const SizedBox(height: 16),
          Text(status!, textAlign: TextAlign.center, style: const TextStyle(color: ClvColors.danger)),
          const SizedBox(height: 8),
          FilledButton(onPressed: _start, child: const Text('Show a new code')),
        ],
        const SizedBox(height: 24),
        TextButton(
          onPressed: () => setState(() => showServer = !showServer),
          child: Text(showServer ? 'Hide server' : 'Company server (self-hosted)?'),
        ),
        if (showServer)
          TextField(controller: server, decoration: InputDecoration(labelText: 'Server', suffixIcon: IconButton(icon: const Icon(Icons.refresh), onPressed: _start))),
        const SizedBox(height: 8),
        const Text(
          'Only the phone that scans this can approve it, and your vault travels end-to-end encrypted. '
          'Next time this device locks you will need your master password or this device\'s biometrics.',
          style: TextStyle(color: ClvColors.textDim, fontSize: 12),
        ),
      ]),
    );
  }
}

/// Approving phone: scan another device's QR code and approve it.
Future<void> scanAndApproveLink(BuildContext context, AppState app, {String? scanned}) async {
  final value = scanned ??
      await Navigator.of(context).push<String>(
        MaterialPageRoute(builder: (_) => const ScanScreen(accept: _isLink, title: 'Scan sign-in QR code')),
      );
  if (value == null || !context.mounted) return;
  LinkInspection l;
  try {
    l = await app.inspectLink(value);
  } catch (e) {
    if (context.mounted) showError(context, e);
    return;
  }
  if (!context.mounted) return;
  final ok = await showDialog<bool>(
    context: context,
    builder: (c) => AlertDialog(
      title: const Text('Sign in this device?'),
      content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text('${l.deviceName}${l.platform.isEmpty ? '' : ' (${l.platform})'}', style: const TextStyle(fontWeight: FontWeight.w600)),
        if (l.ip.isNotEmpty) Text('Network address ${l.ip}', style: const TextStyle(color: ClvColors.textDim)),
        const SizedBox(height: 16),
        const Text('Check the other screen shows:'),
        Text(l.code, style: const TextStyle(fontSize: 26, letterSpacing: 4, fontFamily: 'monospace', color: ClvColors.gold400)),
        const SizedBox(height: 16),
        const Text(
          'It will get full access to your vault. Only approve a device you are holding or sitting at. '
          'Never approve a code someone else sent you.',
          style: TextStyle(color: ClvColors.textDim, fontSize: 13),
        ),
      ]),
      actions: [
        TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Decline')),
        FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('Approve')),
      ],
    ),
  );
  try {
    if (ok == true) {
      await app.approveLink(l);
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('${l.deviceName} is signed in.')));
      }
    } else {
      await app.denyLink(l);
    }
  } catch (e) {
    if (context.mounted) showError(context, e);
  }
}

bool _isLink(String v) => v.startsWith('clavium://link');
