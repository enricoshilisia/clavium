import 'dart:math';

import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';
import 'package:share_plus/share_plus.dart';

import '../core/app_state.dart';
import '../core/models.dart';
import '../core/native.dart';
import 'theme.dart';
import 'widgets.dart';

const _expiry = {1: '1 hour', 24: '1 day', 168: '7 days', 720: '30 days'};
const _views = {1: 'once', 2: '2 times', 3: '3 times', 5: '5 times', 10: '10 times'};

String _passphrase() {
  const w = ['simba', 'jua', 'mvua', 'mlima', 'ziwa', 'nyota', 'pwani', 'bahari', 'kahawa', 'chai', 'mango', 'baobab', 'safari', 'tembo', 'twiga', 'kiboko', 'duma', 'mto', 'upepo', 'mwezi'];
  final r = Random.secure();
  return '${w[r.nextInt(w.length)]}-${w[r.nextInt(w.length)]}-${w[r.nextInt(w.length)]}-${r.nextInt(100)}';
}

/// Share an item (or, with [record] null, a note) as a one-time link.
Future<void> showShareSheet(BuildContext context, AppState app, VaultRecord? record) => showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      isScrollControlled: true,
      builder: (_) => Padding(
        padding: EdgeInsets.only(bottom: MediaQuery.viewInsetsOf(context).bottom),
        child: _ShareSheet(app: app, record: record),
      ),
    );

class _ShareSheet extends StatefulWidget {
  const _ShareSheet({required this.app, required this.record});
  final AppState app;
  final VaultRecord? record;
  @override
  State<_ShareSheet> createState() => _ShareSheetState();
}

class _ShareSheetState extends State<_ShareSheet> {
  int hours = 24;
  int views = 1;
  bool usePass = false;
  bool includeTotp = false;
  final pass = TextEditingController(text: _passphrase());
  final noteTitle = TextEditingController();
  final note = TextEditingController();
  bool busy = false;
  String? error;
  ({String url, String expiresAt})? link;

  Future<void> _create() async {
    setState(() {
      busy = true;
      error = null;
    });
    try {
      final r = widget.record;
      final out = await widget.app.createShare(
        recordId: r?.id,
        text: r == null ? note.text : null,
        title: r?.title ?? (noteTitle.text.trim().isEmpty ? 'Shared note' : noteTitle.text.trim()),
        passphrase: usePass ? pass.text : null,
        includeTotp: includeTotp,
        hours: hours,
        views: views,
      );
      setState(() => link = out);
    } catch (e) {
      setState(() => error = e is CoreException ? e.message : e.toString());
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final r = widget.record;
    return SafeArea(
      child: ListView(shrinkWrap: true, padding: const EdgeInsets.fromLTRB(20, 0, 20, 20), children: [
        Text(r == null ? 'Share a note' : 'Share "${r.title}"', style: const TextStyle(fontSize: 20, fontWeight: FontWeight.w600)),
        const SizedBox(height: 8),
        if (link == null) ...[
          const Text(
            'Makes a link that shows this to whoever opens it, then stops working. It is encrypted on this phone and the key is only in the link, so the Clavium server cannot read it. Safer than sending a password on WhatsApp.',
            style: TextStyle(color: ClvColors.textDim),
          ),
          if (r == null) ...[
            const SizedBox(height: 12),
            TextField(controller: noteTitle, decoration: const InputDecoration(labelText: 'Title', hintText: 'e.g. Office Wi-Fi')),
            const SizedBox(height: 8),
            TextField(controller: note, minLines: 3, maxLines: 6, decoration: const InputDecoration(labelText: 'Text to share'), onChanged: (_) => setState(() {})),
          ],
          const SizedBox(height: 12),
          Row(children: [
            Expanded(
              child: DropdownButtonFormField<int>(
                isExpanded: true,
                initialValue: hours,
                decoration: const InputDecoration(labelText: 'Expires after'),
                items: [for (final e in _expiry.entries) DropdownMenuItem(value: e.key, child: Text(e.value))],
                onChanged: (v) => setState(() => hours = v ?? 24),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: DropdownButtonFormField<int>(
                isExpanded: true,
                initialValue: views,
                decoration: const InputDecoration(labelText: 'Can be opened'),
                items: [for (final e in _views.entries) DropdownMenuItem(value: e.key, child: Text(e.value))],
                onChanged: (v) => setState(() => views = v ?? 1),
              ),
            ),
          ]),
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('Also require a passphrase'),
            subtitle: const Text('Tell them it another way, e.g. by phone'),
            value: usePass,
            onChanged: (v) => setState(() => usePass = v),
          ),
          if (usePass) TextField(key: const Key('share-passphrase'), controller: pass, decoration: const InputDecoration(labelText: 'Passphrase')),
          if (r?.totpSecret != null)
            CheckboxListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Include the 2FA secret'),
              subtitle: const Text('Usually better to set up 2FA again'),
              value: includeTotp,
              onChanged: (v) => setState(() => includeTotp = v ?? false),
            ),
          if (error != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(error!, style: const TextStyle(color: ClvColors.danger))),
          const SizedBox(height: 12),
          FilledButton(
            key: const Key('create-share'),
            onPressed: busy || (r == null && note.text.trim().isEmpty) ? null : _create,
            child: Text(busy ? 'Encrypting…' : 'Create link'),
          ),
        ] else ...[
          Text('It works ${_views[views]} and expires ${DateTime.parse(link!.expiresAt).toLocal().toString().substring(0, 16)}.',
              style: const TextStyle(color: ClvColors.textDim)),
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(color: ClvColors.navy900, borderRadius: BorderRadius.circular(10)),
            child: SelectableText(link!.url, key: const Key('share-link'), style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
          ),
          const SizedBox(height: 12),
          Row(children: [
            Expanded(
              child: FilledButton.icon(
                icon: const Icon(Icons.ios_share),
                label: const Text('Send'),
                onPressed: () => SharePlus.instance.share(ShareParams(text: link!.url)),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: OutlinedButton.icon(
                icon: const Icon(Icons.copy),
                label: const Text('Copy'),
                onPressed: () async {
                  await Clipboard.setData(ClipboardData(text: link!.url));
                  if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Link copied')));
                },
              ),
            ),
          ]),
          if (usePass)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Text('Passphrase: ${pass.text}. Give it to them separately, not in the same message.', style: const TextStyle(color: ClvColors.gold400)),
            ),
        ],
      ]),
    );
  }
}

/// Coloured verdict for a web address.
class VerdictCard extends StatelessWidget {
  const VerdictCard({super.key, required this.check});
  final Map<String, dynamic> check;

  @override
  Widget build(BuildContext context) {
    final v = check['verdict'] as String;
    final color = {'trusted': ClvColors.success, 'unknown': ClvColors.textDim, 'suspicious': ClvColors.gold500, 'dangerous': ClvColors.danger}[v]!;
    final title = {
      'trusted': 'Looks genuine',
      'unknown': 'Not known to Clavium',
      'suspicious': 'Be careful',
      'dangerous': check['imitates'] != null ? 'Fake: pretends to be ${check['imitates']}' : 'Looks like a fake site',
    }[v]!;
    return Container(
      key: const Key('verdict'),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        border: Border.all(color: color.withValues(alpha: 0.5)),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(title, style: TextStyle(fontWeight: FontWeight.w700, fontSize: 16, color: v == 'unknown' ? null : color)),
        if ((check['host'] as String).isNotEmpty) Text(check['host'] as String, style: const TextStyle(color: ClvColors.textDim, fontSize: 12)),
        const SizedBox(height: 6),
        for (final r in (check['reasons'] as List)) Padding(padding: const EdgeInsets.only(bottom: 4), child: Text(r as String)),
        if (check['official'] != null) Text('Go to the real site by typing ${check['official']} yourself, not by tapping a link.'),
      ]),
    );
  }
}

class LinkCheckScreen extends StatefulWidget {
  const LinkCheckScreen({super.key, required this.app, this.initial});
  final AppState app;
  final String? initial;
  @override
  State<LinkCheckScreen> createState() => _LinkCheckScreenState();
}

class _LinkCheckScreenState extends State<LinkCheckScreen> {
  late final url = TextEditingController(text: widget.initial ?? '');
  Map<String, dynamic>? result;

  @override
  void initState() {
    super.initState();
    if (widget.initial != null) result = widget.app.checkLink(widget.initial!);
  }

  void _check() {
    if (url.text.trim().isEmpty) return;
    setState(() => result = widget.app.checkLink(url.text.trim()));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Check a link')),
      body: ListView(padding: const EdgeInsets.all(20), children: [
        const Text(
          'Got a link by SMS, WhatsApp or email asking you to log in, verify an M-Pesa transaction or claim a refund? Paste it here before opening it. It is checked on this phone and not sent anywhere.',
          style: TextStyle(color: ClvColors.textDim),
        ),
        const SizedBox(height: 16),
        TextField(
          key: const Key('check-url'),
          controller: url,
          keyboardType: TextInputType.url,
          decoration: InputDecoration(
            labelText: 'Link',
            hintText: 'https://…',
            suffixIcon: IconButton(
              tooltip: 'Paste',
              icon: const Icon(Icons.content_paste),
              onPressed: () async {
                final d = await Clipboard.getData(Clipboard.kTextPlain);
                if (d?.text != null) {
                  url.text = d!.text!.trim();
                  _check();
                }
              },
            ),
          ),
          onSubmitted: (_) => _check(),
        ),
        const SizedBox(height: 12),
        FilledButton(key: const Key('check-button'), onPressed: _check, child: const Text('Check')),
        if (result != null) ...[const SizedBox(height: 16), VerdictCard(check: result!)],
      ]),
    );
  }
}

class SharedLinksScreen extends StatefulWidget {
  const SharedLinksScreen({super.key, required this.app});
  final AppState app;
  @override
  State<SharedLinksScreen> createState() => _SharedLinksScreenState();
}

class _SharedLinksScreenState extends State<SharedLinksScreen> {
  List<Map<String, dynamic>>? rows;
  String? error;
  static const status = {
    'active': 'Waiting to be opened',
    'used': 'Opened',
    'expired': 'Expired',
    'revoked': 'Cancelled',
    'locked': 'Locked after wrong passphrases',
  };

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final r = await widget.app.listShares();
      if (mounted) setState(() => rows = r);
    } catch (e) {
      if (mounted) setState(() => error = e.toString());
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Shared links')),
      floatingActionButton: widget.app.shareAllowed
          ? FloatingActionButton.extended(
              icon: const Icon(Icons.note_add_outlined),
              label: const Text('Share a note'),
              onPressed: () async {
                await showShareSheet(context, widget.app, null);
                _load();
              },
            )
          : null,
      body: rows == null
          ? Center(child: error != null ? Text(error!) : const CircularProgressIndicator())
          : rows!.isEmpty
              ? const Center(child: Text('Nothing shared yet. Open an item and choose Share link.', style: TextStyle(color: ClvColors.textDim)))
              : ListView(children: [
                  for (final r in rows!)
                    ListTile(
                      title: Text((r['title'] as String?) ?? 'Shared item'),
                      subtitle: Text('${status[r['status']]} · opened ${r['views']} of ${r['max_views']}${r['has_passphrase'] == true ? ' · passphrase' : ''}'),
                      trailing: r['status'] == 'active'
                          ? TextButton(
                              onPressed: () async {
                                try {
                                  await widget.app.revokeShare(r['id'] as String);
                                  await _load();
                                } catch (e) {
                                  if (context.mounted) showError(context, e);
                                }
                              },
                              child: const Text('Cancel'),
                            )
                          : null,
                    ),
                ]),
    );
  }
}
