import 'package:material_ui/material_ui.dart';

import '../core/app_state.dart';
import '../core/models.dart';
import '../core/native.dart';
import 'scan_screen.dart';
import 'theme.dart';
import 'widgets.dart';

/// Add or edit any kind of record. The fields shown come from the core's
/// definition of each kind, so a new kind needs no UI change here.
class RecordEditScreen extends StatefulWidget {
  const RecordEditScreen({super.key, required this.app, this.record, this.kind, this.prefill});
  final AppState app;
  final VaultRecord? record;
  final String? kind;
  final Map<String, dynamic>? prefill;
  @override
  State<RecordEditScreen> createState() => _RecordEditScreenState();
}

class _RecordEditScreenState extends State<RecordEditScreen> {
  late Map<String, dynamic> input;
  late List<String> kindFields;
  final controllers = <String, TextEditingController>{};
  final fieldControllers = <String, TextEditingController>{};
  late TextEditingController tags;
  bool showPassword = false;
  bool busy = false;

  @override
  void initState() {
    super.initState();
    input = widget.record?.toInput() ??
        {
          'kind': widget.kind ?? 'login',
          'title': '',
          'username': '',
          'password': '',
          'url': '',
          'notes': '',
          'totp_secret': null,
          'fields': <String, String>{},
          'custom_fields': <Map<String, dynamic>>[],
          'category': null,
          'folder': null,
          'tags': <String>[],
          'favorite': false,
          ...?widget.prefill,
        };
    final kinds = (Core.call('kinds') as List).cast<Map<String, dynamic>>();
    kindFields = (kinds.firstWhere((k) => k['kind'] == input['kind'])['fields'] as List).cast<String>();
    for (final k in ['title', 'username', 'password', 'url', 'notes', 'totp_secret', 'folder']) {
      controllers[k] = TextEditingController(text: (input[k] as String?) ?? '');
    }
    final fields = Map<String, String>.from(input['fields'] as Map);
    for (final f in kindFields) {
      fieldControllers[f] = TextEditingController(text: fields[f] ?? '');
    }
    tags = TextEditingController(text: (input['tags'] as List).join(', '));
  }

  bool get _isLoginLike => const {'login', 'server', 'database', 'api_key', 'wifi', 'software_license'}.contains(input['kind']);
  bool get _hasUsername => const {'login', 'server', 'database'}.contains(input['kind']);
  bool get _hasPassword => _isLoginLike;
  bool get _hasUrl => const {'login', 'api_key', 'software_license'}.contains(input['kind']);

  Future<void> _generate() async {
    final pw = Core.call('generate', {'length': 20}) as String;
    setState(() {
      controllers['password']!.text = pw;
      showPassword = true;
    });
  }

  Future<void> _scan() async {
    final uri = await Navigator.of(context).push<String>(MaterialPageRoute(builder: (_) => const ScanScreen()));
    if (uri != null) setState(() => controllers['totp_secret']!.text = uri);
  }

  Future<void> _save() async {
    final out = Map<String, dynamic>.from(input);
    for (final e in controllers.entries) {
      out[e.key] = e.value.text;
    }
    if ((out['totp_secret'] as String).trim().isEmpty) out['totp_secret'] = null;
    if ((out['folder'] as String).trim().isEmpty) out['folder'] = null;
    out['fields'] = {for (final e in fieldControllers.entries) if (e.value.text.isNotEmpty) e.key: e.value.text};
    out['tags'] = tags.text.split(',').map((t) => t.trim()).where((t) => t.isNotEmpty).toList();
    setState(() => busy = true);
    try {
      if (widget.record == null) {
        await widget.app.addRecord(out);
      } else {
        await widget.app.updateRecord(widget.record!.id, out);
      }
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (mounted) showError(context, e);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Widget _text(String key, String label, {bool obscure = false, int lines = 1, Widget? suffix, TextInputType? type}) => Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: TextField(
          key: Key('field-$key'),
          controller: controllers[key] ?? fieldControllers[key],
          obscureText: obscure,
          maxLines: obscure ? 1 : lines,
          keyboardType: type,
          decoration: InputDecoration(labelText: label, suffixIcon: suffix),
        ),
      );

  @override
  Widget build(BuildContext context) {
    final kind = input['kind'] as String;
    final cats = widget.app.categories.where((c) => c.slug != 'uncategorized').toList();
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.record == null ? 'New ${kindLabels[kind]?.toLowerCase() ?? 'item'}' : 'Edit'),
        actions: [
          TextButton(key: const Key('save-record'), onPressed: busy ? null : _save, child: const Text('Save')),
        ],
      ),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        _text('title', 'Title'),
        if (_hasUsername) _text('username', 'Username or email'),
        if (_hasPassword)
          _text('password', kind == 'wifi' ? 'Wi-Fi password' : 'Password',
              obscure: !showPassword,
              suffix: Row(mainAxisSize: MainAxisSize.min, children: [
                IconButton(icon: Icon(showPassword ? Icons.visibility_off : Icons.visibility), onPressed: () => setState(() => showPassword = !showPassword)),
                IconButton(tooltip: 'Generate', icon: const Icon(Icons.casino_outlined), onPressed: _generate),
              ])),
        if (_hasUrl) _text('url', 'Website', type: TextInputType.url),
        for (final f in kindFields)
          _text(f, fieldLabel(f),
              obscure: secretFields.contains(f) && f != 'number',
              lines: multilineFields.contains(f) ? 4 : 1,
              type: const {'number', 'cvv', 'pin', 'port', 'account_number'}.contains(f) ? TextInputType.number : null),
        if (kind == 'login')
          _text('totp_secret', 'Authenticator secret or otpauth:// link',
              suffix: IconButton(tooltip: 'Scan QR code', icon: const Icon(Icons.qr_code_scanner), onPressed: _scan)),
        _text('notes', 'Notes', lines: 4),
        const SizedBox(height: 8),
        DropdownButtonFormField<String?>(
          initialValue: input['category'] as String?,
          isExpanded: true,
          decoration: const InputDecoration(labelText: 'Category'),
          items: [
            const DropdownMenuItem(value: null, child: Text('Automatic')),
            for (final c in cats) DropdownMenuItem(value: c.slug, child: Text(c.label)),
          ],
          onChanged: (v) => setState(() => input['category'] = v),
        ),
        const SizedBox(height: 12),
        _text('folder', 'Folder (optional)'),
        Padding(
          padding: const EdgeInsets.only(bottom: 12),
          child: TextField(controller: tags, decoration: const InputDecoration(labelText: 'Tags, comma separated')),
        ),
        SwitchListTile(
          title: const Text('Favourite'),
          value: input['favorite'] as bool,
          activeThumbColor: ClvColors.gold500,
          onChanged: (v) => setState(() => input['favorite'] = v),
        ),
      ]),
    );
  }
}
