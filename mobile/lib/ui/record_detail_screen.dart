import 'package:material_ui/material_ui.dart';

import '../core/app_state.dart';
import '../core/models.dart';
import 'record_edit_screen.dart';
import 'theme.dart';
import 'totp_view.dart';
import 'widgets.dart';

class RecordDetailScreen extends StatelessWidget {
  const RecordDetailScreen({super.key, required this.app, required this.id});
  final AppState app;
  final String id;

  Future<void> _pickCategory(BuildContext context, VaultRecord r) async {
    final choice = await showModalBottomSheet<String>(
      context: context,
      showDragHandle: true,
      builder: (_) => SafeArea(
        child: ListView(shrinkWrap: true, children: [
          ListTile(
            leading: const Icon(Icons.auto_awesome),
            title: const Text('Automatic'),
            subtitle: const Text('Let Clavium decide from the site and type'),
            onTap: () => Navigator.pop(context, ''),
          ),
          for (final c in app.categories.where((c) => c.slug != 'uncategorized'))
            ListTile(
              leading: Icon(categoryIcon(c.slug)),
              title: Text(c.label),
              selected: c.slug == r.category,
              onTap: () => Navigator.pop(context, c.slug),
            ),
        ]),
      ),
    );
    if (choice == null) return;
    try {
      await app.setCategory(r.id, choice.isEmpty ? null : choice, learn: true);
    } catch (e) {
      if (context.mounted) showError(context, e);
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: app,
      builder: (context, _) {
        final r = app.get(id);
        if (r == null) return const Scaffold(body: Center(child: Text('This item was deleted.')));
        final catLabel = app.categories.where((c) => c.slug == r.category).map((c) => c.label).firstOrNull ?? 'Uncategorised';
        return Scaffold(
          appBar: AppBar(
            title: Text(r.title),
            actions: [
              IconButton(
                tooltip: r.favorite ? 'Remove from favourites' : 'Add to favourites',
                icon: Icon(r.favorite ? Icons.star : Icons.star_outline, color: r.favorite ? ClvColors.gold500 : null),
                onPressed: () => app.toggleFavorite(r.id),
              ),
              IconButton(
                tooltip: 'Edit',
                icon: const Icon(Icons.edit_outlined),
                onPressed: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => RecordEditScreen(app: app, record: r))),
              ),
              PopupMenuButton<String>(
                onSelected: (v) async {
                  if (v != 'delete') return;
                  final ok = await showDialog<bool>(
                    context: context,
                    builder: (c) => AlertDialog(
                      title: Text('Delete "${r.title}"?'),
                      content: const Text('It is removed from every device this vault syncs to.'),
                      actions: [
                        TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
                        FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('Delete')),
                      ],
                    ),
                  );
                  if (ok == true) {
                    await app.deleteRecord(r.id);
                    if (context.mounted) Navigator.of(context).pop();
                  }
                },
                itemBuilder: (_) => const [PopupMenuItem(value: 'delete', child: Text('Delete'))],
              ),
            ],
          ),
          body: ListView(children: [
            ListTile(
              leading: Icon(kindIcon(r.kind), color: ClvColors.blue300),
              title: Text(kindLabels[r.kind] ?? r.kind),
              subtitle: Text([catLabel, if (r.folder != null) r.folder!].join(' · ')),
              trailing: TextButton.icon(
                icon: Icon(categoryIcon(r.category ?? 'uncategorized'), size: 16),
                label: Text(r.categoryByUser ? 'Change' : 'Auto · change'),
                onPressed: () => _pickCategory(context, r),
              ),
            ),
            const Divider(),
            if (r.username.isNotEmpty) FieldTile(label: 'Username', value: r.username),
            if (r.password.isNotEmpty) FieldTile(label: 'Password', value: r.password, secret: true),
            if (r.totpSecret != null)
              ListTile(
                title: const Text('Authenticator code', style: TextStyle(fontSize: 12, color: ClvColors.textDim)),
                subtitle: Padding(padding: const EdgeInsets.only(top: 6), child: TotpView(secret: r.totpSecret!)),
              ),
            if (r.url.isNotEmpty) FieldTile(label: 'Website', value: r.url),
            for (final e in r.fields.entries)
              FieldTile(
                label: fieldLabel(e.key),
                value: e.value,
                secret: secretFields.contains(e.key),
                monospace: multilineFields.contains(e.key),
              ),
            for (final f in r.customFields)
              FieldTile(label: f['name'] as String, value: f['value'] as String, secret: f['hidden'] == true),
            if (r.notes.isNotEmpty) FieldTile(label: 'Notes', value: r.notes),
            if (r.tags.isNotEmpty)
              Padding(
                padding: const EdgeInsets.all(16),
                child: Wrap(spacing: 6, children: [for (final t in r.tags) Chip(label: Text('#$t'))]),
              ),
            Padding(
              padding: const EdgeInsets.all(16),
              child: Text('Last changed ${r.updatedAt.toLocal().toString().substring(0, 16)}',
                  style: const TextStyle(color: ClvColors.textDim, fontSize: 12)),
            ),
          ]),
        );
      },
    );
  }
}
