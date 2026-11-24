import 'package:material_ui/material_ui.dart';

import '../core/app_state.dart';
import '../core/models.dart';
import 'record_edit_screen.dart';
import 'share_screens.dart';
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
        child: ListView(
          shrinkWrap: true,
          children: [
            ListTile(
              leading: const Icon(Icons.auto_awesome),
              title: const Text('Automatic'),
              subtitle: const Text('Let Clavium decide from the site and type'),
              onTap: () => Navigator.pop(context, ''),
            ),
            for (final c in app.categories.where(
              (c) => c.slug != 'uncategorized',
            ))
              ListTile(
                leading: Icon(categoryIcon(c.slug)),
                title: Text(c.label),
                selected: c.slug == r.category,
                onTap: () => Navigator.pop(context, c.slug),
              ),
          ],
        ),
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
        if (r == null) {
          return const Scaffold(
            body: Center(child: Text('This item was deleted.')),
          );
        }
        final catLabel =
            app.categories
                .where((c) => c.slug == r.category)
                .map((c) => c.label)
                .firstOrNull ??
            'Uncategorised';
        final team = app.activeTeam;
        return Scaffold(
          appBar: AppBar(
            title: Text(r.title),
            actions: [
              if (team == null)
                IconButton(
                  tooltip: r.favorite
                      ? 'Remove from favourites'
                      : 'Add to favourites',
                  icon: Icon(
                    r.favorite ? Icons.star : Icons.star_outline,
                    color: r.favorite ? ClvColors.gold500 : null,
                  ),
                  onPressed: () => app.toggleFavorite(r.id),
                ),
              if (app.canEdit)
                IconButton(
                  tooltip: 'Edit',
                  icon: const Icon(Icons.edit_outlined),
                  onPressed: () => Navigator.of(context).push(
                    MaterialPageRoute(
                      builder: (_) => RecordEditScreen(app: app, record: r),
                    ),
                  ),
                ),
              if (app.canEdit)
                PopupMenuButton<String>(
                  onSelected: (v) async {
                    if (v == 'share') {
                      await showShareSheet(context, app, r);
                      return;
                    }
                    if (v != 'delete') return;
                    final ok = await showDialog<bool>(
                      context: context,
                      builder: (c) => AlertDialog(
                        title: Text('Delete "${r.title}"?'),
                        content: Text(
                          team == null
                              ? 'It is removed from every device this vault syncs to.'
                              : 'It is removed for everyone in ${team.name}.',
                        ),
                        actions: [
                          TextButton(
                            onPressed: () => Navigator.pop(c, false),
                            child: const Text('Cancel'),
                          ),
                          FilledButton(
                            onPressed: () => Navigator.pop(c, true),
                            child: const Text('Delete'),
                          ),
                        ],
                      ),
                    );
                    if (ok == true) {
                      await app.deleteRecord(r.id);
                      if (context.mounted) Navigator.of(context).pop();
                    }
                  },
                  itemBuilder: (_) => [
                    if (app.shareAllowed)
                      const PopupMenuItem(
                        value: 'share',
                        child: Text('Share link'),
                      ),
                    const PopupMenuItem(value: 'delete', child: Text('Delete')),
                  ],
                ),
            ],
          ),
          body: ListView(
            children: [
              ListTile(
                leading: Icon(kindIcon(r.kind), color: ClvColors.blue300),
                title: Text(kindLabels[r.kind] ?? r.kind),
                subtitle: Text(
                  [
                    if (team != null) team.name,
                    catLabel,
                    if (r.folder != null) r.folder!,
                  ].join(' · '),
                ),
                trailing: team != null
                    ? null
                    : TextButton.icon(
                        icon: Icon(
                          categoryIcon(r.category ?? 'uncategorized'),
                          size: 16,
                        ),
                        label: Text(
                          r.categoryByUser ? 'Change' : 'Auto · change',
                        ),
                        onPressed: () => _pickCategory(context, r),
                      ),
              ),
              const Divider(),
              if (r.username.isNotEmpty)
                FieldTile(label: 'Username', value: r.username),
              if (r.password.isNotEmpty)
                FieldTile(label: 'Password', value: r.password, secret: true),
              if (r.totpSecret != null)
                ListTile(
                  title: const Text(
                    'Authenticator code',
                    style: TextStyle(fontSize: 12, color: ClvColors.textDim),
                  ),
                  subtitle: Padding(
                    padding: const EdgeInsets.only(top: 6),
                    child: TotpView(secret: r.totpSecret!),
                  ),
                ),
              if (r.url.isNotEmpty) FieldTile(label: 'Website', value: r.url),
              if (r.url.isNotEmpty)
                Builder(
                  builder: (_) {
                    final c = app.checkLink(r.url);
                    if (c['verdict'] != 'dangerous' &&
                        c['verdict'] != 'suspicious') {
                      return const SizedBox.shrink();
                    }
                    return Padding(
                      padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
                      child: VerdictCard(check: c),
                    );
                  },
                ),
              for (final e in r.fields.entries)
                FieldTile(
                  label: fieldLabel(e.key),
                  value: e.value,
                  secret: secretFields.contains(e.key),
                  monospace: multilineFields.contains(e.key),
                ),
              for (final f in r.customFields)
                FieldTile(
                  label: f['name'] as String,
                  value: f['value'] as String,
                  secret: f['hidden'] == true,
                ),
              if (r.notes.isNotEmpty) FieldTile(label: 'Notes', value: r.notes),
              if (r.tags.isNotEmpty)
                Padding(
                  padding: const EdgeInsets.all(16),
                  child: Wrap(
                    spacing: 6,
                    children: [
                      for (final t in r.tags) Chip(label: Text('#$t')),
                    ],
                  ),
                ),
              Padding(
                padding: const EdgeInsets.all(16),
                child: Text(
                  'Last changed ${r.updatedAt.toLocal().toString().substring(0, 16)}',
                  style: const TextStyle(
                    color: ClvColors.textDim,
                    fontSize: 12,
                  ),
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}
