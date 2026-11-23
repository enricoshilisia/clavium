import 'package:material_ui/material_ui.dart';

import '../core/app_state.dart';
import '../core/models.dart';
import 'record_detail_screen.dart';
import 'record_edit_screen.dart';
import 'theme.dart';
import 'widgets.dart';

class VaultTab extends StatelessWidget {
  const VaultTab({super.key, required this.app});
  final AppState app;

  Future<void> _new(BuildContext context) async {
    final kind = await showModalBottomSheet<String>(
      context: context,
      showDragHandle: true,
      builder: (_) => SafeArea(
        child: ListView(shrinkWrap: true, children: [
          for (final e in kindLabels.entries.where((e) => e.key != 'passkey'))
            ListTile(
              leading: Icon(kindIcon(e.key)),
              title: Text(e.value),
              onTap: () => Navigator.pop(context, e.key),
            ),
        ]),
      ),
    );
    if (kind != null && context.mounted) {
      await Navigator.of(context).push(MaterialPageRoute(builder: (_) => RecordEditScreen(app: app, kind: kind)));
    }
  }

  @override
  Widget build(BuildContext context) {
    final cats = app.categories.where((c) => c.count > 0).toList();
    return Scaffold(
      appBar: AppBar(
        title: const Text('Vault'),
        actions: [
          if (app.session != null)
            IconButton(
              tooltip: app.syncError ?? 'Sync now',
              onPressed: app.syncing ? null : app.syncNow,
              icon: app.syncing
                  ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
                  : Icon(app.syncError == null ? Icons.cloud_done_outlined : Icons.cloud_off, color: app.syncError == null ? null : ClvColors.danger),
            ),
          IconButton(tooltip: 'Lock', icon: const Icon(Icons.lock_outline), onPressed: app.lock),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        key: const Key('add-record'),
        backgroundColor: ClvColors.gold500,
        foregroundColor: ClvColors.navy950,
        onPressed: () => _new(context),
        child: const Icon(Icons.add),
      ),
      body: Column(children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 4, 16, 8),
          child: TextField(
            key: const Key('search'),
            decoration: const InputDecoration(prefixIcon: Icon(Icons.search), hintText: 'Search'),
            onChanged: app.setQuery,
          ),
        ),
        SizedBox(
          height: 44,
          child: ListView(scrollDirection: Axis.horizontal, padding: const EdgeInsets.symmetric(horizontal: 12), children: [
            _chip('All', null, app.categoryFilter == null && !app.favoritesOnly, () {
              app.setFavoritesOnly(false);
              app.setCategoryFilter(null);
            }),
            _chip('Favourites', Icons.star_outline, app.favoritesOnly, () => app.setFavoritesOnly(!app.favoritesOnly)),
            for (final c in cats)
              _chip('${c.label} · ${c.count}', categoryIcon(c.slug), app.categoryFilter == c.slug,
                  () => app.setCategoryFilter(app.categoryFilter == c.slug ? null : c.slug)),
          ]),
        ),
        if (app.syncNotice != null)
          MaterialBanner(content: Text(app.syncNotice!), actions: [TextButton(onPressed: () {}, child: const Text('OK'))]),
        Expanded(
          child: app.records.isEmpty
              ? Center(
                  child: Text(
                    app.query.isEmpty && app.categoryFilter == null ? 'Nothing here yet. Tap + to add your first item.' : 'No matches.',
                    style: const TextStyle(color: ClvColors.textDim),
                  ),
                )
              : ListView.builder(
                  itemCount: app.records.length,
                  itemBuilder: (context, i) => _RecordRow(app: app, record: app.records[i]),
                ),
        ),
      ]),
    );
  }

  Widget _chip(String label, IconData? icon, bool selected, VoidCallback onTap) => Padding(
        padding: const EdgeInsets.symmetric(horizontal: 4),
        child: FilterChip(
          label: Text(label),
          avatar: icon == null ? null : Icon(icon, size: 16),
          selected: selected,
          onSelected: (_) => onTap(),
        ),
      );
}

class _RecordRow extends StatelessWidget {
  const _RecordRow({required this.app, required this.record});
  final AppState app;
  final VaultRecord record;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: CircleAvatar(
        backgroundColor: ClvColors.navy700,
        child: Icon(kindIcon(record.kind), color: ClvColors.blue300, size: 20),
      ),
      title: Row(children: [
        Flexible(child: Text(record.title, overflow: TextOverflow.ellipsis)),
        if (record.favorite) const Padding(padding: EdgeInsets.only(left: 6), child: Icon(Icons.star, size: 14, color: ClvColors.gold500)),
      ]),
      subtitle: Text(record.subtitle, maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(color: ClvColors.textDim)),
      trailing: record.password.isNotEmpty
          ? IconButton(
              tooltip: 'Copy password',
              icon: const Icon(Icons.key, size: 20),
              onPressed: () => copySecret(context, record.password, 'Password'),
            )
          : null,
      onTap: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => RecordDetailScreen(app: app, id: record.id))),
    );
  }
}
