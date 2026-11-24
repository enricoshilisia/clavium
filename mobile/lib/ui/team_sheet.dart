import 'package:material_ui/material_ui.dart';

import '../core/app_state.dart';
import '../core/team_service.dart';
import 'theme.dart';
import 'widgets.dart';

/// Who is in a team vault, with key fingerprints. Managing people (adding,
/// roles, Microsoft 365 groups) is done in the desktop app; a manager's
/// phone still hands out keys and replaces them automatically.
Future<void> showTeamSheet(BuildContext context, AppState app, TeamInfo team) => showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      isScrollControlled: true,
      builder: (_) => _TeamSheet(app: app, team: team),
    );

class _TeamSheet extends StatefulWidget {
  const _TeamSheet({required this.app, required this.team});
  final AppState app;
  final TeamInfo team;
  @override
  State<_TeamSheet> createState() => _TeamSheetState();
}

class _TeamSheetState extends State<_TeamSheet> {
  Map<String, dynamic>? view;
  String? error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final v = await widget.app.teams.members(widget.app.session!, widget.team.id);
      if (mounted) setState(() => view = v);
    } catch (e) {
      if (mounted) setState(() => error = e.toString());
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = widget.team;
    final warnings = widget.app.teams.keyWarnings.where((w) => w['team'] == t.name).toList();
    return SafeArea(
      child: ConstrainedBox(
        constraints: BoxConstraints(maxHeight: MediaQuery.sizeOf(context).height * 0.8),
        child: ListView(padding: const EdgeInsets.fromLTRB(20, 0, 20, 20), shrinkWrap: true, children: [
          Text(t.name, style: const TextStyle(fontSize: 20, fontWeight: FontWeight.w600)),
          Text('${t.orgName} · ${t.role == null ? 'admin' : roleLabels[t.role]}', style: const TextStyle(color: ClvColors.textDim)),
          const SizedBox(height: 12),
          const Text('Only the people below can read this vault. Not even the Clavium server can.', style: TextStyle(color: ClvColors.textDim)),
          if (t.needsRotation)
            const Padding(
              padding: EdgeInsets.only(top: 12),
              child: Text("Someone who had access left. A manager's app replaces the key the next time it syncs.", style: TextStyle(color: ClvColors.gold400)),
            ),
          for (final w in warnings)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Text(
                "${w['email']}'s key changed (new fingerprint ${w['fingerprint']}). Check it with them in the desktop app before they get access again.",
                style: const TextStyle(color: ClvColors.danger),
              ),
            ),
          const SizedBox(height: 12),
          if (error != null) Text(error!, style: const TextStyle(color: ClvColors.danger)),
          if (view == null && error == null) const Center(child: Padding(padding: EdgeInsets.all(24), child: CircularProgressIndicator())),
          for (final m in (view?['members'] as List?) ?? [])
            ListTile(
              contentPadding: EdgeInsets.zero,
              title: Text((m['name'] as String?)?.isNotEmpty == true ? m['name'] as String : m['email'] as String),
              subtitle: Text([
                if ((m['name'] as String?)?.isNotEmpty == true) m['email'],
                m['has_key'] == true ? 'has access' : 'waiting for access',
                if (m['source'] == 'group') 'Microsoft 365 group',
                if (m['public_key'] != null) 'key ${widget.app.teams.fingerprint(m['public_key'] as String)}',
              ].join(' · ')),
              trailing: Text(roleLabels[m['role']] ?? '', style: const TextStyle(color: ClvColors.textDim)),
            ),
          if (t.canManage)
            const Padding(
              padding: EdgeInsets.only(top: 8),
              child: Text('Add people, change roles and give Microsoft 365 groups access in the Clavium desktop app.', style: TextStyle(color: ClvColors.textDim, fontSize: 13)),
            ),
          if (t.role != null && t.role != 'manager')
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: OutlinedButton(
                onPressed: () async {
                  final ok = await showDialog<bool>(
                    context: context,
                    builder: (c) => AlertDialog(
                      title: Text('Leave ${t.name}?'),
                      content: const Text('You will need a manager to add you back.'),
                      actions: [
                        TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
                        FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('Leave')),
                      ],
                    ),
                  );
                  if (ok != true) return;
                  try {
                    await widget.app.teams.leave(widget.app.session!, t.id);
                    widget.app.selectTeam(null);
                    await widget.app.syncTeams();
                    if (context.mounted) Navigator.pop(context);
                  } catch (e) {
                    if (context.mounted) showError(context, e);
                  }
                },
                child: const Text('Leave this team vault'),
              ),
            ),
        ]),
      ),
    );
  }
}
