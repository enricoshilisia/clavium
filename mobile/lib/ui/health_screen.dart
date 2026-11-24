import 'package:material_ui/material_ui.dart';

import '../core/app_state.dart';
import 'record_detail_screen.dart';
import 'theme.dart';
import 'widgets.dart';

class HealthScreen extends StatelessWidget {
  const HealthScreen({super.key, required this.app});
  final AppState app;

  @override
  Widget build(BuildContext context) => ListenableBuilder(listenable: app, builder: (context, _) => _build(context));

  Widget _build(BuildContext context) {
    final h = app.health();
    final breached = app.breachHits.where((x) => x['team_id'] == null && app.get(x['id'] as String) != null).toList();
    final teamBreached = app.breachHits.where((x) => x['team_id'] != null).length;
    final score = h['score'] as int;
    final weak = (h['weak'] as List).cast<String>();
    final reused = (h['reused'] as List).map((g) => (g as List).cast<String>()).toList();
    final old = (h['old'] as List).cast<String>();
    final noTotp = (h['without_totp'] as List).cast<String>();
    final color = score >= 80 ? ClvColors.success : (score >= 50 ? ClvColors.gold500 : ClvColors.danger);

    Widget section(String title, String help, List<String> ids) => ExpansionTile(
          title: Text('$title (${ids.length})'),
          subtitle: Text(help, style: const TextStyle(color: ClvColors.textDim, fontSize: 12)),
          children: [
            for (final id in ids)
              Builder(builder: (context) {
                final r = app.get(id);
                if (r == null) return const SizedBox();
                return ListTile(
                  title: Text(r.title),
                  subtitle: Text(r.subtitle),
                  onTap: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => RecordDetailScreen(app: app, id: id))),
                );
              }),
          ],
        );

    return Scaffold(
      appBar: AppBar(title: const Text('Password health')),
      body: ListView(children: [
        Padding(
          padding: const EdgeInsets.all(24),
          child: Column(children: [
            Text('$score', style: TextStyle(fontSize: 64, color: color, fontWeight: FontWeight.w300)),
            const Text('out of 100', style: TextStyle(color: ClvColors.textDim)),
            const SizedBox(height: 8),
            const Text('Worked out on this device. Your passwords are never sent anywhere.',
                style: TextStyle(color: ClvColors.textDim, fontSize: 12)),
          ]),
        ),
        ExpansionTile(
          key: const Key('breached-section'),
          initiallyExpanded: breached.isNotEmpty,
          title: Text(app.breachCheckedAt == null ? 'Breached (not checked yet)' : 'Breached (${breached.length})',
              style: TextStyle(color: breached.isEmpty ? null : ClvColors.danger)),
          subtitle: const Text('Found in leaked password lists: change these first', style: TextStyle(color: ClvColors.textDim, fontSize: 12)),
          children: [
            for (final b in breached)
              ListTile(
                title: Text(b['title'] as String),
                subtitle: Text('Seen ${b['count']} times in leaks'),
                onTap: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => RecordDetailScreen(app: app, id: b['id'] as String))),
              ),
            if (teamBreached > 0)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Text('Also $teamBreached in team vaults (open the team vault to see them).', style: const TextStyle(color: ClvColors.textDim)),
              ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
              child: Row(children: [
                FilledButton.tonal(
                  key: const Key('check-breaches'),
                  onPressed: app.breachChecking
                      ? null
                      : () => app.checkBreaches().catchError((Object e) {
                            if (context.mounted) showError(context, e);
                          }),
                  child: Text(app.breachChecking ? 'Checking…' : 'Check now'),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    app.breachCheckedAt == null ? 'Not checked yet.' : 'Checked ${TimeOfDay.fromDateTime(app.breachCheckedAt!).format(context)}.',
                    style: const TextStyle(color: ClvColors.textDim, fontSize: 12),
                  ),
                ),
              ]),
            ),
            const Padding(
              padding: EdgeInsets.fromLTRB(16, 0, 16, 4),
              child: Text(
                'Only a 5-character fingerprint of each password goes to Have I Been Pwned. The password itself never leaves this device.',
                style: TextStyle(color: ClvColors.textDim, fontSize: 12),
              ),
            ),
            FutureBuilder<bool>(
              future: app.breachAutoEnabled(),
              builder: (context, snap) => SwitchListTile(
                title: const Text('Check automatically'),
                value: snap.data ?? true,
                onChanged: (v) => app.setBreachAuto(v),
              ),
            ),
          ],
        ),
        section('Weak', 'Short, common or predictable', weak),
        section('Reused', 'The same password on more than one site', reused.expand((g) => g).toList()),
        section('Old', 'Not changed in over a year', old),
        section('No two-factor code', 'Logins without an authenticator code', noTotp),
        _EmailBreaches(app: app),
      ]),
    );
  }
}


class _EmailBreaches extends StatefulWidget {
  const _EmailBreaches({required this.app});
  final AppState app;
  @override
  State<_EmailBreaches> createState() => _EmailBreachesState();
}

class _EmailBreachesState extends State<_EmailBreaches> {
  Map<String, dynamic>? st;

  @override
  void initState() {
    super.initState();
    widget.app.emailBreaches().then((v) {
      if (mounted) setState(() => st = v);
    });
  }

  @override
  Widget build(BuildContext context) {
    final s = st;
    if (s == null || s['available'] != true) return const SizedBox.shrink();
    final list = (s['breaches'] as List).cast<Map>();
    final email = widget.app.session?.email ?? 'Your email';
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 24),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('Your email in data breaches', style: TextStyle(fontWeight: FontWeight.w600, fontSize: 16)),
        const SizedBox(height: 6),
        if (s['monitored'] != true)
          const Text('Find out if your email address shows up in known data breaches. Only the address is sent to Have I Been Pwned.',
              style: TextStyle(color: ClvColors.textDim))
        else if (list.isEmpty)
          Text('$email was not found in any known breach.', style: const TextStyle(color: ClvColors.textDim))
        else ...[
          Text('$email appeared in ${list.length} breach${list.length == 1 ? '' : 'es'}. Change your password on these sites and anywhere you reused it:',
              style: const TextStyle(color: ClvColors.danger)),
          for (final b in list.take(8))
            Padding(
              padding: const EdgeInsets.only(top: 6),
              child: Text('${b['title']} (${b['date']}): ${(b['data'] as List).take(4).join(', ')}'),
            ),
        ],
        const SizedBox(height: 8),
        if (s['monitored'] != true || s['opted_in'] == true)
          OutlinedButton(
            onPressed: () async {
              try {
                final v = await widget.app.setEmailBreachCheck(s['opted_in'] != true);
                if (mounted) setState(() => st = v);
              } catch (e) {
                if (context.mounted) showError(context, e);
              }
            },
            child: Text(s['opted_in'] == true ? 'Stop checking my email' : 'Check my email'),
          )
        else
          const Text('Your organization checks this address every week.', style: TextStyle(color: ClvColors.textDim, fontSize: 12)),
      ]),
    );
  }
}
