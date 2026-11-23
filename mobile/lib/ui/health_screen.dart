import 'package:material_ui/material_ui.dart';

import '../core/app_state.dart';
import 'record_detail_screen.dart';
import 'theme.dart';

class HealthScreen extends StatelessWidget {
  const HealthScreen({super.key, required this.app});
  final AppState app;

  @override
  Widget build(BuildContext context) {
    final h = app.health();
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
            Text('Checked on this device. Nothing here is sent anywhere.',
                style: const TextStyle(color: ClvColors.textDim, fontSize: 12)),
          ]),
        ),
        section('Weak', 'Short, common or predictable', weak),
        section('Reused', 'The same password on more than one site', reused.expand((g) => g).toList()),
        section('Old', 'Not changed in over a year', old),
        section('No two-factor code', 'Logins without an authenticator code', noTotp),
      ]),
    );
  }
}
