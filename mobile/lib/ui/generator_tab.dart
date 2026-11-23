import 'package:material_ui/material_ui.dart';

import '../core/native.dart';
import 'theme.dart';
import 'widgets.dart';

class GeneratorTab extends StatefulWidget {
  const GeneratorTab({super.key});
  @override
  State<GeneratorTab> createState() => _GeneratorTabState();
}

class _GeneratorTabState extends State<GeneratorTab> {
  bool passphrase = false;
  double length = 20;
  double words = 5;
  bool upper = true, lower = true, digits = true, symbols = true;
  String value = '';
  double bits = 0;

  void regen() {
    try {
      final v = passphrase
          ? Core.call('passphrase', {'words': words.round(), 'separator': '-'}) as String
          : Core.call('generate', {'length': length.round(), 'upper': upper, 'lower': lower, 'digits': digits, 'symbols': symbols}) as String;
      final s = Core.call('password_strength', {'password': v}) as Map;
      setState(() {
        value = v;
        bits = (s['bits'] as num).toDouble();
      });
    } on CoreException catch (e) {
      showError(context, e);
    }
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => regen());
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Generator')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(children: [
              SelectableText(value, key: const Key('generated'), style: const TextStyle(fontFamily: 'monospace', fontSize: 20)),
              const SizedBox(height: 12),
              PasswordStrengthBar(bits: bits),
              const SizedBox(height: 8),
              Row(mainAxisAlignment: MainAxisAlignment.end, children: [
                IconButton(tooltip: 'New', icon: const Icon(Icons.refresh), onPressed: regen),
                IconButton(tooltip: 'Copy', icon: const Icon(Icons.copy), onPressed: () => copySecret(context, value, 'Password')),
              ]),
            ]),
          ),
        ),
        const SizedBox(height: 8),
        SegmentedButton<bool>(
          segments: const [
            ButtonSegment(value: false, label: Text('Password')),
            ButtonSegment(value: true, label: Text('Passphrase')),
          ],
          selected: {passphrase},
          onSelectionChanged: (s) {
            passphrase = s.first;
            regen();
          },
        ),
        const SizedBox(height: 16),
        if (!passphrase) ...[
          Text('Length: ${length.round()}', style: const TextStyle(color: ClvColors.textDim)),
          Slider(value: length, min: 8, max: 64, divisions: 56, onChanged: (v) => setState(() => length = v), onChangeEnd: (_) => regen()),
          for (final (label, get, set) in [
            ('Uppercase A-Z', () => upper, (bool v) => upper = v),
            ('Lowercase a-z', () => lower, (bool v) => lower = v),
            ('Digits 0-9', () => digits, (bool v) => digits = v),
            ('Symbols !@#', () => symbols, (bool v) => symbols = v),
          ])
            SwitchListTile(title: Text(label), value: get(), onChanged: (v) {
              set(v);
              regen();
            }),
        ] else ...[
          Text('Words: ${words.round()}', style: const TextStyle(color: ClvColors.textDim)),
          Slider(value: words, min: 3, max: 10, divisions: 7, onChanged: (v) => setState(() => words = v), onChangeEnd: (_) => regen()),
        ],
      ]),
    );
  }
}
