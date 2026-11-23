import 'dart:async';

import 'package:material_ui/material_ui.dart';

import '../core/native.dart';
import 'theme.dart';
import 'widgets.dart';

/// A live authenticator code with its countdown ring.
class TotpView extends StatefulWidget {
  const TotpView({super.key, required this.secret, this.large = false});
  final String secret;
  final bool large;
  @override
  State<TotpView> createState() => _TotpViewState();
}

class _TotpViewState extends State<TotpView> {
  Timer? timer;
  String code = '';
  int remaining = 30;
  int period = 30;
  String? error;

  void _tick() {
    try {
      final r = Core.call('totp', {'secret': widget.secret}) as Map;
      setState(() {
        code = r['code'] as String;
        remaining = r['seconds_remaining'] as int;
        period = r['period'] as int;
        error = null;
      });
    } on CoreException catch (e) {
      setState(() => error = e.message);
    }
  }

  @override
  void initState() {
    super.initState();
    _tick();
    timer = Timer.periodic(const Duration(seconds: 1), (_) => _tick());
  }

  @override
  void didUpdateWidget(TotpView old) {
    super.didUpdateWidget(old);
    if (old.secret != widget.secret) _tick();
  }

  @override
  void dispose() {
    timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (error != null) return Text(error!, style: const TextStyle(color: ClvColors.danger));
    final half = code.length ~/ 2;
    final pretty = code.isEmpty ? '' : '${code.substring(0, half)} ${code.substring(half)}';
    final urgent = remaining <= 5;
    return InkWell(
      onTap: () => copySecret(context, code, 'Code'),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Text(
          pretty,
          style: TextStyle(
            fontSize: widget.large ? 32 : 22,
            fontFamily: 'monospace',
            letterSpacing: 2,
            color: urgent ? ClvColors.gold400 : ClvColors.text,
          ),
        ),
        const SizedBox(width: 12),
        SizedBox(
          width: 22,
          height: 22,
          child: CircularProgressIndicator(
            value: remaining / period,
            strokeWidth: 3,
            color: urgent ? ClvColors.gold500 : ClvColors.blue400,
            backgroundColor: ClvColors.navy700,
          ),
        ),
      ]),
    );
  }
}
