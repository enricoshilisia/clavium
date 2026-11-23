import 'package:material_ui/material_ui.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

bool _isOtpauth(String v) => v.startsWith('otpauth://');

/// Scans a QR code (an authenticator otpauth:// link by default).
class ScanScreen extends StatefulWidget {
  const ScanScreen({super.key, this.accept = _isOtpauth, this.title = 'Scan QR code'});

  /// Which scanned values this screen returns.
  final bool Function(String) accept;
  final String title;
  @override
  State<ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<ScanScreen> {
  bool done = false;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(widget.title)),
      body: MobileScanner(
        onDetect: (capture) {
          if (done) return;
          for (final b in capture.barcodes) {
            final v = b.rawValue;
            if (v != null && widget.accept(v)) {
              done = true;
              Navigator.of(context).pop(v);
              return;
            }
          }
        },
      ),
    );
  }
}
