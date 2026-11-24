import 'dart:async';

import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/services.dart';
import 'package:image_picker/image_picker.dart';
import 'package:material_ui/material_ui.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import 'theme.dart';

bool _isOtpauth(String v) => v.startsWith('otpauth://');

/// Scans a QR code (an authenticator otpauth:// link by default).
///
/// Built for real-world conditions: QR-only detection at a high camera
/// resolution, auto zoom on Android, tap to focus, pinch or slider zoom,
/// a torch, scanning from a screenshot, pasting a copied link, and a clear
/// message when the camera sees a QR code that is not the right kind.
class ScanScreen extends StatefulWidget {
  const ScanScreen({
    super.key,
    this.accept = _isOtpauth,
    this.title = 'Scan QR code',
    this.hint = 'Point your camera at the QR code',
    this.rejectMessage = 'That QR code is not a 2FA setup code.',
  });

  /// Which scanned values this screen returns.
  final bool Function(String) accept;
  final String title;
  final String hint;

  /// Shown when a QR code is read but [accept] says no.
  final String rejectMessage;

  @override
  State<ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<ScanScreen> {
  final controller = MobileScannerController(
    formats: const [BarcodeFormat.qrCode],
    detectionSpeed: DetectionSpeed.normal,
    detectionTimeoutMs: 150,
    // Dense codes (sign-in links, long otpauth URIs) need the pixels.
    cameraResolution: const Size(1920, 1080),
    autoZoom: true,
  );

  bool done = false;
  String? notice;
  bool noticeIsError = false;
  Timer? _noticeTimer;
  double _pinchStart = 0;

  @override
  void dispose() {
    _noticeTimer?.cancel();
    controller.dispose();
    super.dispose();
  }

  void _show(String message, {bool error = true}) {
    _noticeTimer?.cancel();
    setState(() {
      notice = message;
      noticeIsError = error;
    });
    _noticeTimer = Timer(const Duration(seconds: 3), () {
      if (mounted) setState(() => notice = null);
    });
  }

  /// Returns true if one of the values was accepted.
  bool _consider(Iterable<String?> values, {bool reportMiss = true}) {
    if (done) return true;
    var sawSomething = false;
    for (final raw in values) {
      final v = raw?.trim();
      if (v == null || v.isEmpty) continue;
      sawSomething = true;
      if (widget.accept(v)) {
        done = true;
        HapticFeedback.mediumImpact();
        unawaited(controller.stop());
        Navigator.of(context).pop(v);
        return true;
      }
    }
    if (sawSomething && reportMiss && notice == null) {
      HapticFeedback.lightImpact();
      _show(widget.rejectMessage);
    }
    return false;
  }

  Future<void> _fromImage() async {
    final XFile? file;
    try {
      file = await ImagePicker().pickImage(source: ImageSource.gallery);
    } catch (_) {
      _show('Could not open your photos.');
      return;
    }
    if (file == null || !mounted) return;
    try {
      final capture = await controller.analyzeImage(file.path, formats: const [BarcodeFormat.qrCode]);
      if (!mounted) return;
      final values = capture?.barcodes.map((b) => b.rawValue) ?? const <String?>[];
      if (values.isEmpty) {
        _show('No QR code found in that picture. Try a sharper screenshot.');
      } else {
        _consider(values);
      }
    } catch (_) {
      if (mounted) _show('No QR code found in that picture.');
    }
  }

  Future<void> _paste() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (!mounted) return;
    final text = data?.text?.trim() ?? '';
    if (text.isEmpty) {
      _show('The clipboard is empty. Copy the link first.');
    } else if (!_consider([text], reportMiss: false)) {
      _show('The copied text is not the right kind of link.');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: Text(widget.title),
        actions: [
          IconButton(tooltip: 'Paste link', icon: const Icon(Icons.content_paste), onPressed: _paste),
        ],
      ),
      body: LayoutBuilder(builder: (context, constraints) {
        final side = (constraints.biggest.shortestSide * 0.72).clamp(200.0, 340.0);
        final window = Rect.fromCenter(
          center: Offset(constraints.maxWidth / 2, constraints.maxHeight * 0.42),
          width: side,
          height: side,
        );
        return GestureDetector(
          onScaleStart: (_) => _pinchStart = controller.value.zoomScale,
          onScaleUpdate: (d) {
            if (d.pointerCount < 2) return;
            controller.setZoomScale((_pinchStart + (d.scale - 1) * 0.5).clamp(0.0, 1.0));
          },
          child: Stack(fit: StackFit.expand, children: [
            // The whole frame is scanned, not only the box: a code a bit
            // off-centre still reads. The box is only a guide.
            MobileScanner(
              controller: controller,
              tapToFocus: true,
              onDetect: (capture) => _consider(capture.barcodes.map((b) => b.rawValue)),
              errorBuilder: (context, error) => _CameraProblem(error: error, onPick: _fromImage, onPaste: _paste),
            ),
            IgnorePointer(child: CustomPaint(painter: _FramePainter(window))),
            Positioned(
              left: 24,
              right: 24,
              top: window.bottom + 20,
              child: Column(children: [
                Text(
                  widget.hint,
                  textAlign: TextAlign.center,
                  style: const TextStyle(color: Colors.white, fontSize: 15, fontWeight: FontWeight.w500),
                ),
                const SizedBox(height: 4),
                const Text(
                  'Hold steady about 20 cm away. Tap to focus, pinch to zoom.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Colors.white70, fontSize: 12),
                ),
                const SizedBox(height: 12),
                AnimatedOpacity(
                  opacity: notice == null ? 0 : 1,
                  duration: const Duration(milliseconds: 180),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                    decoration: BoxDecoration(
                      color: (noticeIsError ? ClvColors.danger : ClvColors.blue500).withValues(alpha: 0.92),
                      borderRadius: BorderRadius.circular(20),
                    ),
                    child: Text(notice ?? '', key: const Key('scan-notice'), textAlign: TextAlign.center, style: const TextStyle(color: Colors.white)),
                  ),
                ),
              ]),
            ),
            Positioned(left: 0, right: 0, bottom: 0, child: _Controls(controller: controller, onPick: _fromImage)),
          ]),
        );
      }),
    );
  }
}

class _Controls extends StatelessWidget {
  const _Controls({required this.controller, required this.onPick});
  final MobileScannerController controller;
  final VoidCallback onPick;

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      top: false,
      child: Container(
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 12),
        color: Colors.black54,
        child: ValueListenableBuilder<MobileScannerState>(
          valueListenable: controller,
          builder: (context, state, _) {
            final running = state.isInitialized && state.isRunning;
            return Column(mainAxisSize: MainAxisSize.min, children: [
              // Browsers expose no camera zoom, so the slider is app-only.
              if (!kIsWeb) Row(children: [
                const Icon(Icons.zoom_out, color: Colors.white70, size: 20),
                Expanded(
                  child: Slider(
                    value: state.zoomScale.clamp(0.0, 1.0),
                    onChanged: running ? (v) => controller.setZoomScale(v) : null,
                  ),
                ),
                const Icon(Icons.zoom_in, color: Colors.white70, size: 20),
              ]),
              Row(mainAxisAlignment: MainAxisAlignment.spaceEvenly, children: [
                _RoundButton(
                  icon: state.torchState == TorchState.on ? Icons.flash_on : Icons.flash_off,
                  label: 'Light',
                  active: state.torchState == TorchState.on,
                  onTap: running && state.torchState != TorchState.unavailable ? () => controller.toggleTorch() : null,
                ),
                _RoundButton(icon: Icons.photo_library_outlined, label: 'From photo', onTap: onPick),
                _RoundButton(
                  icon: Icons.cameraswitch_outlined,
                  label: 'Flip',
                  onTap: running && (state.availableCameras ?? 2) > 1 ? () => controller.switchCamera() : null,
                ),
              ]),
            ]);
          },
        ),
      ),
    );
  }
}

class _RoundButton extends StatelessWidget {
  const _RoundButton({required this.icon, required this.label, this.onTap, this.active = false});
  final IconData icon;
  final String label;
  final VoidCallback? onTap;
  final bool active;

  @override
  Widget build(BuildContext context) {
    final enabled = onTap != null;
    return InkWell(
      borderRadius: BorderRadius.circular(32),
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          CircleAvatar(
            radius: 24,
            backgroundColor: active ? ClvColors.gold400 : Colors.white.withValues(alpha: enabled ? 0.18 : 0.08),
            child: Icon(icon, color: active ? Colors.black : (enabled ? Colors.white : Colors.white38)),
          ),
          const SizedBox(height: 4),
          Text(label, style: TextStyle(color: enabled ? Colors.white : Colors.white38, fontSize: 12)),
        ]),
      ),
    );
  }
}

class _CameraProblem extends StatelessWidget {
  const _CameraProblem({required this.error, required this.onPick, required this.onPaste});
  final MobileScannerException error;
  final VoidCallback onPick;
  final VoidCallback onPaste;

  @override
  Widget build(BuildContext context) {
    final denied = error.errorCode == MobileScannerErrorCode.permissionDenied;
    final unsupported = error.errorCode == MobileScannerErrorCode.unsupported;
    return ColoredBox(
      color: ClvColors.navy950,
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            const Icon(Icons.no_photography_outlined, size: 48, color: ClvColors.textDim),
            const SizedBox(height: 16),
            Text(
              denied ? 'Clavium needs the camera to scan' : (unsupported ? 'This device has no usable camera' : 'The camera could not start'),
              textAlign: TextAlign.center,
              style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
            ),
            const SizedBox(height: 8),
            Text(
              denied
                  ? 'Allow camera access for Clavium in your phone\'s Settings, then come back. You can also scan from a screenshot.'
                  : 'Close and reopen this screen, or scan from a screenshot instead.',
              textAlign: TextAlign.center,
              style: const TextStyle(color: ClvColors.textDim),
            ),
            const SizedBox(height: 20),
            FilledButton.icon(onPressed: onPick, icon: const Icon(Icons.photo_library_outlined), label: const Text('Scan from a photo')),
            const SizedBox(height: 8),
            TextButton.icon(onPressed: onPaste, icon: const Icon(Icons.content_paste), label: const Text('Paste a copied link')),
          ]),
        ),
      ),
    );
  }
}

/// Dims everything outside the guide box and draws gold corner brackets.
class _FramePainter extends CustomPainter {
  _FramePainter(this.window);
  final Rect window;

  @override
  void paint(Canvas canvas, Size size) {
    final box = RRect.fromRectAndRadius(window, const Radius.circular(18));
    final shade = Path()
      ..fillType = PathFillType.evenOdd
      ..addRect(Offset.zero & size)
      ..addRRect(box);
    canvas.drawPath(shade, Paint()..color = Colors.black.withValues(alpha: 0.55));

    final pen = Paint()
      ..color = ClvColors.gold400
      ..style = PaintingStyle.stroke
      ..strokeWidth = 4
      ..strokeCap = StrokeCap.round;
    const len = 34.0;
    final r = window;
    for (final (corner, dx, dy) in [
      (r.topLeft, 1.0, 1.0),
      (r.topRight, -1.0, 1.0),
      (r.bottomLeft, 1.0, -1.0),
      (r.bottomRight, -1.0, -1.0),
    ]) {
      canvas.drawLine(corner + Offset(0, dy * 18), corner + Offset(0, dy * len), pen);
      canvas.drawLine(corner + Offset(dx * 18, 0), corner + Offset(dx * len, 0), pen);
      canvas.drawArc(
        Rect.fromCircle(center: corner + Offset(dx * 18, dy * 18), radius: 18),
        _startAngle(dx, dy),
        1.5708,
        false,
        pen,
      );
    }
  }

  double _startAngle(double dx, double dy) {
    if (dx > 0 && dy > 0) return 3.1416; // top left
    if (dx < 0 && dy > 0) return -1.5708; // top right
    if (dx > 0 && dy < 0) return 1.5708; // bottom left
    return 0; // bottom right
  }

  @override
  bool shouldRepaint(_FramePainter old) => old.window != window;
}
