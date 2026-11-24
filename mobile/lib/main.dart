import 'package:local_auth/local_auth.dart';
import 'package:material_ui/material_ui.dart';

import 'core/api_client.dart';
import 'core/app_state.dart';
import 'core/storage.dart';
import 'ui/autofill_screen.dart';
import 'ui/home_screen.dart';
import 'ui/onboarding_screen.dart';
import 'ui/theme.dart';
import 'ui/unlock_screen.dart';

class DeviceBiometrics implements BiometricPrompt {
  final _auth = LocalAuthentication();
  @override
  Future<bool> available() async {
    try {
      return await _auth.isDeviceSupported();
    } catch (_) {
      return false;
    }
  }

  @override
  Future<bool> authenticate(String reason) async {
    try {
      return await _auth.authenticate(localizedReason: reason);
    } catch (_) {
      return false;
    }
  }
}

/// Entry point for Android's "Fill from Clavium" screen (AutofillActivity).
@pragma('vm:entry-point')
void autofillMain() {
  WidgetsFlutterBinding.ensureInitialized();
  final app = AppState(storage: DeviceStorage(), api: ApiClient(), biometrics: DeviceBiometrics(), liveSync: false);
  runApp(AutofillApp(app: app));
}

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final app = AppState(storage: DeviceStorage(), api: ApiClient(), biometrics: DeviceBiometrics());
  app.init();
  runApp(ClaviumApp(app: app));
}

class ClaviumApp extends StatefulWidget {
  const ClaviumApp({super.key, required this.app});
  final AppState app;
  @override
  State<ClaviumApp> createState() => _ClaviumAppState();
}

class _ClaviumAppState extends State<ClaviumApp> with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused || state == AppLifecycleState.hidden) {
      widget.app.onBackgrounded();
    } else if (state == AppLifecycleState.resumed) {
      widget.app.onResumed();
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Clavium',
      debugShowCheckedModeBanner: false,
      theme: claviumTheme(),
      home: ListenableBuilder(
        listenable: widget.app,
        builder: (context, _) => switch (widget.app.phase) {
          Phase.loading => const Scaffold(body: Center(child: CircularProgressIndicator())),
          Phase.onboarding => OnboardingScreen(app: widget.app),
          Phase.locked => UnlockScreen(app: widget.app),
          Phase.unlocked => HomeScreen(app: widget.app),
        },
      ),
    );
  }
}
