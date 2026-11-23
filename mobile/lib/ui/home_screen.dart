import 'package:material_ui/material_ui.dart';

import '../core/app_state.dart';
import 'codes_tab.dart';
import 'generator_tab.dart';
import 'settings_tab.dart';
import 'vault_tab.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key, required this.app});
  final AppState app;
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int tab = 0;

  @override
  Widget build(BuildContext context) {
    final pages = [
      VaultTab(app: widget.app),
      CodesTab(app: widget.app),
      const GeneratorTab(),
      SettingsTab(app: widget.app),
    ];
    return Scaffold(
      body: pages[tab],
      bottomNavigationBar: NavigationBar(
        selectedIndex: tab,
        onDestinationSelected: (i) => setState(() => tab = i),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.lock_outline), label: 'Vault'),
          NavigationDestination(icon: Icon(Icons.pin_outlined), label: 'Codes'),
          NavigationDestination(icon: Icon(Icons.casino_outlined), label: 'Generator'),
          NavigationDestination(icon: Icon(Icons.settings_outlined), label: 'Settings'),
        ],
      ),
    );
  }
}
