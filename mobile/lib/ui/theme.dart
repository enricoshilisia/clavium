import 'package:material_ui/material_ui.dart';

// Clavium brand: navy/blue for trust, gold reserved for the one thing on a
// screen that deserves attention.
class ClvColors {
  static const navy950 = Color(0xFF060E1C);
  static const navy900 = Color(0xFF0A1730);
  static const navy800 = Color(0xFF102244);
  static const navy700 = Color(0xFF16305C);
  static const blue500 = Color(0xFF2A5AA0);
  static const blue400 = Color(0xFF3D74C4);
  static const blue300 = Color(0xFF6B9AD8);
  static const gold500 = Color(0xFFC9A227);
  static const gold400 = Color(0xFFD9B84A);
  static const text = Color(0xFFE9EDF5);
  static const textDim = Color(0xFF9FB0C9);
  static const danger = Color(0xFFD9534F);
  static const success = Color(0xFF3FAE6B);
}

ThemeData claviumTheme() {
  final scheme = ColorScheme.fromSeed(
    seedColor: ClvColors.blue500,
    brightness: Brightness.dark,
  ).copyWith(
    primary: ClvColors.blue400,
    onPrimary: Colors.white,
    secondary: ClvColors.gold500,
    onSecondary: ClvColors.navy950,
    surface: ClvColors.navy900,
    onSurface: ClvColors.text,
    surfaceContainerHighest: ClvColors.navy700,
    surfaceContainerHigh: ClvColors.navy800,
    surfaceContainer: ClvColors.navy800,
    error: ClvColors.danger,
  );
  return ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    scaffoldBackgroundColor: ClvColors.navy950,
    appBarTheme: const AppBarTheme(backgroundColor: ClvColors.navy950, elevation: 0, centerTitle: false),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: ClvColors.navy900,
      indicatorColor: ClvColors.blue500.withValues(alpha: 0.35),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: ClvColors.navy800,
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(10), borderSide: BorderSide.none),
    ),
    cardTheme: CardThemeData(
      color: ClvColors.navy800,
      elevation: 0,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
    ),
  );
}
