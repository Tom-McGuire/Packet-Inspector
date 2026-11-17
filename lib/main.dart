import 'dart:async';

import 'package:material_ui/material_ui.dart';
import 'package:provider/provider.dart';

import 'core/config/feature_flags.dart';
import 'core/theme/app_theme.dart';
import 'data/repositories/packet_repository.dart';
import 'data/services/storage/shared_device_database.dart';
import 'ui/features/ai_assistant/views/ai_assistant_panel.dart';
import 'ui/features/compare/view_models/capture_compare_view_model.dart';
import 'ui/features/inspector/view_models/inspector_view_model.dart';
import 'ui/features/inspector/views/inspector_screen.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final initialMode = await SharedDeviceDatabase.instance.getThemeMode();
  AppTheme.isDark = (initialMode == 'dark');
  runApp(const PacketInspectorApp());
}

class PacketInspectorApp extends StatefulWidget {
  const PacketInspectorApp({super.key, this.database});

  final SharedDeviceDatabase? database;

  @override
  State<PacketInspectorApp> createState() => _PacketInspectorAppState();
}

class _PacketInspectorAppState extends State<PacketInspectorApp> {
  StreamSubscription<void>? _dbSub;
  String _themeMode = AppTheme.isDark ? 'dark' : 'light';

  SharedDeviceDatabase get _db =>
      widget.database ?? SharedDeviceDatabase.instance;

  @override
  void initState() {
    super.initState();
    _syncTheme();
    _dbSub = _db.onDatabaseChanged.listen((_) {
      _syncTheme();
    });
  }

  Future<void> _syncTheme() async {
    final mode = await _db.getThemeMode();
    if (!mounted) return;
    if (mode != _themeMode || (mode == 'dark') != AppTheme.isDark) {
      setState(() {
        _themeMode = mode;
        AppTheme.isDark = (mode == 'dark');
      });
    }
  }

  @override
  void dispose() {
    _dbSub?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider(
          create: (_) => InspectorViewModel(repository: PacketRepository()),
        ),
        ChangeNotifierProvider(
          create: (_) => CaptureCompareViewModel(),
        ),
      ],
      child: MaterialApp(
        title: 'Packet Inspector',
        debugShowCheckedModeBanner: false,
        themeMode: AppTheme.isDark ? ThemeMode.dark : ThemeMode.light,
        theme: AppTheme.lightTheme(),
        darkTheme: AppTheme.darkTheme(),
        home: KeyedSubtree(
          key: ValueKey(_themeMode),
          child: const InspectorScreen(
            aiPanelSlot:
                FeatureFlags.enableAiAssistant ? AiAssistantPanel() : null,
          ),
        ),
      ),
    );
  }
}
