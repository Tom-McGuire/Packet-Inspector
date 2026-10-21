import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'data/repositories/packet_repository.dart';
import 'ui/features/inspector/view_models/inspector_view_model.dart';
import 'ui/features/capture/view_models/capture_view_model.dart';
import 'ui/features/inspector/views/inspector_screen.dart';
import 'ui/features/ai_assistant/views/ai_assistant_panel.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const PacketInspectorApp());
}

class PacketInspectorApp extends StatelessWidget {
  const PacketInspectorApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider(
          create: (_) => InspectorViewModel(repository: PacketRepository()),
        ),
        ChangeNotifierProvider(
          create: (_) => CaptureViewModel(),
        ),
      ],
      child: MaterialApp(
        title: 'Packet Inspector',
        debugShowCheckedModeBanner: false,
        themeMode: ThemeMode.dark,
        theme: ThemeData(
          useMaterial3: true,
          colorSchemeSeed: Colors.indigo,
          brightness: Brightness.light,
        ),
        darkTheme: ThemeData(
          useMaterial3: true,
          colorSchemeSeed: Colors.indigo,
          brightness: Brightness.dark,
          scaffoldBackgroundColor: const Color(0xFF121418),
        ),
        home: const InspectorScreen(
          aiPanelSlot: AiAssistantPanel(),
        ),
      ),
    );
  }
}
