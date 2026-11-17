import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:packet_inspector/core/theme/app_theme.dart';
import 'package:packet_inspector/data/repositories/packet_repository.dart';
import 'package:packet_inspector/data/services/storage/shared_device_database.dart';
import 'package:packet_inspector/main.dart';
import 'package:packet_inspector/ui/features/inspector/view_models/inspector_view_model.dart';
import 'package:packet_inspector/ui/features/inspector/views/inspector_screen.dart';
import 'package:path/path.dart' as p;
import 'package:provider/provider.dart';

void main() {
  tearDown(() {
    AppTheme.isDark = true;
  });

  group('Issue #1: Interactive Demo Spotlight Walkthrough', () {
    testWidgets(
      'Load Demo starts 5-step guided tour and Finish & Clear auto-clears demo data',
      (tester) async {
        tester.view.physicalSize = const Size(1400, 900);
        tester.view.devicePixelRatio = 1.0;
        addTearDown(tester.view.resetPhysicalSize);

        final repo = PacketRepository();
        final vm = InspectorViewModel(repository: repo);
        addTearDown(vm.dispose);

        await tester.pumpWidget(
          MultiProvider(
            providers: [
              ChangeNotifierProvider<InspectorViewModel>.value(value: vm),
            ],
            child: const MaterialApp(
              home: InspectorScreen(),
            ),
          ),
        );
        await tester.pumpAndSettle();

        expect(vm.isDemoMode, isFalse);
        expect(vm.packets, isEmpty);
        expect(find.text('Load Demo'), findsOneWidget);

        // Click Load Demo in the top bar
        await tester.tap(find.text('Load Demo'));
        await tester.pumpAndSettle();

        expect(vm.isDemoMode, isTrue);
        expect(vm.loadedFileName, 'demo_capture.pcap');
        expect(vm.packets, isNotEmpty);
        expect(find.text('Exit Demo'), findsOneWidget);
        expect(find.text('DEMO WALKTHROUGH • STEP 1 OF 5'), findsOneWidget);
        expect(find.text('1. Open PCAP & Protocol Library'), findsOneWidget);

        // Step 2
        await tester.tap(find.text('Next'));
        await tester.pumpAndSettle();
        expect(find.text('DEMO WALKTHROUGH • STEP 2 OF 5'), findsOneWidget);
        expect(find.text('2. Timeline Spike Scrubber'), findsOneWidget);

        // Step 3
        await tester.tap(find.text('Next'));
        await tester.pumpAndSettle();
        expect(find.text('DEMO WALKTHROUGH • STEP 3 OF 5'), findsOneWidget);
        expect(find.text('3. Dual-Mode Filter Bar'), findsOneWidget);

        // Step 4 auto-selects first packet for inspection
        await tester.tap(find.text('Next'));
        await tester.pumpAndSettle();
        expect(find.text('DEMO WALKTHROUGH • STEP 4 OF 5'), findsOneWidget);
        expect(find.text('4. High-Density Packet Table'), findsOneWidget);
        expect(vm.selectedPacket, isNotNull);

        // Step 5
        await tester.tap(find.text('Next'));
        await tester.pumpAndSettle();
        expect(find.text('DEMO WALKTHROUGH • STEP 5 OF 5'), findsOneWidget);
        expect(
          find.text('5. Protocol Tree & Hex Byte Inspector'),
          findsOneWidget,
        );
        expect(find.text('Finish & Clear'), findsOneWidget);

        // Finish & Clear resets workspace and clears all demo packets
        await tester.tap(find.text('Finish & Clear'));
        await tester.pumpAndSettle();

        expect(vm.isDemoMode, isFalse);
        expect(vm.loadedFileName, isNull);
        expect(vm.packets, isEmpty);
        expect(find.text('No Capture File Loaded'), findsOneWidget);
        expect(find.text('Load Demo'), findsOneWidget);
      },
    );

    testWidgets(
      'End Demo and Escape key both exit walkthrough and clear demo data',
      (tester) async {
        tester.view.physicalSize = const Size(1400, 900);
        tester.view.devicePixelRatio = 1.0;
        addTearDown(tester.view.resetPhysicalSize);

        final repo = PacketRepository();
        final vm = InspectorViewModel(repository: repo);
        addTearDown(vm.dispose);

        await tester.pumpWidget(
          MultiProvider(
            providers: [
              ChangeNotifierProvider<InspectorViewModel>.value(value: vm),
            ],
            child: const MaterialApp(
              home: InspectorScreen(),
            ),
          ),
        );
        await tester.pumpAndSettle();

        // Start via empty-state Load Demo Capture button
        await tester.tap(find.text('Load Demo Capture'));
        await tester.pumpAndSettle();
        expect(vm.isDemoMode, isTrue);
        expect(vm.packets, isNotEmpty);

        // Click End Demo button on overlay card
        await tester.tap(find.text('End Demo'));
        await tester.pumpAndSettle();
        expect(vm.isDemoMode, isFalse);
        expect(vm.loadedFileName, isNull);
        expect(vm.packets, isEmpty);

        // Start again and dismiss with Escape key
        await tester.tap(find.text('Load Demo'));
        await tester.pumpAndSettle();
        expect(vm.isDemoMode, isTrue);

        await tester.sendKeyEvent(LogicalKeyboardKey.escape);
        await tester.pumpAndSettle();
        expect(vm.isDemoMode, isFalse);
        expect(vm.loadedFileName, isNull);
        expect(vm.packets, isEmpty);
      },
    );
  });

  group('Issue #2: Synchronized Light & Dark Mode', () {
    test('AppTheme dynamic getters return dark vs light palette tokens', () {
      AppTheme.isDark = true;
      expect(AppTheme.scaffoldBg, const Color(0xFF141414));
      expect(AppTheme.surface, const Color(0xFF1E1E1E));
      expect(AppTheme.surfaceHigh, const Color(0xFF252526));
      expect(AppTheme.border, const Color(0xFF2C2C2C));
      expect(AppTheme.textPrimary, const Color(0xFFE0E0E0));
      expect(AppTheme.textSecondary, const Color(0xFF9E9E9E));
      expect(AppTheme.textMuted, const Color(0xFF6E6E6E));

      AppTheme.isDark = false;
      expect(AppTheme.scaffoldBg, const Color(0xFFF3F4F6));
      expect(AppTheme.surface, const Color(0xFFFFFFFF));
      expect(AppTheme.surfaceHigh, const Color(0xFFF9FAFB));
      expect(AppTheme.border, const Color(0xFFE5E7EB));
      expect(AppTheme.textPrimary, const Color(0xFF111827));
      expect(AppTheme.textSecondary, const Color(0xFF4B5563));
      expect(AppTheme.textMuted, const Color(0xFF6B7280));

      // Calling lightTheme() / darkTheme() must preserve current isDark state
      final light = AppTheme.lightTheme();
      expect(light.brightness, Brightness.light);
      expect(AppTheme.isDark, isFalse);

      final dark = AppTheme.darkTheme();
      expect(dark.brightness, Brightness.dark);
      expect(AppTheme.isDark, isFalse);
    });

    test('SharedDeviceDatabase persists theme_mode across instances and notifies listeners', () async {
      final tempDir = Directory.systemTemp.createTempSync('shared_theme_test_');
      final dbPath = p.join(tempDir.path, 'shared_devices.db');
      final dbWriter = SharedDeviceDatabase(customPath: dbPath);
      final dbReader = SharedDeviceDatabase(customPath: dbPath);
      try {
        expect(await dbReader.getThemeMode(), 'dark');

        var notifications = 0;
        final sub = dbWriter.onDatabaseChanged.listen((_) => notifications++);
        await dbWriter.setThemeMode('light');
        await Future<void>.delayed(const Duration(milliseconds: 20));

        expect(notifications, greaterThanOrEqualTo(1));
        expect(await dbWriter.getThemeMode(), 'light');
        expect(await dbReader.getThemeMode(), 'light');

        await dbWriter.setThemeMode('dark');
        expect(await dbReader.getThemeMode(), 'dark');
        await sub.cancel();
      } finally {
        dbWriter.dispose();
        dbReader.dispose();
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      }
    });

    testWidgets(
      'PacketInspectorApp rebuilds between Dark and Light modes when SharedDeviceDatabase changes',
      (tester) async {
        tester.view.physicalSize = const Size(1400, 900);
        tester.view.devicePixelRatio = 1.0;
        addTearDown(tester.view.resetPhysicalSize);

        final tempDir = Directory.systemTemp.createTempSync('app_theme_live_');
        final dbPath = p.join(tempDir.path, 'shared_devices.db');
        final db = SharedDeviceDatabase(customPath: dbPath);
        addTearDown(() async {
          db.dispose();
          if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
        });

        await db.setThemeMode('dark');
        AppTheme.isDark = true;

        await tester.pumpWidget(PacketInspectorApp(database: db));
        await tester.pumpAndSettle();

        var materialApp = tester.widget<MaterialApp>(find.byType(MaterialApp));
        expect(materialApp.themeMode, ThemeMode.dark);
        expect(AppTheme.isDark, isTrue);

        // Simulate Net-App-Launcher toggling Light Mode
        await db.setThemeMode('light');
        await tester.pumpAndSettle();

        materialApp = tester.widget<MaterialApp>(find.byType(MaterialApp));
        expect(materialApp.themeMode, ThemeMode.light);
        expect(AppTheme.isDark, isFalse);

        // Toggle back to Dark Mode
        await db.setThemeMode('dark');
        await tester.pumpAndSettle();

        materialApp = tester.widget<MaterialApp>(find.byType(MaterialApp));
        expect(materialApp.themeMode, ThemeMode.dark);
        expect(AppTheme.isDark, isTrue);
      },
    );
  });
}
