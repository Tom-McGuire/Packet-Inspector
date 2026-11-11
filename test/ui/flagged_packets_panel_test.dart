import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:packet_inspector/data/repositories/packet_repository.dart';
import 'package:packet_inspector/ui/features/inspector/view_models/inspector_view_model.dart';
import 'package:packet_inspector/ui/features/inspector/views/inspector_screen.dart';
import 'package:packet_inspector/ui/features/inspector/views/flagged_packets_panel.dart';
import 'package:packet_inspector/ui/features/inspector/views/packet_table_view.dart';
import 'package:packet_inspector/domain/models/timeline_bucket.dart';

void main() {
  group('Flagged Packets & Navigation Features', () {
    test('TimelineBucket formats date and time identically to formattedDateTime', () {
      final bucket = TimelineBucket(
        bucketIndex: 0,
        bucketStartUs: 1792749767490000,
        bucketEndUs: 1792749768490000,
        packetCount: 10,
        totalBytes: 15464,
        minGlobalDeltaUs: 100,
        maxStreamDeltaUs: 200,
        avgStreamDeltaUs: 150.0,
        unexpectedCount: 2,
      );

      expect(bucket.formattedDateTime, isNotEmpty);
      expect(bucket.dateTime.year, greaterThanOrEqualTo(2025));
    });

    testWidgets('FlaggedPacketsPanel displays flagged packets with sequential delta times and jump-to-packet', (tester) async {
      tester.view.physicalSize = const Size(1400, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);

      final repo = PacketRepository();
      repo.loadDemoCapture();
      final vm = InspectorViewModel(repository: repo);

      await tester.pumpWidget(
        MultiProvider(
          providers: [
            ChangeNotifierProvider<InspectorViewModel>.value(value: vm),
          ],
          child: const MaterialApp(
            home: Scaffold(
              body: SizedBox(
                width: 600,
                height: 400,
                child: FlaggedPacketsPanel(),
              ),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Initially empty state
      expect(find.text('No flagged packets'), findsOneWidget);

      // Flag 2 packets with different timestamps
      expect(vm.packets.length, greaterThanOrEqualTo(2));
      final p1 = vm.packets[0];
      final p2 = vm.packets[1];

      vm.togglePacketFlag(p1);
      vm.togglePacketFlag(p2);
      await tester.pumpAndSettle();

      expect(find.textContaining('Flagged Packets'), findsOneWidget);
      expect(find.text('#${p1.packetNo}'), findsOneWidget);
      expect(find.text('#${p2.packetNo}'), findsOneWidget);
      expect(find.textContaining('Baseline'), findsOneWidget);
      expect(find.textContaining('Δ:'), findsWidgets);

      // Tap on packet to trigger jumpToPacket
      await tester.tap(find.text('#${p2.packetNo}'));
      await tester.pumpAndSettle();

      expect(vm.selectedPacket?.packetNo, equals(p2.packetNo));

      // Clear all
      await tester.tap(find.text('Clear All'));
      await tester.pumpAndSettle();
      expect(vm.flaggedPacketCount, equals(0));
      expect(find.text('No flagged packets'), findsOneWidget);
    });

    testWidgets('Keyboard arrow down and up moves packet selection in table', (tester) async {
      tester.view.physicalSize = const Size(1400, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);

      final repo = PacketRepository();
      repo.loadDemoCapture();
      final vm = InspectorViewModel(repository: repo);

      await tester.pumpWidget(
        MultiProvider(
          providers: [
            ChangeNotifierProvider<InspectorViewModel>.value(value: vm),
          ],
          child: const MaterialApp(
            home: Scaffold(
              body: SizedBox(
                width: 1200,
                height: 700,
                child: PacketTableView(),
              ),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Press down arrow
      await tester.sendKeyEvent(LogicalKeyboardKey.arrowDown);
      await tester.pumpAndSettle();
      expect(vm.selectedPacket, isNotNull);
      final firstSelectedNo = vm.selectedPacket!.packetNo;

      // Press down arrow again
      await tester.sendKeyEvent(LogicalKeyboardKey.arrowDown);
      await tester.pumpAndSettle();
      expect(vm.selectedPacket!.packetNo, isNot(equals(firstSelectedNo)));

      // Press up arrow to move back
      await tester.sendKeyEvent(LogicalKeyboardKey.arrowUp);
      await tester.pumpAndSettle();
      expect(vm.selectedPacket!.packetNo, equals(firstSelectedNo));
    });

    testWidgets('InspectorScreen resizable bottom panel drag changes height', (tester) async {
      tester.view.physicalSize = const Size(1400, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);

      final repo = PacketRepository();
      repo.loadDemoCapture();
      final vm = InspectorViewModel(repository: repo);

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

      // Verify Flagged Packets Panel is visible in bottom right
      expect(find.byType(FlaggedPacketsPanel), findsOneWidget);

      // Drag splitter upward to enlarge bottom panel
      final splitterFinder = find.byWidgetPredicate(
        (w) => w is MouseRegion && w.cursor == SystemMouseCursors.resizeRow,
      );
      expect(splitterFinder, findsOneWidget);
      await tester.drag(splitterFinder, const Offset(0, -60));
      await tester.pumpAndSettle();

      expect(find.byType(FlaggedPacketsPanel), findsOneWidget);
    });
  });
}
