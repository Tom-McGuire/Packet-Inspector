import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:packet_inspector/data/repositories/packet_repository.dart';
import 'package:packet_inspector/ui/features/inspector/view_models/inspector_view_model.dart';
import 'package:packet_inspector/ui/features/inspector/views/inspector_screen.dart';
import 'package:packet_inspector/ui/features/protocol_library/views/add_protocol_dialog.dart';

void main() {
  testWidgets('InspectorScreen renders toolbar, table, and allows triage mode toggle', (tester) async {
    // Large surface size for desktop layout
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

    // Verify Title and Toolbar buttons
    expect(find.text('Packet Inspector'), findsOneWidget);
    expect(find.text('Open PCAP'), findsOneWidget);
    expect(find.text('Load Demo'), findsOneWidget);
    expect(find.text('AI Assistant'), findsOneWidget);

    // Verify Baseline Triage mode chips
    expect(find.text('Baseline Triage'), findsOneWidget);
    expect(find.text('Silence LAN Chatter'), findsOneWidget);
    expect(find.textContaining('Expected'), findsWidgets);

    // Toggle Triage Mode -> Quick-Filter Pills
    final modeSwitch = find.byType(Switch).first;
    await tester.tap(modeSwitch);
    await tester.pumpAndSettle();

    expect(find.text('Quick-Filter Pills'), findsOneWidget);
    expect(find.textContaining('DNS ('), findsWidgets);

    // Tap on a packet row to select it
    final dnsRow = find.textContaining('DNS Standard query').first;
    await tester.tap(dnsRow);
    await tester.pumpAndSettle();

    // Verify HexByteInspector shows selected packet
    expect(find.textContaining('Packet #'), findsOneWidget);
    expect(find.text('L4 Payload'), findsOneWidget);
  });

  testWidgets('AddProtocolDialog opens and configures Tier 1 and Tier 2 rules', (tester) async {
    tester.view.physicalSize = const Size(1200, 800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);

    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: Center(
            child: AddProtocolDialog(
              prefillMagicOffset: 0,
              prefillMagicHex: '41 43 4D 45',
            ),
          ),
        ),
      ),
    );

    await tester.pumpAndSettle();

    expect(find.text('Add Custom Protocol to Library'), findsOneWidget);
    expect(find.text('Tier 1: Transport & Port Matching'), findsOneWidget);
    expect(find.text('Tier 2: Fixed-Offset Magic Bytes (Optional)'), findsOneWidget);
    expect(find.text('41 43 4D 45'), findsOneWidget);
    expect(find.text('Save & Re-label Capture'), findsOneWidget);
  });
}
