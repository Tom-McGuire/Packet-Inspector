import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:packet_inspector/main.dart';

void main() {
  testWidgets('PacketInspectorApp launches and displays main screen with analysis tools', (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);

    await tester.pumpWidget(const PacketInspectorApp());
    await tester.pumpAndSettle();

    expect(find.text('Packet Inspector'), findsOneWidget);
    expect(find.text('Source IP'), findsOneWidget);
    expect(find.text('Destination IP'), findsOneWidget);
    expect(find.text('No Capture File Loaded'), findsOneWidget);

    // Verify main analysis toolbar buttons
    expect(find.text('Open PCAP'), findsOneWidget);
    expect(find.text('Load Demo'), findsOneWidget);
    expect(find.text('Custom Library'), findsOneWidget);

    // Click 'Load Demo Capture' from the empty state
    await tester.tap(find.text('Load Demo Capture').first);
    await tester.pumpAndSettle();

    // Verify demo capture is loaded and table shows packets
    expect(find.text('demo_capture.pcap'), findsOneWidget);
    expect(find.textContaining('DNS Standard query'), findsWidgets);
  });
}
