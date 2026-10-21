import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:packet_inspector/main.dart';

void main() {
  testWidgets('PacketInspectorApp launches and displays main screen', (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);

    await tester.pumpWidget(const PacketInspectorApp());
    await tester.pumpAndSettle();

    expect(find.text('Packet Inspector'), findsOneWidget);
    expect(find.text('Baseline Triage'), findsOneWidget);
    expect(find.text('No Capture File Loaded'), findsOneWidget);

    // Click 'Load Demo Capture' from the empty state
    await tester.tap(find.text('Load Demo Capture').first);
    await tester.pumpAndSettle();

    // Verify demo capture is loaded and table shows packets
    expect(find.text('demo_capture.pcap'), findsOneWidget);
    expect(find.textContaining('DNS Standard query'), findsWidgets);

    // Verify Capture button is present in AppBar
    expect(find.text('Capture'), findsOneWidget);
    await tester.tap(find.text('Capture'));
    await tester.pumpAndSettle();

    // Verify Capture dialog opens
    expect(find.text('TShark Packet Capture'), findsOneWidget);
    expect(
      find.byWidgetPredicate(
        (w) => w is Text && (w.data == 'Storage Destination' || w.data == 'Wireshark / TShark not detected'),
      ),
      findsOneWidget,
    );

    // Close the dialog
    final closeBtn = find.text('Close');
    final cancelBtn = find.text('Cancel');
    if (closeBtn.evaluate().isNotEmpty) {
      await tester.tap(closeBtn);
    } else {
      await tester.tap(cancelBtn);
    }
    await tester.pumpAndSettle();
    expect(find.text('TShark Packet Capture'), findsNothing);
  });
}
