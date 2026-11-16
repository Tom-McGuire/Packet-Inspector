import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:packet_inspector/domain/models/endpoint_rule.dart';
import 'package:packet_inspector/ui/features/protocol_library/views/add_endpoint_dialog.dart';

void main() {
  testWidgets('AddEndpointDialog creates new Source rule with prefilled data', (tester) async {
    EndpointRule? result;

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (context) => ElevatedButton(
              onPressed: () async {
                result = await showDialog<EndpointRule>(
                  context: context,
                  builder: (_) => const AddEndpointDialog(
                    type: EndpointType.sender,
                    prefillIp: '192.168.1.100',
                    prefillPort: 8080,
                  ),
                );
              },
              child: const Text('Open Dialog'),
            ),
          ),
        ),
      ),
    );

    await tester.tap(find.text('Open Dialog'));
    await tester.pumpAndSettle();

    expect(find.text('Add Source to Library'), findsOneWidget);
    expect(find.text('192.168.1.100'), findsOneWidget);
    expect(find.text('8080'), findsOneWidget);

    // Tap the orange preset color
    final orangeBadge = find.byWidgetPredicate((w) =>
        w is Container &&
        w.decoration is BoxDecoration &&
        (w.decoration as BoxDecoration).color == const Color(0xFFFF9800));
    expect(orangeBadge, findsOneWidget);
    await tester.tap(orangeBadge);
    await tester.pumpAndSettle();

    // Tap Add Source
    await tester.tap(find.text('Add Source'));
    await tester.pumpAndSettle();

    expect(result, isNotNull);
    expect(result!.ipAddress, equals('192.168.1.100'));
    expect(result!.port, equals(8080));
    expect(result!.type, equals(EndpointType.sender));
    expect(result!.colorHex, equals(0xFFFF9800));
  });

  testWidgets('AddEndpointDialog edits existing Destination rule and supports Cancel', (tester) async {
    EndpointRule? result;
    const existing = EndpointRule(
      id: 'ep_edit',
      name: 'Old Destination',
      ipAddress: '10.0.0.1',
      port: 443,
      type: EndpointType.receiver,
      colorHex: 0xFF9C27B0,
    );

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (context) => ElevatedButton(
              onPressed: () async {
                result = await showDialog<EndpointRule>(
                  context: context,
                  builder: (_) => const AddEndpointDialog(
                    type: EndpointType.receiver,
                    existingRule: existing,
                  ),
                );
              },
              child: const Text('Open Dialog'),
            ),
          ),
        ),
      ),
    );

    await tester.tap(find.text('Open Dialog'));
    await tester.pumpAndSettle();

    expect(find.text('Edit Destination'), findsOneWidget);
    expect(find.text('Old Destination'), findsOneWidget);

    // Test Cancel button
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(result, isNull);

    // Reopen and save changes
    await tester.tap(find.text('Open Dialog'));
    await tester.pumpAndSettle();

    // Change Name
    await tester.enterText(find.byType(TextField).first, 'New Destination Host');
    await tester.tap(find.text('Save Changes'));
    await tester.pumpAndSettle();

    expect(result, isNotNull);
    expect(result!.id, equals('ep_edit'));
    expect(result!.name, equals('New Destination Host'));
    expect(result!.type, equals(EndpointType.receiver));
  });

  testWidgets('AddEndpointDialog does not save if required fields are cleared', (tester) async {
    EndpointRule? result;

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (context) => ElevatedButton(
              onPressed: () async {
                result = await showDialog<EndpointRule>(
                  context: context,
                  builder: (_) => const AddEndpointDialog(
                    type: EndpointType.sender,
                  ),
                );
              },
              child: const Text('Open Dialog'),
            ),
          ),
        ),
      ),
    );

    await tester.tap(find.text('Open Dialog'));
    await tester.pumpAndSettle();

    // Clear IP (it is empty by default)
    await tester.tap(find.text('Add Source'));
    await tester.pumpAndSettle();

    // Dialog should still be open because IP is empty
    expect(find.text('Add Source to Library'), findsOneWidget);
    expect(result, isNull);

    // Close via close icon
    await tester.tap(find.byIcon(Icons.close));
    await tester.pumpAndSettle();
    expect(find.text('Add Source to Library'), findsNothing);
  });
}
