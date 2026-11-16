import 'dart:io';
import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:packet_inspector/data/repositories/packet_repository.dart';
import 'package:packet_inspector/data/services/storage/protocol_library_service.dart';
import 'package:packet_inspector/domain/models/endpoint_rule.dart';
import 'package:packet_inspector/ui/features/inspector/view_models/inspector_view_model.dart';
import 'package:packet_inspector/ui/features/protocol_library/views/protocol_library_dialog.dart';

void main() {
  late Directory tempDir;
  late PacketRepository repository;
  late InspectorViewModel viewModel;

  setUp(() async {
    tempDir = Directory.systemTemp.createTempSync('proto_lib_dialog_test_');
    repository = PacketRepository(
      storageService: ProtocolLibraryService(storageDirectory: tempDir),
    );
    repository.loadDemoCapture();
    viewModel = InspectorViewModel(repository: repository);
  });

  tearDown(() {
    viewModel.dispose();
    if (tempDir.existsSync()) {
      tempDir.deleteSync(recursive: true);
    }
  });

  testWidgets('ProtocolLibraryDialog opens directly and renders requested initialTab', (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);

    // Seed a sender and receiver
    viewModel.addSender(
      const EndpointRule(
        id: 'sender_1',
        name: 'Console Alpha',
        ipAddress: '192.168.1.50',
        port: 6454,
        type: EndpointType.sender,
        isVisible: true,
      ),
    );
    viewModel.addReceiver(
      const EndpointRule(
        id: 'receiver_1',
        name: 'Fixture Group',
        ipAddress: '192.168.1.100',
        type: EndpointType.receiver,
        isVisible: true,
      ),
    );

    // Open with initialTab: 1 (Sources tab)
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: ProtocolLibraryDialog(
            viewModel: viewModel,
            initialTab: 1,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Console Alpha'), findsOneWidget);
    expect(find.text('Add Source'), findsOneWidget);

    // Switch to Destinations tab (Tab index 2)
    await tester.tap(find.textContaining('Destinations ('));
    await tester.pumpAndSettle();

    expect(find.text('Fixture Group'), findsOneWidget);
    expect(find.text('Add Destination'), findsOneWidget);

    // Toggle visibility on receiver
    final visibilityBtn = find.byIcon(Icons.visibility);
    expect(visibilityBtn, findsOneWidget);
    await tester.tap(visibilityBtn);
    await tester.pumpAndSettle();

    expect(find.byIcon(Icons.visibility_off), findsOneWidget);
    expect(find.text('Hidden'), findsOneWidget);

    // Switch to Protocols tab
    await tester.tap(find.textContaining('Protocols ('));
    await tester.pumpAndSettle();

    expect(find.text('Add Protocol'), findsOneWidget);
  });
}
