import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:packet_inspector/data/repositories/packet_repository.dart';
import 'package:packet_inspector/data/services/storage/protocol_library_service.dart';
import 'package:packet_inspector/ui/features/inspector/view_models/inspector_view_model.dart';
import 'package:packet_inspector/ui/features/inspector/views/inspector_screen.dart';
import 'package:packet_inspector/ui/features/protocol_library/views/custom_library_dialog.dart';
import 'package:packet_inspector/ui/features/protocol_library/views/add_protocol_dialog.dart';
import 'package:packet_inspector/domain/models/custom_protocol_rule.dart';
import 'package:packet_inspector/domain/models/endpoint_rule.dart';
import 'package:packet_inspector/domain/models/packet_record.dart';

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
          home: InspectorScreen(
            showAiAssistant: true,
            aiPanelSlot: SizedBox(),
          ),
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

  testWidgets('InspectorScreen hides AI Assistant button and drawer when showAiAssistant is false', (tester) async {
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
          home: InspectorScreen(
            showAiAssistant: false,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    // Verify Title and other Toolbar buttons exist
    expect(find.text('Packet Inspector'), findsOneWidget);
    expect(find.text('Open PCAP'), findsOneWidget);
    expect(find.text('Load Demo'), findsOneWidget);

    // Verify AI Assistant button is completely hidden
    expect(find.text('AI Assistant'), findsNothing);
    expect(find.byIcon(Icons.auto_awesome), findsNothing);
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

  testWidgets('PacketTable columns are sortable and resizable with context menu triage', (tester) async {
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
          home: InspectorScreen(
            showAiAssistant: true,
            aiPanelSlot: SizedBox(),
          ),
        ),
      ),
    );

    await tester.pumpAndSettle();

    // 1. Verify sort toggle on clicking 'Len' column header
    final lenHeader = find.text('Len');
    expect(lenHeader, findsOneWidget);

    await tester.tap(lenHeader);
    await tester.pumpAndSettle();

    expect(vm.sortColumn, equals('captured_length'));
    expect(vm.sortAscending, isTrue);

    // Tap 'Len' again to sort descending
    await tester.tap(lenHeader);
    await tester.pumpAndSettle();

    expect(vm.sortColumn, equals('captured_length'));
    expect(vm.sortAscending, isFalse);

    // Verify sort arrow icon is displayed
    expect(find.byIcon(Icons.arrow_drop_down), findsWidgets);

    // Sort back to Packet No ascending
    final noHeader = find.text('No.');
    await tester.tap(noHeader);
    await tester.pumpAndSettle();

    // 2. Secondary tap (right-click) on packet table row opens context menu with triage classification options
    final dnsCell = find.text('DNS').first;
    await tester.tap(dnsCell, buttons: 2); // secondary click on DNS cell
    await tester.pumpAndSettle();

    expect(find.textContaining('Save Source ('), findsOneWidget);
    expect(find.textContaining('to Source Library...'), findsOneWidget);
    expect(find.textContaining('Save Destination ('), findsOneWidget);
    expect(find.textContaining('to Destination Library...'), findsOneWidget);
    expect(find.textContaining('Mark Source IP'), findsOneWidget);
    expect(find.textContaining('Flag Source IP'), findsOneWidget);
    expect(find.textContaining('Reset Source IP'), findsOneWidget);
    expect(find.textContaining('Set Packet #'), findsWidgets);

    // Flag source IP as Unexpected
    final flagUnexpectedOption = find.textContaining('Flag Source IP');
    await tester.tap(flagUnexpectedOption);
    await tester.pumpAndSettle();

    // Verify triage status updated in VM and repository
    expect(vm.baselineProfile.unexpectedIps.isNotEmpty, isTrue);
    expect(vm.triageCounts[TriageStatus.unexpected], greaterThan(0));

    // Verify pagination behavior with 1000 batch size
    expect(vm.pageSize, equals(1000));
    vm.setPageSize(5);
    expect(vm.packets.length, equals(5));
    expect(vm.hasMorePackets, isTrue);

    vm.loadMorePackets();
    expect(vm.packets.length, equals(10));
  });

  testWidgets('Quick-Filter Pills bar displays custom protocols from library and allows filtering', (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);

    final repo = PacketRepository();
    repo.loadDemoCapture();
    final customRule = const CustomProtocolRule(
      id: 'custom_sacn_priority',
      name: 'sACN Per Address Priority',
      colorHex: 0xFF9C27B0,
      defaultTriageStatus: TriageStatus.expected,
      ipProtocol: 17,
      port: 57313,
      magicBytesOffset: 153,
      magicBytesHex: [0xDD],
    );
    repo.addCustomProtocol(customRule);

    final vm = InspectorViewModel(repository: repo);
    vm.setTriageMode(false);

    await tester.pumpWidget(
      MultiProvider(
        providers: [
          ChangeNotifierProvider<InspectorViewModel>.value(value: vm),
        ],
        child: const MaterialApp(
          home: InspectorScreen(
            showAiAssistant: true,
            aiPanelSlot: SizedBox(),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    // Verify 'Add Protocol' action chip exists in Quick-Filter Pills bar
    expect(find.text('Add Protocol'), findsOneWidget);

    // Verify custom protocol pill appears even if 0 packets match
    expect(find.textContaining('sACN Per Address Priority'), findsOneWidget);

    // Tap on the custom protocol pill to filter by it
    final pillFinder = find.textContaining('sACN Per Address Priority');
    await tester.tap(pillFinder);
    await tester.pumpAndSettle();

    expect(vm.selectedProtocolPills.contains('sACN Per Address Priority'), isTrue);
  });

  testWidgets('Quick-Filter 3-row matrix filters by Protocol, Sender, and Receiver', (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);

    final repo = PacketRepository();
    repo.loadDemoCapture();

    // Add a sender and receiver to library
    repo.addSender(const EndpointRule(
      id: 'sender_1',
      name: 'DNS Client',
      ipAddress: '192.168.1.50',
      colorHex: 0xFF2196F3,
      type: EndpointType.sender,
    ));
    repo.addReceiver(const EndpointRule(
      id: 'receiver_1',
      name: 'Gateway DNS',
      ipAddress: '192.168.1.1',
      port: 53,
      colorHex: 0xFF4CAF50,
      type: EndpointType.receiver,
    ));

    final vm = InspectorViewModel(repository: repo);
    vm.setTriageMode(false);

    await tester.pumpWidget(
      MultiProvider(
        providers: [
          ChangeNotifierProvider<InspectorViewModel>.value(value: vm),
        ],
        child: const MaterialApp(
          home: InspectorScreen(
            showAiAssistant: true,
            aiPanelSlot: SizedBox(),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    // Verify all 3 row headers exist
    expect(find.text('Protocols'), findsOneWidget);
    expect(find.text('Sources'), findsOneWidget);
    expect(find.text('Destinations'), findsOneWidget);

    // Verify 'Add Source' and 'Add Destination' buttons exist
    expect(find.text('Add Source'), findsOneWidget);
    expect(find.text('Add Destination'), findsOneWidget);

    // Verify library items are present in rows
    expect(find.textContaining('DNS Client'), findsOneWidget);
    expect(find.textContaining('Gateway DNS'), findsOneWidget);

    // Select Sender pill 'DNS Client'
    await tester.tap(find.textContaining('DNS Client'));
    await tester.pumpAndSettle();
    expect(vm.selectedSenderKeys.contains('192.168.1.50'), isTrue);

    // Select Receiver pill 'Gateway DNS'
    await tester.tap(find.textContaining('Gateway DNS'));
    await tester.pumpAndSettle();
    expect(vm.selectedReceiverKeys.contains('192.168.1.1:53'), isTrue);

    // Packets are now filtered to only 192.168.1.50 -> 192.168.1.1:53
    for (final p in vm.packets) {
      expect(p.srcIp, equals('192.168.1.50'));
      expect(p.dstIp, equals('192.168.1.1'));
      expect(p.dstPort, equals(53));
    }

    // Verify Clear All Filters clears both
    final clearBtn = find.text('Clear All Filters');
    expect(clearBtn, findsOneWidget);
    await tester.tap(clearBtn);
    await tester.pumpAndSettle();

    expect(vm.selectedSenderKeys.isEmpty, isTrue);
    expect(vm.selectedReceiverKeys.isEmpty, isTrue);
  });

  testWidgets('Auto-Detected toggle hides standard and discovered filters from all 3 rows', (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);

    final tempDir = Directory.systemTemp.createTempSync('test_autodetect_');
    addTearDown(() => tempDir.deleteSync(recursive: true));
    final repo = PacketRepository(
      storageService: ProtocolLibraryService(storageDirectory: tempDir),
    );
    repo.loadDemoCapture();
    repo.addCustomProtocol(const CustomProtocolRule(
      id: 'proto_test',
      name: 'Custom UDP Test',
      colorHex: 0xFF9C27B0,
      defaultTriageStatus: TriageStatus.expected,
      port: 5000,
    ));
    repo.addSender(const EndpointRule(
      id: 'sender_test',
      name: 'Test Sender',
      ipAddress: '10.0.0.1',
      type: EndpointType.sender,
    ));

    final vm = InspectorViewModel(repository: repo);
    vm.setTriageMode(false); // Quick filters

    await tester.pumpWidget(
      MultiProvider(
        providers: [
          ChangeNotifierProvider<InspectorViewModel>.value(value: vm),
        ],
        child: const MaterialApp(
          home: InspectorScreen(
            showAiAssistant: true,
            aiPanelSlot: SizedBox(),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    // Verify Auto-Detected switch is present and initially ON
    expect(find.text('Auto-Detected'), findsOneWidget);
    expect(find.byWidgetPredicate((w) => w is FilterChip && w.label is Text && ((w.label as Text).data?.startsWith('DNS (') ?? false)), findsOneWidget);

    // Toggle Auto-Detected switch OFF
    final autoDetectedSwitch = find.byType(Switch).at(1);
    await tester.tap(autoDetectedSwitch);
    await tester.pumpAndSettle();

    expect(vm.showAutoDetected, isFalse);
    // Custom item is still present
    expect(find.textContaining('Custom UDP Test'), findsOneWidget);
    expect(find.textContaining('Test Sender'), findsOneWidget);
    // Auto-detected standard protocols like DNS (1) are hidden from filter pills!
    expect(find.byWidgetPredicate((w) => w is FilterChip && w.label is Text && ((w.label as Text).data?.startsWith('DNS (') ?? false)), findsNothing);
  });

  testWidgets('Custom Library dialog displays 3 tabs, edit and visibility toggle', (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);

    final tempDir = Directory.systemTemp.createTempSync('test_customlib_');
    addTearDown(() => tempDir.deleteSync(recursive: true));
    final repo = PacketRepository(
      storageService: ProtocolLibraryService(storageDirectory: tempDir),
    );
    repo.loadDemoCapture();
    repo.addCustomProtocol(const CustomProtocolRule(
      id: 'proto_eye_test',
      name: 'Visible Protocol',
      colorHex: 0xFF9C27B0,
      defaultTriageStatus: TriageStatus.expected,
      port: 6000,
      isVisible: true,
    ));

    final vm = InspectorViewModel(repository: repo);
    vm.setTriageMode(false);

    await tester.pumpWidget(
      MultiProvider(
        providers: [
          ChangeNotifierProvider<InspectorViewModel>.value(value: vm),
        ],
        child: const MaterialApp(
          home: InspectorScreen(
            showAiAssistant: true,
            aiPanelSlot: SizedBox(),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    // Initially Visible Protocol is visible in quick-filter row
    expect(find.textContaining('Visible Protocol'), findsOneWidget);

    // Open Custom Library Dialog
    final customLibBtn = find.text('Custom Library');
    expect(customLibBtn, findsOneWidget);
    await tester.tap(customLibBtn);
    await tester.pumpAndSettle();

    // Verify dialog title and 3 tabs
    expect(find.text('Custom Library'), findsWidgets);
    expect(find.textContaining('Protocols ('), findsOneWidget);
    expect(find.textContaining('Sources ('), findsOneWidget);
    expect(find.textContaining('Destinations ('), findsOneWidget);

    // Verify eye visibility button, edit button, and delete button exist
    expect(find.byIcon(Icons.visibility), findsOneWidget);
    expect(find.byIcon(Icons.edit), findsOneWidget);
    expect(find.byIcon(Icons.delete_outline), findsOneWidget);

    // Tap Eye button to toggle visibility for 'Visible Protocol'
    final eyeButton = find.byIcon(Icons.visibility);
    await tester.tap(eyeButton);
    await tester.pumpAndSettle();

    // Now icon changes to visibility_off and badge says Hidden
    expect(find.byIcon(Icons.visibility_off), findsOneWidget);
    expect(find.text('Hidden'), findsOneWidget);

    // Close Dialog
    await tester.tap(find.text('Close'));
    await tester.pumpAndSettle();

    // Verify Visible Protocol is now hidden from the main screen filter bar
    expect(find.textContaining('Visible Protocol'), findsNothing);
  });
}
