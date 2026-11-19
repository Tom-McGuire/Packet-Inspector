import 'dart:io';
import 'dart:typed_data';
import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:packet_inspector/data/repositories/packet_repository.dart';
import 'package:packet_inspector/data/services/database/packet_database_service.dart';
import 'package:packet_inspector/data/services/storage/protocol_library_service.dart';
import 'package:packet_inspector/domain/models/custom_protocol_rule.dart';
import 'package:packet_inspector/domain/models/packet_record.dart';
import 'package:packet_inspector/ui/features/inspector/view_models/inspector_view_model.dart';
import 'package:packet_inspector/ui/features/inspector/views/dual_mode_filter_bar.dart';
import 'package:packet_inspector/ui/features/inspector/views/packet_table_view.dart';
import 'package:packet_inspector/ui/features/inspector/views/timeline_spike_scrubber.dart';
import 'package:packet_inspector/ui/features/protocol_library/views/add_protocol_dialog.dart';

PacketRecord _makePacket({
  required int packetNo,
  int timestampUs = 1000000,
  int globalDeltaUs = 1000,
  int streamDeltaUs = 1000,
  String srcIp = '192.168.1.10',
  String dstIp = '192.168.1.20',
  int ipProto = 17,
  int? srcPort = 45820,
  int? dstPort = 45820,
  String detectedProtocol = 'UDP',
  TriageStatus triageStatus = TriageStatus.unclassified,
  Uint8List? payloadPreview,
}) {
  return PacketRecord(
    packetNo: packetNo,
    timestampUs: timestampUs,
    globalDeltaUs: globalDeltaUs,
    streamDeltaUs: streamDeltaUs,
    flowHash: 12345,
    ethType: 0x0800,
    srcIp: srcIp,
    dstIp: dstIp,
    ipProto: ipProto,
    srcPort: srcPort,
    dstPort: dstPort,
    detectedProtocol: detectedProtocol,
    capturedLength: 64,
    originalLength: 64,
    fileByteOffset: 0,
    payloadFileOffset: 0,
    payloadLength: 16,
    payloadPreview: payloadPreview ?? Uint8List.fromList([0x41, 0x43, 0x4D, 0x45, 0x00, 0x2A]),
    summary: 'Test packet #$packetNo',
    triageStatus: triageStatus,
    isLanNoise: false,
  );
}

void main() {
  late Directory tempDir;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('m3_inspector_ui_test_');
  });

  tearDown(() {
    if (tempDir.existsSync()) {
      tempDir.deleteSync(recursive: true);
    }
  });

  test('F4: _refreshPackets refreshes _selectedPacket with updated protocol, summary, and customFields', () {
    final db = PacketDatabaseService();
    db.insertPacketsBatch([
      _makePacket(packetNo: 1, srcPort: 45820, dstPort: 45820),
    ]);
    db.buildFlowsAndBuckets();

    final repo = PacketRepository(
      dbService: db,
      storageService: ProtocolLibraryService(storageDirectory: tempDir),
    );
    final vm = InspectorViewModel(repository: repo);
    addTearDown(vm.dispose);

    expect(vm.packets, hasLength(1));
    vm.selectPacket(vm.packets.first);
    expect(vm.selectedPacket?.detectedProtocol, equals('UDP'));
    expect(vm.selectedPacket?.customFields, isEmpty);

    // Add a custom protocol rule with a field slice; _refreshState -> _refreshPackets runs
    vm.addCustomProtocol(
      const CustomProtocolRule(
        id: 'acme_test',
        name: 'ACME Telemetry',
        colorHex: 0xFF9C27B0,
        defaultTriageStatus: TriageStatus.expected,
        ipProtocol: 17,
        port: 45820,
        portDirection: PortMatchDirection.either,
        fieldSlices: [
          ProtocolFieldSlice(
            name: 'SensorID',
            byteOffset: 4,
            byteLength: 2,
            dataType: FieldDataType.uint16Be,
          ),
        ],
      ),
    );

    expect(vm.selectedPacket, isNotNull);
    expect(vm.selectedPacket!.detectedProtocol, equals('ACME Telemetry'));
    expect(vm.selectedPacket!.customFields['SensorID'], equals(42));
  });

  test('F5: exportFilteredPacketsCsv exports all matching packets beyond 1,000 pagination limit', () {
    final db = PacketDatabaseService();
    final records = List.generate(
      1250,
      (i) => _makePacket(
        packetNo: i + 1,
        timestampUs: 1000000 + i * 1000,
      ),
    );
    db.insertPacketsBatch(records);
    db.buildFlowsAndBuckets();

    final repo = PacketRepository(
      dbService: db,
      storageService: ProtocolLibraryService(storageDirectory: tempDir),
    );
    final vm = InspectorViewModel(repository: repo);
    addTearDown(vm.dispose);

    // Default page size is 1,000
    expect(vm.packets.length, equals(1000));
    expect(vm.totalPacketCount, equals(1250));

    final csv = vm.exportFilteredPacketsCsv();
    final lines = csv.trim().split('\n');
    // 1 header + 1,250 data rows
    expect(lines.length, equals(1251));
  });

  testWidgets('F8: AddProtocolDialog preserves ipAddressFilter and colorHex on edit and save', (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);

    const existing = CustomProtocolRule(
      id: 'rule_1',
      name: 'Existing Proto',
      colorHex: 0xFF4CAF50,
      defaultTriageStatus: TriageStatus.expected,
      ipProtocol: 17,
      port: 5000,
      ipAddressFilter: '10.1.2.3',
    );

    CustomProtocolRule? savedRule;

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (context) => ElevatedButton(
              onPressed: () async {
                savedRule = await showDialog<CustomProtocolRule>(
                  context: context,
                  builder: (_) => const AddProtocolDialog(existingRule: existing),
                );
              },
              child: const Text('Open'),
            ),
          ),
        ),
      ),
    );

    await tester.tap(find.text('Open'));
    await tester.pumpAndSettle();

    // Existing IP filter is prefilled
    expect(find.text('10.1.2.3'), findsOneWidget);

    // Update IP filter
    final ipField = find.widgetWithText(TextField, 'IP Address Filter (Optional)');
    await tester.enterText(ipField, '192.168.50.10');

    // Select a different color preset (Orange: 0xFFFF9800)
    final orangeSwatch = find.byWidgetPredicate(
      (w) =>
          w is Container &&
          w.decoration is BoxDecoration &&
          (w.decoration as BoxDecoration).shape == BoxShape.circle &&
          (w.decoration as BoxDecoration).color == const Color(0xFFFF9800),
    );
    expect(orangeSwatch, findsOneWidget);
    await tester.tap(orangeSwatch);
    await tester.pumpAndSettle();

    await tester.tap(find.text('Save Changes'));
    await tester.pumpAndSettle();

    expect(savedRule, isNotNull);
    expect(savedRule!.ipAddressFilter, equals('192.168.50.10'));
    expect(savedRule!.colorHex, equals(0xFFFF9800));
  });

  testWidgets('F12: PacketTableView highlights micro-burst (<50us) and stall (>100ms) delta badges', (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);

    final db = PacketDatabaseService();
    db.insertPacketsBatch([
      _makePacket(packetNo: 1, globalDeltaUs: 25, streamDeltaUs: 25), // micro-burst
      _makePacket(packetNo: 2, globalDeltaUs: 150000, streamDeltaUs: 150000), // stall
      _makePacket(packetNo: 3, globalDeltaUs: 5000, streamDeltaUs: 5000), // normal
    ]);
    db.buildFlowsAndBuckets();

    final repo = PacketRepository(
      dbService: db,
      storageService: ProtocolLibraryService(storageDirectory: tempDir),
    );
    final vm = InspectorViewModel(repository: repo);
    addTearDown(vm.dispose);

    await tester.pumpWidget(
      ChangeNotifierProvider<InspectorViewModel>.value(
        value: vm,
        child: const MaterialApp(
          home: Scaffold(
            body: PacketTableView(),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    // Micro-burst badge (amber container)
    final amberBadge = find.byWidgetPredicate(
      (w) =>
          w is Container &&
          w.decoration is BoxDecoration &&
          (w.decoration as BoxDecoration).color == Colors.amber.withValues(alpha: 0.18),
    );
    expect(amberBadge, findsWidgets);

    // Stall badge (red container)
    final redBadge = find.byWidgetPredicate(
      (w) =>
          w is Container &&
          w.decoration is BoxDecoration &&
          (w.decoration as BoxDecoration).color == Colors.red.withValues(alpha: 0.16),
    );
    expect(redBadge, findsWidgets);
  });

  testWidgets('F12: TimelineSpikeScrubber supports horizontal drag-to-brush zoom', (tester) async {
    tester.view.physicalSize = const Size(1200, 400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);

    final db = PacketDatabaseService();
    // Spread packets across 5 seconds so multiple buckets are generated
    final records = List.generate(
      20,
      (i) => _makePacket(
        packetNo: i + 1,
        timestampUs: 1000000 + i * 250000,
      ),
    );
    db.insertPacketsBatch(records);
    db.buildFlowsAndBuckets();

    final repo = PacketRepository(
      dbService: db,
      storageService: ProtocolLibraryService(storageDirectory: tempDir),
    );
    final vm = InspectorViewModel(repository: repo);
    addTearDown(vm.dispose);

    expect(vm.timelineBuckets.length, greaterThanOrEqualTo(3));

    await tester.pumpWidget(
      ChangeNotifierProvider<InspectorViewModel>.value(
        value: vm,
        child: const MaterialApp(
          home: Scaffold(
            body: SizedBox(
              width: 1000,
              height: 150,
              child: TimelineSpikeScrubber(),
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(vm.timeWindowStartUs, isNull);
    expect(vm.timeWindowEndUs, isNull);

    final scrubberFinder = find.byType(TimelineSpikeScrubber);
    final rect = tester.getRect(scrubberFinder);
    final startOffset = Offset(rect.left + 100, rect.bottom - 30);
    final endOffset = Offset(rect.left + 600, rect.bottom - 30);

    final gesture = await tester.startGesture(startOffset);
    await tester.pump();
    await gesture.moveTo(endOffset);
    await tester.pump();

    // Brush overlay should be visible while dragging
    expect(find.byKey(const Key('timeline_brush_overlay')), findsOneWidget);

    await gesture.up();
    await tester.pumpAndSettle();

    expect(vm.timeWindowStartUs, isNotNull);
    expect(vm.timeWindowEndUs, isNotNull);
    expect(vm.timeWindowEndUs!, greaterThan(vm.timeWindowStartUs!));
  });

  testWidgets('F19: DualModeFilterBar debounces search input by 150ms and clears immediately', (tester) async {
    tester.view.physicalSize = const Size(1200, 400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);

    final repo = PacketRepository(
      storageService: ProtocolLibraryService(storageDirectory: tempDir),
    );
    repo.loadDemoCapture();
    final vm = InspectorViewModel(repository: repo);
    addTearDown(vm.dispose);

    await tester.pumpWidget(
      ChangeNotifierProvider<InspectorViewModel>.value(
        value: vm,
        child: const MaterialApp(
          home: Scaffold(
            body: DualModeFilterBar(),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    final srcField = find.widgetWithText(TextField, 'Source IP');
    await tester.enterText(srcField, '192.168.1.50');

    // Before 150ms, ViewModel should NOT be updated yet
    await tester.pump(const Duration(milliseconds: 50));
    expect(vm.sourceSearch, isEmpty);

    // After 150ms, ViewModel IS updated
    await tester.pump(const Duration(milliseconds: 120));
    await tester.pumpAndSettle();
    expect(vm.sourceSearch, equals('192.168.1.50'));

    // Clear button resets immediately without waiting 150ms
    final clearBtn = find.byIcon(Icons.clear).first;
    await tester.tap(clearBtn);
    await tester.pump();
    expect(vm.sourceSearch, isEmpty);
  });
}
