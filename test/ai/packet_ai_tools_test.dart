import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:packet_inspector/domain/models/custom_protocol_rule.dart';
import 'package:packet_inspector/domain/models/endpoint_rule.dart';
import 'package:packet_inspector/domain/models/packet_record.dart';
import 'package:packet_inspector/data/repositories/packet_repository.dart';
import 'package:packet_inspector/data/services/storage/protocol_library_service.dart';
import 'package:packet_inspector/data/services/ai/packet_ai_tools.dart';
import 'package:packet_inspector/data/services/ai/ai_filter_references.dart';
import 'package:packet_inspector/ui/features/inspector/view_models/inspector_view_model.dart';
import 'package:packet_inspector/ui/features/ai_assistant/views/ai_assistant_panel.dart';

void main() {
  group('PacketAiTools Unit Tests', () {
    late Directory tempDir;
    late PacketRepository repo;
    late PacketAiTools tools;

    setUp(() {
      tempDir = Directory.systemTemp.createTempSync('packet_ai_test_');
      repo = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir),
      );
      repo.loadDemoCapture();
      tools = PacketAiTools(repository: repo);
    });

    tearDown(() {
      repo.dispose();
      try {
        tempDir.deleteSync(recursive: true);
      } catch (_) {}
    });

    test('getCaptureSummary returns summary data and widget payload', () {
      final result = tools.getCaptureSummary();
      expect(result.toolName, equals('get_capture_summary'));
      expect(result.widgetType, equals('summary_card'));
      expect(result.data['totalPackets'], greaterThan(15));
      expect(result.summaryText, contains('Total Packets:'));
      expect(result.summaryText, contains('Top Protocols:'));
    });

    test('getTopTalkers returns conversation flows sorted by bytes', () {
      final result = tools.getTopTalkers(metric: 'bytes', limit: 5);
      expect(result.toolName, equals('get_top_talkers'));
      expect(result.widgetType, equals('top_talkers_chart'));
      final talkers = result.data['talkers'] as List<dynamic>;
      expect(talkers.isNotEmpty, isTrue);
      expect(talkers.first['src_ip'], isNotEmpty);
      expect(talkers.first['total_bytes'], greaterThan(0));
    });

    test('findTimingAnomalies identifies micro-burst traffic spikes and stalls', () {
      // Find micro-bursts (global delta < 100us)
      final bursts = tools.findTimingAnomalies(isBurst: true, thresholdUs: 100);
      expect(bursts.toolName, equals('find_timing_anomalies'));
      expect(bursts.widgetType, equals('timing_spikes_table'));
      final spikeList = bursts.data['spikes'] as List<dynamic>;
      expect(spikeList.isNotEmpty, isTrue);

      // Find stream stalls
      final stalls = tools.findTimingAnomalies(isBurst: false, thresholdUs: 100000);
      final stallList = stalls.data['spikes'] as List<dynamic>;
      expect(stallList.isNotEmpty, isTrue);
    });

    test('suggestCustomProtocolSignature inspects UDP port 45820 and infers ACME magic bytes', () {
      final result = tools.suggestCustomProtocolSignature(port: 45820, ipProto: 17);
      expect(result.toolName, equals('suggest_custom_protocol_signature'));
      expect(result.widgetType, equals('custom_protocol_suggestion'));
      expect(result.data['suggestedName'], equals('ACME'));
      expect(result.data['magicBytesHex'], contains('41 43 4d 45'));
    });

    test('AiFilterReferences parses /p, /s, /r references and resolves library specs', () {
      repo.addCustomProtocol(const CustomProtocolRule(
        id: 'proto_sacn',
        name: 'sACN Per Address Priority',
        colorHex: 0xFF9C27B0,
        defaultTriageStatus: TriageStatus.expected,
        ipProtocol: 17,
        port: 57313,
        magicBytesOffset: 153,
        magicBytesHex: [0xDD],
      ));
      repo.addSender(const EndpointRule(
        id: 'sender_1',
        name: 'Lighting Controller',
        ipAddress: '10.101.50.109',
        type: EndpointType.sender,
      ));
      repo.addReceiver(const EndpointRule(
        id: 'receiver_1',
        name: 'Stage Gateway',
        ipAddress: '239.255.0.1',
        port: 57313,
        type: EndpointType.receiver,
      ));

      const input = 'Show analysis for /p:"sACN Per Address Priority" from /s:10.101.50.109 to /r:"Stage Gateway"';
      final refs = AiFilterReferences.parse(input, repo);

      expect(refs.hasAnyReferences, isTrue);
      expect(refs.rawProtocols, contains('sACN Per Address Priority'));
      expect(refs.rawSenders, contains('10.101.50.109'));
      expect(refs.rawReceivers, contains('Stage Gateway'));

      expect(refs.matchedProtocolRules.length, equals(1));
      expect(refs.matchedProtocolRules.first.name, equals('sACN Per Address Priority'));
      expect(refs.matchedSenders.length, equals(1));
      expect(refs.matchedSenders.first.name, equals('Lighting Controller'));
      expect(refs.matchedReceivers.length, equals(1));
      expect(refs.matchedReceivers.first.name, equals('Stage Gateway'));

      final summary = refs.buildLibraryContextSummary();
      expect(summary, contains('sACN Per Address Priority'));
      expect(summary, contains('Lighting Controller'));
      expect(summary, contains('Stage Gateway'));
      expect(summary, contains('Magic bytes: [0xdd] at offset 153'));
    });

    test('generateFilteredReport calculates traffic volume and time span for filtered subset', () {
      const refs = AiFilterReferences(
        rawProtocols: ['DNS'],
        rawSenders: ['192.168.1.10'],
        rawReceivers: [],
        matchedProtocolRules: [],
        standardProtocols: ['DNS'],
        matchedSenders: [],
        unmatchedSenderIps: ['192.168.1.10'],
        matchedReceivers: [],
        unmatchedReceiverIps: [],
      );

      final report = tools.generateFilteredReport(refs: refs);
      expect(report.toolName, equals('generate_filtered_report'));
      expect(report.widgetType, equals('filtered_library_report'));
      expect(report.data['matchingPacketCount'], greaterThan(0));
      expect(report.summaryText, contains('Filtered Traffic Analysis'));
      expect(report.summaryText, contains('Matching Packets:'));
    });
  });

  group('LlmProviderService & GenUI Widget Tests', () {
    late Directory tempWidgetDir;

    setUp(() {
      tempWidgetDir = Directory.systemTemp.createTempSync('packet_ai_widget_test_');
    });

    tearDown(() {
      try {
        tempWidgetDir.deleteSync(recursive: true);
      } catch (_) {}
    });

    testWidgets('AiAssistantPanel renders starter prompts and executes offline deterministic tool', (tester) async {
      tester.view.physicalSize = const Size(1200, 800);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);

      final repo = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempWidgetDir),
      );
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
                width: 380,
                child: AiAssistantPanel(),
              ),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Verify AI panel header & welcome message
      expect(find.text('AI Assistant'), findsOneWidget);
      expect(find.textContaining('Welcome to'), findsOneWidget);

      // Verify Starter Prompt Chips
      expect(find.text('Show capture summary'), findsOneWidget);
      expect(find.text('Chart top talkers by bytes'), findsOneWidget);

      // Tap "Show capture summary" chip (first chip)
      await tester.tap(find.text('Show capture summary'));
      await tester.pumpAndSettle();

      // Verify GenUI Summary card rendered
      expect(find.text('Capture Protocol Breakdown'), findsOneWidget);

      // Enter query in text field and tap Send
      await tester.enterText(find.byType(TextField), 'Show top talkers by bytes');
      await tester.tap(find.byIcon(Icons.send));
      await tester.pumpAndSettle();

      // Verify GenUI Top Talkers card rendered
      expect(find.textContaining('Top Conversations by BYTES'), findsOneWidget);
      expect(find.text('CSV'), findsOneWidget);
    });

    testWidgets('AiAssistantPanel supports /p, /s, /r autocomplete suggestions and applies filters to main view', (tester) async {
      tester.view.physicalSize = const Size(1200, 800);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);

      final repo = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempWidgetDir),
      );
      repo.loadDemoCapture();
      repo.addCustomProtocol(const CustomProtocolRule(
        id: 'proto_sacn_ai',
        name: 'sACN AI Test',
        colorHex: 0xFF9C27B0,
        defaultTriageStatus: TriageStatus.expected,
        port: 57313,
      ));
      repo.addSender(const EndpointRule(
        id: 'sender_ai',
        name: 'Main Stage Sender',
        ipAddress: '10.101.50.109',
        type: EndpointType.sender,
      ));

      final vm = InspectorViewModel(repository: repo);

      await tester.pumpWidget(
        MultiProvider(
          providers: [
            ChangeNotifierProvider<InspectorViewModel>.value(value: vm),
          ],
          child: const MaterialApp(
            home: Scaffold(
              body: SizedBox(
                width: 420,
                child: AiAssistantPanel(),
              ),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Verify filter shortcut chips exist
      expect(find.text('/p Protocol'), findsOneWidget);
      expect(find.text('/s Sender'), findsOneWidget);
      expect(find.text('/r Receiver'), findsOneWidget);

      // Tap '/p Protocol' chip to open protocol suggestion popup
      await tester.tap(find.text('/p Protocol'));
      await tester.pumpAndSettle();

      expect(find.text('Select Protocol (/p)'), findsOneWidget);
      expect(find.text('sACN AI Test'), findsOneWidget);

      // Tap 'sACN AI Test' item to insert into text field
      await tester.tap(find.text('sACN AI Test'));
      await tester.pumpAndSettle();

      // Verify text field now contains /p:"sACN AI Test"
      final inputField = tester.widget<TextField>(find.byType(TextField));
      expect(inputField.controller?.text, contains('/p:'));

      // Send the message to AI
      await tester.tap(find.byIcon(Icons.send));
      await tester.pumpAndSettle();

      // Verify Filtered Traffic Report GenUI card is rendered
      expect(find.text('Filtered Traffic Report'), findsOneWidget);
      expect(find.text('Apply to Filter Bar'), findsOneWidget);

      // Tap 'Apply to Filter Bar'
      await tester.tap(find.text('Apply to Filter Bar'));
      await tester.pumpAndSettle();

      // Verify ViewModel now has this filter active
      expect(vm.isTriageMode, isFalse);
      expect(vm.selectedProtocolPills.contains('sACN AI Test'), isTrue);
    });
  });
}
