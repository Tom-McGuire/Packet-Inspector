import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:packet_inspector/data/repositories/packet_repository.dart';
import 'package:packet_inspector/data/services/ai/packet_ai_tools.dart';
import 'package:packet_inspector/ui/features/inspector/view_models/inspector_view_model.dart';
import 'package:packet_inspector/ui/features/ai_assistant/views/ai_assistant_panel.dart';

void main() {
  group('PacketAiTools Unit Tests', () {
    late PacketRepository repo;
    late PacketAiTools tools;

    setUp(() {
      repo = PacketRepository();
      repo.loadDemoCapture();
      tools = PacketAiTools(repository: repo);
    });

    tearDown(() {
      repo.dispose();
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
  });

  group('LlmProviderService & GenUI Widget Tests', () {
    testWidgets('AiAssistantPanel renders starter prompts and executes offline deterministic tool', (tester) async {
      tester.view.physicalSize = const Size(1200, 800);
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
  });
}
