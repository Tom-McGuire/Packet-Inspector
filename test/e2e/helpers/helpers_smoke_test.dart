import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:packet_inspector/data/services/ai/cli_llm_service.dart';
import 'package:packet_inspector/data/services/ai/llm_provider_service.dart';
import 'package:packet_inspector/data/services/diff/multi_capture_diff_engine.dart';
import 'package:packet_inspector/data/services/export/csv_export_service.dart';
import 'package:network_suite_shared/network_suite_shared.dart';
import 'package:packet_inspector/domain/models/packet_diff_record.dart';

import 'e2e_test_harness.dart';
import 'mock_llm_backends.dart';
import 'pcap_fixture_builder.dart';

void main() {
  group('pcap_fixture_builder smoke tests', () {
    test('classic PCAP LE/BE microsecond & nanosecond offsets & truncation', () async {
      final harness = E2eTestHarness.create();
      for (final endian in [Endian.little, Endian.big]) {
        for (final nano in [false, true]) {
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture(
            endian: endian,
            nanosecond: nano,
          );
          final parsed = PcapBinaryReader.parseBytes(fixture.bytes);
          expect(parsed.length, equals(fixture.expectations.length));

          for (int i = 0; i < parsed.length; i++) {
            final exp = fixture.expectations[i];
            expect(parsed[i].data, equals(exp.frameBytes));
            expect(parsed[i].timestampUs, equals(exp.timestampUs));
            expect(
              fixture.bytes.sublist(
                exp.expectedFrameFileOffset,
                exp.expectedFrameFileOffset + exp.frameBytes.length,
              ),
              equals(exp.frameBytes),
            );
            expect(
              fixture.bytes.sublist(
                exp.expectedPayloadFileOffset,
                exp.expectedPayloadFileOffset + exp.l4PayloadBytes.length,
              ),
              equals(exp.l4PayloadBytes),
            );
          }

          // Verify 1400-byte payload expectation is present
          expect(
            fixture.expectations.any((e) => e.l4PayloadBytes.length == 1400),
            isTrue,
          );
        }
      }

      // Link types + VLAN + truncation boundary
      for (final linkType in [1, 113, 0, 101]) {
        final b = ClassicPcapBuilder(linkType: linkType);
        final built = switch (linkType) {
          1 => PcapFrameFactory.ethernetUdp(
              srcIp: '10.0.0.1',
              dstIp: '10.0.0.2',
              srcPort: 1000,
              dstPort: 2000,
              vlanId: 42,
              payload: Uint8List.fromList([1, 2, 3, 4]),
            ),
          113 => PcapFrameFactory.linuxSllUdp(
              srcIp: '10.0.0.1',
              dstIp: '10.0.0.2',
              srcPort: 1000,
              dstPort: 2000,
              payload: Uint8List.fromList([1, 2, 3, 4]),
            ),
          0 => PcapFrameFactory.loopbackUdp(
              srcIp: '10.0.0.1',
              dstIp: '10.0.0.2',
              srcPort: 1000,
              dstPort: 2000,
              payload: Uint8List.fromList([1, 2, 3, 4]),
            ),
          _ => PcapFrameFactory.rawIpUdp(
              srcIp: '10.0.0.1',
              dstIp: '10.0.0.2',
              srcPort: 1000,
              dstPort: 2000,
              payload: Uint8List.fromList([1, 2, 3, 4]),
            ),
        };
        b.addBuiltFrame(built, timestampUs: 1700000000000000);
        b.appendTruncatedTrailingPacket(timestampUs: 1700000000001000);

        final parsed = PcapBinaryReader.parseBytes(b.buildBytes());
        expect(parsed.length, equals(1));
        expect(parsed.first.linkType, equals(linkType));
        expect(parsed.first.data, equals(built.frameBytes));
      }

      // Bulk (>1000) capture file ingest & CSV decoding
      final bulk = PcapFixtureBuilder.buildBulkPcap(packetCount: 1200);
      final file = harness.writeTempCaptureFile('bulk_1200.pcap', bulk.bytes);
      harness.repository.loadFromFile(file);
      expect(harness.repository.getPacketCount(), equals(1200));

      final allRows = harness.repository.queryPackets(limit: 1200, offset: 0);
      final csv = CsvExportService.exportPacketsToCsv(allRows);
      final decoded = E2eTestHarness.parseCsvRows(csv);
      expect(decoded.length, equals(1201)); // 1 header + 1200 data rows
    });

    test('PCAPNG multi-SHB, multi-IDB (0x80|32 tsresol), EPB & SPB fixture', () {
      final fixture = PcapFixtureBuilder.buildMultiIdbPcapNg();
      final parsed = PcapBinaryReader.parseBytes(fixture.bytes);
      expect(parsed.length, equals(4));
      expect(fixture.expectations.length, equals(4));

      for (int i = 0; i < fixture.expectations.length; i++) {
        final exp = fixture.expectations[i];
        expect(
          fixture.bytes.sublist(
            exp.expectedFrameFileOffset,
            exp.expectedFrameFileOffset + exp.frameBytes.length,
          ),
          equals(exp.frameBytes),
        );
        expect(
          parsed[i].data.sublist(0, exp.frameBytes.length),
          equals(exp.frameBytes),
        );
      }
    });

    test('multi-hop diff fixture exercises drops, mutations, gaps, ooo, spikes', () async {
      final harness = E2eTestHarness.create();
      final diffFixture = PcapFixtureBuilder.buildMultiHopDiffCaptures(
        tempDir: harness.tempDir,
      );
      expect(diffFixture.files.length, equals(3));
      expect(diffFixture.inputs.length, equals(3));

      final engine = MultiCaptureDiffEngine();
      addTearDown(engine.dispose);
      await engine.ingestCaptures(diffFixture.inputs);

      expect(engine.slots.length, equals(3));
      final records = engine.queryDiffRecords(
        filterMode: DiffFilterMode.sharedFlowsOnly,
      );
      expect(records, isNotEmpty);

      final allStatuses = records.expand((r) => r.statuses).toSet();
      expect(allStatuses, contains(DiffStatus.dropped));
      expect(allStatuses, contains(DiffStatus.qosVlanMutated));
      expect(allStatuses, contains(DiffStatus.sourceGap));
      expect(allStatuses, contains(DiffStatus.outOfOrder));
      expect(allStatuses, contains(DiffStatus.latencySpike));
    });
  });

  group('mock_llm_backends smoke tests', () {
    test('MockHttpLlmServer intercepts Gemini, Ollama chat & Ollama /api/tags', () async {
      final harness = E2eTestHarness.create();
      harness.repository.loadDemoCapture();

      // Verify standalone MockHttpLlmServer + createMockLlmService factory directly
      final standaloneHttp = MockHttpLlmServer(
        geminiResponseText: 'Standalone Gemini response.',
      );
      final standaloneLlm = createMockLlmService(
        repository: harness.repository,
        storageService: harness.aiStorage,
        cliBackend: harness.cliBackend,
        backendMode: LlmBackendMode.geminiCloud,
      );
      await standaloneHttp.runWithHttpMock(() async {
        final r = await standaloneLlm.sendMessage('Summarize traffic');
        expect(r.text, contains('Standalone Gemini response.'));
        expect(standaloneHttp.recordedCalls.length, equals(1));
      });

      await harness.httpServer.runWithHttpMock(() async {
        // 1. Ollama model discovery
        harness.llmService.ollamaUrl = 'http://localhost:11434';
        final models = await harness.llmService.listOllamaModels();
        expect(models, equals(['gemma2:9b', 'gemma3:4b', 'llama3.2:latest']));

        // 2. Ollama chat
        harness.llmService.backendMode = LlmBackendMode.localGemma;
        final ollamaReply = await harness.llmService.sendMessage('Show top talkers');
        expect(ollamaReply.text, contains('Mock Ollama network analysis.'));
        expect(ollamaReply.toolResult, isNotNull);

        // 3. Gemini Cloud
        harness.llmService.backendMode = LlmBackendMode.geminiCloud;
        harness.llmService.geminiApiKey = 'test-key';
        final geminiReply = await harness.llmService.sendMessage('Summarize traffic');
        expect(geminiReply.text, contains('Mock Gemini network analysis.'));
        expect(harness.httpServer.recordedCalls.length, equals(3));

        // 4. HTTP 500 fallback to deterministic analyzer
        harness.httpServer.geminiStatusCode = 500;
        final fallbackReply = await harness.llmService.sendMessage('Summarize traffic');
        expect(fallbackReply.text, contains('deterministic offline analyzer'));
      });
    });

    test('MockCliLlmBackend exercises agy, claude, codex status, models & fallback', () async {
      final harness = E2eTestHarness.create();
      harness.repository.loadDemoCapture();

      expect(File(harness.cliBackend.agyDummyPath).existsSync(), isTrue);
      expect(File(harness.cliBackend.claudeDummyPath).existsSync(), isTrue);
      expect(File(harness.cliBackend.codexDummyPath).existsSync(), isTrue);

      final agyStatus = await harness.cliBackend.cliService.checkStatus(
        CliType.antigravity,
        customPath: harness.cliBackend.agyDummyPath,
      );
      expect(agyStatus.isInstalled, isTrue);
      expect(agyStatus.isAuthenticated, isTrue);

      final models = await harness.cliBackend.cliService.listAgyModels(
        customPath: harness.cliBackend.agyDummyPath,
      );
      expect(models.map((m) => m.id), contains('gemini-3.8-flash-low'));

      // Query each CLI mode through LlmProviderService
      for (final mode in [
        LlmBackendMode.antigravityCli,
        LlmBackendMode.claudeCodeCli,
        LlmBackendMode.chatGptCodexCli,
      ]) {
        harness.llmService.backendMode = mode;
        final reply = await harness.llmService.sendMessage('Find timing bursts');
        expect(reply.toolResult, isNotNull);
        expect(reply.text, contains('Mock'));
      }
      expect(harness.cliBackend.recordedCalls.length, greaterThanOrEqualTo(3));

      // Unauthenticated fallback check
      harness.cliBackend.claudeConfig.authenticated = false;
      harness.llmService.backendMode = LlmBackendMode.claudeCodeCli;
      final authFallback = await harness.llmService.sendMessage('Summarize traffic');
      expect(authFallback.text, contains('deterministic offline analyzer'));
    });
  });

  group('e2e_test_harness widget smoke tests', () {
    testWidgets('pumps InspectorScreen with & without CompareProvider and handles search', (
      WidgetTester tester,
    ) async {
      final harness1 = E2eTestHarness.create();
      harness1.repository.loadDemoCapture();
      await harness1.pumpInspectorWorkspace(
        tester,
        showAiAssistant: true,
        includeCompareProvider: true,
      );
      expect(find.text('Packet Inspector'), findsOneWidget);
      expect(find.text('AI Assistant'), findsOneWidget);

      final searchFields = find.byType(TextField);
      expect(searchFields, findsWidgets);
      await E2eTestHarness.enterSearchText(tester, searchFields.first, '192.168.1.10');
      expect(harness1.inspectorVm.packets, isNotEmpty);

      // Pump without CaptureCompareViewModel in MultiProvider
      final harness2 = E2eTestHarness.create();
      harness2.repository.loadDemoCapture();
      await harness2.pumpInspectorWorkspace(
        tester,
        showAiAssistant: true,
        includeCompareProvider: false,
      );
      expect(find.text('Packet Inspector'), findsOneWidget);
    });

    testWidgets('pumps PacketInspectorApp cleanly with in-memory SharedDeviceDatabase', (
      WidgetTester tester,
    ) async {
      final harness = E2eTestHarness.create();
      await harness.pumpPacketInspectorApp(tester);
      expect(find.text('Packet Inspector'), findsOneWidget);
    });
  });
}
