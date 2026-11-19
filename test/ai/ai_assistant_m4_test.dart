import 'dart:io';
import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:packet_inspector/data/repositories/packet_repository.dart';
import 'package:packet_inspector/data/services/ai/cli_llm_service.dart';
import 'package:packet_inspector/data/services/ai/llm_provider_service.dart';
import 'package:packet_inspector/data/services/ai/packet_ai_tools.dart';
import 'package:packet_inspector/data/services/diff/demo_diff_generator.dart';
import 'package:packet_inspector/data/services/storage/ai_settings_storage_service.dart';
import 'package:packet_inspector/data/services/storage/protocol_library_service.dart';
import 'package:packet_inspector/domain/models/packet_diff_record.dart';
import 'package:packet_inspector/ui/features/ai_assistant/views/ai_assistant_panel.dart';
import 'package:packet_inspector/ui/features/compare/view_models/capture_compare_view_model.dart';
import 'package:packet_inspector/ui/features/inspector/view_models/inspector_view_model.dart';

void main() {
  group('Milestone M4 AI Assistant Tests', () {
    late Directory tempDir;

    setUp(() {
      tempDir = Directory.systemTemp.createTempSync('ai_m4_test_');
    });

    tearDown(() {
      try {
        tempDir.deleteSync(recursive: true);
      } catch (_) {}
    });

    testWidgets('Backend menu exposes all 6 LlmBackendMode options and CLI config dialog tests connection & discovers models', (tester) async {
      tester.view.physicalSize = const Size(1200, 800);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);

      final dummyAgy = File('${tempDir.path}/agy')..createSync();
      final recordedPrompts = <String>[];

      final cliService = CliLlmService(
        processRunner: (exe, args, {runInShell = false, timeout}) async {
          if (args.contains('--version')) {
            return ProcessResult(1, 0, '2.0.0', '');
          }
          if (args.contains('models')) {
            return ProcessResult(
              1,
              0,
              'gemini-3.8-flash-low\tGemini 3.8 Flash (Low)\nclaude-sonnet-5-5-high\tClaude Sonnet 5.5 (High)',
              '',
            );
          }
          if (args.contains('ping')) {
            return ProcessResult(1, 0, 'pong', '');
          }
          recordedPrompts.add(args.join(' '));
          return ProcessResult(1, 0, 'CLI mock reply', '');
        },
      );

      final repo = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir),
      );
      repo.loadDemoCapture();
      final storage = AiSettingsStorageService(storageDirectory: tempDir);
      final llmService = LlmProviderService(
        tools: PacketAiTools(repository: repo),
        storageService: storage,
        cliService: cliService,
      );
      final vm = InspectorViewModel(
        repository: repo,
        aiSettingsStorage: storage,
      );

      await tester.pumpWidget(
        MultiProvider(
          providers: [
            ChangeNotifierProvider<InspectorViewModel>.value(value: vm),
          ],
          child: MaterialApp(
            home: Scaffold(
              body: SizedBox(
                width: 420,
                child: AiAssistantPanel(llmService: llmService),
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Open backend menu and verify all 6 options
      await tester.tap(find.byTooltip('Backend Model'));
      await tester.pumpAndSettle();

      for (final mode in LlmBackendMode.values) {
        expect(
          find.byWidgetPredicate((w) => w is PopupMenuItem<LlmBackendMode> && w.value == mode),
          findsOneWidget,
        );
      }

      // Select Antigravity CLI
      await tester.tap(
        find.byWidgetPredicate((w) => w is PopupMenuItem<LlmBackendMode> && w.value == LlmBackendMode.antigravityCli),
      );
      await tester.pumpAndSettle();

      expect(find.text('AI Model Configuration'), findsOneWidget);
      final pathField = find.descendant(
        of: find.byType(AlertDialog),
        matching: find.byType(TextField),
      );
      await tester.enterText(pathField.first, dummyAgy.path);
      await tester.pumpAndSettle();

      // Test Connection
      await tester.tap(find.text('Test Connection'));
      await tester.pumpAndSettle();
      expect(find.textContaining('Active subscription ready'), findsOneWidget);

      // Verify discovered models in DropdownButton<String>
      final dropdown = find.descendant(
        of: find.byType(AlertDialog),
        matching: find.byWidgetPredicate((w) => w is DropdownButton<String>),
      );
      expect(dropdown, findsOneWidget);

      // Save
      await tester.tap(find.text('Save'));
      await tester.pumpAndSettle();

      final saved = storage.loadSettings();
      expect(saved.backendMode, equals(LlmBackendMode.antigravityCli));
      expect(saved.agyPath, equals(dummyAgy.path));
    });

    test('LlmProviderService runs deterministic tool first and injects capture ground truth into CLI prompts', () async {
      final dummyClaude = File('${tempDir.path}/claude')..createSync();
      String? capturedPrompt;

      final cliService = CliLlmService(
        processRunner: (exe, args, {runInShell = false, timeout}) async {
          final idx = args.indexOf('-p');
          if (idx >= 0 && idx + 1 < args.length) {
            capturedPrompt = args[idx + 1];
          }
          return ProcessResult(1, 0, 'Claude observed the top talkers.', '');
        },
      );

      final repo = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir),
      );
      repo.loadDemoCapture();

      final llmService = LlmProviderService(
        tools: PacketAiTools(repository: repo),
        cliService: cliService,
        backendMode: LlmBackendMode.claudeCodeCli,
        claudePath: dummyClaude.path,
      );

      final reply = await llmService.sendMessage(
        'Who are the top talkers?',
        contextEnvelope: 'Scope: Whole Capture',
      );

      expect(capturedPrompt, isNotNull);
      expect(capturedPrompt, contains('Scope: Whole Capture'));
      expect(capturedPrompt, contains('Total Packets:'));
      expect(capturedPrompt, contains('Top 5 Talkers'));
      expect(reply.text, contains('Claude observed the top talkers.'));
      expect(reply.toolResult?.widgetType, equals('top_talkers_chart'));
    });

    testWidgets('AiAssistantPanel renders compare_summary_card and Jump to First Drop updates CaptureCompareViewModel', (tester) async {
      tester.view.physicalSize = const Size(1200, 800);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);

      final repo = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir),
      );
      repo.loadDemoCapture();
      final vm = InspectorViewModel(repository: repo);

      final compareVm = CaptureCompareViewModel();
      await compareVm.loadCaptures(DemoDiffGenerator.buildDemoCaptures());
      expect(compareVm.isCompareMode, isTrue);
      expect(compareVm.selectedRecord, isNull);

      await tester.pumpWidget(
        MultiProvider(
          providers: [
            ChangeNotifierProvider<InspectorViewModel>.value(value: vm),
            ChangeNotifierProvider<CaptureCompareViewModel>.value(value: compareVm),
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

      await tester.enterText(find.byType(TextField), 'Compare captures and find packet drops');
      await tester.tap(find.byIcon(Icons.send));
      await tester.pumpAndSettle();

      expect(find.text('Multi-Capture Path Comparison'), findsOneWidget);
      expect(find.text('Jump to First Drop'), findsOneWidget);

      await tester.tap(find.text('Jump to First Drop'));
      await tester.pumpAndSettle();

      expect(compareVm.selectedRecord, isNotNull);
      expect(compareVm.selectedRecord!.statuses, contains(DiffStatus.dropped));
    });
  });
}
