import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:packet_inspector/data/services/ai/ai_filter_references.dart';
import 'package:packet_inspector/data/services/ai/llm_provider_service.dart';
import 'package:packet_inspector/data/services/diff/multi_capture_diff_engine.dart';
import 'package:packet_inspector/data/services/storage/ai_settings_storage_service.dart';
import 'package:packet_inspector/data/services/storage/shared_device_database.dart';
import 'package:packet_inspector/domain/models/custom_protocol_rule.dart';
import 'package:packet_inspector/domain/models/endpoint_rule.dart';
import 'package:packet_inspector/domain/models/packet_diff_record.dart';
import 'package:packet_inspector/domain/models/packet_record.dart';
import 'package:packet_inspector/ui/features/ai_assistant/views/ai_assistant_panel.dart';
import 'package:packet_inspector/ui/features/inspector/view_models/inspector_view_model.dart';
import 'package:path/path.dart' as p;

import 'helpers/e2e_test_harness.dart';
import 'helpers/mock_llm_backends.dart';
import 'helpers/pcap_fixture_builder.dart';

/// E2E suite for Milestone M_E2E_5_ai_assistant covering:
/// - F9: AiAssistantPanel CLI backends & config/model-discovery UI
/// - F10: LlmProviderService deterministic-first execution & prompt injection
/// - F11: compareCapturesSummary & compare_summary_card + nullable CaptureCompareViewModel?
/// - F14/F15/F17 (AI): Canonical AI tools & AiFilterReferences contracts
/// - F21 (AI storage): AiSettingsStorageService cross-platform directory, encryption & resilience
void main() {
  const desktopSize = Size(1680, 900);

  Future<void> loadRichCapture(E2eTestHarness harness) async {
    final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
    final file = harness.writeTempCaptureFile('rich_ai_capture.pcap', fixture.bytes);
    harness.inspectorVm.loadFile(file);
  }

  Future<void> openAiAssistant(WidgetTester tester) async {
    final aiButton = find.text('AI Assistant');
    await tester.ensureVisible(aiButton);
    await tester.tap(aiButton);
    await tester.pumpAndSettle();
    expect(find.byType(AiAssistantPanel), findsOneWidget);
  }

  Future<void> openBackendMenuAndSelect(
    WidgetTester tester,
    LlmBackendMode mode,
  ) async {
    final menuBtn = find.descendant(
      of: find.byType(AiAssistantPanel),
      matching: find.byTooltip('Backend Model'),
    );
    expect(menuBtn, findsOneWidget);
    await tester.tap(menuBtn);
    await tester.pumpAndSettle();

    final itemFinder = find.byWidgetPredicate(
      (w) => w is PopupMenuItem<LlmBackendMode> && w.value == mode,
    );
    expect(
      itemFinder,
      findsOneWidget,
      reason: 'Backend menu must expose ${mode.name}',
    );
    await tester.tap(itemFinder);
    await tester.pumpAndSettle();
  }

  Future<void> sendAiPrompt(WidgetTester tester, String prompt) async {
    final inputFinder = find.descendant(
      of: find.byType(AiAssistantPanel),
      matching: find.byType(TextField),
    );
    expect(inputFinder, findsOneWidget);
    await tester.enterText(inputFinder, prompt);
    await tester.pump();

    // Clear any transient SnackBar before tapping Send at bottom-right
    ScaffoldMessenger.maybeOf(
      tester.element(find.byType(AiAssistantPanel)),
    )?.clearSnackBars();
    await tester.pumpAndSettle();

    final sendBtn = find.descendant(
      of: find.byType(AiAssistantPanel),
      matching: find.byIcon(Icons.send),
    );
    expect(sendBtn, findsOneWidget);
    await tester.tap(sendBtn);
    await tester.pumpAndSettle();
  }

  Finder dialogTextFieldMatching(RegExp pattern) {
    final inDialog = find.descendant(
      of: find.byType(AlertDialog),
      matching: find.byType(TextField),
    );
    final labeled = find.descendant(
      of: find.byType(AlertDialog),
      matching: find.byWidgetPredicate((w) {
        if (w is! TextField) return false;
        final dec = w.decoration;
        final label = dec?.labelText ?? '';
        final hint = dec?.hintText ?? '';
        return pattern.hasMatch('$label $hint');
      }),
    );
    return labeled.evaluate().isNotEmpty ? labeled : inDialog;
  }

  String extractGeminiPromptText(RecordedHttpCall call) {
    final contents = call.decodedJson?['contents'] as List<dynamic>?;
    final first = contents?.first as Map<String, dynamic>?;
    final parts = first?['parts'] as List<dynamic>?;
    final part = parts?.first as Map<String, dynamic>?;
    return part?['text'] as String? ?? '';
  }

  String extractOllamaPromptText(RecordedHttpCall call) {
    final messages = call.decodedJson?['messages'] as List<dynamic>? ?? const [];
    for (final m in messages) {
      if (m is Map<String, dynamic> && m['role'] == 'user') {
        return m['content'] as String? ?? '';
      }
    }
    return '';
  }

  String extractCliPromptText(RecordedCliCall call) {
    return call.arguments.firstWhere(
      (arg) => arg.contains('User Question:') || arg.length > 20,
      orElse: () => call.arguments.join(' '),
    );
  }

  // =========================================================================
  // Group 1: F9 — AiAssistantPanel CLI Backends & Config/Model-Discovery UI
  // =========================================================================
  group('F9 — AiAssistantPanel CLI Backends & Config/Model-Discovery UI', () {
    group('Tier 1 — Feature Coverage', () {
      testWidgets('[F9][T1-1] backend menu exposes all 6 LlmBackendMode options', (
        WidgetTester tester,
      ) async {
        final harness = E2eTestHarness.create();
        await loadRichCapture(harness);
        await harness.pumpInspectorWorkspace(
          tester,
          showAiAssistant: true,
          viewportSize: desktopSize,
        );
        await openAiAssistant(tester);

        final menuBtn = find.descendant(
          of: find.byType(AiAssistantPanel),
          matching: find.byTooltip('Backend Model'),
        );
        await tester.tap(menuBtn);
        await tester.pumpAndSettle();

        for (final mode in LlmBackendMode.values) {
          expect(
            find.byWidgetPredicate(
              (w) => w is PopupMenuItem<LlmBackendMode> && w.value == mode,
            ),
            findsOneWidget,
            reason: 'Expected PopupMenuItem for ${mode.name}',
          );
        }
      });

      testWidgets(
        '[F9][T1-2] Antigravity CLI config dialog sets binary path, tests connection, discovers agy models & persists',
        (WidgetTester tester) async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);
          await harness.pumpInspectorWorkspace(
            tester,
            showAiAssistant: true,
            viewportSize: desktopSize,
          );
          await openAiAssistant(tester);

          await openBackendMenuAndSelect(tester, LlmBackendMode.antigravityCli);
          expect(find.text('AI Model Configuration'), findsOneWidget);

          final pathField = dialogTextFieldMatching(
            RegExp(r'path|binary|agy|executable', caseSensitive: false),
          );
          expect(pathField, findsWidgets);
          await tester.enterText(pathField.first, harness.cliBackend.agyDummyPath);
          await tester.pumpAndSettle();

          final testConnBtn = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.textContaining('Test Connection'),
          );
          expect(testConnBtn, findsOneWidget);
          await tester.ensureVisible(testConnBtn);
          await tester.tap(testConnBtn);
          await tester.pumpAndSettle();

          expect(
            harness.cliBackend.recordedCalls.any(
              (c) => c.executable == harness.cliBackend.agyDummyPath,
            ),
            isTrue,
          );

          // Discovered agy models should be available (dropdown or list)
          final dropdownFinder = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.byWidgetPredicate((w) => w is DropdownButton<String>),
          );
          if (dropdownFinder.evaluate().isNotEmpty) {
            await tester.ensureVisible(dropdownFinder.first);
            await tester.tap(dropdownFinder.first);
            await tester.pumpAndSettle();
            final flashOption = find.textContaining('gemini-3.8-flash-low');
            final targetOption = flashOption.evaluate().isNotEmpty
                ? flashOption.last
                : find.textContaining('Gemini 3.8 Flash (Low)').last;
            await tester.tap(targetOption);
            await tester.pumpAndSettle();
          } else {
            expect(
              find.descendant(
                of: find.byType(AlertDialog),
                matching: find.textContaining('gemini-3.8-flash'),
              ),
              findsWidgets,
            );
          }

          final saveBtn = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.text('Save'),
          );
          await tester.ensureVisible(saveBtn);
          await tester.tap(saveBtn);
          await tester.pumpAndSettle();

          final saved = harness.aiStorage.loadSettings();
          expect(saved.backendMode, equals(LlmBackendMode.antigravityCli));
          expect(saved.agyPath, equals(harness.cliBackend.agyDummyPath));
        },
      );

      testWidgets(
        '[F9][T1-3] Claude Code CLI config dialog runs status check, selects sonnet model & saves',
        (WidgetTester tester) async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);
          await harness.pumpInspectorWorkspace(
            tester,
            showAiAssistant: true,
            viewportSize: desktopSize,
          );
          await openAiAssistant(tester);

          await openBackendMenuAndSelect(tester, LlmBackendMode.claudeCodeCli);
          expect(find.text('AI Model Configuration'), findsOneWidget);

          final pathField = dialogTextFieldMatching(
            RegExp(r'path|binary|claude|executable', caseSensitive: false),
          );
          expect(pathField, findsWidgets);
          await tester.enterText(pathField.first, harness.cliBackend.claudeDummyPath);
          await tester.pumpAndSettle();

          final testConnBtn = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.textContaining('Test Connection'),
          );
          expect(testConnBtn, findsOneWidget);
          await tester.ensureVisible(testConnBtn);
          await tester.tap(testConnBtn);
          await tester.pumpAndSettle();

          expect(
            harness.cliBackend.recordedCalls.any(
              (c) => c.executable == harness.cliBackend.claudeDummyPath,
            ),
            isTrue,
          );

          final dropdownFinder = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.byWidgetPredicate((w) => w is DropdownButton<String>),
          );
          expect(dropdownFinder, findsWidgets);
          await tester.ensureVisible(dropdownFinder.first);
          await tester.tap(dropdownFinder.first);
          await tester.pumpAndSettle();

          final sonnetOption = find.textContaining(
            RegExp(r'sonnet', caseSensitive: false),
          );
          expect(sonnetOption, findsWidgets);
          await tester.tap(sonnetOption.last);
          await tester.pumpAndSettle();

          final saveBtn = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.text('Save'),
          );
          await tester.ensureVisible(saveBtn);
          await tester.tap(saveBtn);
          await tester.pumpAndSettle();

          final saved = harness.aiStorage.loadSettings();
          expect(saved.backendMode, equals(LlmBackendMode.claudeCodeCli));
          expect(saved.claudePath, equals(harness.cliBackend.claudeDummyPath));
          expect(saved.claudeModel.toLowerCase(), contains('sonnet'));
        },
      );

      testWidgets(
        '[F9][T1-4] Codex CLI config dialog sets codex path & gpt-4o model, then chat executes codex exec',
        (WidgetTester tester) async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);
          await harness.pumpInspectorWorkspace(
            tester,
            showAiAssistant: true,
            viewportSize: desktopSize,
          );
          await openAiAssistant(tester);

          await openBackendMenuAndSelect(tester, LlmBackendMode.chatGptCodexCli);
          expect(find.text('AI Model Configuration'), findsOneWidget);

          final pathField = dialogTextFieldMatching(
            RegExp(r'path|binary|codex|executable', caseSensitive: false),
          );
          expect(pathField, findsWidgets);
          await tester.enterText(pathField.first, harness.cliBackend.codexDummyPath);
          await tester.pumpAndSettle();

          final dropdownFinder = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.byWidgetPredicate((w) => w is DropdownButton<String>),
          );
          expect(dropdownFinder, findsWidgets);
          await tester.ensureVisible(dropdownFinder.first);
          await tester.tap(dropdownFinder.first);
          await tester.pumpAndSettle();

          final gpt4oItem = find.byWidgetPredicate(
            (w) =>
                w is DropdownMenuItem<String> &&
                w.value == 'gpt-4o',
          );
          if (gpt4oItem.evaluate().isNotEmpty) {
            await tester.tap(gpt4oItem.last);
          } else {
            await tester.tap(find.textContaining('GPT-4o (Standard)').last);
          }
          await tester.pumpAndSettle();

          final saveBtn = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.text('Save'),
          );
          await tester.ensureVisible(saveBtn);
          await tester.tap(saveBtn);
          await tester.pumpAndSettle();

          harness.cliBackend.clearRecordedCalls();
          await sendAiPrompt(tester, 'Summarize capture');

          expect(
            harness.cliBackend.recordedCalls.any(
              (c) =>
                  c.executable == harness.cliBackend.codexDummyPath &&
                  c.arguments.contains('exec') &&
                  c.arguments.contains('gpt-4o'),
            ),
            isTrue,
          );
          expect(
            find.descendant(
              of: find.byType(AiAssistantPanel),
              matching: find.textContaining(harness.cliBackend.codexConfig.replyText),
            ),
            findsOneWidget,
          );
        },
      );

      testWidgets(
        '[F9][T1-5] Local Gemma (Ollama) config dialog discovers /api/tags models and persists selection',
        (WidgetTester tester) async {
          final harness = E2eTestHarness.create();
          harness.httpServer.ollamaModels = ['gemma3:12b', 'qwen2.5-coder:7b'];
          await loadRichCapture(harness);

          await harness.httpServer.runWithHttpMock(() async {
            await harness.pumpInspectorWorkspace(
              tester,
              showAiAssistant: true,
              viewportSize: desktopSize,
            );
            await openAiAssistant(tester);
            await openBackendMenuAndSelect(tester, LlmBackendMode.localGemma);
            expect(find.text('AI Model Configuration'), findsOneWidget);

            // Trigger refresh/discover button if not auto-fetched on open
            if (!harness.httpServer.recordedCalls
                .any((c) => c.url.path.endsWith('/api/tags'))) {
              final refreshBtn = find.descendant(
                of: find.byType(AlertDialog),
                matching: find.byWidgetPredicate(
                  (w) =>
                      (w is IconButton) ||
                      (w is TextButton) ||
                      (w is OutlinedButton),
                ),
              );
              final discoverCandidate = find.descendant(
                of: find.byType(AlertDialog),
                matching: find.byIcon(Icons.refresh),
              );
              if (discoverCandidate.evaluate().isNotEmpty) {
                await tester.tap(discoverCandidate.first);
                await tester.pumpAndSettle();
              } else if (refreshBtn.evaluate().length > 2) {
                await tester.tap(refreshBtn.first);
                await tester.pumpAndSettle();
              }
            }

            expect(
              harness.httpServer.recordedCalls
                  .any((c) => c.url.path.endsWith('/api/tags')),
              isTrue,
              reason: 'Ollama config UI must query /api/tags via listOllamaModels()',
            );

            final dropdownFinder = find.descendant(
              of: find.byType(AlertDialog),
              matching: find.byWidgetPredicate((w) => w is DropdownButton<String>),
            );
            if (dropdownFinder.evaluate().isNotEmpty) {
              await tester.ensureVisible(dropdownFinder.first);
              await tester.tap(dropdownFinder.first);
              await tester.pumpAndSettle();
              await tester.tap(find.textContaining('gemma3:12b').last);
              await tester.pumpAndSettle();
            } else {
              expect(
                find.descendant(
                  of: find.byType(AlertDialog),
                  matching: find.textContaining('gemma3:12b'),
                ),
                findsWidgets,
              );
            }

            final saveBtn = find.descendant(
              of: find.byType(AlertDialog),
              matching: find.text('Save'),
            );
            await tester.ensureVisible(saveBtn);
            await tester.tap(saveBtn);
            await tester.pumpAndSettle();

            expect(harness.aiStorage.loadSettings().ollamaModel, equals('gemma3:12b'));
          });
        },
      );
    });

    group('Tier 2 — Boundary & Corner Cases', () {
      testWidgets(
        '[F9][T2-1] CLI missing binary (installed=false) surfaces not-found status and falls back on chat',
        (WidgetTester tester) async {
          final harness = E2eTestHarness.create();
          harness.cliBackend.agyConfig.installed = false;
          harness.cliBackend.syncDummyBinaries();
          await loadRichCapture(harness);

          await harness.pumpInspectorWorkspace(
            tester,
            showAiAssistant: true,
            viewportSize: desktopSize,
          );
          await openAiAssistant(tester);
          await openBackendMenuAndSelect(tester, LlmBackendMode.antigravityCli);

          final pathField = dialogTextFieldMatching(
            RegExp(r'path|binary|agy|executable', caseSensitive: false),
          );
          expect(pathField, findsWidgets);
          await tester.enterText(pathField.first, harness.cliBackend.agyDummyPath);
          await tester.pumpAndSettle();

          final testConnBtn = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.textContaining('Test Connection'),
          );
          expect(testConnBtn, findsOneWidget);
          await tester.ensureVisible(testConnBtn);
          await tester.tap(testConnBtn);
          await tester.pumpAndSettle();

          expect(
            find.descendant(
              of: find.byType(AlertDialog),
              matching: find.textContaining(
                RegExp(r'not found|not installed|missing', caseSensitive: false),
              ),
            ),
            findsWidgets,
          );

          final saveBtn = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.text('Save'),
          );
          await tester.ensureVisible(saveBtn);
          await tester.tap(saveBtn);
          await tester.pumpAndSettle();

          await sendAiPrompt(tester, 'Show capture summary');
          expect(tester.takeException(), isNull);
          expect(
            find.descendant(
              of: find.byType(AiAssistantPanel),
              matching: find.textContaining('deterministic offline analyzer'),
            ),
            findsOneWidget,
          );
        },
      );

      testWidgets(
        '[F9][T2-2] CLI unauthenticated (authenticated=false) surfaces auth error in dialog and falls back with GenUI card',
        (WidgetTester tester) async {
          final harness = E2eTestHarness.create();
          harness.cliBackend.claudeConfig.authenticated = false;
          await loadRichCapture(harness);

          await harness.pumpInspectorWorkspace(
            tester,
            showAiAssistant: true,
            viewportSize: desktopSize,
          );
          await openAiAssistant(tester);
          await openBackendMenuAndSelect(tester, LlmBackendMode.claudeCodeCli);

          final pathField = dialogTextFieldMatching(
            RegExp(r'path|binary|claude|executable', caseSensitive: false),
          );
          expect(pathField, findsWidgets);
          await tester.enterText(pathField.first, harness.cliBackend.claudeDummyPath);
          await tester.pumpAndSettle();

          final testConnBtn = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.textContaining('Test Connection'),
          );
          expect(testConnBtn, findsOneWidget);
          await tester.ensureVisible(testConnBtn);
          await tester.tap(testConnBtn);
          await tester.pumpAndSettle();

          expect(
            find.descendant(
              of: find.byType(AlertDialog),
              matching: find.textContaining(
                RegExp(r'auth|login|unauthenticated', caseSensitive: false),
              ),
            ),
            findsWidgets,
          );

          final saveBtn = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.text('Save'),
          );
          await tester.ensureVisible(saveBtn);
          await tester.tap(saveBtn);
          await tester.pumpAndSettle();

          await sendAiPrompt(tester, 'Show capture summary');
          expect(
            find.descendant(
              of: find.byType(AiAssistantPanel),
              matching: find.text('Capture Protocol Breakdown'),
            ),
            findsOneWidget,
          );
        },
      );

      testWidgets(
        '[F9][T2-3] Ollama /api/tags HTTP 500 and SocketException fall back to default model catalog safely',
        (WidgetTester tester) async {
          final harness = E2eTestHarness.create();
          harness.httpServer.ollamaTagsStatusCode = 500;
          await loadRichCapture(harness);

          await harness.httpServer.runWithHttpMock(() async {
            final modelsOn500 = await harness.llmService.listOllamaModels();
            expect(modelsOn500, contains('gemma2:9b'));
            expect(modelsOn500, contains('mistral'));

            harness.httpServer.throwOnOllamaTags = true;
            final modelsOnSocket = await harness.llmService.listOllamaModels();
            expect(modelsOnSocket, contains('gemma2:9b'));

            await harness.pumpInspectorWorkspace(
              tester,
              showAiAssistant: true,
              viewportSize: desktopSize,
            );
            await openAiAssistant(tester);
            await openBackendMenuAndSelect(tester, LlmBackendMode.localGemma);
            expect(tester.takeException(), isNull);
            expect(find.text('AI Model Configuration'), findsOneWidget);

            final closeBtn = find.descendant(
              of: find.byType(AlertDialog),
              matching: find.text('Close'),
            );
            await tester.tap(closeBtn);
            await tester.pumpAndSettle();
          });
        },
      );

      testWidgets(
        '[F9][T2-4] Close button in AI Model Configuration discards unsaved Gemini/CLI edits',
        (WidgetTester tester) async {
          final harness = E2eTestHarness.create();
          harness.llmService.geminiApiKey = 'original-secret-key';
          harness.llmService.geminiModel = 'gemini-3.8-flash';
          harness.llmService.saveSettings();
          await loadRichCapture(harness);

          await harness.pumpInspectorWorkspace(
            tester,
            showAiAssistant: true,
            viewportSize: desktopSize,
          );
          await openAiAssistant(tester);
          await openBackendMenuAndSelect(tester, LlmBackendMode.geminiCloud);

          final fields = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.byType(TextField),
          );
          expect(fields, findsNWidgets(2));
          await tester.enterText(fields.at(0), 'discard-this-key');
          await tester.enterText(fields.at(1), 'discard-this-model');
          await tester.pump();

          final closeBtn = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.text('Close'),
          );
          await tester.tap(closeBtn);
          await tester.pumpAndSettle();

          expect(harness.llmService.geminiApiKey, equals('original-secret-key'));
          expect(harness.llmService.geminiModel, equals('gemini-3.8-flash'));
          expect(
            harness.aiStorage.loadSettings().geminiApiKey,
            equals('original-secret-key'),
          );
        },
      );

      testWidgets(
        '[F9][T2-5] Empty Gemini model defaults to gemini-3.8-flash and CLI error/empty stdout re-enables Send',
        (WidgetTester tester) async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);

          await harness.pumpInspectorWorkspace(
            tester,
            showAiAssistant: true,
            viewportSize: desktopSize,
          );
          await openAiAssistant(tester);
          await openBackendMenuAndSelect(tester, LlmBackendMode.geminiCloud);

          final modelField = dialogTextFieldMatching(
            RegExp(r'model', caseSensitive: false),
          );
          await tester.enterText(modelField.last, '   ');
          final saveBtn = find.descendant(
            of: find.byType(AlertDialog),
            matching: find.text('Save'),
          );
          await tester.tap(saveBtn);
          await tester.pumpAndSettle();

          expect(harness.llmService.geminiModel, equals('gemini-3.8-flash'));
          expect(
            harness.aiStorage.loadSettings().geminiModel,
            equals('gemini-3.8-flash'),
          );

          // Now verify CLI empty stdout & non-zero exit recover cleanly in UI
          harness.llmService.backendMode = LlmBackendMode.chatGptCodexCli;
          harness.cliBackend.codexConfig.emptyOutput = true;
          await sendAiPrompt(tester, 'Summarize capture');
          expect(
            find.descendant(
              of: find.byType(AiAssistantPanel),
              matching: find.textContaining('deterministic offline analyzer'),
            ),
            findsOneWidget,
          );

          harness.cliBackend.codexConfig.emptyOutput = false;
          harness.cliBackend.codexConfig.exitCode = 2;
          harness.cliBackend.codexConfig.stderrText = 'CLI crashed';
          await sendAiPrompt(tester, 'Show top talkers');

          final sendIconBtn = tester.widget<IconButton>(
            find.ancestor(
              of: find.byIcon(Icons.send),
              matching: find.byType(IconButton),
            ),
          );
          expect(sendIconBtn.onPressed, isNotNull);
        },
      );
    });
  });

  // =========================================================================
  // Group 2: F10 — LlmProviderService Deterministic-First & Prompt Injection
  // =========================================================================
  group('F10 — LlmProviderService Deterministic-First & Prompt Injection', () {
    group('Tier 1 — Feature Coverage', () {
      test(
        '[F10][T1-1] Gemini Cloud injects capture summary + top talkers output before HTTP POST',
        () async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);
          harness.llmService.backendMode = LlmBackendMode.geminiCloud;
          harness.llmService.geminiApiKey = 'mock-gemini-key';

          await harness.httpServer.runWithHttpMock(() async {
            final reply = await harness.llmService.sendMessage(
              'Who are the top talkers?',
            );
            expect(harness.httpServer.recordedCalls.length, equals(1));

            final sentPrompt = extractGeminiPromptText(
              harness.httpServer.recordedCalls.single,
            );
            expect(sentPrompt, contains('Total Packets:'));
            expect(sentPrompt, contains('Top 5 Talkers'));
            expect(sentPrompt, contains('192.168.1.10'));
            expect(reply.text, contains(harness.httpServer.geminiResponseText));
            expect(reply.toolResult?.widgetType, equals('top_talkers_chart'));
          });
        },
      );

      test(
        '[F10][T1-2] Local Gemma (Ollama) injects capture summary + timing anomaly output before HTTP POST',
        () async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);
          harness.llmService.backendMode = LlmBackendMode.localGemma;

          await harness.httpServer.runWithHttpMock(() async {
            final reply = await harness.llmService.sendMessage(
              'Find micro-burst timing spikes',
            );
            expect(harness.httpServer.recordedCalls.length, equals(1));

            final sentPrompt = extractOllamaPromptText(
              harness.httpServer.recordedCalls.single,
            );
            expect(sentPrompt, contains('Total Packets:'));
            expect(sentPrompt, contains('Micro-Bursts'));
            expect(reply.text, contains(harness.httpServer.ollamaResponseText));
            expect(reply.toolResult?.widgetType, equals('timing_spikes_table'));
          });
        },
      );

      test(
        '[F10][T1-3] Antigravity CLI injects capture summary + ACME UDP/45820 signature output before queryAgy',
        () async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);
          harness.llmService.backendMode = LlmBackendMode.antigravityCli;

          final reply = await harness.llmService.sendMessage(
            'Analyze unknown UDP port 45820',
          );
          expect(harness.cliBackend.recordedCalls.length, equals(1));

          final sentPrompt = extractCliPromptText(
            harness.cliBackend.recordedCalls.single,
          );
          expect(sentPrompt, contains('Total Packets:'));
          expect(sentPrompt, contains('ACME'));
          expect(sentPrompt, contains('41 43 4d 45'));
          expect(reply.text, contains(harness.cliBackend.agyConfig.replyText));
          expect(
            reply.toolResult?.widgetType,
            equals('custom_protocol_suggestion'),
          );
        },
      );

      test(
        '[F10][T1-4] Claude Code CLI injects /p /s /d library specs + capture stats + filtered report before queryClaude',
        () async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);
          harness.repository.addCustomProtocol(
            const CustomProtocolRule(
              id: 'acme_proto',
              name: 'ACME',
              colorHex: 0xFF9C27B0,
              defaultTriageStatus: TriageStatus.expected,
              ipProtocol: 17,
              port: 45820,
              magicBytesOffset: 0,
              magicBytesHex: [0x41, 0x43, 0x4D, 0x45],
            ),
          );
          harness.repository.addSender(
            const EndpointRule(
              id: 'src_ctrl',
              name: 'Main Controller',
              ipAddress: '192.168.1.10',
              type: EndpointType.sender,
            ),
          );
          harness.llmService.backendMode = LlmBackendMode.claudeCodeCli;

          final reply = await harness.llmService.sendMessage(
            'Analyze /p:ACME from /s:192.168.1.10',
          );
          expect(harness.cliBackend.recordedCalls.length, equals(1));

          final sentPrompt = extractCliPromptText(
            harness.cliBackend.recordedCalls.single,
          );
          expect(sentPrompt, contains('Custom Protocol Library Specifications:'));
          expect(sentPrompt, contains('Total Packets:'));
          expect(sentPrompt, contains('Matching Packets:'));
          expect(reply.text, contains(harness.cliBackend.claudeConfig.replyText));
          expect(reply.toolResult?.widgetType, equals('filtered_library_report'));
        },
      );

      test(
        '[F10][T1-5] Codex CLI injects contextEnvelope + deterministic capture summary into exec prompt',
        () async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);
          harness.llmService.backendMode = LlmBackendMode.chatGptCodexCli;

          final reply = await harness.llmService.sendMessage(
            'Summarize capture',
            contextEnvelope: 'View: Triage Unexpected',
          );
          expect(harness.cliBackend.recordedCalls.length, equals(1));

          final call = harness.cliBackend.recordedCalls.single;
          expect(call.arguments.first, equals('exec'));
          final sentPrompt = extractCliPromptText(call);
          expect(sentPrompt, contains('View: Triage Unexpected'));
          expect(sentPrompt, contains('Total Packets:'));
          expect(reply.text, contains(harness.cliBackend.codexConfig.replyText));
          expect(reply.toolResult?.widgetType, equals('summary_card'));
        },
      );
    });

    group('Tier 2 — Boundary & Corner Cases', () {
      test(
        '[F10][T2-1] empty capture (0 packets) injects Total Packets: 0 safely in Gemini & CLI modes',
        () async {
          final harness = E2eTestHarness.create();
          // Intentionally do NOT load any capture
          await harness.httpServer.runWithHttpMock(() async {
            harness.llmService.backendMode = LlmBackendMode.geminiCloud;
            harness.llmService.geminiApiKey = 'mock-key';
            final geminiReply = await harness.llmService.sendMessage(
              'Summarize capture',
            );
            final geminiPrompt = extractGeminiPromptText(
              harness.httpServer.recordedCalls.single,
            );
            expect(geminiPrompt, contains('Total Packets: 0'));
            expect(geminiReply.toolResult?.data['totalPackets'], equals(0));
            expect(geminiReply.toolResult?.widgetType, equals('summary_card'));
          });

          harness.llmService.backendMode = LlmBackendMode.antigravityCli;
          final agyReply = await harness.llmService.sendMessage(
            'Summarize capture',
          );
          final agyPrompt = extractCliPromptText(
            harness.cliBackend.recordedCalls.single,
          );
          expect(agyPrompt, contains('Total Packets: 0'));
          expect(agyReply.toolResult?.data['totalPackets'], equals(0));
        },
      );

      test(
        '[F10][T2-2] empty Gemini API key falls back immediately with zero HTTP calls and non-null toolResult',
        () async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);
          harness.llmService.backendMode = LlmBackendMode.geminiCloud;
          harness.llmService.geminiApiKey = '';

          await harness.httpServer.runWithHttpMock(() async {
            final reply = await harness.llmService.sendMessage(
              'Show top talkers',
            );
            expect(harness.httpServer.recordedCalls, isEmpty);
            expect(reply.text, contains('Gemini API Key is empty'));
            expect(reply.text, contains('deterministic offline analyzer'));
            expect(reply.toolResult?.widgetType, equals('top_talkers_chart'));
          });
        },
      );

      test(
        '[F10][T2-3] HTTP 500 & SocketException fall back deterministically across Gemini and Ollama',
        () async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);

          await harness.httpServer.runWithHttpMock(() async {
            harness.llmService.backendMode = LlmBackendMode.geminiCloud;
            harness.llmService.geminiApiKey = 'mock-key';

            harness.httpServer.geminiStatusCode = 500;
            final r1 = await harness.llmService.sendMessage('Summarize traffic');
            expect(r1.text, contains('deterministic offline analyzer'));
            expect(r1.toolResult?.widgetType, equals('summary_card'));

            harness.httpServer.geminiStatusCode = 200;
            harness.httpServer.throwOnGemini = true;
            final r2 = await harness.llmService.sendMessage('Find timing bursts');
            expect(r2.text, contains('deterministic offline analyzer'));
            expect(r2.toolResult?.widgetType, equals('timing_spikes_table'));

            harness.llmService.backendMode = LlmBackendMode.localGemma;
            harness.httpServer.ollamaStatusCode = 500;
            final r3 = await harness.llmService.sendMessage('Show top talkers');
            expect(r3.text, contains('deterministic offline analyzer'));
            expect(r3.toolResult?.widgetType, equals('top_talkers_chart'));

            harness.httpServer.ollamaStatusCode = 200;
            harness.httpServer.throwOnOllamaChat = true;
            final r4 = await harness.llmService.sendMessage('Summarize traffic');
            expect(r4.text, contains('deterministic offline analyzer'));
            expect(r4.toolResult?.widgetType, equals('summary_card'));
          });

          expect(harness.llmService.history.length, equals(8));
        },
      );

      test(
        '[F10][T2-4] CLI ProcessException crash, non-zero exit & empty stdout fall back deterministically',
        () async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);

          harness.llmService.backendMode = LlmBackendMode.antigravityCli;
          harness.cliBackend.agyConfig.throwOnQuery = true;
          final r1 = await harness.llmService.sendMessage('Summarize traffic');
          expect(r1.text, contains('deterministic offline analyzer'));
          expect(r1.toolResult?.widgetType, equals('summary_card'));

          harness.llmService.backendMode = LlmBackendMode.claudeCodeCli;
          harness.cliBackend.claudeConfig.exitCode = 137;
          harness.cliBackend.claudeConfig.stderrText = 'Killed by signal 9';
          final r2 = await harness.llmService.sendMessage('Show top talkers');
          expect(r2.text, contains('deterministic offline analyzer'));
          expect(r2.toolResult?.widgetType, equals('top_talkers_chart'));

          harness.llmService.backendMode = LlmBackendMode.chatGptCodexCli;
          harness.cliBackend.codexConfig.emptyOutput = true;
          final r3 = await harness.llmService.sendMessage('Find timing spikes');
          expect(r3.text, contains('deterministic offline analyzer'));
          expect(r3.toolResult?.widgetType, equals('timing_spikes_table'));
        },
      );

      test(
        '[F10][T2-5] unmatched /p:UnknownProto999 still injects capture summary + Matching Packets: 0',
        () async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);
          harness.llmService.backendMode = LlmBackendMode.localGemma;

          await harness.httpServer.runWithHttpMock(() async {
            final reply = await harness.llmService.sendMessage(
              'Inspect /p:UnknownProto999',
            );
            final sentPrompt = extractOllamaPromptText(
              harness.httpServer.recordedCalls.single,
            );
            expect(sentPrompt, contains('Total Packets:'));
            expect(sentPrompt, contains('Matching Packets: 0'));
            expect(
              reply.toolResult?.widgetType,
              equals('filtered_library_report'),
            );
            expect(reply.toolResult?.data['matchingPacketCount'], equals(0));
          });
        },
      );
    });
  });

  // =========================================================================
  // Group 3: F11 — compareCapturesSummary, compare_summary_card & Nullable Provider
  // =========================================================================
  group(
    'F11 — compareCapturesSummary, compare_summary_card & Nullable CaptureCompareViewModel?',
    () {
      group('Tier 1 — Feature Coverage', () {
        test(
          '[F11][T1-1] 3-hop PacketAiTools.compareCapturesSummary returns hop delivery percentages, faults & firstDropRowIndex',
          () async {
            final harness = E2eTestHarness.create();
            final diffFixture = PcapFixtureBuilder.buildMultiHopDiffCaptures(
              tempDir: harness.tempDir,
            );
            await harness.compareVm.loadCaptures(diffFixture.inputs);

            final result = harness.aiTools.compareCapturesSummary(
              harness.compareVm.engine,
            );

            expect(result.toolName, equals('compare_captures_summary'));
            expect(result.widgetType, equals('compare_summary_card'));
            expect(result.data['hasComparison'], isTrue);
            expect(result.data['droppedCount'], greaterThan(0));
            expect(result.data['firstDropRowIndex'], isNotNull);
            expect(result.data['firstDropFrameNumber'], isNotNull);
            expect(result.summaryText, contains('Hop 1'));
            expect(result.summaryText, contains('Hop 2'));
            expect(result.summaryText, contains('%'));
            expect(result.summaryText, contains('Skew:'));
            expect(result.summaryText, contains('First Drop:'));
          },
        );

        testWidgets(
          '[F11][T1-2] AiAssistantPanel renders compare_summary_card in compare mode with hop percentages & Jump to First Drop',
          (WidgetTester tester) async {
            final harness = E2eTestHarness.create();
            await loadRichCapture(harness);
            final diffFixture = PcapFixtureBuilder.buildMultiHopDiffCaptures(
              tempDir: harness.tempDir,
            );
            await harness.compareVm.loadCaptures(diffFixture.inputs);

            await harness.pumpInspectorWorkspace(
              tester,
              showAiAssistant: true,
              includeCompareProvider: true,
              viewportSize: desktopSize,
            );
            await openAiAssistant(tester);

            await sendAiPrompt(
              tester,
              'Compare captures and summarize drops across hops',
            );

            expect(
              find.descendant(
                of: find.byType(AiAssistantPanel),
                matching: find.text('Jump to First Drop'),
              ),
              findsOneWidget,
            );
            expect(
              find.descendant(
                of: find.byType(AiAssistantPanel),
                matching: find.textContaining('%'),
              ),
              findsWidgets,
            );
          },
        );

        testWidgets(
          '[F11][T1-3] Jump to First Drop button inside AiAssistantPanel updates CaptureCompareViewModel selectedRecord & scroll request',
          (WidgetTester tester) async {
            final harness = E2eTestHarness.create();
            await loadRichCapture(harness);
            final diffFixture = PcapFixtureBuilder.buildMultiHopDiffCaptures(
              tempDir: harness.tempDir,
            );
            await harness.compareVm.loadCaptures(diffFixture.inputs);
            expect(harness.compareVm.selectedRecord, isNull);

            await harness.pumpInspectorWorkspace(
              tester,
              showAiAssistant: true,
              includeCompareProvider: true,
              viewportSize: desktopSize,
            );
            await openAiAssistant(tester);
            await sendAiPrompt(tester, 'Compare captures and find drops');

            final jumpBtn = find.descendant(
              of: find.byType(AiAssistantPanel),
              matching: find.text('Jump to First Drop'),
            );
            expect(jumpBtn, findsOneWidget);
            await tester.ensureVisible(jumpBtn);
            await tester.tap(jumpBtn);
            await tester.pumpAndSettle();

            final firstDrop = harness.compareVm.visibleRecords.firstWhere(
              (r) => r.statuses.contains(DiffStatus.dropped),
            );
            expect(harness.compareVm.selectedRecord, isNotNull);
            expect(
              harness.compareVm.selectedRecord!.statuses,
              contains(DiffStatus.dropped),
            );
            expect(
              harness.compareVm.selectedRecord!.rowIndex,
              equals(firstDrop.rowIndex),
            );
          },
        );

        testWidgets(
          '[F11][T1-4] Nullable CaptureCompareViewModel? resilience when includeCompareProvider is false',
          (WidgetTester tester) async {
            final harness = E2eTestHarness.create();
            await loadRichCapture(harness);

            await harness.pumpInspectorWorkspace(
              tester,
              showAiAssistant: true,
              includeCompareProvider: false,
              viewportSize: desktopSize,
            );
            await openAiAssistant(tester);

            await tester.tap(find.text('Show capture summary'));
            await tester.pumpAndSettle();
            expect(tester.takeException(), isNull);
            expect(find.text('Capture Protocol Breakdown'), findsOneWidget);

            await sendAiPrompt(tester, 'Compare captures for packet drops');
            expect(tester.takeException(), isNull);
          },
        );

        testWidgets(
          '[F11][T1-5] Hybrid Gemini Cloud + compare_summary_card injects comparison stats and renders card below LLM reply',
          (WidgetTester tester) async {
            final harness = E2eTestHarness.create();
            await loadRichCapture(harness);
            final diffFixture = PcapFixtureBuilder.buildMultiHopDiffCaptures(
              tempDir: harness.tempDir,
            );
            await harness.compareVm.loadCaptures(diffFixture.inputs);

            harness.llmService.backendMode = LlmBackendMode.geminiCloud;
            harness.llmService.geminiApiKey = 'mock-gemini-key';

            await harness.httpServer.runWithHttpMock(() async {
              await harness.pumpInspectorWorkspace(
                tester,
                showAiAssistant: true,
                includeCompareProvider: true,
                viewportSize: desktopSize,
              );
              await openAiAssistant(tester);
              await sendAiPrompt(tester, 'Explain packet drops across hops');

              expect(harness.httpServer.recordedCalls.length, equals(1));
              final sentPrompt = extractGeminiPromptText(
                harness.httpServer.recordedCalls.single,
              );
              expect(
                sentPrompt,
                contains(RegExp(r'Shared-Flow|Dropped|Hop 1')),
              );
              expect(
                find.descendant(
                  of: find.byType(AiAssistantPanel),
                  matching: find.textContaining(
                    harness.httpServer.geminiResponseText,
                  ),
                ),
                findsOneWidget,
              );
              expect(
                find.descendant(
                  of: find.byType(AiAssistantPanel),
                  matching: find.text('Jump to First Drop'),
                ),
                findsOneWidget,
              );
            });
          },
        );
      });

      group('Tier 2 — Boundary & Corner Cases', () {
        test(
          '[F11][T2-1] compareCapturesSummary with 0 or 1 capture slot returns hasComparison: false',
          () async {
            final harness = E2eTestHarness.create();

            final emptyEngine = MultiCaptureDiffEngine();
            addTearDown(emptyEngine.dispose);
            final res0 = harness.aiTools.compareCapturesSummary(emptyEngine);
            expect(res0.widgetType, equals('compare_summary_card'));
            expect(res0.data['hasComparison'], isFalse);
            expect(
              res0.summaryText,
              contains('No active multi-capture comparison loaded'),
            );

            final singleEngine = MultiCaptureDiffEngine();
            addTearDown(singleEngine.dispose);
            final rich = PcapFixtureBuilder.buildRichInspectorCapture();
            await expectLater(
              singleEngine.ingestCaptures([
                CaptureSourceInput(
                  label: 'A: Only Hop',
                  filePath: 'only_hop.pcap',
                  bytes: rich.bytes,
                ),
              ]),
              throwsArgumentError,
            );
            final res1 = harness.aiTools.compareCapturesSummary(singleEngine);
            expect(res1.widgetType, equals('compare_summary_card'));
            expect(res1.data['hasComparison'], isFalse);
          },
        );

        testWidgets(
          '[F11][T2-2] Zero-drop 3-hop comparison sets droppedCount=0, firstDropRowIndex=null & avoids broken drop action',
          (WidgetTester tester) async {
            final harness = E2eTestHarness.create();
            await loadRichCapture(harness);
            final noDropFixture = PcapFixtureBuilder.buildMultiHopDiffCaptures(
              tempDir: harness.tempDir,
              includeDrop: false,
            );
            await harness.compareVm.loadCaptures(noDropFixture.inputs);

            final toolRes = harness.aiTools.compareCapturesSummary(
              harness.compareVm.engine,
            );
            expect(toolRes.data['hasComparison'], isTrue);
            expect(toolRes.data['droppedCount'], equals(0));
            expect(toolRes.data['firstDropRowIndex'], isNull);

            await harness.pumpInspectorWorkspace(
              tester,
              showAiAssistant: true,
              includeCompareProvider: true,
              viewportSize: desktopSize,
            );
            await openAiAssistant(tester);
            await sendAiPrompt(tester, 'Compare captures across hops');

            expect(tester.takeException(), isNull);
            final aiJumpBtn = find.descendant(
              of: find.byType(AiAssistantPanel),
              matching: find.text('Jump to First Drop'),
            );
            expect(aiJumpBtn, findsNothing);
          },
        );

        testWidgets(
          '[F11][T2-3] Compare query when CaptureCompareViewModel is provided but isCompareMode == false',
          (WidgetTester tester) async {
            final harness = E2eTestHarness.create();
            await loadRichCapture(harness);
            expect(harness.compareVm.isCompareMode, isFalse);

            await harness.pumpInspectorWorkspace(
              tester,
              showAiAssistant: true,
              includeCompareProvider: true,
              viewportSize: desktopSize,
            );
            await openAiAssistant(tester);
            await sendAiPrompt(tester, 'Any packet drops across hops?');

            expect(tester.takeException(), isNull);
            expect(
              find.descendant(
                of: find.byType(AiAssistantPanel),
                matching: find.text('Jump to First Drop'),
              ),
              findsNothing,
            );
          },
        );

        test(
          '[F11][T2-4] All-packet-drop 2-hop comparison reports 0.0% delivery and firstDropRowIndex == 1',
          () async {
            final harness = E2eTestHarness.create();
            final hop0Builder = ClassicPcapBuilder();
            hop0Builder.addBuiltFrame(
              PcapFrameFactory.ethernetUdp(
                srcIp: '10.10.1.10',
                dstIp: '239.255.0.1',
                srcPort: 5568,
                dstPort: 5568,
                payload: PcapFrameFactory.sacnDmxPayload(seq: 1),
              ),
              timestampUs: 1700000000000000,
            );
            hop0Builder.addBuiltFrame(
              PcapFrameFactory.ethernetUdp(
                srcIp: '10.10.1.10',
                dstIp: '239.255.0.1',
                srcPort: 5568,
                dstPort: 5568,
                payload: PcapFrameFactory.sacnDmxPayload(seq: 2),
              ),
              timestampUs: 1700000000010000,
            );
            final emptyHop1 = ClassicPcapBuilder().buildBytes();

            final engine = MultiCaptureDiffEngine();
            addTearDown(engine.dispose);
            await engine.ingestCaptures([
              CaptureSourceInput(
                label: 'A: Source',
                filePath: 'hop0.pcap',
                bytes: hop0Builder.buildBytes(),
              ),
              CaptureSourceInput(
                label: 'B: EmptyHop',
                filePath: 'hop1.pcap',
                bytes: emptyHop1,
              ),
            ]);

            final result = harness.aiTools.compareCapturesSummary(engine);
            expect(result.data['hasComparison'], isTrue);
            expect(result.data['totalShared'], equals(2));
            expect(result.data['droppedCount'], equals(2));
            expect(result.data['firstDropRowIndex'], equals(1));
            expect(result.summaryText, contains('0/2 (0.0%)'));
          },
        );

        testWidgets(
          '[F11][T2-5] exitCompareMode() after rendering compare_summary_card does not throw or corrupt state',
          (WidgetTester tester) async {
            final harness = E2eTestHarness.create();
            await loadRichCapture(harness);
            final diffFixture = PcapFixtureBuilder.buildMultiHopDiffCaptures(
              tempDir: harness.tempDir,
            );
            await harness.compareVm.loadCaptures(diffFixture.inputs);

            await harness.pumpInspectorWorkspace(
              tester,
              showAiAssistant: true,
              includeCompareProvider: true,
              viewportSize: desktopSize,
            );
            await openAiAssistant(tester);
            await sendAiPrompt(tester, 'Compare captures and summarize drops');

            harness.compareVm.exitCompareMode();
            await tester.pumpAndSettle();

            expect(tester.takeException(), isNull);
            expect(harness.compareVm.isCompareMode, isFalse);
            expect(harness.inspectorVm.totalPacketCount, greaterThan(0));
          },
        );
      });
    },
  );

  // =========================================================================
  // Group 4: F14 / F15 / F17 — Canonical AI Contracts & /p /s /r /d Parsing
  // =========================================================================
  group('F14/F15/F17 — Canonical AI Contracts & Filter Reference Parsing', () {
    group('Tier 1 — Feature Coverage', () {
      test(
        '[F14-17][T1-1] canonical PacketAiTools.getCaptureSummary() returns exact capture counts and protocol breakdown',
        () async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);

          final summary = harness.aiTools.getCaptureSummary();
          expect(summary.toolName, equals('get_capture_summary'));
          expect(summary.widgetType, equals('summary_card'));
          expect(summary.data['totalPackets'], equals(21));

          final expected = summary.data['expectedCount'] as int;
          final unclassified = summary.data['unclassifiedCount'] as int;
          final unexpected = summary.data['unexpectedCount'] as int;
          expect(expected + unclassified + unexpected, equals(21));

          final protocols = summary.data['protocols'] as Map<String, int>;
          expect(protocols, isNotEmpty);
          expect(summary.summaryText, contains('Total Packets: 21'));
        },
      );

      test(
        '[F14-17][T1-2] canonical PacketAiTools.generateFilteredReport(refs: refs) returns matching counts, span & samples',
        () async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);

          final refs = AiFilterReferences.parse(
            'Inspect /p:DNS from /s:192.168.1.10',
            harness.repository,
          );
          final report = harness.aiTools.generateFilteredReport(refs: refs);

          expect(report.toolName, equals('generate_filtered_report'));
          expect(report.widgetType, equals('filtered_library_report'));
          expect(report.data['matchingPacketCount'], equals(1));
          expect(report.data['totalCaptureCount'], equals(21));
          expect(report.data['percentage'], isNotEmpty);
          expect((report.data['samplePackets'] as List).length, equals(1));
        },
      );

      test(
        '[F14-17][T1-3] canonical AiFilterReferences fields and /r vs /d parity resolve identically',
        () async {
          final harness = E2eTestHarness.create();
          harness.repository.addCustomProtocol(
            const CustomProtocolRule(
              id: 'acme_id',
              name: 'ACME Telemetry',
              colorHex: 0xFF9C27B0,
              defaultTriageStatus: TriageStatus.expected,
              ipProtocol: 17,
              port: 45820,
            ),
          );
          harness.repository.addSender(
            const EndpointRule(
              id: 's1',
              name: 'Console',
              ipAddress: '192.168.1.10',
              type: EndpointType.sender,
            ),
          );
          harness.repository.addReceiver(
            const EndpointRule(
              id: 'r1',
              name: 'Gateway',
              ipAddress: '192.168.1.200',
              type: EndpointType.receiver,
            ),
          );

          final refsD = AiFilterReferences.parse(
            '/p:"ACME Telemetry" /s:192.168.1.10 /d:192.168.1.200 /d:10.0.5.50',
            harness.repository,
          );
          final refsR = AiFilterReferences.parse(
            '/p:"ACME Telemetry" /s:192.168.1.10 /r:192.168.1.200 /r:10.0.5.50',
            harness.repository,
          );

          for (final refs in [refsD, refsR]) {
            expect(refs.hasAnyReferences, isTrue);
            expect(refs.rawProtocols, equals(['ACME Telemetry']));
            expect(refs.rawSenders, equals(['192.168.1.10']));
            expect(refs.rawReceivers, equals(['192.168.1.200', '10.0.5.50']));
            expect(refs.matchedProtocolRules.length, equals(1));
            expect(refs.matchedSenders.length, equals(1));
            expect(refs.unmatchedSenderIps, isEmpty);
            expect(refs.matchedReceivers.length, equals(1));
            expect(refs.unmatchedReceiverIps, equals(['10.0.5.50']));
            expect(refs.allProtocolNames, equals({'ACME Telemetry'}));
            expect(refs.allSenderKeys, equals({'192.168.1.10'}));
            expect(
              refs.allReceiverKeys,
              equals({'192.168.1.200', '10.0.5.50'}),
            );
          }
        },
      );

      testWidgets(
        '[F14-17][T1-4] UI /p, /s, /d chip autocomplete inserts mentions and Apply to Filter Bar updates InspectorViewModel',
        (WidgetTester tester) async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);
          await harness.pumpInspectorWorkspace(
            tester,
            showAiAssistant: true,
            viewportSize: desktopSize,
          );
          await openAiAssistant(tester);

          // Open /p Protocol autocomplete overlay and select DNS
          await tester.tap(find.text('/p Protocol'));
          await tester.pumpAndSettle();
          expect(find.text('Select Protocol (/p)'), findsOneWidget);

          final dnsTile = find.descendant(
            of: find.byType(AiAssistantPanel),
            matching: find.widgetWithText(ListTile, 'DNS'),
          );
          expect(dnsTile, findsOneWidget);
          await tester.tap(dnsTile);
          await tester.pumpAndSettle();

          // Submit the inserted /p:DNS prompt
          final sendBtn = find.descendant(
            of: find.byType(AiAssistantPanel),
            matching: find.byIcon(Icons.send),
          );
          await tester.tap(sendBtn);
          await tester.pumpAndSettle();

          expect(find.text('Filtered Traffic Report'), findsOneWidget);
          final applyBtn = find.text('Apply to Filter Bar');
          expect(applyBtn, findsOneWidget);
          await tester.ensureVisible(applyBtn);
          await tester.tap(applyBtn);
          await tester.pumpAndSettle();

          expect(harness.inspectorVm.selectedProtocolPills, contains('DNS'));
          expect(harness.inspectorVm.isTriageMode, isFalse);
        },
      );

      testWidgets(
        '[F14-17][T1-5] AI pipeline runs across deterministic, HTTP & CLI modes without context-scope widgets/params',
        (WidgetTester tester) async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);

          await harness.pumpInspectorWorkspace(
            tester,
            showAiAssistant: true,
            viewportSize: desktopSize,
          );
          await openAiAssistant(tester);

          await sendAiPrompt(tester, 'Show capture summary');
          expect(find.text('Capture Protocol Breakdown'), findsOneWidget);

          harness.llmService.backendMode = LlmBackendMode.geminiCloud;
          harness.llmService.geminiApiKey = 'scope-free-key';
          await harness.httpServer.runWithHttpMock(() async {
            await sendAiPrompt(tester, 'Chart top talkers by bytes');
          });
          expect(find.textContaining('Top Conversations'), findsOneWidget);

          harness.llmService.backendMode = LlmBackendMode.antigravityCli;
          await sendAiPrompt(tester, 'Find timing spikes');
          expect(find.text('Traffic Burst Spikes'), findsOneWidget);
        },
      );
    });

    group('Tier 2 — Boundary & Corner Cases', () {
      test(
        '[F14-17][T2-1] case-insensitive /P:, /S:, /R:, /D: and whitespace-separated /p DNS parse cleanly',
        () {
          final harness = E2eTestHarness.create();
          final refs = AiFilterReferences.parse(
            'Check /P DNS from /S 192.168.1.10 to /R:8.8.8.8 and /D:10.0.0.1',
            harness.repository,
          );

          expect(refs.hasAnyReferences, isTrue);
          expect(refs.standardProtocols, equals(['DNS']));
          expect(refs.unmatchedSenderIps, equals(['192.168.1.10']));
          expect(refs.unmatchedReceiverIps, equals(['8.8.8.8', '10.0.0.1']));
        },
      );

      test(
        '[F14-17][T2-2] quoted multi-word names and trailing comma boundaries parse accurately',
        () {
          final harness = E2eTestHarness.create();
          harness.repository.addCustomProtocol(
            const CustomProtocolRule(
              id: 'p_v2',
              name: 'My Proto, v2',
              colorHex: 0xFF00BCD4,
              defaultTriageStatus: TriageStatus.expected,
              ipProtocol: 17,
              port: 7777,
            ),
          );
          harness.repository.addSender(
            const EndpointRule(
              id: 's_ctrl',
              name: 'Main Controller',
              ipAddress: '192.168.1.10',
              type: EndpointType.sender,
            ),
          );

          final refs = AiFilterReferences.parse(
            'Analyze /p:"My Proto, v2", /s:"Main Controller" /d:10.0.0.1,',
            harness.repository,
          );

          expect(refs.matchedProtocolRules.map((r) => r.name), equals(['My Proto, v2']));
          expect(refs.matchedSenders.map((s) => s.name), equals(['Main Controller']));
          expect(refs.unmatchedReceiverIps, equals(['10.0.0.1']));
        },
      );

      test(
        '[F14-17][T2-3] empty, whitespace-only and malformed slash tokens produce empty AiFilterReferences',
        () async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);

          for (final badInput in ['', '   \n\t', '/p: /s: /d: /x:foo /']) {
            final refs = AiFilterReferences.parse(badInput, harness.repository);
            expect(refs.hasAnyReferences, isFalse);
            expect(refs.rawProtocols, isEmpty);
            expect(refs.rawSenders, isEmpty);
            expect(refs.rawReceivers, isEmpty);
            expect(refs.allProtocolNames, isEmpty);
            expect(refs.allSenderKeys, isEmpty);
            expect(refs.allReceiverKeys, isEmpty);
          }

          final emptyRefs = AiFilterReferences.parse('/x:ignored', harness.repository);
          final report = harness.aiTools.generateFilteredReport(refs: emptyRefs);
          expect(report.toolName, equals('generate_filtered_report'));
          expect(report.data['matchingPacketCount'], equals(21));
        },
      );

      test(
        '[F14-17][T2-4] duplicate protocol and endpoint tokens deduplicate cleanly',
        () {
          final harness = E2eTestHarness.create();
          harness.repository.addCustomProtocol(
            const CustomProtocolRule(
              id: 'dup_p',
              name: 'CustomX',
              colorHex: 0xFF4CAF50,
              defaultTriageStatus: TriageStatus.expected,
              port: 1234,
            ),
          );

          final refs = AiFilterReferences.parse(
            '/p:DNS /p:DNS /p:CustomX /p:CustomX /s:192.168.1.10 /s:192.168.1.10 /d:8.8.8.8 /r:8.8.8.8',
            harness.repository,
          );

          expect(refs.matchedProtocolRules.length, equals(1));
          expect(refs.standardProtocols, equals(['DNS']));
          expect(refs.allProtocolNames, equals({'CustomX', 'DNS'}));
          expect(refs.allSenderKeys, equals({'192.168.1.10'}));
          expect(refs.allReceiverKeys, equals({'8.8.8.8'}));
        },
      );

      test(
        '[F14-17][T2-5] SQL-metacharacter tokens in AiFilterReferences & generateFilteredReport execute safely',
        () async {
          final harness = E2eTestHarness.create();
          await loadRichCapture(harness);

          final refs = AiFilterReferences.parse(
            '/p:"Proto\'; DROP TABLE packets;--" /s:10.0.0.1\'"',
            harness.repository,
          );
          final report = harness.aiTools.generateFilteredReport(refs: refs);
          expect(report.data['matchingPacketCount'], equals(0));
          expect(
            harness.repository.getPacketCount(silenceLanChatter: false),
            equals(21),
          );
        },
      );
    });
  });

  // =========================================================================
  // Group 5: F21 — AiSettingsStorageService Cross-Platform Fallback & Security
  // =========================================================================
  group('F21 — AiSettingsStorageService Writable Fallback, Directory Creation & Encryption', () {
    group('Tier 1 — Feature Coverage', () {
      test(
        '[F21][T1-1] default storageDirectory=null resolves to SharedDeviceDatabase.getDefaultDirectoryPath()/ai_settings.json',
        () {
          final defaultService = AiSettingsStorageService();
          final expectedPath = p.join(
            SharedDeviceDatabase.getDefaultDirectoryPath(),
            'ai_settings.json',
          );
          expect(defaultService.resolvedFilePath, equals(expectedPath));
          expect(defaultService.resolvedFilePath, isNot(equals('./ai_settings.json')));
        },
      );

      test(
        '[F21][T1-2] recursive nested directory creation and full 11-field AiSettings round-trip',
        () {
          final harness = E2eTestHarness.create();
          final deepDir = Directory(
            p.join(harness.tempDir.path, 'deep', 'nested', 'ai_cfg'),
          );
          expect(deepDir.existsSync(), isFalse);

          final storage = AiSettingsStorageService(storageDirectory: deepDir);
          const expected = AiSettings(
            backendMode: LlmBackendMode.chatGptCodexCli,
            geminiApiKey: 'AIzaSyTestKey12345',
            geminiModel: 'gemini-3.8-pro',
            ollamaUrl: 'http://192.168.1.50:11434',
            ollamaModel: 'qwen2.5-coder:7b',
            agyPath: '/opt/bin/agy',
            claudePath: '/opt/bin/claude',
            codexPath: '/opt/bin/codex',
            agyModel: 'gemini-3.8-flash-high',
            claudeModel: 'opus',
            codexModel: 'o3-mini',
          );

          storage.saveSettings(expected);
          expect(deepDir.existsSync(), isTrue);
          expect(File(storage.resolvedFilePath).existsSync(), isTrue);

          final reloaded = storage.loadSettings();
          expect(reloaded.backendMode, equals(expected.backendMode));
          expect(reloaded.geminiApiKey, equals(expected.geminiApiKey));
          expect(reloaded.geminiModel, equals(expected.geminiModel));
          expect(reloaded.ollamaUrl, equals(expected.ollamaUrl));
          expect(reloaded.ollamaModel, equals(expected.ollamaModel));
          expect(reloaded.agyPath, equals(expected.agyPath));
          expect(reloaded.claudePath, equals(expected.claudePath));
          expect(reloaded.codexPath, equals(expected.codexPath));
          expect(reloaded.agyModel, equals(expected.agyModel));
          expect(reloaded.claudeModel, equals(expected.claudeModel));
          expect(reloaded.codexModel, equals(expected.codexModel));
        },
      );

      test(
        '[F21][T1-3] Gemini API key is encrypted at rest as gemini_api_key_enc and never stored in plaintext',
        () {
          final harness = E2eTestHarness.create();
          const secret = 'AIzaSySuperSecretE2EKey987654321';

          harness.aiStorage.saveSettings(
            const AiSettings(
              backendMode: LlmBackendMode.geminiCloud,
              geminiApiKey: secret,
            ),
          );

          final rawDiskText = File(harness.aiStorage.resolvedFilePath).readAsStringSync();
          expect(rawDiskText, isNot(contains(secret)));

          final decoded = jsonDecode(rawDiskText) as Map<String, dynamic>;
          expect(decoded['gemini_api_key_enc'], isA<String>());
          expect((decoded['gemini_api_key_enc'] as String), isNotEmpty);

          expect(harness.aiStorage.loadSettings().geminiApiKey, equals(secret));
        },
      );

      testWidgets(
        '[F21][T1-4] InspectorViewModel auto-hydrates persisted AiSettings into LlmProviderService & AiAssistantPanel',
        (WidgetTester tester) async {
          final harness = E2eTestHarness.create();
          harness.aiStorage.saveSettings(
            AiSettings(
              backendMode: LlmBackendMode.geminiCloud,
              geminiApiKey: 'hydrated-key-xyz',
              geminiModel: 'gemini-3.8-flash-custom',
              ollamaUrl: 'http://10.0.0.5:11434',
              ollamaModel: 'llama3.2:latest',
              agyPath: harness.cliBackend.agyDummyPath,
              claudePath: harness.cliBackend.claudeDummyPath,
              codexPath: harness.cliBackend.codexDummyPath,
              agyModel: 'gemini-3.8-flash-medium',
              claudeModel: 'sonnet',
              codexModel: 'gpt-4o',
            ),
          );

          // Construct a fresh InspectorViewModel using the pre-populated storage
          final freshVm = InspectorViewModel(
            repository: harness.repository,
            aiSettingsStorage: harness.aiStorage,
          );
          addTearDown(freshVm.dispose);

          expect(freshVm.llmService.backendMode, equals(LlmBackendMode.geminiCloud));
          expect(freshVm.llmService.geminiApiKey, equals('hydrated-key-xyz'));
          expect(freshVm.llmService.geminiModel, equals('gemini-3.8-flash-custom'));
          expect(freshVm.llmService.agyPath, equals(harness.cliBackend.agyDummyPath));
          expect(freshVm.llmService.claudeModel, equals('sonnet'));
          expect(freshVm.llmService.codexModel, equals('gpt-4o'));

          await harness.pumpInspectorWorkspace(
            tester,
            showAiAssistant: true,
            viewportSize: desktopSize,
            overrideInspectorVm: freshVm,
          );
          await openAiAssistant(tester);
          await openBackendMenuAndSelect(tester, LlmBackendMode.geminiCloud);
          expect(
            find.descendant(
              of: find.byType(AlertDialog),
              matching: find.text('gemini-3.8-flash-custom'),
            ),
            findsOneWidget,
          );
        },
      );

      test(
        '[F21][T1-5] strict tempDir workspace isolation writes zero files to CWD',
        () {
          final harness = E2eTestHarness.create();
          final cwdFile = File('ai_settings.json');
          final existedBefore = cwdFile.existsSync();
          final modifiedBefore = existedBefore ? cwdFile.lastModifiedSync() : null;

          final isolatedStorage = AiSettingsStorageService(
            storageDirectory: harness.createSubDir('isolated_ai'),
          );
          isolatedStorage.saveSettings(
            const AiSettings(
              backendMode: LlmBackendMode.localGemma,
              ollamaModel: 'gemma3:4b',
            ),
          );

          expect(File(isolatedStorage.resolvedFilePath).existsSync(), isTrue);
          expect(cwdFile.existsSync(), equals(existedBefore));
          if (existedBefore) {
            expect(cwdFile.lastModifiedSync(), equals(modifiedBefore));
          }
        },
      );
    });

    group('Tier 2 — Boundary & Corner Cases', () {
      test(
        '[F21][T2-1] missing ai_settings.json returns exact safe AiSettings defaults',
        () {
          final harness = E2eTestHarness.create();
          final emptyDir = harness.createSubDir('empty_ai');
          final storage = AiSettingsStorageService(storageDirectory: emptyDir);

          final loaded = storage.loadSettings();
          expect(loaded.backendMode, equals(LlmBackendMode.deterministicLocal));
          expect(loaded.geminiApiKey, isEmpty);
          expect(loaded.geminiModel, equals('gemini-3.8-flash'));
          expect(loaded.ollamaUrl, equals('http://localhost:11434'));
          expect(loaded.ollamaModel, equals('gemma2:9b'));
          expect(loaded.agyModel, equals('gemini-3.8-flash-low'));
          expect(loaded.claudeModel, equals('haiku'));
          expect(loaded.codexModel, equals('gpt-4o-mini'));
        },
      );

      test(
        '[F21][T2-2] corrupt or truncated JSON in ai_settings.json returns default AiSettings without throwing',
        () {
          final harness = E2eTestHarness.create();
          final corruptDir = harness.createSubDir('corrupt_ai');
          final storage = AiSettingsStorageService(storageDirectory: corruptDir);
          File(storage.resolvedFilePath).writeAsStringSync('{not-valid-json');

          final loaded = storage.loadSettings();
          expect(loaded.backendMode, equals(LlmBackendMode.deterministicLocal));
          expect(loaded.geminiApiKey, isEmpty);
          expect(loaded.geminiModel, equals('gemini-3.8-flash'));
        },
      );

      test(
        '[F21][T2-3] out-of-range backend_mode index and blank gemini_model clamp safely',
        () {
          final harness = E2eTestHarness.create();
          final dir = harness.createSubDir('clamp_ai');
          final storage = AiSettingsStorageService(storageDirectory: dir);

          File(storage.resolvedFilePath).writeAsStringSync(
            jsonEncode({
              'backend_mode': 999,
              'gemini_model': '   ',
            }),
          );
          final highLoaded = storage.loadSettings();
          expect(highLoaded.backendMode, equals(LlmBackendMode.deterministicLocal));
          expect(highLoaded.geminiModel, equals('gemini-3.8-flash'));

          File(storage.resolvedFilePath).writeAsStringSync(
            jsonEncode({'backend_mode': -1}),
          );
          final negLoaded = storage.loadSettings();
          expect(negLoaded.backendMode, equals(LlmBackendMode.deterministicLocal));
        },
      );

      test(
        '[F21][T2-4] tampered or truncated gemini_api_key_enc fails HMAC verification and returns empty string',
        () {
          final harness = E2eTestHarness.create();
          final enc = AiSettingsStorageService.encryptSecret('secret-token-value');
          final rawBytes = base64Decode(enc);
          rawBytes[rawBytes.length - 1] ^= 0xFF;
          final tamperedEnc = base64Encode(rawBytes);

          expect(AiSettingsStorageService.decryptSecret(tamperedEnc), isEmpty);
          expect(AiSettingsStorageService.decryptSecret('AAAA'), isEmpty);
          expect(AiSettingsStorageService.decryptSecret('not-base64!@#'), isEmpty);

          final dir = harness.createSubDir('tamper_ai');
          final storage = AiSettingsStorageService(storageDirectory: dir);
          File(storage.resolvedFilePath).writeAsStringSync(
            jsonEncode({
              'backend_mode': LlmBackendMode.geminiCloud.index,
              'gemini_api_key_enc': tamperedEnc,
            }),
          );
          expect(storage.loadSettings().geminiApiKey, isEmpty);
        },
      );

      test(
        '[F21][T2-5] unwritable parent path on saveSettings handles FileSystemException gracefully without throwing',
        () {
          final harness = E2eTestHarness.create();
          final blockingFile = File(p.join(harness.tempDir.path, 'blocker'));
          blockingFile.writeAsStringSync('not a directory');

          final blockedDir = Directory(p.join(blockingFile.path, 'nested_ai'));
          final storage = AiSettingsStorageService(storageDirectory: blockedDir);

          expect(
            () => storage.saveSettings(
              const AiSettings(
                backendMode: LlmBackendMode.geminiCloud,
                geminiApiKey: 'should-not-crash',
              ),
            ),
            returnsNormally,
          );
          expect(storage.loadSettings().backendMode, equals(LlmBackendMode.deterministicLocal));
        },
      );
    });
  });
}
