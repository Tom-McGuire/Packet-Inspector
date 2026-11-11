import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:packet_inspector/data/services/ai/cli_llm_service.dart';
import 'package:packet_inspector/data/services/ai/llm_provider_service.dart';
import 'package:packet_inspector/data/services/ai/packet_ai_tools.dart';
import 'package:packet_inspector/data/services/storage/ai_settings_storage_service.dart';
import 'package:packet_inspector/data/services/storage/protocol_library_service.dart';
import 'package:packet_inspector/data/repositories/packet_repository.dart';

void main() {
  group('CliLlmService Tests', () {
    test('checkStatus reports not installed when executable cannot be found', () async {
      final cli = CliLlmService(
        processRunner: (exe, args, {runInShell = false, timeout}) async {
          return ProcessResult(1, 1, '', 'not found');
        },
      );

      final status = await cli.checkStatus(CliType.claudeCode, customPath: '/non/existent/claude');
      expect(status.isInstalled, isFalse);
      expect(status.isAuthenticated, isFalse);
      expect(status.message.contains('not found'), isTrue);
    });

    test('checkStatus reports unauthenticated when agy returns login prompt', () async {
      final cli = CliLlmService(
        processRunner: (exe, args, {runInShell = false, timeout}) async {
          if (args.contains('--version')) {
            return ProcessResult(1, 0, '1.4.12', '');
          }
          return ProcessResult(
            1,
            0,
            'Authentication required. Please visit the URL to log in: https://accounts.google.com/...',
            '',
          );
        },
      );

      final status = await cli.checkStatus(CliType.antigravity, customPath: '/snap/bin/agy');
      expect(status.isInstalled, isTrue);
      expect(status.isAuthenticated, isFalse);
      expect(status.version, equals('1.4.12'));
      expect(status.message.contains('authentication required'), isTrue);
    });

    test('checkStatus reports authenticated when agy succeeds', () async {
      final cli = CliLlmService(
        processRunner: (exe, args, {runInShell = false, timeout}) async {
          if (args.contains('--version')) {
            return ProcessResult(1, 0, '1.4.12', '');
          }
          return ProcessResult(1, 0, 'pong', '');
        },
      );

      final status = await cli.checkStatus(CliType.antigravity, customPath: '/snap/bin/agy');
      expect(status.isInstalled, isTrue);
      expect(status.isAuthenticated, isTrue);
      expect(status.version, equals('1.4.12'));
      expect(status.message.contains('Active subscription ready'), isTrue);
    });

    test('queryAgy returns stdout text on success', () async {
      final cli = CliLlmService(
        processRunner: (exe, args, {runInShell = false, timeout}) async {
          expect(args.contains('-p'), isTrue);
          expect(args.contains('--dangerously-skip-permissions'), isTrue);
          return ProcessResult(1, 0, 'Traffic analysis completed: normal HTTPS traffic.', '');
        },
      );

      final result = await cli.queryAgy('Analyze traffic', customPath: '/snap/bin/agy');
      expect(result, equals('Traffic analysis completed: normal HTTPS traffic.'));
    });

    test('queryAgy surfaces clear message on auth failure', () async {
      final cli = CliLlmService(
        processRunner: (exe, args, {runInShell = false, timeout}) async {
          return ProcessResult(
            1,
            1,
            'Authentication required. Please visit the URL to log in',
            '',
          );
        },
      );

      expect(
        () => cli.queryAgy('Analyze traffic', customPath: '/snap/bin/agy'),
        throwsA(predicate((e) => e.toString().contains('run "agy" to authenticate your subscription'))),
      );
    });

    test('queryClaude returns output on success', () async {
      final tempDir = Directory.systemTemp.createTempSync('claude_test_');
      final tempFile = File('${tempDir.path}/dummy_claude_bin')..createSync();
      try {
        final cli = CliLlmService(
          processRunner: (exe, args, {runInShell = false, timeout}) async {
            expect(args.contains('-p'), isTrue);
            return ProcessResult(1, 0, 'Claude analysis result', '');
          },
        );

        final result = await cli.queryClaude('Analyze traffic', customPath: tempFile.path);
        expect(result, equals('Claude analysis result'));
      } finally {
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      }
    });

    test('checkStatus reports unauthenticated when codex requires login', () async {
      final tempDir = Directory.systemTemp.createTempSync('codex_test_');
      final tempFile = File('${tempDir.path}/dummy_codex_bin')..createSync();
      try {
        final cli = CliLlmService(
          processRunner: (exe, args, {runInShell = false, timeout}) async {
            if (args.contains('--version')) {
              return ProcessResult(1, 0, '0.1.0', '');
            }
            return ProcessResult(1, 1, 'Sign in with ChatGPT to continue', '');
          },
        );

        final status = await cli.checkStatus(CliType.codex, customPath: tempFile.path);
        expect(status.isInstalled, isTrue);
        expect(status.isAuthenticated, isFalse);
        expect(status.message.contains('authentication required'), isTrue);
      } finally {
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      }
    });

    test('queryCodex returns output on success', () async {
      final tempDir = Directory.systemTemp.createTempSync('codex_test_');
      final tempFile = File('${tempDir.path}/dummy_codex_bin')..createSync();
      try {
        final cli = CliLlmService(
          processRunner: (exe, args, {runInShell = false, timeout}) async {
            expect(args.contains('exec'), isTrue);
            expect(args.contains('--ephemeral'), isTrue);
            return ProcessResult(1, 0, 'Codex traffic insights', '');
          },
        );

        final result = await cli.queryCodex('Analyze traffic', customPath: tempFile.path);
        expect(result, equals('Codex traffic insights'));
      } finally {
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      }
    });

    test('queryCodex surfaces clear message on auth failure', () async {
      final tempDir = Directory.systemTemp.createTempSync('codex_test_');
      final tempFile = File('${tempDir.path}/dummy_codex_bin')..createSync();
      try {
        final cli = CliLlmService(
          processRunner: (exe, args, {runInShell = false, timeout}) async {
            return ProcessResult(1, 1, 'Sign in with ChatGPT to get started', '');
          },
        );

        expect(
          cli.queryCodex('Analyze traffic', customPath: tempFile.path),
          throwsA(predicate((e) => e.toString().contains('link your ChatGPT subscription'))),
        );
      } finally {
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      }
    });

    test('listAgyModels dynamically parses models and tags economical options', () async {
      final tempDir = Directory.systemTemp.createTempSync('agy_test_');
      final tempFile = File('${tempDir.path}/dummy_agy_bin')..createSync();
      try {
        final cli = CliLlmService(
          processRunner: (exe, args, {runInShell = false, timeout}) async {
            if (args.contains('models')) {
              return ProcessResult(
                1,
                0,
                'Fetching available models...\n'
                'gemini-4-argon-high\tGemini 4 Argon (High)\n'
                'gemini-3.8-flash-low\tGemini 3.8 Flash (Low)\n'
                'claude-opus-5-5-high\tClaude Opus 5.5 (High)\n',
                '',
              );
            }
            return ProcessResult(1, 1, '', 'unknown arg');
          },
        );

        final models = await cli.listAgyModels(customPath: tempFile.path);
        expect(models.length, equals(3));
        expect(models[0].id, equals('gemini-4-argon-high'));
        expect(models[0].isEconomical, isFalse);
        expect(models[1].id, equals('gemini-3.8-flash-low'));
        expect(models[1].isEconomical, isTrue);
      } finally {
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      }
    });

    test('queryAgy, queryClaude, and queryCodex pass --model flag when specified', () async {
      final tempDir = Directory.systemTemp.createTempSync('multi_bin_test_');
      final agyFile = File('${tempDir.path}/dummy_agy_bin')..createSync();
      final claudeFile = File('${tempDir.path}/dummy_claude_bin')..createSync();
      final codexFile = File('${tempDir.path}/dummy_codex_bin')..createSync();

      try {
        final cli = CliLlmService(
          processRunner: (exe, args, {runInShell = false, timeout}) async {
            expect(args.contains('--model'), isTrue);
            if (exe.contains('agy')) {
              final idx = args.indexOf('--model');
              expect(args[idx + 1], equals('gemini-3.8-flash-low'));
              return ProcessResult(1, 0, 'agy response', '');
            } else if (exe.contains('claude')) {
              final idx = args.indexOf('--model');
              expect(args[idx + 1], equals('haiku'));
              return ProcessResult(1, 0, 'claude response', '');
            } else {
              final idx = args.indexOf('--model');
              expect(args[idx + 1], equals('gpt-4o-mini'));
              return ProcessResult(1, 0, 'codex response', '');
            }
          },
        );

        final resAgy = await cli.queryAgy('test', model: 'gemini-3.8-flash-low', customPath: agyFile.path);
        expect(resAgy, equals('agy response'));

        final resClaude = await cli.queryClaude('test', model: 'haiku', customPath: claudeFile.path);
        expect(resClaude, equals('claude response'));

        final resCodex = await cli.queryCodex('test', model: 'gpt-4o-mini', customPath: codexFile.path);
        expect(resCodex, equals('codex response'));
      } finally {
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      }
    });
  });

  group('LlmProviderService CLI Integration Tests', () {
    late Directory tempDir;
    late PacketRepository repo;
    late AiSettingsStorageService storage;

    setUp(() {
      tempDir = Directory.systemTemp.createTempSync('cli_ai_test_');
      storage = AiSettingsStorageService(storageDirectory: tempDir);
      repo = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir),
      );
    });

    tearDown(() {
      if (tempDir.existsSync()) {
        tempDir.deleteSync(recursive: true);
      }
    });

    test('sendMessage routes to Antigravity CLI and returns combined assistant message', () async {
      storage.saveSettings(const AiSettings(
        backendMode: LlmBackendMode.antigravityCli,
        agyPath: '/snap/bin/agy',
      ));

      final mockCli = CliLlmService(
        processRunner: (exe, args, {runInShell = false, timeout}) async {
          return ProcessResult(1, 0, 'High frequency HTTP packets detected from 192.168.1.10.', '');
        },
      );

      final llmService = LlmProviderService(
        tools: PacketAiTools(repository: repo),
        storageService: storage,
        cliService: mockCli,
      );

      final response = await llmService.sendMessage('Summarize capture');
      expect(response.role, equals('assistant'));
      expect(response.text.contains('High frequency HTTP packets detected'), isTrue);
      expect(response.toolResult, isNotNull);
      expect(llmService.history.length, equals(2)); // user + assistant
    });

    test('sendMessage falls back to deterministic analysis when CLI fails', () async {
      storage.saveSettings(const AiSettings(
        backendMode: LlmBackendMode.antigravityCli,
        agyPath: '/snap/bin/agy',
      ));

      final mockCli = CliLlmService(
        processRunner: (exe, args, {runInShell = false, timeout}) async {
          return ProcessResult(1, 1, '', 'CLI connection timed out');
        },
      );

      final llmService = LlmProviderService(
        tools: PacketAiTools(repository: repo),
        storageService: storage,
        cliService: mockCli,
      );

      final response = await llmService.sendMessage('Summarize capture');
      expect(response.role, equals('assistant'));
      expect(response.text.contains('executing deterministic offline analyzer'), isTrue);
      expect(response.toolResult, isNotNull);
    });

    test('sendMessage routes to Codex CLI in chatGptCodexCli mode', () async {
      final tempFile = File('${tempDir.path}/dummy_codex_bin')..createSync();
      storage.saveSettings(AiSettings(
        backendMode: LlmBackendMode.chatGptCodexCli,
        codexPath: tempFile.path,
      ));

        final mockCli = CliLlmService(
          processRunner: (exe, args, {runInShell = false, timeout}) async {
            return ProcessResult(1, 0, 'Codex analysis: DNS query spike observed.', '');
          },
        );

        final llmService = LlmProviderService(
          tools: PacketAiTools(repository: repo),
          storageService: storage,
          cliService: mockCli,
        );

        final response = await llmService.sendMessage('Find DNS spikes');
        expect(response.role, equals('assistant'));
        expect(response.text.contains('DNS query spike observed'), isTrue);
        expect(response.toolResult, isNotNull);
    });

    test('AiSettingsStorageService persists and restores CLI backend modes, custom paths, and selected models', () {
      storage.saveSettings(const AiSettings(
        backendMode: LlmBackendMode.chatGptCodexCli,
        agyPath: '/custom/bin/agy',
        claudePath: '/custom/bin/claude',
        codexPath: '/custom/bin/codex',
        agyModel: 'gemini-3.8-flash-low',
        claudeModel: 'haiku',
        codexModel: 'gpt-4o-mini',
        ollamaUrl: 'http://127.0.0.1:11434',
        ollamaModel: 'llama3:8b',
      ));

      final loaded = storage.loadSettings();
      expect(loaded.backendMode, equals(LlmBackendMode.chatGptCodexCli));
      expect(loaded.agyPath, equals('/custom/bin/agy'));
      expect(loaded.claudePath, equals('/custom/bin/claude'));
      expect(loaded.codexPath, equals('/custom/bin/codex'));
      expect(loaded.agyModel, equals('gemini-3.8-flash-low'));
      expect(loaded.claudeModel, equals('haiku'));
      expect(loaded.codexModel, equals('gpt-4o-mini'));
      expect(loaded.ollamaUrl, equals('http://127.0.0.1:11434'));
      expect(loaded.ollamaModel, equals('llama3:8b'));
    });
  });
}
