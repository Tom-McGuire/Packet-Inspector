import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:packet_inspector/data/repositories/packet_repository.dart';
import 'package:packet_inspector/data/services/ai/cli_llm_service.dart';
import 'package:packet_inspector/data/services/ai/llm_provider_service.dart';
import 'package:packet_inspector/data/services/ai/packet_ai_tools.dart';
import 'package:packet_inspector/data/services/storage/ai_settings_storage_service.dart';

/// Recorded outbound HTTP request captured by [MockHttpLlmServer].
class RecordedHttpCall {
  const RecordedHttpCall({
    required this.method,
    required this.url,
    required this.headers,
    required this.body,
    required this.decodedJson,
  });

  final String method;
  final Uri url;
  final Map<String, String> headers;
  final String body;
  final Map<String, dynamic>? decodedJson;
}

class _NonClosingHttpClient extends http.BaseClient {
  _NonClosingHttpClient(this._inner);

  final http.Client _inner;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    return _inner.send(request);
  }

  @override
  void close() {
    // Intentionally a no-op because top-level http.get/http.post close the
    // zone client after every request.
  }
}

/// Zero-network HTTP mock for Gemini (`generateContent`) and Ollama
/// (`/v1/chat/completions`, `/api/tags`) using `http.runWithClient`.
class MockHttpLlmServer {
  MockHttpLlmServer({
    this.geminiResponseText = 'Mock Gemini network analysis.',
    this.geminiStatusCode = 200,
    this.geminiErrorBody = '{"error": {"message": "Mock Gemini error"}}',
    this.throwOnGemini = false,
    this.ollamaResponseText = 'Mock Ollama network analysis.',
    this.ollamaStatusCode = 200,
    this.ollamaErrorBody = '{"error": "Mock Ollama error"}',
    this.throwOnOllamaChat = false,
    this.ollamaModels = const ['gemma2:9b', 'gemma3:4b', 'llama3.2:latest'],
    this.ollamaTagsStatusCode = 200,
    this.throwOnOllamaTags = false,
  }) {
    _mockClient = MockClient(_handleRequest);
    _nonClosingClient = _NonClosingHttpClient(_mockClient);
  }

  String geminiResponseText;
  int geminiStatusCode;
  String geminiErrorBody;
  bool throwOnGemini;

  String ollamaResponseText;
  int ollamaStatusCode;
  String ollamaErrorBody;
  bool throwOnOllamaChat;

  List<String> ollamaModels;
  int ollamaTagsStatusCode;
  bool throwOnOllamaTags;

  final List<RecordedHttpCall> recordedCalls = [];
  late final MockClient _mockClient;
  late final _NonClosingHttpClient _nonClosingClient;

  void clearRecordedCalls() => recordedCalls.clear();

  /// Executes [body] inside an `http.runWithClient` zone so all top-level
  /// `http.get`/`http.post` calls in [LlmProviderService] hit this mock.
  Future<T> runWithHttpMock<T>(Future<T> Function() body) {
    return http.runWithClient(body, () => _nonClosingClient);
  }

  Future<http.Response> _handleRequest(http.Request request) async {
    Map<String, dynamic>? decoded;
    if (request.body.isNotEmpty) {
      try {
        final parsed = jsonDecode(request.body);
        if (parsed is Map<String, dynamic>) {
          decoded = parsed;
        }
      } catch (_) {}
    }

    recordedCalls.add(
      RecordedHttpCall(
        method: request.method,
        url: request.url,
        headers: Map<String, String>.from(request.headers),
        body: request.body,
        decodedJson: decoded,
      ),
    );

    final url = request.url;

    // 1. Gemini generateContent endpoint
    if (url.host.contains('generativelanguage.googleapis.com') &&
        url.path.contains(':generateContent')) {
      if (throwOnGemini) {
        throw const SocketException('Simulated Gemini network failure');
      }
      if (geminiStatusCode != 200) {
        return http.Response(geminiErrorBody, geminiStatusCode);
      }
      return http.Response(
        jsonEncode({
          'candidates': [
            {
              'content': {
                'parts': [
                  {'text': geminiResponseText},
                ],
              },
            },
          ],
        }),
        200,
        headers: {'content-type': 'application/json'},
      );
    }

    // 2. Ollama chat completions endpoint
    if (url.path.endsWith('/v1/chat/completions')) {
      if (throwOnOllamaChat) {
        throw const SocketException('Simulated Ollama connection refused');
      }
      if (ollamaStatusCode != 200) {
        return http.Response(ollamaErrorBody, ollamaStatusCode);
      }
      return http.Response(
        jsonEncode({
          'choices': [
            {
              'message': {'content': ollamaResponseText},
            },
          ],
        }),
        200,
        headers: {'content-type': 'application/json'},
      );
    }

    // 3. Ollama model discovery (/api/tags)
    if (url.path.endsWith('/api/tags')) {
      if (throwOnOllamaTags) {
        throw const SocketException('Simulated Ollama tags unreachable');
      }
      if (ollamaTagsStatusCode != 200) {
        return http.Response('{"error":"tags unavailable"}', ollamaTagsStatusCode);
      }
      return http.Response(
        jsonEncode({
          'models': ollamaModels.map((m) => {'name': m}).toList(),
        }),
        200,
        headers: {'content-type': 'application/json'},
      );
    }

    return http.Response('Not Found: ${request.url}', 404);
  }
}

/// Recorded subprocess invocation captured by [MockCliLlmBackend].
class RecordedCliCall {
  const RecordedCliCall({
    required this.executable,
    required this.arguments,
  });

  final String executable;
  final List<String> arguments;
}

/// Configurable mock state for a single CLI LLM backend (`agy`, `claude`, `codex`).
class CliBackendConfig {
  CliBackendConfig({
    this.installed = true,
    this.authenticated = true,
    this.version = '1.4.12',
    this.replyText = 'Mock CLI network analysis.',
    this.exitCode = 0,
    this.stderrText = '',
    this.emptyOutput = false,
    this.agyModelsOutput =
        'gemini-3.8-flash-low\tGemini 3.8 Flash (Low)\n'
            'gemini-3.8-flash-high\tGemini 3.8 Flash (High)\n'
            'claude-sonnet-5-5-low\tClaude Sonnet 5.5 (Low)\n',
    this.authErrorText,
    this.throwOnQuery = false,
  });

  bool installed;
  bool authenticated;
  String version;
  String replyText;
  int exitCode;
  String stderrText;
  bool emptyOutput;
  String agyModelsOutput;
  String? authErrorText;
  bool throwOnQuery;
}

/// Zero-subprocess CLI mock backend creating dummy executables in [tempDir]
/// and capturing every invocation made by [CliLlmService].
class MockCliLlmBackend {
  MockCliLlmBackend({
    required this.tempDir,
    CliBackendConfig? agyConfig,
    CliBackendConfig? claudeConfig,
    CliBackendConfig? codexConfig,
  })  : agyConfig = agyConfig ?? CliBackendConfig(replyText: 'Mock agy CLI analysis.'),
        claudeConfig = claudeConfig ?? CliBackendConfig(replyText: 'Mock claude CLI analysis.'),
        codexConfig = codexConfig ?? CliBackendConfig(replyText: 'Mock codex CLI analysis.') {
    syncDummyBinaries();
    _cliService = CliLlmService(processRunner: _runProcess);
  }

  final Directory tempDir;
  final CliBackendConfig agyConfig;
  final CliBackendConfig claudeConfig;
  final CliBackendConfig codexConfig;

  final List<RecordedCliCall> recordedCalls = [];
  late final CliLlmService _cliService;

  String get agyDummyPath =>
      '${tempDir.path}${Platform.pathSeparator}dummy_agy_bin';
  String get claudeDummyPath =>
      '${tempDir.path}${Platform.pathSeparator}dummy_claude_bin';
  String get codexDummyPath =>
      '${tempDir.path}${Platform.pathSeparator}dummy_codex_bin';

  CliLlmService get cliService => _cliService;
  ProcessRunner get processRunner => _runProcess;

  void clearRecordedCalls() => recordedCalls.clear();

  /// Creates or deletes dummy binary files inside [tempDir] to match
  /// each backend's `installed` flag.
  void syncDummyBinaries() {
    _syncBinary(agyDummyPath, agyConfig.installed);
    _syncBinary(claudeDummyPath, claudeConfig.installed);
    _syncBinary(codexDummyPath, codexConfig.installed);
  }

  void _syncBinary(String path, bool installed) {
    final f = File(path);
    if (installed) {
      f.parent.createSync(recursive: true);
      if (!f.existsSync()) {
        f.writeAsStringSync('#!/bin/sh\nexit 0\n');
      }
    } else if (f.existsSync()) {
      f.deleteSync();
    }
  }

  /// Builds [AiSettings] pointing at the temp dummy binaries inside [tempDir].
  AiSettings buildSettings({
    LlmBackendMode backendMode = LlmBackendMode.antigravityCli,
    String geminiApiKey = 'mock-gemini-key',
    String geminiModel = 'gemini-3.8-flash',
    String ollamaUrl = 'http://localhost:11434',
    String ollamaModel = 'gemma2:9b',
    String agyModel = 'gemini-3.8-flash-low',
    String claudeModel = 'haiku',
    String codexModel = 'gpt-4o-mini',
  }) {
    return AiSettings(
      backendMode: backendMode,
      geminiApiKey: geminiApiKey,
      geminiModel: geminiModel,
      ollamaUrl: ollamaUrl,
      ollamaModel: ollamaModel,
      agyPath: agyConfig.installed ? agyDummyPath : '${tempDir.path}/missing_agy_bin',
      claudePath: claudeConfig.installed ? claudeDummyPath : '${tempDir.path}/missing_claude_bin',
      codexPath: codexConfig.installed ? codexDummyPath : '${tempDir.path}/missing_codex_bin',
      agyModel: agyModel,
      claudeModel: claudeModel,
      codexModel: codexModel,
    );
  }

  CliBackendConfig? _configForExecutable(String executable) {
    final lower = executable.toLowerCase();
    if (lower.contains('agy')) return agyConfig;
    if (lower.contains('claude')) return claudeConfig;
    if (lower.contains('codex')) return codexConfig;
    return null;
  }

  CliType? _typeForExecutable(String executable) {
    final lower = executable.toLowerCase();
    if (lower.contains('agy')) return CliType.antigravity;
    if (lower.contains('claude')) return CliType.claudeCode;
    if (lower.contains('codex')) return CliType.codex;
    return null;
  }

  Future<ProcessResult> _runProcess(
    String executable,
    List<String> arguments, {
    bool runInShell = false,
    Duration? timeout,
  }) async {
    recordedCalls.add(
      RecordedCliCall(
        executable: executable,
        arguments: List<String>.from(arguments),
      ),
    );

    // Handle `which` / `where` path discovery calls
    if (executable == 'which' || executable == 'where') {
      final target = arguments.isNotEmpty ? arguments.first : '';
      if (target == 'agy' && agyConfig.installed) {
        return ProcessResult(1, 0, agyDummyPath, '');
      }
      if (target == 'claude' && claudeConfig.installed) {
        return ProcessResult(1, 0, claudeDummyPath, '');
      }
      if (target == 'codex' && codexConfig.installed) {
        return ProcessResult(1, 0, codexDummyPath, '');
      }
      return ProcessResult(1, 1, '', 'not found');
    }

    final cfg = _configForExecutable(executable);
    final cliType = _typeForExecutable(executable);
    if (cfg == null || cliType == null) {
      return ProcessResult(1, 127, '', 'Unknown mock CLI executable: $executable');
    }

    if (!cfg.installed) {
      return ProcessResult(1, 127, '', 'No such file: $executable');
    }

    if (arguments.contains('--version')) {
      return ProcessResult(1, 0, cfg.version, '');
    }

    if (cliType == CliType.antigravity &&
        arguments.isNotEmpty &&
        arguments.first == 'models') {
      return ProcessResult(1, 0, cfg.agyModelsOutput, '');
    }

    final isStatusProbe = (arguments.length >= 2 &&
            arguments[0] == '-p' &&
            arguments[1] == 'ping') ||
        (arguments.length >= 2 &&
            arguments[0] == 'exec' &&
            arguments[1] == 'ping');

    if (!cfg.authenticated) {
      final defaultAuthMsg = switch (cliType) {
        CliType.antigravity =>
          'Authentication required. Please visit the URL to log in.',
        CliType.claudeCode => 'Unauthorized: please login with claude.',
        CliType.codex => 'Sign in with ChatGPT required.',
      };
      final errMsg = cfg.authErrorText ?? defaultAuthMsg;
      return ProcessResult(1, 1, '', errMsg);
    }

    if (isStatusProbe) {
      return ProcessResult(1, 0, 'pong', '');
    }

    if (cfg.throwOnQuery) {
      throw ProcessException(executable, arguments, 'Simulated CLI crash', 1);
    }

    if (cfg.exitCode != 0) {
      return ProcessResult(1, cfg.exitCode, '', cfg.stderrText);
    }

    if (cfg.emptyOutput) {
      return ProcessResult(1, 0, '', '');
    }

    return ProcessResult(1, 0, cfg.replyText, '');
  }
}

/// Wires an [LlmProviderService] with isolated [storageService], [PacketRepository],
/// and optional [MockCliLlmBackend] using post-cleanup signatures only.
LlmProviderService createMockLlmService({
  required PacketRepository repository,
  required AiSettingsStorageService storageService,
  MockCliLlmBackend? cliBackend,
  LlmBackendMode backendMode = LlmBackendMode.deterministicLocal,
  String geminiApiKey = 'mock-gemini-key',
  String geminiModel = 'gemini-3.8-flash',
  String ollamaUrl = 'http://localhost:11434',
  String ollamaModel = 'gemma2:9b',
}) {
  final settings = cliBackend != null
      ? cliBackend.buildSettings(
          backendMode: backendMode,
          geminiApiKey: geminiApiKey,
          geminiModel: geminiModel,
          ollamaUrl: ollamaUrl,
          ollamaModel: ollamaModel,
        )
      : AiSettings(
          backendMode: backendMode,
          geminiApiKey: geminiApiKey,
          geminiModel: geminiModel,
          ollamaUrl: ollamaUrl,
          ollamaModel: ollamaModel,
        );
  storageService.saveSettings(settings);

  return LlmProviderService(
    tools: PacketAiTools(repository: repository),
    storageService: storageService,
    cliService: cliBackend?.cliService,
    backendMode: backendMode,
    geminiApiKey: geminiApiKey,
    geminiModel: geminiModel,
    ollamaUrl: ollamaUrl,
    ollamaModel: ollamaModel,
    agyPath: settings.agyPath,
    claudePath: settings.claudePath,
    codexPath: settings.codexPath,
    agyModel: settings.agyModel,
    claudeModel: settings.claudeModel,
    codexModel: settings.codexModel,
  );
}
