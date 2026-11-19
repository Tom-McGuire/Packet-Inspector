import 'dart:convert';
import 'package:http/http.dart' as http;
import 'packet_ai_tools.dart';
import 'ai_filter_references.dart';
import 'cli_llm_service.dart';
import '../diff/multi_capture_diff_engine.dart';
import '../storage/ai_settings_storage_service.dart';

enum LlmBackendMode {
  deterministicLocal,
  geminiCloud,
  localGemma, // Local OpenAI / Ollama
  antigravityCli, // Antigravity CLI (agy -p)
  claudeCodeCli, // Claude Code CLI (claude -p)
  chatGptCodexCli, // OpenAI Codex CLI (codex exec)
}

class ChatMessage {
  ChatMessage({
    required this.role, // 'user' or 'assistant'
    required this.text,
    this.toolResult,
  });

  final String role;
  final String text;
  final AiToolResult? toolResult;
}

class LlmProviderService {
  LlmProviderService({
    required this.tools,
    this.storageService,
    CliLlmService? cliService,
    this.diffEngineProvider,
    this.backendMode = LlmBackendMode.deterministicLocal,
    this.geminiApiKey = '',
    this.geminiModel = 'gemini-3.8-flash',
    this.ollamaUrl = 'http://localhost:11434',
    this.ollamaModel = 'gemma2:9b',
    this.agyPath = '',
    this.claudePath = '',
    this.codexPath = '',
    this.agyModel = 'gemini-3.8-flash-low',
    this.claudeModel = 'haiku',
    this.codexModel = 'gpt-4o-mini',
  }) : cliService = cliService ?? CliLlmService() {
    if (storageService != null) {
      loadSettings();
    }
  }

  final PacketAiTools tools;
  final AiSettingsStorageService? storageService;
  final CliLlmService cliService;
  final MultiCaptureDiffEngine? Function()? diffEngineProvider;
  LlmBackendMode backendMode;
  String geminiApiKey;
  String geminiModel;
  String ollamaUrl;
  String ollamaModel;
  String agyPath;
  String claudePath;
  String codexPath;
  String agyModel;
  String claudeModel;
  String codexModel;

  final List<ChatMessage> history = [];

  void loadSettings() {
    if (storageService == null) return;
    final s = storageService!.loadSettings();
    backendMode = s.backendMode;
    geminiApiKey = s.geminiApiKey;
    geminiModel = s.geminiModel.isNotEmpty ? s.geminiModel : 'gemini-3.8-flash';
    ollamaUrl = s.ollamaUrl;
    ollamaModel = s.ollamaModel;
    agyPath = s.agyPath;
    claudePath = s.claudePath;
    codexPath = s.codexPath;
    agyModel = s.agyModel.isNotEmpty ? s.agyModel : 'gemini-3.8-flash-low';
    claudeModel = s.claudeModel.isNotEmpty ? s.claudeModel : 'haiku';
    codexModel = s.codexModel.isNotEmpty ? s.codexModel : 'gpt-4o-mini';
  }

  void saveSettings() {
    if (storageService == null) return;
    storageService!.saveSettings(AiSettings(
      backendMode: backendMode,
      geminiApiKey: geminiApiKey,
      geminiModel: geminiModel.isNotEmpty ? geminiModel : 'gemini-3.8-flash',
      ollamaUrl: ollamaUrl,
      ollamaModel: ollamaModel,
      agyPath: agyPath,
      claudePath: claudePath,
      codexPath: codexPath,
      agyModel: agyModel,
      claudeModel: claudeModel,
      codexModel: codexModel,
    ));
  }

  Future<ChatMessage> sendMessage(
    String userMessage, {
    String? contextEnvelope,
    MultiCaptureDiffEngine? diffEngine,
  }) async {
    history.add(ChatMessage(role: 'user', text: userMessage));
    final effectiveDiffEngine = diffEngine ?? diffEngineProvider?.call();

    switch (backendMode) {
      case LlmBackendMode.deterministicLocal:
        final reply = _handleDeterministic(
          userMessage,
          contextEnvelope: contextEnvelope,
          diffEngine: effectiveDiffEngine,
        );
        history.add(reply);
        return reply;

      case LlmBackendMode.geminiCloud:
        try {
          final reply = await _callGeminiApi(
            userMessage,
            contextEnvelope: contextEnvelope,
            diffEngine: effectiveDiffEngine,
          );
          history.add(reply);
          return reply;
        } catch (e) {
          final fallback = _handleDeterministic(
            userMessage,
            fallbackReason: e.toString(),
            contextEnvelope: contextEnvelope,
            diffEngine: effectiveDiffEngine,
          );
          history.add(fallback);
          return fallback;
        }

      case LlmBackendMode.localGemma:
        try {
          final reply = await _callOllamaApi(
            userMessage,
            contextEnvelope: contextEnvelope,
            diffEngine: effectiveDiffEngine,
          );
          history.add(reply);
          return reply;
        } catch (e) {
          final fallback = _handleDeterministic(
            userMessage,
            fallbackReason: e.toString(),
            contextEnvelope: contextEnvelope,
            diffEngine: effectiveDiffEngine,
          );
          history.add(fallback);
          return fallback;
        }

      case LlmBackendMode.antigravityCli:
        try {
          final reply = await _callAgyCli(
            userMessage,
            contextEnvelope: contextEnvelope,
            diffEngine: effectiveDiffEngine,
          );
          history.add(reply);
          return reply;
        } catch (e) {
          final fallback = _handleDeterministic(
            userMessage,
            fallbackReason: e.toString(),
            contextEnvelope: contextEnvelope,
            diffEngine: effectiveDiffEngine,
          );
          history.add(fallback);
          return fallback;
        }

      case LlmBackendMode.claudeCodeCli:
        try {
          final reply = await _callClaudeCli(
            userMessage,
            contextEnvelope: contextEnvelope,
            diffEngine: effectiveDiffEngine,
          );
          history.add(reply);
          return reply;
        } catch (e) {
          final fallback = _handleDeterministic(
            userMessage,
            fallbackReason: e.toString(),
            contextEnvelope: contextEnvelope,
            diffEngine: effectiveDiffEngine,
          );
          history.add(fallback);
          return fallback;
        }

      case LlmBackendMode.chatGptCodexCli:
        try {
          final reply = await _callCodexCli(
            userMessage,
            contextEnvelope: contextEnvelope,
            diffEngine: effectiveDiffEngine,
          );
          history.add(reply);
          return reply;
        } catch (e) {
          final fallback = _handleDeterministic(
            userMessage,
            fallbackReason: e.toString(),
            contextEnvelope: contextEnvelope,
            diffEngine: effectiveDiffEngine,
          );
          history.add(fallback);
          return fallback;
        }
    }
  }

  ChatMessage _handleDeterministic(
    String prompt, {
    String? fallbackReason,
    String? contextEnvelope,
    MultiCaptureDiffEngine? diffEngine,
  }) {
    final lower = prompt.toLowerCase();
    AiToolResult? toolResult;
    String textReply = '';

    final refs = AiFilterReferences.parse(prompt, tools.repository);
    final isCompareQuery = lower.contains('compare') ||
        lower.contains('diff') ||
        lower.contains('drop') ||
        lower.contains('hop') ||
        lower.contains('skew') ||
        lower.contains('mutat');

    if (refs.hasAnyReferences) {
      toolResult = tools.generateFilteredReport(refs: refs);
      textReply = '${toolResult.summaryText}\n\n*Interactive filtered traffic card rendered below. Click "Apply to Filter Bar" to isolate this traffic on your main inspector screen.*';
    } else if (diffEngine != null && diffEngine.slots.length >= 2 && isCompareQuery) {
      toolResult = tools.compareCapturesSummary(diffEngine);
      textReply = '${toolResult.summaryText}\n\n*Interactive multi-capture comparison card rendered below.*';
    } else if (lower.contains('top') || lower.contains('talker') || lower.contains('conversation')) {
      final metric = lower.contains('pkt') || lower.contains('packet') ? 'packets' : 'bytes';
      final unexpected = lower.contains('unexpected');
      toolResult = tools.getTopTalkers(metric: metric, limit: 5, onlyUnexpected: unexpected);
      textReply = '${toolResult.summaryText}\n\n*Interactive chart & table generated below.*';
    } else if (lower.contains('timing') || lower.contains('spike') || lower.contains('burst') || lower.contains('stall')) {
      final isBurst = !lower.contains('stall') && !lower.contains('latency');
      toolResult = tools.findTimingAnomalies(isBurst: isBurst);
      textReply = '${toolResult.summaryText}\n\n*Click "Jump to Spike" in the card below to zoom the main timeline.*';
    } else if (lower.contains('custom') || lower.contains('unknown') || lower.contains('45820') || lower.contains('acme') || lower.contains('magic')) {
      toolResult = tools.suggestCustomProtocolSignature(port: 45820);
      textReply = '${toolResult.summaryText}\n\n*You can save this custom protocol signature directly with one click below.*';
    } else {
      // Default summary
      toolResult = tools.getCaptureSummary();
      textReply = '${toolResult.summaryText}\n\n*Protocol breakdown chart rendered below.*';
    }

    if (contextEnvelope != null && contextEnvelope.trim().isNotEmpty) {
      final firstLine = contextEnvelope.trim().split(RegExp(r'[\r\n]+')).first;
      textReply = '*(Analyzed using $firstLine)*\n\n$textReply';
    }

    if (fallbackReason != null) {
      textReply = '*(Note: Network call to backend failed ($fallbackReason); executing deterministic offline analyzer:)*\n\n$textReply';
    }

    return ChatMessage(
      role: 'assistant',
      text: textReply,
      toolResult: toolResult,
    );
  }

  String _buildEnrichedPrompt(
    String prompt,
    AiToolResult? localToolResult, {
    String? contextEnvelope,
  }) {
    final refs = AiFilterReferences.parse(prompt, tools.repository);
    final sb = StringBuffer(prompt);

    if (refs.hasAnyReferences) {
      sb.write('\n\n[Context from Packet Inspector Library]:\n${refs.buildLibraryContextSummary()}');
    }
    if (contextEnvelope != null && contextEnvelope.trim().isNotEmpty) {
      sb.write('\n\n$contextEnvelope');
    }

    final captureSummary = tools.getCaptureSummary().summaryText;
    sb.write('\n\n[Deterministic Capture Summary]:\n$captureSummary');

    if (localToolResult != null && localToolResult.toolName != 'get_capture_summary') {
      sb.write('\n\n[Deterministic Tool Analysis (${localToolResult.toolName})]:\n${localToolResult.summaryText}');
    }

    return sb.toString();
  }

  Future<ChatMessage> _callGeminiApi(
    String prompt, {
    String? contextEnvelope,
    MultiCaptureDiffEngine? diffEngine,
  }) async {
    if (geminiApiKey.isEmpty) {
      throw Exception('Gemini API Key is empty. Please enter your API key in Settings.');
    }

    final localResult = _handleDeterministic(
      prompt,
      contextEnvelope: contextEnvelope,
      diffEngine: diffEngine,
    );
    final enrichedPrompt = _buildEnrichedPrompt(
      prompt,
      localResult.toolResult,
      contextEnvelope: contextEnvelope,
    );

    final modelName = geminiModel.isNotEmpty ? geminiModel : 'gemini-3.8-flash';
    final url = Uri.parse(
      'https://generativelanguage.googleapis.com/v1beta/models/$modelName:generateContent?key=$geminiApiKey',
    );

    final payload = {
      'contents': [
        {
          'role': 'user',
          'parts': [{'text': enrichedPrompt}],
        }
      ],
      'systemInstruction': {
        'parts': [
          {
            'text': 'You are Packet Inspector AI, an expert network analyst. '
                'Analyze traffic stats accurately and provide concise network insights.'
          }
        ]
      }
    };

    final resp = await http.post(
      url,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(payload),
    );

    if (resp.statusCode != 200) {
      throw Exception('Gemini HTTP ${resp.statusCode}: ${resp.body}');
    }

    final data = jsonDecode(resp.body) as Map<String, dynamic>;
    final candidates = data['candidates'] as List<dynamic>?;
    final text = candidates?.first['content']['parts'][0]['text'] as String? ?? 'No response text.';

    return ChatMessage(
      role: 'assistant',
      text: '$text\n\n---\n${localResult.text}',
      toolResult: localResult.toolResult,
    );
  }

  Future<ChatMessage> _callOllamaApi(
    String prompt, {
    String? contextEnvelope,
    MultiCaptureDiffEngine? diffEngine,
  }) async {
    final cleanUrl = ollamaUrl.endsWith('/') ? ollamaUrl.substring(0, ollamaUrl.length - 1) : ollamaUrl;
    final endpoint = Uri.parse('$cleanUrl/v1/chat/completions');

    final localResult = _handleDeterministic(
      prompt,
      contextEnvelope: contextEnvelope,
      diffEngine: diffEngine,
    );
    final enrichedPrompt = _buildEnrichedPrompt(
      prompt,
      localResult.toolResult,
      contextEnvelope: contextEnvelope,
    );

    final payload = {
      'model': ollamaModel,
      'messages': [
        {'role': 'system', 'content': 'You are Packet Inspector AI. Analyze packet metadata succinctly.'},
        {'role': 'user', 'content': enrichedPrompt},
      ],
    };

    final resp = await http.post(
      endpoint,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(payload),
    ).timeout(const Duration(seconds: 15));

    if (resp.statusCode != 200) {
      throw Exception('Ollama HTTP ${resp.statusCode}: ${resp.body}');
    }

    final data = jsonDecode(resp.body) as Map<String, dynamic>;
    final choices = data['choices'] as List<dynamic>?;
    final text = choices?.first['message']['content'] as String? ?? 'No response';

    return ChatMessage(
      role: 'assistant',
      text: '$text\n\n---\n${localResult.text}',
      toolResult: localResult.toolResult,
    );
  }

  Future<ChatMessage> _callAgyCli(
    String prompt, {
    String? contextEnvelope,
    MultiCaptureDiffEngine? diffEngine,
  }) async {
    final localResult = _handleDeterministic(
      prompt,
      contextEnvelope: contextEnvelope,
      diffEngine: diffEngine,
    );
    final enrichedPrompt = _buildEnrichedPrompt(
      prompt,
      localResult.toolResult,
      contextEnvelope: contextEnvelope,
    );

    final fullPrompt = 'You are Packet Inspector AI, an expert network analyst. Analyze traffic stats accurately and provide concise network insights.\n\nUser Question:\n$enrichedPrompt';
    final text = await cliService.queryAgy(
      fullPrompt,
      model: agyModel.isNotEmpty ? agyModel : null,
      customPath: agyPath.isNotEmpty ? agyPath : null,
    );

    return ChatMessage(
      role: 'assistant',
      text: '$text\n\n---\n${localResult.text}',
      toolResult: localResult.toolResult,
    );
  }

  Future<ChatMessage> _callClaudeCli(
    String prompt, {
    String? contextEnvelope,
    MultiCaptureDiffEngine? diffEngine,
  }) async {
    final localResult = _handleDeterministic(
      prompt,
      contextEnvelope: contextEnvelope,
      diffEngine: diffEngine,
    );
    final enrichedPrompt = _buildEnrichedPrompt(
      prompt,
      localResult.toolResult,
      contextEnvelope: contextEnvelope,
    );

    final fullPrompt = 'You are Packet Inspector AI, an expert network analyst. Analyze traffic stats accurately and provide concise network insights.\n\nUser Question:\n$enrichedPrompt';
    final text = await cliService.queryClaude(
      fullPrompt,
      model: claudeModel.isNotEmpty ? claudeModel : null,
      customPath: claudePath.isNotEmpty ? claudePath : null,
    );

    return ChatMessage(
      role: 'assistant',
      text: '$text\n\n---\n${localResult.text}',
      toolResult: localResult.toolResult,
    );
  }

  Future<ChatMessage> _callCodexCli(
    String prompt, {
    String? contextEnvelope,
    MultiCaptureDiffEngine? diffEngine,
  }) async {
    final localResult = _handleDeterministic(
      prompt,
      contextEnvelope: contextEnvelope,
      diffEngine: diffEngine,
    );
    final enrichedPrompt = _buildEnrichedPrompt(
      prompt,
      localResult.toolResult,
      contextEnvelope: contextEnvelope,
    );

    final fullPrompt = 'You are Packet Inspector AI, an expert network analyst. Analyze traffic stats accurately and provide concise network insights.\n\nUser Question:\n$enrichedPrompt';
    final text = await cliService.queryCodex(
      fullPrompt,
      model: codexModel.isNotEmpty ? codexModel : null,
      customPath: codexPath.isNotEmpty ? codexPath : null,
    );

    return ChatMessage(
      role: 'assistant',
      text: '$text\n\n---\n${localResult.text}',
      toolResult: localResult.toolResult,
    );
  }

  /// Discovers models from a local Ollama instance (`/api/tags`).
  Future<List<String>> listOllamaModels({String? customUrl}) async {
    final baseUrl = (customUrl != null && customUrl.trim().isNotEmpty)
        ? customUrl.trim()
        : (ollamaUrl.isNotEmpty ? ollamaUrl : 'http://localhost:11434');

    try {
      final uri = Uri.parse('$baseUrl/api/tags');
      final resp = await http.get(uri).timeout(const Duration(seconds: 5));
      if (resp.statusCode == 200) {
        final data = jsonDecode(resp.body) as Map<String, dynamic>;
        final models = data['models'] as List<dynamic>? ?? [];
        final names = <String>[];
        for (final m in models) {
          final n = m['name'] as String?;
          if (n != null && n.isNotEmpty) {
            names.add(n);
          }
        }
        if (names.isNotEmpty) return names;
      }
    } catch (_) {}
    return const ['gemma2:9b', 'gemma3:4b', 'llama3.2:latest', 'mistral', 'deepseek-r1'];
  }
}
