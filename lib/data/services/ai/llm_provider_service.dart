import 'dart:convert';
import 'package:http/http.dart' as http;
import 'packet_ai_tools.dart';

enum LlmBackendMode {
  deterministicLocal,
  geminiCloud,
  localGemma, // Ollama / LM Studio
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
    this.backendMode = LlmBackendMode.deterministicLocal,
    this.geminiApiKey = '',
    this.geminiModel = 'gemini-2.5-flash',
    this.ollamaUrl = 'http://localhost:11434',
    this.ollamaModel = 'gemma2:9b',
  });

  final PacketAiTools tools;
  LlmBackendMode backendMode;
  String geminiApiKey;
  String geminiModel;
  String ollamaUrl;
  String ollamaModel;

  final List<ChatMessage> history = [];

  Future<ChatMessage> sendMessage(String userMessage) async {
    history.add(ChatMessage(role: 'user', text: userMessage));

    switch (backendMode) {
      case LlmBackendMode.deterministicLocal:
        final reply = _handleDeterministic(userMessage);
        history.add(reply);
        return reply;

      case LlmBackendMode.geminiCloud:
        try {
          final reply = await _callGeminiApi(userMessage);
          history.add(reply);
          return reply;
        } catch (e) {
          final fallback = _handleDeterministic(userMessage, fallbackReason: e.toString());
          history.add(fallback);
          return fallback;
        }

      case LlmBackendMode.localGemma:
        try {
          final reply = await _callOllamaApi(userMessage);
          history.add(reply);
          return reply;
        } catch (e) {
          final fallback = _handleDeterministic(userMessage, fallbackReason: e.toString());
          history.add(fallback);
          return fallback;
        }
    }
  }

  ChatMessage _handleDeterministic(String prompt, {String? fallbackReason}) {
    final lower = prompt.toLowerCase();
    AiToolResult? toolResult;
    String textReply = '';

    if (lower.contains('top') || lower.contains('talker') || lower.contains('conversation')) {
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

    if (fallbackReason != null) {
      textReply = '*(Note: Network call to backend failed ($fallbackReason); executing deterministic offline analyzer:)*\n\n$textReply';
    }

    return ChatMessage(
      role: 'assistant',
      text: textReply,
      toolResult: toolResult,
    );
  }

  Future<ChatMessage> _callGeminiApi(String prompt) async {
    if (geminiApiKey.isEmpty) {
      throw Exception('Gemini API Key is empty. Please enter your API key in Settings.');
    }

    final url = Uri.parse(
      'https://generativelanguage.googleapis.com/v1beta/models/$geminiModel:generateContent?key=$geminiApiKey',
    );

    final payload = {
      'contents': [
        {
          'role': 'user',
          'parts': [{'text': prompt}],
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

    // Execute relevant tool to pair with the AI answer
    final localResult = _handleDeterministic(prompt);

    return ChatMessage(
      role: 'assistant',
      text: '$text\n\n---\n${localResult.text}',
      toolResult: localResult.toolResult,
    );
  }

  Future<ChatMessage> _callOllamaApi(String prompt) async {
    final cleanUrl = ollamaUrl.endsWith('/') ? ollamaUrl.substring(0, ollamaUrl.length - 1) : ollamaUrl;
    final endpoint = Uri.parse('$cleanUrl/v1/chat/completions');

    final payload = {
      'model': ollamaModel,
      'messages': [
        {'role': 'system', 'content': 'You are Packet Inspector AI. Analyze packet metadata succinctly.'},
        {'role': 'user', 'content': prompt},
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

    final localResult = _handleDeterministic(prompt);
    return ChatMessage(
      role: 'assistant',
      text: '$text\n\n---\n${localResult.text}',
      toolResult: localResult.toolResult,
    );
  }
}
