import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:packet_inspector/data/services/ai/cli_llm_service.dart';
import 'package:packet_inspector/data/services/ai/llm_provider_service.dart';
import 'package:packet_inspector/data/services/ai/packet_ai_tools.dart';
import 'package:packet_inspector/data/services/storage/protocol_library_service.dart';
import 'package:packet_inspector/data/repositories/packet_repository.dart';

void main() {
  test('Live real agy CLI integration test with active subscription', () async {
    final cliService = CliLlmService();
    final status = await cliService.checkStatus(CliType.antigravity);

    // If agy is installed and authenticated, verify live query
    if (status.isInstalled && status.isAuthenticated) {
      final reply = await cliService.queryAgy(
        'In 5 words or less, what is ARP used for in networking?',
        timeout: const Duration(seconds: 30),
      );
      expect(reply.trim().isNotEmpty, isTrue);

      final tempDir = Directory.systemTemp.createTempSync('live_agy_test_');
      final repo = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir),
      );
      final llmService = LlmProviderService(
        tools: PacketAiTools(repository: repo),
        backendMode: LlmBackendMode.antigravityCli,
      );

      final chatMsg = await llmService.sendMessage('What are top talkers?');
      expect(chatMsg.role, equals('assistant'));
      expect(chatMsg.text.contains('executing deterministic offline analyzer'), isFalse);
      expect(chatMsg.toolResult, isNotNull);

      tempDir.deleteSync(recursive: true);
    }
  }, timeout: const Timeout(Duration(seconds: 120)));
}
