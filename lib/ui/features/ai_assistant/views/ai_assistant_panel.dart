import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../../../domain/models/custom_protocol_rule.dart';
import '../../../../domain/models/packet_record.dart';
import '../../../features/inspector/view_models/inspector_view_model.dart';
import '../../../../data/services/ai/packet_ai_tools.dart';
import '../../../../data/services/ai/llm_provider_service.dart';
import '../../../../data/services/export/csv_export_service.dart';

class AiAssistantPanel extends StatefulWidget {
  const AiAssistantPanel({super.key});

  @override
  State<AiAssistantPanel> createState() => _AiAssistantPanelState();
}

class _AiAssistantPanelState extends State<AiAssistantPanel> {
  late final LlmProviderService _llmService;
  final TextEditingController _inputCtrl = TextEditingController();
  final ScrollController _scrollCtrl = ScrollController();
  bool _isSending = false;

  @override
  void initState() {
    super.initState();
    final vm = context.read<InspectorViewModel>();
    _llmService = LlmProviderService(
      tools: PacketAiTools(repository: vm.repository),
    );
    // Add welcome message
    _llmService.history.add(ChatMessage(
      role: 'assistant',
      text: '👋 Welcome to **Packet Inspector AI**!\n\n'
          'I can summarize your capture, hunt for timing spikes, chart top talkers, or suggest signatures for custom binary protocols.',
    ));
  }

  @override
  void dispose() {
    _inputCtrl.dispose();
    _scrollCtrl.dispose();
    super.dispose();
  }

  void _sendMessage([String? textToSend]) async {
    final text = textToSend ?? _inputCtrl.text.trim();
    if (text.isEmpty) return;
    _inputCtrl.clear();

    setState(() {
      _isSending = true;
    });

    try {
      await _llmService.sendMessage(text);
    } finally {
      if (mounted) {
        setState(() {
          _isSending = false;
        });
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (_scrollCtrl.hasClients) {
            _scrollCtrl.animateTo(
              _scrollCtrl.position.maxScrollExtent,
              duration: const Duration(milliseconds: 250),
              curve: Curves.easeOut,
            );
          }
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<InspectorViewModel>();

    return Container(
      color: Theme.of(context).colorScheme.surface,
      child: Column(
        children: [
          // Header
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
              border: Border(
                bottom: BorderSide(
                  color: Theme.of(context).dividerColor.withValues(alpha: 0.3),
                ),
              ),
            ),
            child: Row(
              children: [
                const Icon(Icons.auto_awesome, size: 16, color: Colors.purpleAccent),
                const SizedBox(width: 8),
                const Expanded(
                  child: Text(
                    'AI Assistant',
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                PopupMenuButton<LlmBackendMode>(
                  tooltip: 'Backend Model',
                  padding: EdgeInsets.zero,
                  icon: const Icon(Icons.tune, size: 16),
                  onSelected: (mode) {
                    setState(() {
                      _llmService.backendMode = mode;
                    });
                    if (mode != LlmBackendMode.deterministicLocal) {
                      _showBackendConfigDialog(context);
                    }
                  },
                  itemBuilder: (ctx) => [
                    PopupMenuItem(
                      value: LlmBackendMode.deterministicLocal,
                      child: Text(
                        '⚡ Deterministic (Offline Instant)',
                        style: TextStyle(
                          fontWeight: _llmService.backendMode == LlmBackendMode.deterministicLocal
                              ? FontWeight.bold
                              : FontWeight.normal,
                        ),
                      ),
                    ),
                    PopupMenuItem(
                      value: LlmBackendMode.geminiCloud,
                      child: Text(
                        '☁️ Cloud Google Gemini API',
                        style: TextStyle(
                          fontWeight: _llmService.backendMode == LlmBackendMode.geminiCloud
                              ? FontWeight.bold
                              : FontWeight.normal,
                        ),
                      ),
                    ),
                    PopupMenuItem(
                      value: LlmBackendMode.localGemma,
                      child: Text(
                        '💻 Local Gemma (Ollama / LAN)',
                        style: TextStyle(
                          fontWeight: _llmService.backendMode == LlmBackendMode.localGemma
                              ? FontWeight.bold
                              : FontWeight.normal,
                        ),
                      ),
                    ),
                  ],
                ),
                IconButton(
                  padding: EdgeInsets.zero,
                  visualDensity: VisualDensity.compact,
                  icon: const Icon(Icons.close, size: 16),
                  onPressed: () => vm.setAiPanelOpen(false),
                ),
              ],
            ),
          ),

          // Starter Prompt Chips
          Container(
            height: 38,
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            child: ListView(
              scrollDirection: Axis.horizontal,
              children: [
                _buildPromptChip('Show capture summary'),
                _buildPromptChip('Chart top talkers by bytes'),
                _buildPromptChip('Find timing spikes'),
                _buildPromptChip('Analyze unknown UDP ports'),
              ],
            ),
          ),
          const Divider(height: 1),

          // Messages
          Expanded(
            child: ListView.builder(
              controller: _scrollCtrl,
              padding: const EdgeInsets.all(12),
              itemCount: _llmService.history.length,
              itemBuilder: (context, index) {
                final msg = _llmService.history[index];
                return _buildMessageBubble(context, vm, msg);
              },
            ),
          ),

          if (_isSending)
            const Padding(
              padding: EdgeInsets.symmetric(vertical: 4),
              child: LinearProgressIndicator(minHeight: 2),
            ),

          // Input field
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
              border: Border(
                top: BorderSide(
                  color: Theme.of(context).dividerColor.withValues(alpha: 0.3),
                ),
              ),
            ),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _inputCtrl,
                    decoration: const InputDecoration(
                      hintText: 'Ask AI or command a filter...',
                      isDense: true,
                      border: OutlineInputBorder(),
                      contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                    ),
                    onSubmitted: (val) => _sendMessage(val),
                  ),
                ),
                const SizedBox(width: 8),
                IconButton.filled(
                  icon: const Icon(Icons.send, size: 16),
                  onPressed: _isSending ? null : () => _sendMessage(),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildPromptChip(String prompt) {
    return Padding(
      padding: const EdgeInsets.only(right: 6),
      child: ActionChip(
        label: Text(prompt, style: const TextStyle(fontSize: 10)),
        visualDensity: VisualDensity.compact,
        padding: EdgeInsets.zero,
        onPressed: _isSending ? null : () => _sendMessage(prompt),
      ),
    );
  }

  Widget _buildMessageBubble(
    BuildContext context,
    InspectorViewModel vm,
    ChatMessage msg,
  ) {
    final isUser = msg.role == 'user';

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Column(
        crossAxisAlignment: isUser ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: isUser
                  ? Theme.of(context).colorScheme.primaryContainer
                  : Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.6),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Text(
              msg.text,
              style: const TextStyle(fontSize: 12, height: 1.4),
            ),
          ),

          // GenUI Widget Slot (if any tool result attached)
          if (!isUser && msg.toolResult != null) ...[
            const SizedBox(height: 8),
            _buildGenUiWidget(context, vm, msg.toolResult!),
          ],
        ],
      ),
    );
  }

  Widget _buildGenUiWidget(
    BuildContext context,
    InspectorViewModel vm,
    AiToolResult result,
  ) {
    switch (result.widgetType) {
      case 'summary_card':
        return _buildSummaryCard(context, result);
      case 'top_talkers_chart':
        return _buildTopTalkersCard(context, vm, result);
      case 'timing_spikes_table':
        return _buildTimingSpikesCard(context, vm, result);
      case 'custom_protocol_suggestion':
        return _buildCustomProtocolSuggestionCard(context, vm, result);
      default:
        return const SizedBox.shrink();
    }
  }

  Widget _buildSummaryCard(BuildContext context, AiToolResult result) {
    final d = result.data;
    final protocols = (d['protocols'] as Map<String, int>?) ?? {};

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Theme.of(context).dividerColor),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Row(
            children: [
              Icon(Icons.pie_chart_outline, size: 16, color: Colors.blueAccent),
              SizedBox(width: 6),
              Expanded(
                child: Text('Capture Protocol Breakdown', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12)),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 6,
            runSpacing: 4,
            children: protocols.entries.map((e) {
              return Chip(
                label: Text('${e.key}: ${e.value}', style: const TextStyle(fontSize: 10)),
                visualDensity: VisualDensity.compact,
                padding: EdgeInsets.zero,
              );
            }).toList(),
          ),
        ],
      ),
    );
  }

  Widget _buildTopTalkersCard(BuildContext context, InspectorViewModel vm, AiToolResult result) {
    final talkers = (result.data['talkers'] as List<dynamic>?) ?? [];
    final metric = result.data['metric'] as String? ?? 'bytes';

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Theme.of(context).dividerColor),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              const Icon(Icons.bar_chart, size: 16, color: Colors.green),
              const SizedBox(width: 6),
              Expanded(
                child: Text(
                  'Top Conversations by ${metric.toUpperCase()}',
                  style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 12),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              TextButton.icon(
                icon: const Icon(Icons.download, size: 12),
                label: const Text('CSV', style: TextStyle(fontSize: 10)),
                onPressed: () {
                  final csv = CsvExportService.exportTableToCsv(
                    headers: ['Source IP', 'Dest IP', 'Protocol', 'Packets', 'Bytes'],
                    dataRows: talkers.map((t) => [t['src_ip'], t['dst_ip'], t['protocol'], t['packet_count'], t['total_bytes']]).toList(),
                  );
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Exported ${talkers.length} talkers to CSV (${csv.length} bytes)')),
                  );
                },
              ),
            ],
          ),
          const SizedBox(height: 6),
          ...talkers.map((t) => Padding(
                padding: const EdgeInsets.symmetric(vertical: 2),
                child: Row(
                  children: [
                    Expanded(
                      child: Text(
                        '${t['src_ip']} → ${t['dst_ip']}',
                        style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    Text(
                      '${t['total_bytes']} B',
                      style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
                    ),
                  ],
                ),
              )),
        ],
      ),
    );
  }

  Widget _buildTimingSpikesCard(BuildContext context, InspectorViewModel vm, AiToolResult result) {
    final spikes = (result.data['spikes'] as List<dynamic>?) ?? [];
    final isBurst = result.data['isBurst'] as bool? ?? true;

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Colors.redAccent.withValues(alpha: 0.5)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              const Icon(Icons.speed, size: 16, color: Colors.redAccent),
              const SizedBox(width: 6),
              Text(
                isBurst ? 'Traffic Burst Spikes' : 'Stream Latency Stalls',
                style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 12, color: Colors.redAccent),
              ),
            ],
          ),
          const SizedBox(height: 6),
          ...spikes.take(4).map((s) {
            final tsUs = s['timestampUs'] as int;
            final deltaMs = s['deltaMs'] as num;

            return Padding(
              padding: const EdgeInsets.symmetric(vertical: 3),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      'Pkt #${s['packetNo']} (${deltaMs.toStringAsFixed(3)}ms)',
                      style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
                    ),
                  ),
                  FilledButton.tonal(
                    style: FilledButton.styleFrom(
                      visualDensity: VisualDensity.compact,
                      padding: const EdgeInsets.symmetric(horizontal: 8),
                    ),
                    onPressed: () {
                      // Jump to spike on the main timeline!
                      final startUs = tsUs > 200000 ? tsUs - 200000 : 0;
                      final endUs = tsUs + 200000;
                      vm.setTimeRange(startUs, endUs);
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text('Timeline zoomed to spike at Packet #${s['packetNo']}!')),
                      );
                    },
                    child: const Text('Jump to Spike', style: TextStyle(fontSize: 10)),
                  ),
                ],
              ),
            );
          }),
        ],
      ),
    );
  }

  Widget _buildCustomProtocolSuggestionCard(
    BuildContext context,
    InspectorViewModel vm,
    AiToolResult result,
  ) {
    final d = result.data;
    final name = d['suggestedName'] as String? ?? 'Custom_Protocol';
    final port = d['port'] as int? ?? 45820;
    final magicHex = d['magicBytesHex'] as String? ?? '';
    final magicList = (d['magicBytesList'] as List<dynamic>?)?.map((e) => e as int).toList();

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.purple.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Colors.purpleAccent),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              const Icon(Icons.auto_fix_high, size: 16, color: Colors.purpleAccent),
              const SizedBox(width: 6),
              Text('Suggested: $name', style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 12)),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            'Port: UDP $port\nMagic Bytes: $magicHex (Offset 0)',
            style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
          ),
          const SizedBox(height: 8),
          FilledButton.icon(
            icon: const Icon(Icons.bookmark_add, size: 14),
            label: const Text('1-Click Save to Protocol Library', style: TextStyle(fontSize: 11)),
            onPressed: () {
              final rule = CustomProtocolRule(
                id: 'proto_${DateTime.now().millisecondsSinceEpoch}',
                name: name,
                colorHex: 0xFF9C27B0,
                defaultTriageStatus: TriageStatus.expected,
                ipProtocol: 17,
                port: port,
                magicBytesOffset: 0,
                magicBytesHex: magicList,
              );
              vm.addCustomProtocol(rule);
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('Custom protocol "$name" saved and capture re-labeled!'),
                  backgroundColor: Colors.purple,
                ),
              );
            },
          ),
        ],
      ),
    );
  }

  void _showBackendConfigDialog(BuildContext context) {
    final apiKeyCtrl = TextEditingController(text: _llmService.geminiApiKey);
    final ollamaUrlCtrl = TextEditingController(text: _llmService.ollamaUrl);
    final ollamaModelCtrl = TextEditingController(text: _llmService.ollamaModel);

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('AI Model Configuration'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (_llmService.backendMode == LlmBackendMode.geminiCloud) ...[
              const Text('Google Gemini Cloud API Settings:'),
              const SizedBox(height: 8),
              TextField(
                controller: apiKeyCtrl,
                obscureText: true,
                decoration: const InputDecoration(
                  labelText: 'Gemini API Key',
                  border: OutlineInputBorder(),
                  isDense: true,
                ),
              ),
            ] else ...[
              const Text('Local / LAN Gemma (Ollama / LM Studio):'),
              const SizedBox(height: 8),
              TextField(
                controller: ollamaUrlCtrl,
                decoration: const InputDecoration(
                  labelText: 'Endpoint URL',
                  hintText: 'http://localhost:11434',
                  border: OutlineInputBorder(),
                  isDense: true,
                ),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: ollamaModelCtrl,
                decoration: const InputDecoration(
                  labelText: 'Model Name',
                  hintText: 'gemma2:9b or gemma3:4b',
                  border: OutlineInputBorder(),
                  isDense: true,
                ),
              ),
            ],
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Close'),
          ),
          FilledButton(
            onPressed: () {
              setState(() {
                _llmService.geminiApiKey = apiKeyCtrl.text.trim();
                _llmService.ollamaUrl = ollamaUrlCtrl.text.trim();
                _llmService.ollamaModel = ollamaModelCtrl.text.trim();
              });
              Navigator.of(ctx).pop();
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );
  }
}
