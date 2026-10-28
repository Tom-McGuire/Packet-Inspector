import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:provider/provider.dart';
import '../../../../domain/models/custom_protocol_rule.dart';
import '../../../../domain/models/packet_record.dart';
import '../../../features/inspector/view_models/inspector_view_model.dart';
import '../../../../data/services/ai/packet_ai_tools.dart';
import '../../../../data/services/ai/llm_provider_service.dart';
import '../../../../data/services/export/csv_export_service.dart';

class AiAssistantPanel extends StatefulWidget {
  const AiAssistantPanel({super.key, this.llmService});

  final LlmProviderService? llmService;

  @override
  State<AiAssistantPanel> createState() => _AiAssistantPanelState();
}

class _AiAssistantPanelState extends State<AiAssistantPanel> {
  late final LlmProviderService _llmService;
  final TextEditingController _inputCtrl = TextEditingController();
  final ScrollController _scrollCtrl = ScrollController();
  bool _isSending = false;

  String? _activeTriggerType; // 'p', 's', or 'r'
  String _activeTriggerQuery = '';
  int _triggerStartIndex = -1;

  @override
  void initState() {
    super.initState();
    final vm = context.read<InspectorViewModel>();
    _llmService = widget.llmService ?? vm.llmService;
    _inputCtrl.addListener(_onInputChanged);

    // Add welcome message with /p, /s, /r guidance only once
    if (_llmService.history.isEmpty) {
      _llmService.history.add(ChatMessage(
        role: 'assistant',
        text: '👋 Welcome to **Packet Inspector AI**!\n\n'
            'I can summarize your capture, hunt for timing spikes, chart top talkers, or generate specific reports on your custom library.\n\n'
            '💡 **Filter Mentions**: Type `/p` for protocols, `/s` for sources, or `/d` for destinations (or use the chips below) to reference specific items!',
      ));
    }
  }

  @override
  void dispose() {
    _inputCtrl.removeListener(_onInputChanged);
    _inputCtrl.dispose();
    _scrollCtrl.dispose();
    super.dispose();
  }

  void _onInputChanged() {
    final text = _inputCtrl.text;
    final selection = _inputCtrl.selection;
    if (!selection.isValid || selection.baseOffset < 0) {
      if (_activeTriggerType != null) {
        setState(() => _activeTriggerType = null);
      }
      return;
    }

    final cursor = selection.baseOffset;
    final textBeforeCursor = text.substring(0, cursor);

    // Look for /p, /s, /d, or /r token right before cursor
    final match = RegExp(r'(?:^|\s)(/[psrd])([^\s]*)$', caseSensitive: false).firstMatch(textBeforeCursor);
    if (match != null) {
      final trigger = match.group(1)!.toLowerCase(); // '/p', '/s', '/d', '/r'
      final rawQuery = match.group(2) ?? '';
      final query = rawQuery.startsWith(':') ? rawQuery.substring(1) : rawQuery;
      final rawType = trigger.substring(1);
      final triggerType = rawType == 'r' ? 'd' : rawType;
      final rawStart = match.start;
      final startIdx = textBeforeCursor[rawStart] == ' ' ? rawStart + 1 : rawStart;

      setState(() {
        _activeTriggerType = triggerType;
        _activeTriggerQuery = query.replaceAll('"', '').toLowerCase();
        _triggerStartIndex = startIdx;
      });
    } else {
      if (_activeTriggerType != null) {
        setState(() => _activeTriggerType = null);
      }
    }
  }

  void _insertReference(String tag, String value) {
    final token = value.contains(' ') ? '/$tag:"$value" ' : '/$tag:$value ';
    final text = _inputCtrl.text;

    if (_triggerStartIndex >= 0 && _triggerStartIndex <= text.length) {
      final cursor = _inputCtrl.selection.isValid ? _inputCtrl.selection.baseOffset : text.length;
      final before = text.substring(0, _triggerStartIndex);
      final after = cursor <= text.length ? text.substring(cursor) : '';
      final newText = '$before$token$after';
      _inputCtrl.value = TextEditingValue(
        text: newText,
        selection: TextSelection.collapsed(offset: before.length + token.length),
      );
    } else {
      final cursor = _inputCtrl.selection.isValid ? _inputCtrl.selection.baseOffset : text.length;
      final before = text.substring(0, cursor);
      final after = text.substring(cursor);
      final newText = '$before$token$after';
      _inputCtrl.value = TextEditingValue(
        text: newText,
        selection: TextSelection.collapsed(offset: before.length + token.length),
      );
    }

    setState(() {
      _activeTriggerType = null;
      _triggerStartIndex = -1;
    });
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
                      _llmService.saveSettings();
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

          // Autocomplete suggestion overlay if user is typing /p, /s, or /r
          if (_activeTriggerType != null)
            _buildAutocompleteOverlay(context, vm),

          // Filter reference shortcut helper chips (/p, /s, /r)
          _buildReferenceHelperBar(context, vm),

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
                      hintText: 'Ask AI or filter by /p, /s, /r...',
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
      case 'filtered_library_report':
        return _buildFilteredReportCard(context, vm, result);
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
                  _saveCsvFile(context, 'top_conversations.csv', csv);
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
    final geminiModelCtrl = TextEditingController(text: _llmService.geminiModel);
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
                  helperText: '🔒 Encrypted at rest (machine-bound)',
                ),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: geminiModelCtrl,
                decoration: const InputDecoration(
                  labelText: 'Gemini Model',
                  hintText: 'gemini-3.8-flash',
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
                _llmService.geminiModel = geminiModelCtrl.text.trim().isNotEmpty
                    ? geminiModelCtrl.text.trim()
                    : 'gemini-3.8-flash';
                _llmService.ollamaUrl = ollamaUrlCtrl.text.trim();
                _llmService.ollamaModel = ollamaModelCtrl.text.trim();
                _llmService.saveSettings();
              });
              Navigator.of(ctx).pop();
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('AI settings and encrypted key saved.'),
                  duration: Duration(seconds: 2),
                ),
              );
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );
  }

  Future<void> _saveCsvFile(BuildContext context, String defaultName, String csvContent) async {
    try {
      final uri = await FilePicker.saveFile(
        dialogTitle: 'Save CSV File',
        fileName: defaultName,
        bytes: Uint8List.fromList(utf8.encode(csvContent)),
      );

      if (uri != null && context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Saved CSV successfully!')),
        );
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to save file: $e'), backgroundColor: Colors.red),
        );
      }
    }
  }

  Widget _buildReferenceHelperBar(BuildContext context, InspectorViewModel vm) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Row(
          children: [
            const Text('Filters: ', style: TextStyle(fontSize: 10, color: Colors.grey)),
            ActionChip(
              avatar: const Icon(Icons.tune, size: 11, color: Colors.indigoAccent),
              label: const Text('/p Protocol', style: TextStyle(fontSize: 10)),
              visualDensity: VisualDensity.compact,
              padding: EdgeInsets.zero,
              onPressed: () {
                setState(() {
                  _activeTriggerType = 'p';
                  _activeTriggerQuery = '';
                  _triggerStartIndex = _inputCtrl.selection.isValid ? _inputCtrl.selection.baseOffset : _inputCtrl.text.length;
                });
              },
            ),
            const SizedBox(width: 4),
            ActionChip(
              avatar: const Icon(Icons.arrow_upward, size: 11, color: Colors.blueAccent),
              label: const Text('/s Source', style: TextStyle(fontSize: 10)),
              visualDensity: VisualDensity.compact,
              padding: EdgeInsets.zero,
              onPressed: () {
                setState(() {
                  _activeTriggerType = 's';
                  _activeTriggerQuery = '';
                  _triggerStartIndex = _inputCtrl.selection.isValid ? _inputCtrl.selection.baseOffset : _inputCtrl.text.length;
                });
              },
            ),
            const SizedBox(width: 4),
            ActionChip(
              avatar: const Icon(Icons.arrow_downward, size: 11, color: Colors.greenAccent),
              label: const Text('/d Destination', style: TextStyle(fontSize: 10)),
              visualDensity: VisualDensity.compact,
              padding: EdgeInsets.zero,
              onPressed: () {
                setState(() {
                  _activeTriggerType = 'd';
                  _activeTriggerQuery = '';
                  _triggerStartIndex = _inputCtrl.selection.isValid ? _inputCtrl.selection.baseOffset : _inputCtrl.text.length;
                });
              },
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildAutocompleteOverlay(BuildContext context, InspectorViewModel vm) {
    final type = _activeTriggerType!;
    final query = _activeTriggerQuery;

    final String title;
    final IconData icon;
    final Color color;
    final List<Widget> items = [];

    if (type == 'p') {
      title = 'Select Protocol (/p)';
      icon = Icons.tune;
      color = Colors.indigoAccent;

      final matchingCustom = vm.customRules
          .where((r) => r.name.toLowerCase().contains(query))
          .toList();
      for (final r in matchingCustom) {
        items.add(Material(
          type: MaterialType.transparency,
          child: ListTile(
            dense: true,
            visualDensity: VisualDensity.compact,
            leading: CircleAvatar(radius: 6, backgroundColor: Color(r.colorHex)),
            title: Text(r.name, style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
            subtitle: Text(
              '${r.ipProtocol == 6 ? "TCP" : (r.ipProtocol == 17 ? "UDP" : "IP")} Port ${r.port ?? "*"}',
              style: const TextStyle(fontSize: 10),
            ),
            onTap: () => _insertReference('p', r.name),
          ),
        ));
      }

      final standardProtos = vm.protocolCounts.keys
          .where((name) => !vm.customRules.any((r) => r.name == name) && name.toLowerCase().contains(query))
          .toList();
      for (final name in standardProtos) {
        final count = vm.protocolCounts[name] ?? 0;
        items.add(Material(
          type: MaterialType.transparency,
          child: ListTile(
            dense: true,
            visualDensity: VisualDensity.compact,
            leading: const Icon(Icons.stream, size: 14, color: Colors.grey),
            title: Text(name, style: const TextStyle(fontSize: 12)),
            subtitle: Text('$count packets', style: const TextStyle(fontSize: 10)),
            onTap: () => _insertReference('p', name),
          ),
        ));
      }
    } else if (type == 's') {
      title = 'Select Source (/s)';
      icon = Icons.arrow_upward;
      color = Colors.blueAccent;

      final matchingSenders = vm.senders
          .where((s) => s.name.toLowerCase().contains(query) || s.ipAddress.contains(query))
          .toList();
      for (final s in matchingSenders) {
        items.add(Material(
          type: MaterialType.transparency,
          child: ListTile(
            dense: true,
            visualDensity: VisualDensity.compact,
            leading: CircleAvatar(radius: 6, backgroundColor: Color(s.colorHex)),
            title: Text(s.name, style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
            subtitle: Text(s.port != null ? '${s.ipAddress}:${s.port}' : s.ipAddress, style: const TextStyle(fontSize: 10)),
            onTap: () => _insertReference('s', s.filterKey),
          ),
        ));
      }

      final discoveredSenders = vm.senderCounts.keys
          .where((ip) => !vm.senders.any((s) => s.ipAddress == ip || s.filterKey == ip) && ip.contains(query))
          .take(10)
          .toList();
      for (final ip in discoveredSenders) {
        final count = vm.senderCounts[ip] ?? 0;
        items.add(Material(
          type: MaterialType.transparency,
          child: ListTile(
            dense: true,
            visualDensity: VisualDensity.compact,
            leading: const Icon(Icons.arrow_upward, size: 14, color: Colors.grey),
            title: Text(ip, style: const TextStyle(fontSize: 12)),
            subtitle: Text('$count pkts sent', style: const TextStyle(fontSize: 10)),
            onTap: () => _insertReference('s', ip),
          ),
        ));
      }
    } else {
      title = 'Select Destination (/d)';
      icon = Icons.arrow_downward;
      color = Colors.greenAccent;

      final matchingReceivers = vm.receivers
          .where((r) => r.name.toLowerCase().contains(query) || r.ipAddress.contains(query))
          .toList();
      for (final r in matchingReceivers) {
        items.add(Material(
          type: MaterialType.transparency,
          child: ListTile(
            dense: true,
            visualDensity: VisualDensity.compact,
            leading: CircleAvatar(radius: 6, backgroundColor: Color(r.colorHex)),
            title: Text(r.name, style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
            subtitle: Text(r.port != null ? '${r.ipAddress}:${r.port}' : r.ipAddress, style: const TextStyle(fontSize: 10)),
            onTap: () => _insertReference('d', r.filterKey),
          ),
        ));
      }

      final discoveredReceivers = vm.receiverCounts.keys
          .where((ip) => !vm.receivers.any((r) => r.ipAddress == ip || r.filterKey == ip) && ip.contains(query))
          .take(10)
          .toList();
      for (final ip in discoveredReceivers) {
        final count = vm.receiverCounts[ip] ?? 0;
        items.add(Material(
          type: MaterialType.transparency,
          child: ListTile(
            dense: true,
            visualDensity: VisualDensity.compact,
            leading: const Icon(Icons.arrow_downward, size: 14, color: Colors.grey),
            title: Text(ip, style: const TextStyle(fontSize: 12)),
            subtitle: Text('$count pkts received', style: const TextStyle(fontSize: 10)),
            onTap: () => _insertReference('d', ip),
          ),
        ));
      }
    }

    return Container(
      constraints: const BoxConstraints(maxHeight: 180),
      margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withValues(alpha: 0.6)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.2),
            blurRadius: 6,
            offset: const Offset(0, -2),
          ),
        ],
      ),
      child: Material(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(8),
        clipBehavior: Clip.antiAlias,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.15),
              ),
              child: Row(
                children: [
                  Icon(icon, size: 14, color: color),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Text(
                      title,
                      style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: color),
                    ),
                  ),
                  InkWell(
                    onTap: () => setState(() => _activeTriggerType = null),
                    child: const Icon(Icons.close, size: 14),
                  ),
                ],
              ),
            ),
            Flexible(
              child: items.isEmpty
                  ? const Padding(
                      padding: EdgeInsets.all(12.0),
                      child: Text('No matching items found', style: TextStyle(fontSize: 11, color: Colors.grey)),
                    )
                  : ListView.separated(
                      shrinkWrap: true,
                      itemCount: items.length,
                      separatorBuilder: (_, _) => const Divider(height: 1),
                      itemBuilder: (_, idx) => items[idx],
                    ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFilteredReportCard(
    BuildContext context,
    InspectorViewModel vm,
    AiToolResult result,
  ) {
    final d = result.data;
    final matchingCount = d['matchingPacketCount'] as int? ?? 0;
    final percentage = d['percentage'] as String? ?? '0.0';
    final totalBytes = d['totalBytes'] as int? ?? 0;
    final timeSpan = (d['timeSpan'] as num?)?.toDouble() ?? 0.0;
    final protocols = (d['protocols'] as List<dynamic>? ?? []).map((e) => e.toString()).toList();
    final senders = (d['senders'] as List<dynamic>? ?? []).map((e) => e.toString()).toList();
    final receivers = (d['receivers'] as List<dynamic>? ?? []).map((e) => e.toString()).toList();
    final samplePackets = (d['samplePackets'] as List<dynamic>? ?? []);

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Colors.indigoAccent.withValues(alpha: 0.6)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              const Icon(Icons.analytics_outlined, size: 16, color: Colors.indigoAccent),
              const SizedBox(width: 6),
              const Expanded(
                child: Text(
                  'Filtered Traffic Report',
                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12),
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: Colors.indigoAccent.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Text(
                  '$percentage% of capture',
                  style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Colors.indigoAccent),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),

          // High-level metrics
          Row(
            children: [
              Expanded(
                child: Container(
                  padding: const EdgeInsets.all(6),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.4),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text('Packets', style: TextStyle(fontSize: 10, color: Colors.grey)),
                      Text('$matchingCount', style: const TextStyle(fontSize: 13, fontWeight: FontWeight.bold)),
                    ],
                  ),
                ),
              ),
              const SizedBox(width: 6),
              Expanded(
                child: Container(
                  padding: const EdgeInsets.all(6),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.4),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text('Volume', style: TextStyle(fontSize: 10, color: Colors.grey)),
                      Text('${(totalBytes / 1024).toStringAsFixed(1)} KB', style: const TextStyle(fontSize: 13, fontWeight: FontWeight.bold)),
                    ],
                  ),
                ),
              ),
              const SizedBox(width: 6),
              Expanded(
                child: Container(
                  padding: const EdgeInsets.all(6),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.4),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text('Active Span', style: TextStyle(fontSize: 10, color: Colors.grey)),
                      Text('${timeSpan.toStringAsFixed(2)}s', style: const TextStyle(fontSize: 13, fontWeight: FontWeight.bold)),
                    ],
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),

          // Referenced Tags
          Wrap(
            spacing: 4,
            runSpacing: 4,
            children: [
              ...protocols.map((p) => Chip(
                    avatar: const Icon(Icons.tune, size: 10, color: Colors.purpleAccent),
                    label: Text('/p:$p', style: const TextStyle(fontSize: 10)),
                    visualDensity: VisualDensity.compact,
                    padding: EdgeInsets.zero,
                  )),
              ...senders.map((s) => Chip(
                    avatar: const Icon(Icons.arrow_upward, size: 10, color: Colors.blueAccent),
                    label: Text('/s:$s', style: const TextStyle(fontSize: 10)),
                    visualDensity: VisualDensity.compact,
                    padding: EdgeInsets.zero,
                  )),
              ...receivers.map((r) => Chip(
                    avatar: const Icon(Icons.arrow_downward, size: 10, color: Colors.greenAccent),
                    label: Text('/d:$r', style: const TextStyle(fontSize: 10)),
                    visualDensity: VisualDensity.compact,
                    padding: EdgeInsets.zero,
                  )),
            ],
          ),

          // Sample Packets list
          if (samplePackets.isNotEmpty) ...[
            const SizedBox(height: 8),
            const Text('Sample Packets:', style: TextStyle(fontSize: 10, color: Colors.grey, fontWeight: FontWeight.bold)),
            const SizedBox(height: 4),
            ...samplePackets.take(3).map((p) => Padding(
                  padding: const EdgeInsets.symmetric(vertical: 2),
                  child: Row(
                    children: [
                      Text('#${p['packetNo']}', style: const TextStyle(fontSize: 10, fontFamily: 'monospace', color: Colors.indigoAccent)),
                      const SizedBox(width: 6),
                      Expanded(
                        child: Text(
                          '${p['srcIp']} → ${p['dstIp']} (${p['protocol']})',
                          style: const TextStyle(fontSize: 10, fontFamily: 'monospace'),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ],
                  ),
                )),
          ],

          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(
                child: FilledButton.icon(
                  icon: const Icon(Icons.filter_alt, size: 14),
                  label: const Text('Apply to Filter Bar', style: TextStyle(fontSize: 11)),
                  onPressed: () {
                    vm.applyQuickFilters(
                      protocols: protocols.toSet(),
                      senders: senders.toSet(),
                      receivers: receivers.toSet(),
                    );
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text('Applied $matchingCount filtered packets to main screen!')),
                    );
                  },
                ),
              ),
              const SizedBox(width: 6),
              OutlinedButton.icon(
                icon: const Icon(Icons.download, size: 14),
                label: const Text('CSV', style: TextStyle(fontSize: 11)),
                onPressed: () {
                  final csv = CsvExportService.exportTableToCsv(
                    headers: ['Packet #', 'Time (s)', 'Source IP', 'Dest IP', 'Protocol', 'Summary'],
                    dataRows: samplePackets.map((p) => [
                      p['packetNo'],
                      p['timestampSeconds'],
                      '${p['srcIp']}:${p['srcPort'] ?? ""}',
                      '${p['dstIp']}:${p['dstPort'] ?? ""}',
                      p['protocol'],
                      p['summary'],
                    ]).toList(),
                  );
                  _saveCsvFile(context, 'filtered_report_packets.csv', csv);
                },
              ),
            ],
          ),
        ],
      ),
    );
  }
}
