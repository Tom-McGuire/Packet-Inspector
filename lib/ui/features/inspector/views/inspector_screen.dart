import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:file_picker/file_picker.dart';
import '../view_models/inspector_view_model.dart';
import 'dual_mode_filter_bar.dart';
import 'timeline_spike_scrubber.dart';
import 'packet_table_view.dart';
import 'hex_byte_inspector.dart';
import '../../protocol_library/views/custom_library_dialog.dart';
import '../../../../core/config/feature_flags.dart';

class InspectorScreen extends StatelessWidget {
  const InspectorScreen({
    super.key,
    this.aiPanelSlot,
    bool? showAiAssistant,
  }) : showAiAssistant = showAiAssistant ?? (aiPanelSlot != null && FeatureFlags.enableAiAssistant);

  final Widget? aiPanelSlot;
  final bool showAiAssistant;

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<InspectorViewModel>();

    return Scaffold(
      appBar: AppBar(
        centerTitle: false,
        titleSpacing: 16,
        title: FittedBox(
          fit: BoxFit.scaleDown,
          alignment: Alignment.centerLeft,
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.radar, color: Colors.indigoAccent),
              const SizedBox(width: 8),
              const Text(
                'Packet Inspector',
                style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18),
              ),
              if (vm.loadedFileName != null) ...[
                const SizedBox(width: 8),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.5),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.insert_drive_file_outlined, size: 14),
                      const SizedBox(width: 4),
                      Text(
                        vm.loadedFileName!,
                        style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
                      ),
                    ],
                  ),
                ),
              ],
            ],
          ),
        ),
        actions: [
          // Open PCAP / PCAPNG Button
          FilledButton.tonalIcon(
            icon: const Icon(Icons.folder_open, size: 16),
            label: const Text('Open PCAP'),
            onPressed: () => _handleOpenFile(context, vm),
          ),
          const SizedBox(width: 8),

          // Load Demo Capture
          OutlinedButton.icon(
            icon: const Icon(Icons.play_circle_outline, size: 16),
            label: const Text('Load Demo'),
            onPressed: () => vm.loadDemoCapture(),
          ),
          const SizedBox(width: 8),

          // Custom Library Button
          OutlinedButton.icon(
            icon: const Icon(Icons.menu_book, size: 16),
            label: const Text('Custom Library'),
            onPressed: () => showDialog(
              context: context,
              builder: (ctx) => CustomLibraryDialog(viewModel: vm),
            ),
          ),
          const SizedBox(width: 8),

          // Export CSV Dropdown
          PopupMenuButton<String>(
            tooltip: 'Export CSV',
            child: const Padding(
              padding: EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              child: Row(
                children: [
                  Icon(Icons.download, size: 16),
                  SizedBox(width: 6),
                  Text('Export CSV', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w500)),
                  Icon(Icons.arrow_drop_down, size: 16),
                ],
              ),
            ),
            onSelected: (val) {
              if (val == 'packets') {
                final csv = vm.exportFilteredPacketsCsv();
                _showCsvPreviewDialog(context, 'Filtered Packets CSV', csv);
              } else if (val == 'flows') {
                final csv = vm.exportFlowsCsv();
                _showCsvPreviewDialog(context, '5-Tuple Conversation Flows CSV', csv);
              }
            },
            itemBuilder: (ctx) => const [
              PopupMenuItem(
                value: 'packets',
                child: Row(
                  children: [
                    Icon(Icons.table_rows_outlined, size: 16),
                    SizedBox(width: 8),
                    Text('Export Filtered Packets'),
                  ],
                ),
              ),
              PopupMenuItem(
                value: 'flows',
                child: Row(
                  children: [
                    Icon(Icons.swap_horiz, size: 16),
                    SizedBox(width: 8),
                    Text('Export 5-Tuple Flows'),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(width: 8),

          // AI Assistant Drawer Toggle (controlled by build flag / showAiAssistant)
          if (showAiAssistant && aiPanelSlot != null) ...[
            FilledButton.icon(
              style: FilledButton.styleFrom(
                backgroundColor: vm.isAiPanelOpen ? Colors.purple : null,
              ),
              icon: const Icon(Icons.auto_awesome, size: 16),
              label: const Text('AI Assistant'),
              onPressed: () => vm.toggleAiPanel(),
            ),
            const SizedBox(width: 8),
          ],
          const SizedBox(width: 8),
        ],
      ),
      body: Row(
        children: [
          // Main Workspace
          Expanded(
            flex: 3,
            child: Column(
              children: [
                // Top Dual-Mode Filter Bar
                const DualModeFilterBar(),

                // Synchronized Delta-Time Spike Scrubber
                const TimelineSpikeScrubber(),

                // When capture loaded: Split between Packet Table & Hex Inspector.
                // When empty: Full workspace for Packet Table empty state.
                Expanded(
                  child: vm.loadedFileName != null
                      ? const Column(
                          children: [
                            Expanded(
                              flex: 6,
                              child: PacketTableView(),
                            ),
                            Divider(height: 1),
                            Expanded(
                              flex: 4,
                              child: HexByteInspector(),
                            ),
                          ],
                        )
                      : const PacketTableView(),
                ),
              ],
            ),
          ),

          // AI Assistant Panel
          if (showAiAssistant && vm.isAiPanelOpen && aiPanelSlot != null) ...[
            const VerticalDivider(width: 1),
            SizedBox(
              width: 380,
              child: aiPanelSlot!,
            ),
          ],
        ],
      ),
    );
  }

  void _handleOpenFile(BuildContext context, InspectorViewModel vm) async {
    try {
      final files = await FilePicker.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['pcap', 'pcapng', 'cap'],
      );

      if (files.isNotEmpty) {
        final path = files.first.path;
        final name = files.first.name;

        if (path != null) {
          vm.loadFile(File(path));
        } else {
          final bytes = await files.first.readAsBytes();
          vm.loadBytes(bytes, name);
        }
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to open file: $e'), backgroundColor: Colors.red),
        );
      }
    }
  }

  void _showCsvPreviewDialog(BuildContext context, String title, String csvContent) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: SizedBox(
          width: 600,
          height: 350,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                'Generated ${csvContent.split('\n').length} rows (${csvContent.length} bytes)',
                style: const TextStyle(fontSize: 12, color: Colors.grey),
              ),
              const SizedBox(height: 8),
              Expanded(
                child: Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: Colors.black87,
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: SingleChildScrollView(
                    child: Text(
                      csvContent,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        color: Colors.lightGreenAccent,
                        fontSize: 11,
                      ),
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Close'),
          ),
          FilledButton.icon(
            icon: const Icon(Icons.save_alt, size: 16),
            label: const Text('Save CSV to File'),
            onPressed: () async {
              try {
                final defaultFileName = '${title.toLowerCase().replaceAll(' ', '_')}.csv';
                final uri = await FilePicker.saveFile(
                  dialogTitle: 'Save CSV File',
                  fileName: defaultFileName,
                  bytes: Uint8List.fromList(utf8.encode(csvContent)),
                );

                if (uri != null && context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Saved CSV successfully!')),
                  );
                  Navigator.of(ctx).pop();
                }
              } catch (e) {
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Failed to save file: $e'), backgroundColor: Colors.red),
                  );
                }
              }
            },
          ),
        ],
      ),
    );
  }
}
