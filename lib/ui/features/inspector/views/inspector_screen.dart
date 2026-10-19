import 'dart:io';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:file_picker/file_picker.dart';
import '../view_models/inspector_view_model.dart';
import 'dual_mode_filter_bar.dart';
import 'timeline_spike_scrubber.dart';
import 'packet_table_view.dart';
import 'hex_byte_inspector.dart';

class InspectorScreen extends StatelessWidget {
  const InspectorScreen({super.key, this.aiPanelSlot});

  final Widget? aiPanelSlot;

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<InspectorViewModel>();

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 16,
        title: Row(
          children: [
            const Icon(Icons.radar, color: Colors.indigoAccent),
            const SizedBox(width: 10),
            const Text(
              'Packet Inspector',
              style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18),
            ),
            const SizedBox(width: 12),
            if (vm.loadedFileName != null)
              Flexible(
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.5),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.insert_drive_file_outlined, size: 14),
                      const SizedBox(width: 4),
                      Flexible(
                        child: Text(
                          vm.loadedFileName!,
                          style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      const SizedBox(width: 6),
                      Text(
                        '(${vm.totalPacketCount} pkts)',
                        style: const TextStyle(fontSize: 11, color: Colors.grey),
                      ),
                    ],
                  ),
                ),
              ),
          ],
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

          // AI Assistant Drawer Toggle
          FilledButton.icon(
            style: FilledButton.styleFrom(
              backgroundColor: vm.isAiPanelOpen ? Colors.purple : null,
            ),
            icon: const Icon(Icons.auto_awesome, size: 16),
            label: const Text('AI Assistant'),
            onPressed: () => vm.toggleAiPanel(),
          ),
          const SizedBox(width: 16),
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

                // Split: Packet Table (flex 5) & Hex Inspector (flex 4)
                Expanded(
                  child: Column(
                    children: [
                      const Expanded(
                        flex: 6,
                        child: PacketTableView(),
                      ),
                      const Divider(height: 1),
                      const Expanded(
                        flex: 4,
                        child: HexByteInspector(),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),

          // AI Assistant Panel
          if (vm.isAiPanelOpen && aiPanelSlot != null) ...[
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
        ],
      ),
    );
  }
}
