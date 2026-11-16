import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';
import 'package:material_ui/material_ui.dart';
import 'package:provider/provider.dart';
import 'package:file_picker/file_picker.dart';
import '../../compare/view_models/capture_compare_view_model.dart';
import '../../compare/views/compare_summary_bar.dart';
import '../../compare/views/diff_packet_table.dart';
import '../../compare/views/diff_timeline_scrubber.dart';
import '../../compare/views/hex_diff_inspector.dart';
import '../view_models/inspector_view_model.dart';
import 'dual_mode_filter_bar.dart';
import 'timeline_spike_scrubber.dart';
import 'packet_table_view.dart';
import 'hex_byte_inspector.dart';
import 'flagged_packets_panel.dart';
import 'inspector_top_control_bar.dart';
import '../../../../core/config/feature_flags.dart';

class InspectorScreen extends StatefulWidget {
  const InspectorScreen({
    super.key,
    this.aiPanelSlot,
    bool? showAiAssistant,
  }) : showAiAssistant = showAiAssistant ?? (aiPanelSlot != null && FeatureFlags.enableAiAssistant);

  final Widget? aiPanelSlot;
  final bool showAiAssistant;

  @override
  State<InspectorScreen> createState() => _InspectorScreenState();
}

class _InspectorScreenState extends State<InspectorScreen> {
  double _bottomPanelHeight = 280.0;

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<InspectorViewModel>();
    final compareVm = Provider.of<CaptureCompareViewModel?>(context);
    final isCompareMode = compareVm?.isCompareMode ?? false;

    return Scaffold(
      appBar: InspectorTopControlBar(
        showAiAssistant: widget.showAiAssistant && widget.aiPanelSlot != null,
        onOpenFile: () => _handleOpenFile(context, vm),
        onExportSelected: (val) {
          if (val == 'packets') {
            final csv = vm.exportFilteredPacketsCsv();
            _showCsvPreviewDialog(context, 'Filtered Packets CSV', csv);
          } else if (val == 'flows') {
            final csv = vm.exportFlowsCsv();
            _showCsvPreviewDialog(context, '5-Tuple Conversation Flows CSV', csv);
          }
        },
      ),
      body: Row(
        children: [
          // Main Workspace
          Expanded(
            flex: 3,
            child: isCompareMode
                ? Column(
                    children: [
                      const CompareSummaryBar(),
                      const DiffTimelineScrubber(),
                      Expanded(
                        child: Column(
                          children: [
                            const Expanded(child: DiffPacketTable()),
                            _buildResizeDivider(context),
                            SizedBox(
                              height: _bottomPanelHeight,
                              child: const HexDiffInspector(),
                            ),
                          ],
                        ),
                      ),
                    ],
                  )
                : Column(
                    children: [
                      // Top Dual-Mode Filter Bar
                      const DualModeFilterBar(),

                      // Synchronized Delta-Time Spike Scrubber
                      const TimelineSpikeScrubber(),

                      // When capture loaded: Split between Packet Table & Resizable Bottom Panel.
                      // When empty: Full workspace for Packet Table empty state.
                      Expanded(
                        child: vm.loadedFileName != null
                            ? Column(
                                children: [
                                  const Expanded(
                                    child: PacketTableView(),
                                  ),
                                  _buildResizeDivider(context),
                                  // Adjustable bottom section: Left half Hex Inspector, Right half Flagged Packets
                                  SizedBox(
                                    height: _bottomPanelHeight,
                                    child: const Row(
                                      crossAxisAlignment: CrossAxisAlignment.stretch,
                                      children: [
                                        Expanded(
                                          child: HexByteInspector(),
                                        ),
                                        VerticalDivider(width: 1),
                                        Expanded(
                                          child: FlaggedPacketsPanel(),
                                        ),
                                      ],
                                    ),
                                  ),
                                ],
                              )
                            : const PacketTableView(),
                      ),
                    ],
                  ),
          ),

          // AI Assistant Panel
          if (widget.showAiAssistant && vm.isAiPanelOpen && widget.aiPanelSlot != null) ...[
            const VerticalDivider(width: 1),
            SizedBox(
              width: 380,
              child: widget.aiPanelSlot!,
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildResizeDivider(BuildContext context) {
    return MouseRegion(
      cursor: SystemMouseCursors.resizeRow,
      child: GestureDetector(
        behavior: HitTestBehavior.translucent,
        onVerticalDragUpdate: (details) {
          setState(() {
            _bottomPanelHeight =
                (_bottomPanelHeight - details.delta.dy).clamp(120.0, 600.0);
          });
        },
        child: Container(
          height: 8,
          color: Theme.of(context).dividerColor.withValues(alpha: 0.15),
          child: Center(
            child: Container(
              width: 48,
              height: 3,
              decoration: BoxDecoration(
                color: Theme.of(context).dividerColor,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),
        ),
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
                    const SnackBar(content: Text('Saved CSV successfully!')),
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
