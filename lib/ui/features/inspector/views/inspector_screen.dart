import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';
import 'dart:ui' show AppExitResponse;
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:file_picker/file_picker.dart';
import '../view_models/inspector_view_model.dart';
import '../../capture/view_models/capture_view_model.dart';
import '../../capture/views/capture_dialog.dart';
import '../../../../domain/models/capture_config.dart';
import 'dual_mode_filter_bar.dart';
import 'timeline_spike_scrubber.dart';
import 'packet_table_view.dart';
import 'hex_byte_inspector.dart';
import '../../protocol_library/views/custom_library_dialog.dart';

class InspectorScreen extends StatefulWidget {
  const InspectorScreen({super.key, this.aiPanelSlot});

  final Widget? aiPanelSlot;

  @override
  State<InspectorScreen> createState() => _InspectorScreenState();
}

class _InspectorScreenState extends State<InspectorScreen> with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  Future<AppExitResponse> didRequestAppExit() async {
    final captureVm = Provider.of<CaptureViewModel?>(context, listen: false);
    if (captureVm == null || !captureVm.isCapturing) {
      return AppExitResponse.exit;
    }

    final mode = captureVm.activeSession?.mode ?? CaptureMode.quick;

    if (mode == CaptureMode.quick) {
      final shouldExit = await showDialog<bool>(
        context: context,
        barrierDismissible: false,
        builder: (ctx) => AlertDialog(
          title: const Row(
            children: [
              Icon(Icons.warning_amber_rounded, color: Colors.orangeAccent),
              SizedBox(width: 8),
              Text('Capture In Progress'),
            ],
          ),
          content: const Text(
            'A Quick Capture is currently active.\n\n'
            'Closing Packet Inspector will stop and finalize this capture file.\n\n'
            'Do you want to stop the capture and exit?',
          ),
          actions: [
            OutlinedButton(
              onPressed: () => Navigator.of(ctx).pop(false),
              child: const Text('Cancel (Keep App Open)'),
            ),
            FilledButton(
              style: FilledButton.styleFrom(backgroundColor: Colors.redAccent),
              onPressed: () => Navigator.of(ctx).pop(true),
              child: const Text('Stop Capture & Exit'),
            ),
          ],
        ),
      );

      if (shouldExit == true) {
        await captureVm.stopCapture();
        return AppExitResponse.exit;
      } else {
        return AppExitResponse.cancel;
      }
    } else {
      final action = await showDialog<String>(
        context: context,
        barrierDismissible: false,
        builder: (ctx) => AlertDialog(
          title: const Row(
            children: [
              Icon(Icons.hourglass_top_rounded, color: Colors.blueAccent),
              SizedBox(width: 8),
              Text('Background Capture Active'),
            ],
          ),
          content: const Text(
            'A Timed or Ring Buffer capture is currently running.\n\n'
            'You can let TShark continue capturing in the background after closing this window, '
            'or stop the capture now.',
          ),
          actions: [
            OutlinedButton(
              onPressed: () => Navigator.of(ctx).pop('cancel'),
              child: const Text('Cancel'),
            ),
            OutlinedButton(
              onPressed: () => Navigator.of(ctx).pop('stop'),
              child: const Text('Stop Capture & Exit'),
            ),
            FilledButton(
              onPressed: () => Navigator.of(ctx).pop('detach'),
              child: const Text('Leave Running in Background'),
            ),
          ],
        ),
      );

      if (action == 'stop') {
        await captureVm.stopCapture();
        return AppExitResponse.exit;
      } else if (action == 'detach') {
        return AppExitResponse.exit;
      } else {
        return AppExitResponse.cancel;
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<InspectorViewModel>();
    final captureVm = Provider.of<CaptureViewModel?>(context);

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
          // TShark Capture Button
          if (captureVm != null) ...[
            _buildCaptureButton(context, captureVm),
            const SizedBox(width: 8),
          ],

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
          if (vm.isAiPanelOpen && widget.aiPanelSlot != null) ...[
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

  Widget _buildCaptureButton(BuildContext context, CaptureViewModel? captureVm) {
    if (captureVm == null) {
      return const SizedBox.shrink();
    }
    if (captureVm.isCapturing) {
      return FilledButton.icon(
        style: FilledButton.styleFrom(
          backgroundColor: Colors.red.shade900,
          foregroundColor: Colors.white,
          side: const BorderSide(color: Colors.redAccent, width: 1.5),
        ),
        icon: const Icon(Icons.fiber_manual_record, color: Colors.redAccent, size: 16),
        label: Text(
          'Capturing (${captureVm.formatDuration(captureVm.elapsed)})',
          style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
        ),
        onPressed: () => showDialog(
          context: context,
          builder: (_) => const CaptureDialog(),
        ),
      );
    }

    return OutlinedButton.icon(
      icon: Icon(
        Icons.sensors,
        size: 16,
        color: captureVm.hasTShark ? Colors.indigoAccent : Colors.grey,
      ),
      label: const Text('Capture'),
      onPressed: () => showDialog(
        context: context,
        builder: (_) => const CaptureDialog(),
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
