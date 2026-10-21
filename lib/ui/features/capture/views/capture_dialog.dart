import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:file_picker/file_picker.dart';
import '../../../../domain/models/capture_config.dart';
import '../view_models/capture_view_model.dart';

class CaptureDialog extends StatefulWidget {
  const CaptureDialog({super.key});

  @override
  State<CaptureDialog> createState() => _CaptureDialogState();
}

class _CaptureDialogState extends State<CaptureDialog> {
  final _hoursController = TextEditingController();
  final _minutesController = TextEditingController();
  final _filesController = TextEditingController();
  final _prefixController = TextEditingController();

  @override
  void initState() {
    super.initState();
    final vm = context.read<CaptureViewModel>();
    _hoursController.text = vm.hours.toString();
    _minutesController.text = vm.minutes.toString();
    _filesController.text = vm.ringFiles.toString();
    _prefixController.text = vm.filePrefix;
  }

  @override
  void dispose() {
    _hoursController.dispose();
    _minutesController.dispose();
    _filesController.dispose();
    _prefixController.dispose();
    super.dispose();
  }

  Future<void> _pickFolder(CaptureViewModel vm) async {
    final selectedDirectory = await FilePicker.getDirectoryPath(
      dialogTitle: 'Select Capture Storage Directory',
      initialDirectory: vm.outputDirectory.isNotEmpty ? vm.outputDirectory : null,
    );
    if (selectedDirectory != null && selectedDirectory.isNotEmpty) {
      vm.setOutputDirectory(selectedDirectory);
    }
  }

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<CaptureViewModel>();
    final isCapturing = vm.isCapturing;

    return Dialog(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 580, maxHeight: 720),
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Header
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: isCapturing
                          ? Colors.redAccent.withValues(alpha: 0.15)
                          : Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.4),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Icon(
                      isCapturing ? Icons.radio_button_checked : Icons.sensors,
                      color: isCapturing ? Colors.redAccent : Theme.of(context).colorScheme.primary,
                      size: 24,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          isCapturing ? 'Capture In Progress' : 'TShark Packet Capture',
                          style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                        ),
                        Text(
                          isCapturing
                              ? 'Active since ${vm.formatDuration(vm.elapsed)}'
                              : (vm.hasTShark ? 'TShark Engine Ready' : 'TShark Not Found'),
                          style: TextStyle(
                            fontSize: 12,
                            color: isCapturing
                                ? Colors.redAccent
                                : (vm.hasTShark ? Colors.greenAccent : Colors.orangeAccent),
                          ),
                        ),
                      ],
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close, size: 20),
                    onPressed: () => Navigator.of(context).pop(),
                  ),
                ],
              ),
              const Divider(height: 24),

              // Reconnected or Error banners
              if (vm.reconnectedNotice != null) ...[
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                  decoration: BoxDecoration(
                    color: Colors.blue.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: Colors.blueAccent.withValues(alpha: 0.3)),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.info_outline, color: Colors.blueAccent, size: 18),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          vm.reconnectedNotice!,
                          style: const TextStyle(fontSize: 12),
                        ),
                      ),
                      IconButton(
                        icon: const Icon(Icons.close, size: 16),
                        onPressed: () => vm.clearNotice(),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 12),
              ],

              if (vm.lastError != null) ...[
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                  decoration: BoxDecoration(
                    color: Colors.red.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: Colors.redAccent.withValues(alpha: 0.3)),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.error_outline, color: Colors.redAccent, size: 18),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          vm.lastError!,
                          style: const TextStyle(fontSize: 12, color: Colors.redAccent),
                        ),
                      ),
                      IconButton(
                        icon: const Icon(Icons.close, size: 16),
                        onPressed: () => vm.clearError(),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 12),
              ],

              // Missing TShark Banner
              if (!vm.hasTShark) ...[
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Colors.amber.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: Colors.amber.withValues(alpha: 0.3)),
                  ),
                  child: const Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Icon(Icons.warning_amber_rounded, color: Colors.amber),
                          SizedBox(width: 8),
                          Text(
                            'Wireshark / TShark not detected',
                            style: TextStyle(fontWeight: FontWeight.bold),
                          ),
                        ],
                      ),
                      SizedBox(height: 8),
                      Text(
                        'Packet Inspector uses TShark (Wireshark command-line) to capture live traffic. Please ensure Wireshark/TShark is installed and added to your system PATH or installed in the default directory.',
                        style: TextStyle(fontSize: 13),
                      ),
                    ],
                  ),
                ),
                const Spacer(),
                Align(
                  alignment: Alignment.centerRight,
                  child: OutlinedButton(
                    onPressed: () => Navigator.of(context).pop(),
                    child: const Text('Close'),
                  ),
                ),
              ] else if (isCapturing) ...[
                // ACTIVE CAPTURE VIEW
                Expanded(
                  child: SingleChildScrollView(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Container(
                          padding: const EdgeInsets.all(16),
                          decoration: BoxDecoration(
                            color: Colors.red.withValues(alpha: 0.08),
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(color: Colors.redAccent.withValues(alpha: 0.3)),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Row(
                                children: [
                                  const Icon(Icons.circle, color: Colors.redAccent, size: 12),
                                  const SizedBox(width: 8),
                                  Text(
                                    'RECORDING [ ${vm.formatDuration(vm.elapsed)} ]',
                                    style: const TextStyle(
                                      fontWeight: FontWeight.bold,
                                      letterSpacing: 1.2,
                                      color: Colors.redAccent,
                                    ),
                                  ),
                                  const Spacer(),
                                  Text(
                                    'PID ${vm.activeSession?.pid ?? 0}',
                                    style: TextStyle(
                                      fontSize: 12,
                                      color: Colors.grey.shade400,
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 12),
                              _buildDetailRow('Interface', vm.activeSession?.interfaceName ?? '-'),
                              const SizedBox(height: 6),
                              _buildDetailRow('Mode', vm.activeSession?.mode.displayName ?? '-'),
                              const SizedBox(height: 6),
                              _buildDetailRow('Output Folder', vm.activeSession?.outputDirectory ?? '-'),
                            ],
                          ),
                        ),
                        const SizedBox(height: 16),
                        OutlinedButton.icon(
                          icon: const Icon(Icons.folder_open, size: 18),
                          label: const Text('Open Output Folder in Explorer'),
                          onPressed: () => vm.openOutputFolder(),
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                Row(
                  children: [
                    OutlinedButton(
                      onPressed: () => Navigator.of(context).pop(),
                      child: const Text('Keep in Background & Close Window'),
                    ),
                    const Spacer(),
                    FilledButton.icon(
                      style: FilledButton.styleFrom(
                        backgroundColor: Colors.redAccent,
                        foregroundColor: Colors.white,
                      ),
                      icon: const Icon(Icons.stop),
                      label: const Text('Stop Capture'),
                      onPressed: vm.isLoading
                          ? null
                          : () async {
                              await vm.stopCapture();
                              if (context.mounted) {
                                Navigator.of(context).pop();
                              }
                            },
                    ),
                  ],
                ),
              ] else ...[
                // INACTIVE / CONFIGURATION VIEW
                Expanded(
                  child: SingleChildScrollView(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        // 1. Interface Dropdown
                        Row(
                          children: [
                            const Text(
                              'Capture Interface',
                              style: TextStyle(fontWeight: FontWeight.w600, fontSize: 13),
                            ),
                            const Spacer(),
                            IconButton(
                              icon: const Icon(Icons.refresh, size: 18),
                              tooltip: 'Refresh Interfaces',
                              onPressed: () => vm.refreshInterfaces(),
                            ),
                          ],
                        ),
                        const SizedBox(height: 4),
                        DropdownButtonFormField<CaptureInterface>(
                          value: vm.selectedInterface,
                          isExpanded: true,
                          decoration: InputDecoration(
                            isDense: true,
                            contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                            border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
                          ),
                          items: vm.interfaces.map((iface) {
                            return DropdownMenuItem(
                              value: iface,
                              child: Text(
                                iface.displayName,
                                overflow: TextOverflow.ellipsis,
                                style: const TextStyle(fontSize: 13),
                              ),
                            );
                          }).toList(),
                          onChanged: (val) => vm.setSelectedInterface(val),
                        ),
                        const SizedBox(height: 16),

                        // 2. Storage Destination
                        const Text(
                          'Storage Destination',
                          style: TextStyle(fontWeight: FontWeight.w600, fontSize: 13),
                        ),
                        const SizedBox(height: 6),
                        Row(
                          children: [
                            Expanded(
                              child: Container(
                                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                                decoration: BoxDecoration(
                                  borderRadius: BorderRadius.circular(8),
                                  border: Border.all(color: Theme.of(context).dividerColor),
                                ),
                                child: Text(
                                  vm.outputDirectory.isNotEmpty ? vm.outputDirectory : 'No directory selected',
                                  style: TextStyle(
                                    fontSize: 12,
                                    color: vm.outputDirectory.isNotEmpty
                                        ? null
                                        : Theme.of(context).hintColor,
                                  ),
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                            ),
                            const SizedBox(width: 8),
                            OutlinedButton.icon(
                              icon: const Icon(Icons.folder_open, size: 16),
                              label: const Text('Browse...'),
                              onPressed: () => _pickFolder(vm),
                            ),
                          ],
                        ),
                        const SizedBox(height: 6),
                        CheckboxListTile(
                          contentPadding: EdgeInsets.zero,
                          dense: true,
                          title: const Text(
                            'Create dedicated session subfolder',
                            style: TextStyle(fontSize: 13),
                          ),
                          subtitle: const Text(
                            'Generates a new timestamped folder for each capture run',
                            style: TextStyle(fontSize: 11),
                          ),
                          value: vm.createSubfolder,
                          onChanged: (val) => vm.setCreateSubfolder(val ?? true),
                          controlAffinity: ListTileControlAffinity.leading,
                        ),
                        const Divider(height: 20),

                        // 3. Quick Capture
                        CheckboxListTile(
                          contentPadding: EdgeInsets.zero,
                          dense: true,
                          title: const Text(
                            'Start Quick Capture',
                            style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
                          ),
                          subtitle: const Text(
                            'Captures continuously until stopped. Stops automatically on app close.',
                            style: TextStyle(fontSize: 12),
                          ),
                          value: vm.isQuickCapture,
                          onChanged: (val) => vm.setQuickCapture(val ?? true),
                          controlAffinity: ListTileControlAffinity.leading,
                        ),

                        // 4. Timed & Ring Buffer Section
                        AnimatedOpacity(
                          opacity: vm.isQuickCapture ? 0.35 : 1.0,
                          duration: const Duration(milliseconds: 200),
                          child: IgnorePointer(
                            ignoring: vm.isQuickCapture,
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const SizedBox(height: 8),
                                const Text(
                                  'Duration / Rollover Interval',
                                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 13),
                                ),
                                const SizedBox(height: 6),
                                Row(
                                  children: [
                                    Expanded(
                                      child: TextField(
                                        controller: _hoursController,
                                        keyboardType: TextInputType.number,
                                        decoration: InputDecoration(
                                          labelText: 'Hours',
                                          isDense: true,
                                          border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
                                        ),
                                        onChanged: (val) {
                                          final parsed = int.tryParse(val) ?? 0;
                                          vm.setHours(parsed);
                                        },
                                      ),
                                    ),
                                    const SizedBox(width: 12),
                                    Expanded(
                                      child: TextField(
                                        controller: _minutesController,
                                        keyboardType: TextInputType.number,
                                        decoration: InputDecoration(
                                          labelText: 'Minutes',
                                          isDense: true,
                                          border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
                                        ),
                                        onChanged: (val) {
                                          final parsed = int.tryParse(val) ?? 10;
                                          vm.setMinutes(parsed);
                                        },
                                      ),
                                    ),
                                  ],
                                ),
                                const SizedBox(height: 12),

                                // Ring Buffer Option
                                CheckboxListTile(
                                  contentPadding: EdgeInsets.zero,
                                  dense: true,
                                  title: const Text(
                                    'Enable Ring Buffer',
                                    style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
                                  ),
                                  subtitle: const Text(
                                    'Rolls over to a new file every [Hours/Minutes] and keeps up to N files',
                                    style: TextStyle(fontSize: 11),
                                  ),
                                  value: vm.isRingBuffer,
                                  onChanged: (val) => vm.setRingBuffer(val ?? false),
                                  controlAffinity: ListTileControlAffinity.leading,
                                ),

                                if (vm.isRingBuffer) ...[
                                  const SizedBox(height: 6),
                                  Row(
                                    children: [
                                      const SizedBox(width: 32),
                                      const Text('Max files retained: ', style: TextStyle(fontSize: 13)),
                                      const SizedBox(width: 8),
                                      SizedBox(
                                        width: 80,
                                        child: TextField(
                                          controller: _filesController,
                                          keyboardType: TextInputType.number,
                                          decoration: InputDecoration(
                                            isDense: true,
                                            contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                                            border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
                                          ),
                                          onChanged: (val) {
                                            final parsed = int.tryParse(val) ?? 5;
                                            vm.setRingFiles(parsed);
                                          },
                                        ),
                                      ),
                                    ],
                                  ),
                                ],
                              ],
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),

                // Bottom Action Buttons
                Row(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    OutlinedButton(
                      onPressed: () => Navigator.of(context).pop(),
                      child: const Text('Cancel'),
                    ),
                    const SizedBox(width: 12),
                    FilledButton.icon(
                      icon: const Icon(Icons.play_arrow),
                      label: const Text('Start Capture'),
                      onPressed: vm.isLoading
                          ? null
                          : () async {
                              final success = await vm.startCapture();
                              if (success && context.mounted) {
                                Navigator.of(context).pop();
                              }
                            },
                    ),
                  ],
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildDetailRow(String label, String value) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 90,
          child: Text(
            label,
            style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Colors.grey),
          ),
        ),
        Expanded(
          child: Text(
            value,
            style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }
}
