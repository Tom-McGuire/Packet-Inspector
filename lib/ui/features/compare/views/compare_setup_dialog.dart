import 'dart:io';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:material_ui/material_ui.dart';
import 'package:provider/provider.dart';

import '../../../../core/theme/app_theme.dart';
import '../../../../data/services/diff/multi_capture_diff_engine.dart';
import '../../../../domain/models/custom_protocol_rule.dart';
import '../../inspector/view_models/inspector_view_model.dart';
import '../view_models/capture_compare_view_model.dart';

class CompareSetupDialog extends StatefulWidget {
  const CompareSetupDialog({super.key});

  @override
  State<CompareSetupDialog> createState() => _CompareSetupDialogState();
}

class _SlotEntry {
  _SlotEntry({required String defaultLabel})
      : labelController = TextEditingController(text: defaultLabel);

  final TextEditingController labelController;
  String? fileName;
  Uint8List? bytes;

  void dispose() {
    labelController.dispose();
  }
}

class _CompareSetupDialogState extends State<CompareSetupDialog> {
  static const List<String> _defaultLabels = [
    'Console Port (Baseline)',
    'FOH Switch Trunk',
    'Dimmer Rack Node',
    'Stage Endpoint',
  ];

  late final List<_SlotEntry> _slots = [
    _SlotEntry(defaultLabel: _defaultLabels[0]),
    _SlotEntry(defaultLabel: _defaultLabels[1]),
  ];

  bool _isBusy = false;
  String? _error;

  @override
  void dispose() {
    for (final slot in _slots) {
      slot.dispose();
    }
    super.dispose();
  }

  Future<void> _pickFileForSlot(int index) async {
    try {
      final files = await FilePicker.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['pcap', 'pcapng', 'cap'],
      );
      if (files.isEmpty) return;
      final file = files.first;
      Uint8List? data;
      if (file.path != null) {
        data = await File(file.path!).readAsBytes();
      } else {
        data = await file.readAsBytes();
      }
      if (data.isEmpty) {
        setState(() => _error = 'Could not read bytes from ${file.name}.');
        return;
      }
      setState(() {
        _slots[index].fileName = file.name;
        _slots[index].bytes = data;
        _error = null;
      });
    } catch (e) {
      setState(() => _error = 'File picker failed: $e');
    }
  }

  void _addSlot() {
    if (_slots.length >= 4) return;
    setState(() {
      _slots.add(_SlotEntry(defaultLabel: _defaultLabels[_slots.length]));
    });
  }

  void _removeSlot(int index) {
    if (_slots.length <= 2) return;
    setState(() {
      _slots[index].dispose();
      _slots.removeAt(index);
    });
  }

  List<CustomProtocolRule> _readCustomRules(BuildContext context) {
    final inspectorVm = Provider.of<InspectorViewModel?>(context, listen: false);
    return inspectorVm?.customRules ?? const [];
  }

  Future<void> _runComparison() async {
    final compareVm =
        Provider.of<CaptureCompareViewModel?>(context, listen: false);
    if (compareVm == null) return;

    final validSlots = _slots.where((s) => s.bytes != null).toList();
    if (validSlots.length < 2) {
      setState(
        () => _error = 'Select at least 2 PCAP/PCAPNG files to compare.',
      );
      return;
    }

    setState(() {
      _isBusy = true;
      _error = null;
    });

    final inputs = <CaptureSourceInput>[];
    for (var i = 0; i < _slots.length; i++) {
      final slot = _slots[i];
      if (slot.bytes == null) continue;
      final label = slot.labelController.text.trim().isEmpty
          ? 'Capture ${inputs.length + 1}'
          : slot.labelController.text.trim();
      inputs.add(
        CaptureSourceInput(
          label: label,
          filePath: slot.fileName ?? 'capture_${inputs.length + 1}.pcap',
          bytes: slot.bytes!,
        ),
      );
    }

    await compareVm.loadCaptures(
      inputs,
      customRules: _readCustomRules(context),
    );

    if (!mounted) return;
    if (compareVm.errorMessage != null) {
      setState(() {
        _isBusy = false;
        _error = compareVm.errorMessage;
      });
      return;
    }
    Navigator.of(context).pop(true);
  }

  Future<void> _loadDemoDiff() async {
    final compareVm =
        Provider.of<CaptureCompareViewModel?>(context, listen: false);
    if (compareVm == null) return;

    setState(() {
      _isBusy = true;
      _error = null;
    });

    await compareVm.loadDemoDiff(
      customRules: _readCustomRules(context),
    );

    if (!mounted) return;
    if (compareVm.errorMessage != null) {
      setState(() {
        _isBusy = false;
        _error = compareVm.errorMessage;
      });
      return;
    }
    Navigator.of(context).pop(true);
  }

  Color get _accentColor =>
      AppTheme.isDark ? const Color(0xFF38BDF8) : AppTheme.accent;

  @override
  Widget build(BuildContext context) {
    final readyCount = _slots.where((s) => s.bytes != null).length;

    return AlertDialog(
      backgroundColor: AppTheme.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: AppTheme.border),
      ),
      title: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(6),
            decoration: BoxDecoration(
              color: _accentColor.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Icon(
              Icons.compare_arrows_rounded,
              color: _accentColor,
              size: 18,
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Multi-Capture Diff & Path Comparison',
                  style: TextStyle(
                    fontSize: 15,
                    fontWeight: FontWeight.w700,
                    color: AppTheme.textPrimary,
                  ),
                ),
                Text(
                  'Correlate 2–4 PCAPs across hops to spot drops, DSCP/VLAN edits & jitter',
                  style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.normal,
                    color: AppTheme.textSecondary,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
      content: SizedBox(
        width: 580,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              for (var i = 0; i < _slots.length; i++) ...[
                _buildSlotCard(i),
                const SizedBox(height: 10),
              ],
              if (_slots.length < 4)
                Align(
                  alignment: Alignment.centerLeft,
                  child: TextButton.icon(
                    onPressed: _isBusy ? null : _addSlot,
                    icon: const Icon(Icons.add_rounded, size: 16),
                    label: Text('Add Hop (${_slots.length}/4)'),
                    style: TextButton.styleFrom(
                      foregroundColor: _accentColor,
                    ),
                  ),
                ),
              if (_error != null) ...[
                const SizedBox(height: 8),
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: AppTheme.error.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(6),
                    border: Border.all(
                      color: AppTheme.error.withValues(alpha: 0.35),
                    ),
                  ),
                  child: Text(
                    _error!,
                    style: TextStyle(
                      color: AppTheme.isDark
                          ? const Color(0xFFFCA5A5)
                          : AppTheme.error,
                      fontSize: 12,
                    ),
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
      actions: [
        TextButton.icon(
          onPressed: _isBusy ? null : _loadDemoDiff,
          icon: const Icon(Icons.auto_fix_high_rounded, size: 15),
          label: const Text('Load Synthetic Demo Diff'),
          style: TextButton.styleFrom(
            foregroundColor: AppTheme.warning,
          ),
        ),
        TextButton(
          onPressed: _isBusy ? null : () => Navigator.of(context).pop(false),
          child: Text(
            'Cancel',
            style: TextStyle(color: AppTheme.textSecondary),
          ),
        ),
        ElevatedButton.icon(
          onPressed: (_isBusy || readyCount < 2) ? null : _runComparison,
          icon: _isBusy
              ? const SizedBox(
                  width: 14,
                  height: 14,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: Colors.white,
                  ),
                )
              : const Icon(Icons.play_arrow_rounded, size: 16),
          label: Text(_isBusy ? 'Correlating...' : 'Compare ($readyCount Hops)'),
          style: ElevatedButton.styleFrom(
            backgroundColor: AppTheme.success,
            foregroundColor: Colors.white,
          ),
        ),
      ],
    );
  }

  Widget _buildSlotCard(int index) {
    final slot = _slots[index];
    final isBaseline = index == 0;
    final hasFile = slot.bytes != null;

    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: AppTheme.scaffoldBg,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: isBaseline
              ? _accentColor.withValues(alpha: 0.35)
              : AppTheme.border,
        ),
      ),
      child: Row(
        children: [
          Container(
            width: 28,
            height: 28,
            alignment: Alignment.center,
            decoration: BoxDecoration(
              color: isBaseline
                  ? _accentColor.withValues(alpha: 0.2)
                  : AppTheme.border,
              borderRadius: BorderRadius.circular(6),
            ),
            child: Text(
              isBaseline ? 'A' : String.fromCharCode(65 + index),
              style: TextStyle(
                fontWeight: FontWeight.w700,
                fontSize: 12,
                color: isBaseline ? _accentColor : AppTheme.textSecondary,
              ),
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            flex: 2,
            child: TextField(
              controller: slot.labelController,
              enabled: !_isBusy,
              style: TextStyle(color: AppTheme.textPrimary, fontSize: 12),
              decoration: InputDecoration(
                isDense: true,
                labelText: isBaseline ? 'Baseline Label' : 'Hop ${index + 1} Label',
                labelStyle: TextStyle(
                  color: AppTheme.textSecondary,
                  fontSize: 11,
                ),
                contentPadding: const EdgeInsets.symmetric(
                  horizontal: 10,
                  vertical: 8,
                ),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(6),
                  borderSide: BorderSide(color: AppTheme.border),
                ),
              ),
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            flex: 2,
            child: OutlinedButton.icon(
              onPressed: _isBusy ? null : () => _pickFileForSlot(index),
              icon: Icon(
                hasFile ? Icons.check_circle_rounded : Icons.folder_open_rounded,
                size: 14,
                color: hasFile ? AppTheme.success : AppTheme.textSecondary,
              ),
              label: Text(
                slot.fileName ?? 'Select PCAP...',
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontSize: 12,
                  color: hasFile
                      ? AppTheme.textPrimary
                      : AppTheme.textSecondary,
                ),
              ),
              style: OutlinedButton.styleFrom(
                side: BorderSide(
                  color: hasFile
                      ? AppTheme.success.withValues(alpha: 0.5)
                      : AppTheme.border,
                ),
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
              ),
            ),
          ),
          if (_slots.length > 2) ...[
            const SizedBox(width: 6),
            IconButton(
              onPressed: _isBusy ? null : () => _removeSlot(index),
              icon: const Icon(Icons.close_rounded, size: 16),
              color: AppTheme.textSecondary,
              tooltip: 'Remove hop',
              constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
              padding: EdgeInsets.zero,
            ),
          ],
        ],
      ),
    );
  }
}
