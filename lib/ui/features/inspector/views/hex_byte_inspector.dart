import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../../../domain/models/custom_protocol_rule.dart';
import '../view_models/inspector_view_model.dart';
import '../../protocol_library/views/add_protocol_dialog.dart';

class HexByteInspector extends StatefulWidget {
  const HexByteInspector({super.key});

  @override
  State<HexByteInspector> createState() => _HexByteInspectorState();
}

class _HexByteInspectorState extends State<HexByteInspector> {
  bool _showPayloadOnly = true;
  int? _selectedByteStart;
  int? _selectedByteEnd;

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<InspectorViewModel>();
    final packet = vm.selectedPacket;

    if (packet == null) {
      return Container(
        alignment: Alignment.center,
        color: Theme.of(context).colorScheme.surface,
        child: const Text('Select a packet from the table above to inspect raw bytes'),
      );
    }

    final bytes = _showPayloadOnly
        ? (vm.selectedPacketPayloadBytes ?? Uint8List(0))
        : (vm.selectedPacketRawBytes ?? Uint8List(0));

    // Custom fields if any
    final customFields = packet.customFields;

    return Container(
      color: Theme.of(context).colorScheme.surface,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Inspector Header
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
            color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
            child: Row(
              children: [
                const Icon(Icons.code, size: 16),
                const SizedBox(width: 8),
                Text(
                  'Packet #${packet.packetNo} Inspector (${bytes.length} bytes)',
                  style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 12),
                ),
                const SizedBox(width: 16),

                // View Toggle: Payload vs Full Frame
                SegmentedButton<bool>(
                  segments: const [
                    ButtonSegment(value: true, label: Text('L4 Payload', style: TextStyle(fontSize: 11))),
                    ButtonSegment(value: false, label: Text('Full Frame', style: TextStyle(fontSize: 11))),
                  ],
                  selected: {_showPayloadOnly},
                  onSelectionChanged: (set) {
                    setState(() {
                      _showPayloadOnly = set.first;
                      _selectedByteStart = null;
                      _selectedByteEnd = null;
                    });
                  },
                  style: const ButtonStyle(
                    visualDensity: VisualDensity.compact,
                    tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                  ),
                ),

                const Spacer(),

                // Use Selection as Magic Bytes Action Button
                if (_selectedByteStart != null && bytes.isNotEmpty) ...[
                  FilledButton.tonalIcon(
                    icon: const Icon(Icons.add_circle_outline, size: 14),
                    label: Text(
                      'Use Selection as Magic Bytes (Offset $_selectedByteStart)',
                      style: const TextStyle(fontSize: 11),
                    ),
                    onPressed: () => _openAddProtocolFromSelection(context, vm, bytes),
                  ),
                  const SizedBox(width: 8),
                  IconButton(
                    icon: const Icon(Icons.clear, size: 16),
                    tooltip: 'Clear selection',
                    onPressed: () {
                      setState(() {
                        _selectedByteStart = null;
                        _selectedByteEnd = null;
                      });
                    },
                  ),
                ],
              ],
            ),
          ),

          // Decoded Custom Protocol Fields Card (if matched)
          if (customFields.isNotEmpty)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              color: Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.3),
              child: Row(
                children: [
                  const Icon(Icons.auto_awesome, size: 16, color: Colors.purple),
                  const SizedBox(width: 8),
                  Text(
                    'Decoded ${packet.detectedProtocol} Fields: ',
                    style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 12),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Wrap(
                      spacing: 8,
                      children: customFields.entries.map((entry) {
                        return Chip(
                          label: Text(
                            '${entry.key}: ${entry.value}',
                            style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
                          ),
                          visualDensity: VisualDensity.compact,
                          padding: EdgeInsets.zero,
                        );
                      }).toList(),
                    ),
                  ),
                ],
              ),
            ),

          // Hex + ASCII Dump
          Expanded(
            child: bytes.isEmpty
                ? const Center(child: Text('No payload bytes available for this packet'))
                : _buildHexDump(context, bytes),
          ),
        ],
      ),
    );
  }

  Widget _buildHexDump(BuildContext context, Uint8List bytes) {
    const bytesPerRow = 16;
    final rowCount = (bytes.length / bytesPerRow).ceil();

    return ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: rowCount,
      itemBuilder: (context, rowIndex) {
        final rowOffset = rowIndex * bytesPerRow;
        final rowBytes = bytes.sublist(
          rowOffset,
          (rowOffset + bytesPerRow <= bytes.length) ? (rowOffset + bytesPerRow) : bytes.length,
        );

        return Padding(
          padding: const EdgeInsets.symmetric(vertical: 1.0),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              // Offset column
              SizedBox(
                width: 60,
                child: Text(
                  rowOffset.toRadixString(16).padLeft(4, '0'),
                  style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                    color: Theme.of(context).colorScheme.outline,
                  ),
                ),
              ),
              const SizedBox(width: 8),

              // Hex columns (8 bytes + gap + 8 bytes)
              Expanded(
                flex: 3,
                child: Row(
                  children: [
                    for (int i = 0; i < bytesPerRow; i++) ...[
                      if (i == 8) const SizedBox(width: 8),
                      if (i < rowBytes.length)
                        InkWell(
                          onTap: () => _handleByteTap(rowOffset + i),
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 2),
                            decoration: BoxDecoration(
                              color: _isByteSelected(rowOffset + i)
                                  ? Theme.of(context).colorScheme.primaryContainer
                                  : Colors.transparent,
                              borderRadius: BorderRadius.circular(2),
                            ),
                            child: Text(
                              rowBytes[i].toRadixString(16).padLeft(2, '0').toUpperCase(),
                              style: TextStyle(
                                fontFamily: 'monospace',
                                fontSize: 12,
                                fontWeight: _isByteSelected(rowOffset + i)
                                    ? FontWeight.bold
                                    : FontWeight.normal,
                              ),
                            ),
                          ),
                        )
                      else
                        const SizedBox(width: 20),
                      const SizedBox(width: 4),
                    ],
                  ],
                ),
              ),

              const SizedBox(width: 16),

              // ASCII column
              Expanded(
                flex: 2,
                child: Row(
                  children: [
                    for (int i = 0; i < rowBytes.length; i++)
                      Text(
                        (rowBytes[i] >= 32 && rowBytes[i] <= 126)
                            ? String.fromCharCode(rowBytes[i])
                            : '.',
                        style: TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 12,
                          color: _isByteSelected(rowOffset + i)
                              ? Theme.of(context).colorScheme.primary
                              : Theme.of(context).colorScheme.onSurface,
                          fontWeight: _isByteSelected(rowOffset + i)
                              ? FontWeight.bold
                              : FontWeight.normal,
                        ),
                      ),
                  ],
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  void _handleByteTap(int index) {
    setState(() {
      if (_selectedByteStart == null) {
        _selectedByteStart = index;
        _selectedByteEnd = index;
      } else if (_selectedByteStart == index && _selectedByteEnd == index) {
        _selectedByteStart = null;
        _selectedByteEnd = null;
      } else {
        if (index >= _selectedByteStart!) {
          _selectedByteEnd = index;
        } else {
          _selectedByteEnd = _selectedByteStart;
          _selectedByteStart = index;
        }
      }
    });
  }

  bool _isByteSelected(int index) {
    if (_selectedByteStart == null || _selectedByteEnd == null) return false;
    return index >= _selectedByteStart! && index <= _selectedByteEnd!;
  }

  void _openAddProtocolFromSelection(
    BuildContext context,
    InspectorViewModel vm,
    Uint8List bytes,
  ) async {
    final start = _selectedByteStart ?? 0;
    final end = _selectedByteEnd ?? start;
    final selectedSlice = bytes.sublist(start, end + 1);
    final hexString = selectedSlice.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ');

    final packet = vm.selectedPacket;
    int magicOffset = start;
    if (!_showPayloadOnly && packet != null && packet.payloadFileOffset > 0) {
      final payloadOffsetInPacket = packet.payloadFileOffset - packet.fileByteOffset;
      if (start >= payloadOffsetInPacket) {
        magicOffset = start - payloadOffsetInPacket;
      }
    }

    final rule = await showDialog<CustomProtocolRule>(
      context: context,
      builder: (ctx) => AddProtocolDialog(
        prefillPacket: packet,
        prefillMagicOffset: magicOffset,
        prefillMagicHex: hexString,
      ),
    );

    if (rule != null) {
      vm.addCustomProtocol(rule);
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Custom protocol "${rule.name}" added and capture re-labeled!'),
            backgroundColor: Colors.green,
          ),
        );
      }
    }
  }
}
