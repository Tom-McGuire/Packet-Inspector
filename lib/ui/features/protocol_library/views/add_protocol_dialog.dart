import 'package:flutter/material.dart';
import '../../../../domain/models/custom_protocol_rule.dart';
import '../../../../domain/models/packet_record.dart';

class AddProtocolDialog extends StatefulWidget {
  const AddProtocolDialog({
    super.key,
    this.prefillPacket,
    this.prefillMagicOffset,
    this.prefillMagicHex,
  });

  final PacketRecord? prefillPacket;
  final int? prefillMagicOffset;
  final String? prefillMagicHex;

  @override
  State<AddProtocolDialog> createState() => _AddProtocolDialogState();
}

class _AddProtocolDialogState extends State<AddProtocolDialog> {
  late final TextEditingController _nameCtrl;
  late final TextEditingController _portCtrl;
  late final TextEditingController _magicOffsetCtrl;
  late final TextEditingController _magicHexCtrl;

  int _selectedIpProto = 17; // Default UDP
  PortMatchDirection _portDirection = PortMatchDirection.either;
  TriageStatus _defaultTriage = TriageStatus.expected;
  final int _colorHex = 0xFF9C27B0; // Default Purple

  final List<ProtocolFieldSlice> _fieldSlices = [];

  @override
  void initState() {
    super.initState();
    final p = widget.prefillPacket;
    _nameCtrl = TextEditingController(text: p != null ? 'Custom Proto ${p.detectedProtocol}' : 'My Custom Protocol');
    _portCtrl = TextEditingController(text: p?.srcPort?.toString() ?? p?.dstPort?.toString() ?? '45820');
    _magicOffsetCtrl = TextEditingController(text: (widget.prefillMagicOffset ?? 0).toString());
    _magicHexCtrl = TextEditingController(text: widget.prefillMagicHex ?? '');

    if (p != null && (p.ipProto == 6 || p.ipProto == 17)) {
      _selectedIpProto = p.ipProto;
    }
  }

  @override
  void dispose() {
    _nameCtrl.dispose();
    _portCtrl.dispose();
    _magicOffsetCtrl.dispose();
    _magicHexCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 600, maxHeight: 680),
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Row(
                children: [
                  CircleAvatar(
                    backgroundColor: Color(_colorHex),
                    radius: 12,
                  ),
                  const SizedBox(width: 12),
                  const Expanded(
                    child: Text(
                      'Add Custom Protocol to Library',
                      style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close),
                    onPressed: () => Navigator.of(context).pop(),
                  ),
                ],
              ),
              const Divider(height: 24),

              Expanded(
                child: ListView(
                  children: [
                    // Protocol Name & Color
                    TextField(
                      controller: _nameCtrl,
                      decoration: const InputDecoration(
                        labelText: 'Protocol Name',
                        hintText: 'e.g. ACME Sensor Telemetry',
                        border: OutlineInputBorder(),
                        isDense: true,
                      ),
                    ),
                    const SizedBox(height: 16),

                    // Tier 1: Transport & Port
                    const Text(
                      'Tier 1: Transport & Port Matching',
                      style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
                    ),
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        Expanded(
                          child: DropdownButtonFormField<int>(
                            initialValue: _selectedIpProto,
                            isExpanded: true,
                            decoration: const InputDecoration(
                              labelText: 'Transport',
                              border: OutlineInputBorder(),
                              isDense: true,
                              contentPadding: EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                            ),
                            items: const [
                              DropdownMenuItem(value: 17, child: Text('UDP (17)')),
                              DropdownMenuItem(value: 6, child: Text('TCP (6)')),
                            ],
                            onChanged: (val) {
                              if (val != null) setState(() => _selectedIpProto = val);
                            },
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: TextField(
                            controller: _portCtrl,
                            keyboardType: TextInputType.number,
                            decoration: const InputDecoration(
                              labelText: 'Port',
                              border: OutlineInputBorder(),
                              isDense: true,
                              contentPadding: EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                            ),
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: DropdownButtonFormField<PortMatchDirection>(
                            initialValue: _portDirection,
                            isExpanded: true,
                            decoration: const InputDecoration(
                              labelText: 'Direction',
                              border: OutlineInputBorder(),
                              isDense: true,
                              contentPadding: EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                            ),
                            items: const [
                              DropdownMenuItem(value: PortMatchDirection.either, child: Text('Either')),
                              DropdownMenuItem(value: PortMatchDirection.src, child: Text('Source')),
                              DropdownMenuItem(value: PortMatchDirection.dst, child: Text('Dest')),
                            ],
                            onChanged: (val) {
                              if (val != null) setState(() => _portDirection = val);
                            },
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),

                    // Tier 2: Magic Bytes
                    const Text(
                      'Tier 2: Fixed-Offset Magic Bytes (Optional)',
                      style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
                    ),
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        SizedBox(
                          width: 120,
                          child: TextField(
                            controller: _magicOffsetCtrl,
                            keyboardType: TextInputType.number,
                            decoration: const InputDecoration(
                              labelText: 'Byte Offset',
                              border: OutlineInputBorder(),
                              isDense: true,
                              contentPadding: EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                            ),
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: TextField(
                            controller: _magicHexCtrl,
                            decoration: const InputDecoration(
                              labelText: 'Magic Bytes (Hex or ASCII)',
                              hintText: 'e.g. 41 43 4D 45 or ACME',
                              border: OutlineInputBorder(),
                              isDense: true,
                              contentPadding: EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),

                    // Default Triage Status
                    Wrap(
                      crossAxisAlignment: WrapCrossAlignment.center,
                      spacing: 12,
                      runSpacing: 8,
                      children: [
                        const Text('Default Triage Classification: '),
                        DropdownButton<TriageStatus>(
                          value: _defaultTriage,
                          items: const [
                            DropdownMenuItem(value: TriageStatus.expected, child: Text('🟢 Expected')),
                            DropdownMenuItem(value: TriageStatus.unclassified, child: Text('🟡 Unclassified')),
                            DropdownMenuItem(value: TriageStatus.unexpected, child: Text('🔴 Unexpected')),
                          ],
                          onChanged: (val) {
                            if (val != null) setState(() => _defaultTriage = val);
                          },
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),

                    // Field Slices
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        const Text(
                          'Decoded Field Slices',
                          style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
                        ),
                        TextButton.icon(
                          icon: const Icon(Icons.add, size: 16),
                          label: const Text('Add Field Slice'),
                          onPressed: _showAddFieldSliceDialog,
                        ),
                      ],
                    ),
                    if (_fieldSlices.isEmpty)
                      const Text(
                        'No field slices configured yet. Field slices parse values at fixed offsets.',
                        style: TextStyle(fontSize: 12, color: Colors.grey),
                      )
                    else
                      ..._fieldSlices.map((slice) => ListTile(
                            dense: true,
                            title: Text(slice.name, style: const TextStyle(fontWeight: FontWeight.bold)),
                            subtitle: Text('Offset ${slice.byteOffset}, Len ${slice.byteLength} (${slice.dataType.displayName})'),
                            trailing: IconButton(
                              icon: const Icon(Icons.delete_outline, size: 18),
                              onPressed: () {
                                setState(() {
                                  _fieldSlices.remove(slice);
                                });
                              },
                            ),
                          )),
                  ],
                ),
              ),

              const SizedBox(height: 16),
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  OutlinedButton(
                    onPressed: () => Navigator.of(context).pop(),
                    child: const Text('Cancel'),
                  ),
                  const SizedBox(width: 12),
                  FilledButton(
                    onPressed: _saveRule,
                    child: const Text('Save & Re-label Capture'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showAddFieldSliceDialog() {
    final nameCtrl = TextEditingController();
    final offsetCtrl = TextEditingController(text: '0');
    final lenCtrl = TextEditingController(text: '2');
    FieldDataType dataType = FieldDataType.uint16Be;

    showDialog(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDialogState) => AlertDialog(
          title: const Text('Add Protocol Field Slice'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: nameCtrl,
                decoration: const InputDecoration(labelText: 'Field Name (e.g. CommandID)'),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: offsetCtrl,
                      keyboardType: TextInputType.number,
                      decoration: const InputDecoration(labelText: 'Offset'),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: TextField(
                      controller: lenCtrl,
                      keyboardType: TextInputType.number,
                      decoration: const InputDecoration(labelText: 'Length'),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              DropdownButtonFormField<FieldDataType>(
                initialValue: dataType,
                decoration: const InputDecoration(labelText: 'Data Type'),
                items: FieldDataType.values
                    .map((t) => DropdownMenuItem(value: t, child: Text(t.displayName)))
                    .toList(),
                onChanged: (v) {
                  if (v != null) setDialogState(() => dataType = v);
                },
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () {
                if (nameCtrl.text.trim().isNotEmpty) {
                  setState(() {
                    _fieldSlices.add(ProtocolFieldSlice(
                      name: nameCtrl.text.trim(),
                      byteOffset: int.tryParse(offsetCtrl.text) ?? 0,
                      byteLength: int.tryParse(lenCtrl.text) ?? 1,
                      dataType: dataType,
                    ));
                  });
                }
                Navigator.of(ctx).pop();
              },
              child: const Text('Add'),
            ),
          ],
        ),
      ),
    );
  }

  void _saveRule() {
    final name = _nameCtrl.text.trim();
    if (name.isEmpty) return;

    final port = int.tryParse(_portCtrl.text.trim());
    final magicOffset = int.tryParse(_magicOffsetCtrl.text.trim()) ?? 0;

    List<int>? magicBytes;
    final magicRaw = _magicHexCtrl.text.trim();
    if (magicRaw.isNotEmpty) {
      if (magicRaw.contains(' ') || RegExp(r'^[0-9a-fA-F]+$').hasMatch(magicRaw)) {
        // Parse hex tokens
        final clean = magicRaw.replaceAll(' ', '');
        magicBytes = <int>[];
        for (int i = 0; i + 1 < clean.length; i += 2) {
          final byte = int.tryParse(clean.substring(i, i + 2), radix: 16);
          if (byte != null) magicBytes.add(byte);
        }
      } else {
        // ASCII string
        magicBytes = magicRaw.codeUnits;
      }
    }

    final rule = CustomProtocolRule(
      id: 'proto_${DateTime.now().millisecondsSinceEpoch}',
      name: name,
      colorHex: _colorHex,
      defaultTriageStatus: _defaultTriage,
      ipProtocol: _selectedIpProto,
      port: port,
      portDirection: _portDirection,
      magicBytesOffset: magicOffset,
      magicBytesHex: magicBytes,
      fieldSlices: _fieldSlices,
    );

    Navigator.of(context).pop(rule);
  }
}
