import 'package:flutter/material.dart';
import '../../../../domain/models/endpoint_rule.dart';

class AddEndpointDialog extends StatefulWidget {
  const AddEndpointDialog({
    super.key,
    required this.type,
    this.existingRule,
    this.prefillIp,
    this.prefillPort,
  });

  final EndpointType type;
  final EndpointRule? existingRule;
  final String? prefillIp;
  final int? prefillPort;

  @override
  State<AddEndpointDialog> createState() => _AddEndpointDialogState();
}

class _AddEndpointDialogState extends State<AddEndpointDialog> {
  late final TextEditingController _nameCtrl;
  late final TextEditingController _ipCtrl;
  late final TextEditingController _portCtrl;
  late int _selectedColorHex;

  static const List<int> _presetColors = [
    0xFF4CAF50, // Green
    0xFF2196F3, // Blue
    0xFF9C27B0, // Purple
    0xFFFF9800, // Orange
    0xFF00BCD4, // Cyan
    0xFFE91E63, // Pink
    0xFFFF5722, // Deep Orange
    0xFF607D8B, // Blue Grey
  ];

  @override
  void initState() {
    super.initState();
    final rule = widget.existingRule;
    final defaultName = widget.type == EndpointType.sender ? 'Source' : 'Destination';

    if (rule != null) {
      _nameCtrl = TextEditingController(text: rule.name);
      _ipCtrl = TextEditingController(text: rule.ipAddress);
      _portCtrl = TextEditingController(text: rule.port?.toString() ?? '');
      _selectedColorHex = rule.colorHex;
    } else {
      final ip = widget.prefillIp ?? '';
      _nameCtrl = TextEditingController(text: ip.isNotEmpty ? '$defaultName $ip' : defaultName);
      _ipCtrl = TextEditingController(text: ip);
      _portCtrl = TextEditingController(text: widget.prefillPort?.toString() ?? '');
      _selectedColorHex = widget.type == EndpointType.sender ? 0xFF2196F3 : 0xFF4CAF50;
    }
  }

  @override
  void dispose() {
    _nameCtrl.dispose();
    _ipCtrl.dispose();
    _portCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final typeName = widget.type == EndpointType.sender ? 'Source' : 'Destination';
    final isEditing = widget.existingRule != null;

    return Dialog(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 480),
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Header
              Row(
                children: [
                  CircleAvatar(
                    backgroundColor: Color(_selectedColorHex),
                    radius: 12,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      isEditing ? 'Edit $typeName' : 'Add $typeName to Library',
                      style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close),
                    onPressed: () => Navigator.of(context).pop(),
                  ),
                ],
              ),
              const Divider(height: 24),

              // Name Field
              TextField(
                controller: _nameCtrl,
                decoration: InputDecoration(
                  labelText: '$typeName Name / Alias',
                  hintText: widget.type == EndpointType.sender
                      ? 'e.g. Lighting Console, Sensor Gateway'
                      : 'e.g. DMX Node 1, Multicast Group',
                  border: const OutlineInputBorder(),
                  isDense: true,
                ),
              ),
              const SizedBox(height: 16),

              // IP & Port Fields
              Row(
                children: [
                  Expanded(
                    flex: 3,
                    child: TextField(
                      controller: _ipCtrl,
                      decoration: const InputDecoration(
                        labelText: 'IP Address',
                        hintText: 'e.g. 192.168.1.10',
                        border: OutlineInputBorder(),
                        isDense: true,
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    flex: 2,
                    child: TextField(
                      controller: _portCtrl,
                      keyboardType: TextInputType.number,
                      decoration: const InputDecoration(
                        labelText: 'Port (Optional)',
                        hintText: 'e.g. 57313',
                        border: OutlineInputBorder(),
                        isDense: true,
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 16),

              // Color Preset Selector
              const Text('Color Badge', style: TextStyle(fontWeight: FontWeight.w500, fontSize: 13)),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                children: _presetColors.map((colorHex) {
                  final isSelected = _selectedColorHex == colorHex;
                  return InkWell(
                    borderRadius: BorderRadius.circular(16),
                    onTap: () => setState(() => _selectedColorHex = colorHex),
                    child: Container(
                      width: 32,
                      height: 32,
                      decoration: BoxDecoration(
                        color: Color(colorHex),
                        shape: BoxShape.circle,
                        border: Border.all(
                          color: isSelected ? Colors.white : Colors.transparent,
                          width: 2.5,
                        ),
                        boxShadow: isSelected
                            ? [
                                BoxShadow(
                                  color: Colors.black.withAlpha(80),
                                  blurRadius: 4,
                                  spreadRadius: 1,
                                )
                              ]
                            : null,
                      ),
                      child: isSelected
                          ? const Icon(Icons.check, size: 16, color: Colors.white)
                          : null,
                    ),
                  );
                }).toList(),
              ),
              const SizedBox(height: 24),

              // Bottom Actions
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  OutlinedButton(
                    onPressed: () => Navigator.of(context).pop(),
                    child: const Text('Cancel'),
                  ),
                  const SizedBox(width: 12),
                  FilledButton(
                    onPressed: _saveEndpoint,
                    child: Text(isEditing ? 'Save Changes' : 'Add $typeName'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _saveEndpoint() {
    final name = _nameCtrl.text.trim();
    final ip = _ipCtrl.text.trim();
    if (name.isEmpty || ip.isEmpty) return;

    final port = int.tryParse(_portCtrl.text.trim());

    final rule = EndpointRule(
      id: widget.existingRule?.id ?? 'ep_${DateTime.now().millisecondsSinceEpoch}',
      name: name,
      ipAddress: ip,
      port: port,
      colorHex: _selectedColorHex,
      type: widget.type,
      isVisible: widget.existingRule?.isVisible ?? true,
    );

    Navigator.of(context).pop(rule);
  }
}
