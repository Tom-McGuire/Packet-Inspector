import 'package:flutter/material.dart';
import '../../../../domain/models/custom_protocol_rule.dart';
import '../../../../domain/models/packet_record.dart';
import '../../inspector/view_models/inspector_view_model.dart';
import 'add_protocol_dialog.dart';

class ProtocolLibraryDialog extends StatefulWidget {
  const ProtocolLibraryDialog({
    super.key,
    required this.viewModel,
  });

  final InspectorViewModel viewModel;

  @override
  State<ProtocolLibraryDialog> createState() => _ProtocolLibraryDialogState();
}

class _ProtocolLibraryDialogState extends State<ProtocolLibraryDialog> {
  @override
  Widget build(BuildContext context) {
    final vm = widget.viewModel;
    final rules = vm.customRules;

    return Dialog(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 720, maxHeight: 600),
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Header
              Row(
                children: [
                  const Icon(Icons.tune, size: 24, color: Colors.indigoAccent),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'Custom Protocol Library',
                          style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                        ),
                        Text(
                          '${rules.length} custom protocol${rules.length == 1 ? '' : 's'} configured',
                          style: const TextStyle(fontSize: 12, color: Colors.grey),
                        ),
                      ],
                    ),
                  ),
                  FilledButton.icon(
                    icon: const Icon(Icons.add, size: 16),
                    label: const Text('Add Protocol'),
                    onPressed: () async {
                      final newRule = await showDialog<CustomProtocolRule>(
                        context: context,
                        builder: (ctx) => const AddProtocolDialog(),
                      );
                      if (newRule != null) {
                        vm.addCustomProtocol(newRule);
                        setState(() {});
                      }
                    },
                  ),
                  const SizedBox(width: 8),
                  IconButton(
                    icon: const Icon(Icons.close),
                    onPressed: () => Navigator.of(context).pop(),
                  ),
                ],
              ),
              const Divider(height: 24),

              // Rules List
              Expanded(
                child: rules.isEmpty
                    ? Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(Icons.extension_off_outlined, size: 48, color: Colors.grey[400]),
                            const SizedBox(height: 12),
                            const Text(
                              'No custom protocols defined yet.',
                              style: TextStyle(fontSize: 14, fontWeight: FontWeight.w500),
                            ),
                            const SizedBox(height: 4),
                            const Text(
                              'Define custom protocols using port and magic byte matching.',
                              style: TextStyle(fontSize: 12, color: Colors.grey),
                            ),
                          ],
                        ),
                      )
                    : ListView.separated(
                        itemCount: rules.length,
                        separatorBuilder: (_, __) => const SizedBox(height: 8),
                        itemBuilder: (context, index) {
                          final rule = rules[index];
                          final hasMagic = rule.magicBytesHex != null && rule.magicBytesHex!.isNotEmpty;
                          final magicHexStr = hasMagic
                              ? rule.magicBytesHex!.map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase()).join(' ')
                              : null;
                          final protoName = rule.ipProtocol == 6
                              ? 'TCP'
                              : rule.ipProtocol == 17
                                  ? 'UDP'
                                  : 'IP ${rule.ipProtocol ?? "*"}';

                          return Card(
                            elevation: 0,
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(8),
                              side: BorderSide(color: Colors.grey.withAlpha(50)),
                            ),
                            child: Padding(
                              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                              child: Row(
                                crossAxisAlignment: CrossAxisAlignment.center,
                                children: [
                                  CircleAvatar(
                                    radius: 14,
                                    backgroundColor: Color(rule.colorHex),
                                  ),
                                  const SizedBox(width: 14),
                                  Expanded(
                                    child: Column(
                                      crossAxisAlignment: CrossAxisAlignment.start,
                                      children: [
                                        Row(
                                          children: [
                                            Flexible(
                                              child: Text(
                                                rule.name,
                                                style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
                                                overflow: TextOverflow.ellipsis,
                                              ),
                                            ),
                                            const SizedBox(width: 8),
                                            _buildTriageChip(rule.defaultTriageStatus),
                                            const SizedBox(width: 6),
                                            Container(
                                              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                              decoration: BoxDecoration(
                                                color: Colors.blueGrey.withAlpha(30),
                                                borderRadius: BorderRadius.circular(4),
                                              ),
                                              child: Text(
                                                'Priority ${rule.specificityScore}',
                                                style: TextStyle(fontSize: 10, color: Colors.blueGrey[700]),
                                              ),
                                            ),
                                          ],
                                        ),
                                        const SizedBox(height: 4),
                                        Wrap(
                                          spacing: 12,
                                          runSpacing: 4,
                                          children: [
                                            Text(
                                              '$protoName port ${rule.port ?? "*"} (${rule.portDirection.name})',
                                              style: const TextStyle(fontSize: 12, color: Colors.grey),
                                            ),
                                            if (hasMagic)
                                              Text(
                                                'Offset ${rule.magicBytesOffset}: [0x$magicHexStr]',
                                                style: const TextStyle(
                                                  fontSize: 12,
                                                  fontFamily: 'monospace',
                                                  color: Colors.deepPurple,
                                                  fontWeight: FontWeight.w500,
                                                ),
                                              ),
                                            if (rule.fieldSlices.isNotEmpty)
                                              Text(
                                                '${rule.fieldSlices.length} field slice${rule.fieldSlices.length == 1 ? '' : 's'}',
                                                style: const TextStyle(fontSize: 12, color: Colors.teal),
                                              ),
                                          ],
                                        ),
                                      ],
                                    ),
                                  ),
                                  // Edit Button
                                  IconButton(
                                    icon: const Icon(Icons.edit_outlined, size: 20),
                                    tooltip: 'Edit Protocol',
                                    onPressed: () async {
                                      final updated = await showDialog<CustomProtocolRule>(
                                        context: context,
                                        builder: (ctx) => AddProtocolDialog(existingRule: rule),
                                      );
                                      if (updated != null) {
                                        vm.updateCustomProtocol(updated);
                                        setState(() {});
                                      }
                                    },
                                  ),
                                  // Delete Button
                                  IconButton(
                                    icon: const Icon(Icons.delete_outline, size: 20, color: Colors.redAccent),
                                    tooltip: 'Delete Protocol',
                                    onPressed: () async {
                                      final confirm = await showDialog<bool>(
                                        context: context,
                                        builder: (ctx) => AlertDialog(
                                          title: const Text('Delete Protocol Rule'),
                                          content: Text('Are you sure you want to delete "${rule.name}"? Packets will be re-labeled.'),
                                          actions: [
                                            TextButton(
                                              onPressed: () => Navigator.of(ctx).pop(false),
                                              child: const Text('Cancel'),
                                            ),
                                            FilledButton(
                                              style: FilledButton.styleFrom(backgroundColor: Colors.redAccent),
                                              onPressed: () => Navigator.of(ctx).pop(true),
                                              child: const Text('Delete'),
                                            ),
                                          ],
                                        ),
                                      );
                                      if (confirm == true) {
                                        vm.deleteCustomProtocol(rule.id);
                                        setState(() {});
                                      }
                                    },
                                  ),
                                ],
                              ),
                            ),
                          );
                        },
                      ),
              ),

              const SizedBox(height: 16),
              Align(
                alignment: Alignment.centerRight,
                child: FilledButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: const Text('Close'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildTriageChip(TriageStatus status) {
    Color bg;
    Color fg;
    String label;
    switch (status) {
      case TriageStatus.expected:
        bg = Colors.green.withAlpha(30);
        fg = Colors.green[800]!;
        label = 'Expected';
        break;
      case TriageStatus.unexpected:
        bg = Colors.red.withAlpha(30);
        fg = Colors.red[800]!;
        label = 'Unexpected';
        break;
      case TriageStatus.unclassified:
        bg = Colors.orange.withAlpha(30);
        fg = Colors.orange[800]!;
        label = 'Unclassified';
        break;
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        label,
        style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: fg),
      ),
    );
  }
}
