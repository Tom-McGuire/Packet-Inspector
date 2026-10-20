import 'package:flutter/material.dart';
import '../../../../domain/models/custom_protocol_rule.dart';
import '../../../../domain/models/endpoint_rule.dart';
import '../../../../domain/models/packet_record.dart';
import '../../inspector/view_models/inspector_view_model.dart';
import 'add_protocol_dialog.dart';
import 'add_endpoint_dialog.dart';

class CustomLibraryDialog extends StatefulWidget {
  const CustomLibraryDialog({
    super.key,
    required this.viewModel,
    this.initialTab = 0,
  });

  final InspectorViewModel viewModel;
  final int initialTab;

  @override
  State<CustomLibraryDialog> createState() => _CustomLibraryDialogState();
}

class _CustomLibraryDialogState extends State<CustomLibraryDialog>
    with SingleTickerProviderStateMixin {
  late final TabController _tabController;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(
      length: 3,
      vsync: this,
      initialIndex: widget.initialTab.clamp(0, 2),
    );
    _tabController.addListener(() {
      if (mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final vm = widget.viewModel;
    final rules = vm.customRules;
    final senders = vm.senders;
    final receivers = vm.receivers;

    final String addLabel;
    final VoidCallback onAddPressed;

    switch (_tabController.index) {
      case 1:
        addLabel = 'Add Sender';
        onAddPressed = () async {
          final newRule = await showDialog<EndpointRule>(
            context: context,
            builder: (ctx) => const AddEndpointDialog(type: EndpointType.sender),
          );
          if (newRule != null) {
            vm.addSender(newRule);
            setState(() {});
          }
        };
        break;
      case 2:
        addLabel = 'Add Receiver';
        onAddPressed = () async {
          final newRule = await showDialog<EndpointRule>(
            context: context,
            builder: (ctx) => const AddEndpointDialog(type: EndpointType.receiver),
          );
          if (newRule != null) {
            vm.addReceiver(newRule);
            setState(() {});
          }
        };
        break;
      case 0:
      default:
        addLabel = 'Add Protocol';
        onAddPressed = () async {
          final newRule = await showDialog<CustomProtocolRule>(
            context: context,
            builder: (ctx) => const AddProtocolDialog(),
          );
          if (newRule != null) {
            vm.addCustomProtocol(newRule);
            setState(() {});
          }
        };
        break;
    }

    return Dialog(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 780, maxHeight: 640),
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Header
              Row(
                children: [
                  const Icon(Icons.menu_book, size: 26, color: Colors.indigoAccent),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'Custom Library',
                          style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                        ),
                        Text(
                          '${rules.length} Protocols • ${senders.length} Senders • ${receivers.length} Receivers',
                          style: const TextStyle(fontSize: 12, color: Colors.grey),
                        ),
                      ],
                    ),
                  ),
                  FilledButton.icon(
                    icon: const Icon(Icons.add, size: 16),
                    label: Text(addLabel),
                    onPressed: onAddPressed,
                  ),
                  const SizedBox(width: 8),
                  IconButton(
                    icon: const Icon(Icons.close),
                    onPressed: () => Navigator.of(context).pop(),
                  ),
                ],
              ),
              const SizedBox(height: 16),

              // TabBar
              TabBar(
                controller: _tabController,
                tabs: [
                  Tab(
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.tune, size: 16),
                        const SizedBox(width: 6),
                        Text('Protocols (${rules.length})'),
                      ],
                    ),
                  ),
                  Tab(
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.arrow_upward, size: 16),
                        const SizedBox(width: 6),
                        Text('Senders (${senders.length})'),
                      ],
                    ),
                  ),
                  Tab(
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.arrow_downward, size: 16),
                        const SizedBox(width: 6),
                        Text('Receivers (${receivers.length})'),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 16),

              // Tab Views
              Expanded(
                child: TabBarView(
                  controller: _tabController,
                  children: [
                    _buildProtocolsTab(context, vm, rules),
                    _buildSendersTab(context, vm, senders),
                    _buildReceiversTab(context, vm, receivers),
                  ],
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

  // ================= Protocols Tab =================
  Widget _buildProtocolsTab(
    BuildContext context,
    InspectorViewModel vm,
    List<CustomProtocolRule> rules,
  ) {
    if (rules.isEmpty) {
      return Center(
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
      );
    }

    return ListView.separated(
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

        return Opacity(
          opacity: rule.isVisible ? 1.0 : 0.55,
          child: Card(
            elevation: 0,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(8),
              side: BorderSide(
                color: rule.isVisible ? Colors.grey.withAlpha(50) : Colors.grey.withAlpha(25),
              ),
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
                            if (!rule.isVisible) ...[
                              const SizedBox(width: 6),
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                decoration: BoxDecoration(
                                  color: Colors.amber.withAlpha(30),
                                  borderRadius: BorderRadius.circular(4),
                                ),
                                child: const Text(
                                  'Hidden',
                                  style: TextStyle(fontSize: 10, color: Colors.amber, fontWeight: FontWeight.bold),
                                ),
                              ),
                            ],
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

                  // 1. Eye (Visibility) Button
                  IconButton(
                    icon: Icon(
                      rule.isVisible ? Icons.visibility : Icons.visibility_off,
                      size: 20,
                      color: rule.isVisible ? Colors.blueAccent : Colors.grey,
                    ),
                    tooltip: rule.isVisible
                        ? 'Visible in quick-filters (Click to hide)'
                        : 'Hidden from quick-filters (Click to show)',
                    onPressed: () {
                      vm.toggleProtocolVisibility(rule.id);
                      setState(() {});
                    },
                  ),

                  // 2. Edit Button
                  IconButton(
                    icon: const Icon(Icons.edit, size: 20),
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

                  // 3. Delete Button
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
          ),
        );
      },
    );
  }

  // ================= Senders Tab =================
  Widget _buildSendersTab(
    BuildContext context,
    InspectorViewModel vm,
    List<EndpointRule> senders,
  ) {
    if (senders.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.arrow_upward_outlined, size: 48, color: Colors.grey[400]),
            const SizedBox(height: 12),
            const Text(
              'No saved senders yet.',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.w500),
            ),
            const SizedBox(height: 4),
            const Text(
              'Save transmitting devices with custom labels, IP addresses, and ports.',
              style: TextStyle(fontSize: 12, color: Colors.grey),
            ),
          ],
        ),
      );
    }

    return ListView.separated(
      itemCount: senders.length,
      separatorBuilder: (_, __) => const SizedBox(height: 8),
      itemBuilder: (context, index) {
        final sender = senders[index];

        return Opacity(
          opacity: sender.isVisible ? 1.0 : 0.55,
          child: Card(
            elevation: 0,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(8),
              side: BorderSide(
                color: sender.isVisible ? Colors.grey.withAlpha(50) : Colors.grey.withAlpha(25),
              ),
            ),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  CircleAvatar(
                    radius: 14,
                    backgroundColor: Color(sender.colorHex),
                    child: const Icon(Icons.arrow_upward, size: 14, color: Colors.white),
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
                                sender.name,
                                style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                            if (!sender.isVisible) ...[
                              const SizedBox(width: 6),
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                decoration: BoxDecoration(
                                  color: Colors.amber.withAlpha(30),
                                  borderRadius: BorderRadius.circular(4),
                                ),
                                child: const Text(
                                  'Hidden',
                                  style: TextStyle(fontSize: 10, color: Colors.amber, fontWeight: FontWeight.bold),
                                ),
                              ),
                            ],
                          ],
                        ),
                        const SizedBox(height: 4),
                        Text(
                          sender.port != null
                              ? '${sender.ipAddress} : Port ${sender.port}'
                              : sender.ipAddress,
                          style: const TextStyle(fontSize: 12, color: Colors.grey),
                        ),
                      ],
                    ),
                  ),

                  // 1. Eye (Visibility) Button
                  IconButton(
                    icon: Icon(
                      sender.isVisible ? Icons.visibility : Icons.visibility_off,
                      size: 20,
                      color: sender.isVisible ? Colors.blueAccent : Colors.grey,
                    ),
                    tooltip: sender.isVisible
                        ? 'Visible in quick-filters (Click to hide)'
                        : 'Hidden from quick-filters (Click to show)',
                    onPressed: () {
                      vm.toggleSenderVisibility(sender.id);
                      setState(() {});
                    },
                  ),

                  // 2. Edit Button
                  IconButton(
                    icon: const Icon(Icons.edit, size: 20),
                    tooltip: 'Edit Sender',
                    onPressed: () async {
                      final updated = await showDialog<EndpointRule>(
                        context: context,
                        builder: (ctx) => AddEndpointDialog(
                          type: EndpointType.sender,
                          existingRule: sender,
                        ),
                      );
                      if (updated != null) {
                        vm.updateSender(updated);
                        setState(() {});
                      }
                    },
                  ),

                  // 3. Delete Button
                  IconButton(
                    icon: const Icon(Icons.delete_outline, size: 20, color: Colors.redAccent),
                    tooltip: 'Delete Sender',
                    onPressed: () async {
                      final confirm = await showDialog<bool>(
                        context: context,
                        builder: (ctx) => AlertDialog(
                          title: const Text('Delete Sender'),
                          content: Text('Are you sure you want to delete "${sender.name}" from the sender library?'),
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
                        vm.deleteSender(sender.id);
                        setState(() {});
                      }
                    },
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  // ================= Receivers Tab =================
  Widget _buildReceiversTab(
    BuildContext context,
    InspectorViewModel vm,
    List<EndpointRule> receivers,
  ) {
    if (receivers.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.arrow_downward_outlined, size: 48, color: Colors.grey[400]),
            const SizedBox(height: 12),
            const Text(
              'No saved receivers yet.',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.w500),
            ),
            const SizedBox(height: 4),
            const Text(
              'Save destination devices or multicast groups with custom labels, IP addresses, and ports.',
              style: TextStyle(fontSize: 12, color: Colors.grey),
            ),
          ],
        ),
      );
    }

    return ListView.separated(
      itemCount: receivers.length,
      separatorBuilder: (_, __) => const SizedBox(height: 8),
      itemBuilder: (context, index) {
        final receiver = receivers[index];

        return Opacity(
          opacity: receiver.isVisible ? 1.0 : 0.55,
          child: Card(
            elevation: 0,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(8),
              side: BorderSide(
                color: receiver.isVisible ? Colors.grey.withAlpha(50) : Colors.grey.withAlpha(25),
              ),
            ),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  CircleAvatar(
                    radius: 14,
                    backgroundColor: Color(receiver.colorHex),
                    child: const Icon(Icons.arrow_downward, size: 14, color: Colors.white),
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
                                receiver.name,
                                style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                            if (!receiver.isVisible) ...[
                              const SizedBox(width: 6),
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                decoration: BoxDecoration(
                                  color: Colors.amber.withAlpha(30),
                                  borderRadius: BorderRadius.circular(4),
                                ),
                                child: const Text(
                                  'Hidden',
                                  style: TextStyle(fontSize: 10, color: Colors.amber, fontWeight: FontWeight.bold),
                                ),
                              ),
                            ],
                          ],
                        ),
                        const SizedBox(height: 4),
                        Text(
                          receiver.port != null
                              ? '${receiver.ipAddress} : Port ${receiver.port}'
                              : receiver.ipAddress,
                          style: const TextStyle(fontSize: 12, color: Colors.grey),
                        ),
                      ],
                    ),
                  ),

                  // 1. Eye (Visibility) Button
                  IconButton(
                    icon: Icon(
                      receiver.isVisible ? Icons.visibility : Icons.visibility_off,
                      size: 20,
                      color: receiver.isVisible ? Colors.blueAccent : Colors.grey,
                    ),
                    tooltip: receiver.isVisible
                        ? 'Visible in quick-filters (Click to hide)'
                        : 'Hidden from quick-filters (Click to show)',
                    onPressed: () {
                      vm.toggleReceiverVisibility(receiver.id);
                      setState(() {});
                    },
                  ),

                  // 2. Edit Button
                  IconButton(
                    icon: const Icon(Icons.edit, size: 20),
                    tooltip: 'Edit Receiver',
                    onPressed: () async {
                      final updated = await showDialog<EndpointRule>(
                        context: context,
                        builder: (ctx) => AddEndpointDialog(
                          type: EndpointType.receiver,
                          existingRule: receiver,
                        ),
                      );
                      if (updated != null) {
                        vm.updateReceiver(updated);
                        setState(() {});
                      }
                    },
                  ),

                  // 3. Delete Button
                  IconButton(
                    icon: const Icon(Icons.delete_outline, size: 20, color: Colors.redAccent),
                    tooltip: 'Delete Receiver',
                    onPressed: () async {
                      final confirm = await showDialog<bool>(
                        context: context,
                        builder: (ctx) => AlertDialog(
                          title: const Text('Delete Receiver'),
                          content: Text('Are you sure you want to delete "${receiver.name}" from the receiver library?'),
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
                        vm.deleteReceiver(receiver.id);
                        setState(() {});
                      }
                    },
                  ),
                ],
              ),
            ),
          ),
        );
      },
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
