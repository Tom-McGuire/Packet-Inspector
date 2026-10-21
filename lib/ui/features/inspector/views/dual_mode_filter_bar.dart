import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../../../domain/models/custom_protocol_rule.dart';
import '../../../../domain/models/endpoint_rule.dart';
import '../../../../domain/models/packet_record.dart';
import '../../protocol_library/views/add_protocol_dialog.dart';
import '../../protocol_library/views/add_endpoint_dialog.dart';
import '../view_models/inspector_view_model.dart';

class DualModeFilterBar extends StatefulWidget {
  const DualModeFilterBar({super.key});

  @override
  State<DualModeFilterBar> createState() => _DualModeFilterBarState();
}

class _DualModeFilterBarState extends State<DualModeFilterBar> {
  bool _isExpanded = true;

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<InspectorViewModel>();
    final isTriage = vm.isTriageMode;
    final hasActiveQuickFilters = vm.selectedProtocolPills.isNotEmpty ||
        vm.selectedSenderKeys.isNotEmpty ||
        vm.selectedReceiverKeys.isNotEmpty;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.4),
        border: Border(
          bottom: BorderSide(
            color: Theme.of(context).dividerColor.withValues(alpha: 0.3),
          ),
        ),
      ),
      child: isTriage
          ? Row(
              children: [
                _buildModeSwitch(context, vm),
                const SizedBox(width: 16),
                const VerticalDivider(width: 1, indent: 6, endIndent: 6),
                const SizedBox(width: 16),
                Expanded(child: _buildTriageControls(context, vm)),
              ],
            )
          : Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // Top control bar
                Row(
                  children: [
                    _buildModeSwitch(context, vm),
                    const SizedBox(width: 8),
                    _buildAutoDetectedSwitch(context, vm),
                    const SizedBox(width: 12),
                    if (hasActiveQuickFilters) ...[
                      ActionChip(
                        avatar: const Icon(Icons.close, size: 14),
                        label: const Text('Clear All Filters'),
                        onPressed: () => vm.clearAllQuickFilters(),
                      ),
                      const SizedBox(width: 8),
                    ],
                    const Spacer(),
                    Tooltip(
                      message: _isExpanded ? 'Collapse filter rows' : 'Expand 3-row filters',
                      child: IconButton(
                        icon: Icon(_isExpanded ? Icons.unfold_less : Icons.unfold_more, size: 18),
                        onPressed: () => setState(() => _isExpanded = !_isExpanded),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),

                // Row 1: Protocols
                _buildProtocolFilterRow(context, vm),

                // Row 2 & 3 when expanded
                if (_isExpanded) ...[
                  const SizedBox(height: 6),
                  _buildSenderFilterRow(context, vm),
                  const SizedBox(height: 6),
                  _buildReceiverFilterRow(context, vm),
                ],
              ],
            ),
    );
  }

  Widget _buildModeSwitch(BuildContext context, InspectorViewModel vm) {
    final isTriage = vm.isTriageMode;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: Theme.of(context).colorScheme.outlineVariant,
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            isTriage ? Icons.shield_outlined : Icons.filter_alt_outlined,
            size: 16,
            color: Theme.of(context).colorScheme.primary,
          ),
          const SizedBox(width: 6),
          Text(
            isTriage ? 'Baseline Triage' : 'Quick-Filter Pills',
            style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
          ),
          const SizedBox(width: 6),
          Switch(
            value: isTriage,
            onChanged: (val) => vm.setTriageMode(val),
            materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
          ),
        ],
      ),
    );
  }

  Widget _buildAutoDetectedSwitch(BuildContext context, InspectorViewModel vm) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: Theme.of(context).colorScheme.outlineVariant,
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.sensors,
            size: 16,
            color: vm.showAutoDetected
                ? Theme.of(context).colorScheme.primary
                : Theme.of(context).colorScheme.onSurfaceVariant,
          ),
          const SizedBox(width: 6),
          const Text(
            'Auto-Detected',
            style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
          ),
          const SizedBox(width: 6),
          Switch(
            value: vm.showAutoDetected,
            onChanged: (val) => vm.setShowAutoDetected(val),
            materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
          ),
        ],
      ),
    );
  }

  Widget _buildTriageControls(BuildContext context, InspectorViewModel vm) {
    final counts = vm.triageCounts;
    final expectedCount = counts[TriageStatus.expected] ?? 0;
    final unclassifiedCount = counts[TriageStatus.unclassified] ?? 0;
    final unexpectedCount = counts[TriageStatus.unexpected] ?? 0;

    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Expected Chip
          FilterChip(
            avatar: const CircleAvatar(
              backgroundColor: Colors.green,
              radius: 5,
            ),
            label: Text('Expected ($expectedCount)'),
            selected: vm.selectedTriageStatuses.contains(TriageStatus.expected),
            onSelected: (_) => vm.toggleTriageStatus(TriageStatus.expected),
          ),
          const SizedBox(width: 8),

          // Unclassified Chip
          FilterChip(
            avatar: const CircleAvatar(
              backgroundColor: Colors.amber,
              radius: 5,
            ),
            label: Text('Unclassified ($unclassifiedCount)'),
            selected: vm.selectedTriageStatuses.contains(TriageStatus.unclassified),
            onSelected: (_) => vm.toggleTriageStatus(TriageStatus.unclassified),
          ),
          const SizedBox(width: 8),

          // Unexpected Chip
          FilterChip(
            avatar: const CircleAvatar(
              backgroundColor: Colors.redAccent,
              radius: 5,
            ),
            label: Text('Unexpected ($unexpectedCount)'),
            selected: vm.selectedTriageStatuses.contains(TriageStatus.unexpected),
            onSelected: (_) => vm.toggleTriageStatus(TriageStatus.unexpected),
          ),

          const SizedBox(width: 16),

          // Silence Common LAN Chatter Toggle
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 2),
            decoration: BoxDecoration(
              color: vm.silenceLanChatter
                  ? Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.5)
                  : Theme.of(context).colorScheme.surface,
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                color: Theme.of(context).colorScheme.outlineVariant,
              ),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  vm.silenceLanChatter ? Icons.volume_off : Icons.volume_up,
                  size: 16,
                  color: vm.silenceLanChatter
                      ? Theme.of(context).colorScheme.primary
                      : Theme.of(context).colorScheme.onSurfaceVariant,
                ),
                const SizedBox(width: 6),
                const Text(
                  'Silence LAN Chatter',
                  style: TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
                ),
                const SizedBox(width: 4),
                Tooltip(
                  message: 'Auto-hides ARP, mDNS, SSDP, NBNS & DHCP noise from view',
                  child: Icon(Icons.info_outline, size: 14, color: Theme.of(context).colorScheme.outline),
                ),
                const SizedBox(width: 4),
                Switch(
                  value: vm.silenceLanChatter,
                  onChanged: (val) => vm.setSilenceLanChatter(val),
                  materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildProtocolFilterRow(BuildContext context, InspectorViewModel vm) {
    final customRules = vm.customRules;
    final protocolCounts = vm.protocolCounts;
    final seenCustomNames = <String>{};
    final distinctCustomRules = customRules
        .where((r) => r.isVisible && seenCustomNames.add(r.name))
        .toList();
    final customRuleNames = customRules.map((r) => r.name).toSet();

    // Standard protocols that are not in custom rules, sorted by count descending
    final standardEntries = vm.showAutoDetected
        ? protocolCounts.entries
            .where((e) => !customRuleNames.contains(e.key))
            .toList()
        : const <MapEntry<String, int>>[];

    return Row(
      children: [
        const Padding(
          padding: EdgeInsets.only(right: 8.0),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.tune, size: 14, color: Colors.indigoAccent),
              SizedBox(width: 4),
              Text('Protocols', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
            ],
          ),
        ),
        Expanded(
          child: SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: [
                // 1. Custom Protocol Library Pills (Always present and prioritized)
                ...distinctCustomRules.map((rule) {
                  final count = protocolCounts[rule.name] ?? 0;
                  final isSelected = vm.selectedProtocolPills.contains(rule.name);

                  return Padding(
                    padding: const EdgeInsets.only(right: 6.0),
                    child: FilterChip(
                      avatar: CircleAvatar(
                        radius: 5,
                        backgroundColor: Color(rule.colorHex),
                      ),
                      label: Text('${rule.name} ($count)'),
                      selected: isSelected,
                      onSelected: (_) => vm.toggleProtocolPill(rule.name),
                      tooltip: 'Custom Protocol: ${rule.name}',
                    ),
                  );
                }),

                // 2. Add Protocol Chip Button
                Padding(
                  padding: const EdgeInsets.only(right: 6.0),
                  child: ActionChip(
                    avatar: const Icon(Icons.add, size: 14),
                    label: const Text('Add Protocol'),
                    tooltip: 'Add new custom protocol to library and filter',
                    onPressed: () async {
                      final newRule = await showDialog<CustomProtocolRule>(
                        context: context,
                        builder: (ctx) => const AddProtocolDialog(),
                      );
                      if (newRule != null) {
                        vm.addCustomProtocol(newRule);
                      }
                    },
                  ),
                ),

                if (distinctCustomRules.isNotEmpty && standardEntries.isNotEmpty) ...[
                  const SizedBox(width: 4),
                  Container(
                    height: 18,
                    width: 1,
                    color: Theme.of(context).dividerColor.withValues(alpha: 0.3),
                  ),
                  const SizedBox(width: 8),
                ],

                // 3. Standard / Discovered Protocol Pills
                ...standardEntries.map((entry) {
                  final proto = entry.key;
                  final count = entry.value;
                  final isSelected = vm.selectedProtocolPills.contains(proto);

                  return Padding(
                    padding: const EdgeInsets.only(right: 6.0),
                    child: FilterChip(
                      label: Text('$proto ($count)'),
                      selected: isSelected,
                      onSelected: (_) => vm.toggleProtocolPill(proto),
                    ),
                  );
                }),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildSenderFilterRow(BuildContext context, InspectorViewModel vm) {
    final senders = vm.senders.where((s) => s.isVisible).toList();
    final senderCounts = vm.senderCounts;
    final senderLibraryKeys = vm.senders.map((s) => s.filterKey).toSet();
    final senderLibraryIps = vm.senders.map((s) => s.ipAddress).toSet();

    final discoveredEntries = vm.showAutoDetected
        ? senderCounts.entries
            .where((e) => !senderLibraryKeys.contains(e.key) && !senderLibraryIps.contains(e.key))
            .toList()
        : const <MapEntry<String, int>>[];

    return Row(
      children: [
        const Padding(
          padding: EdgeInsets.only(right: 8.0),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.arrow_upward, size: 14, color: Colors.blueAccent),
              SizedBox(width: 4),
              Text('Sources', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
            ],
          ),
        ),
        Expanded(
          child: SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: [
                // Source Library Pills
                ...senders.map((rule) {
                  final count = senderCounts[rule.filterKey] ?? 0;
                  final isSelected = vm.selectedSenderKeys.contains(rule.filterKey);

                  return Padding(
                    padding: const EdgeInsets.only(right: 6.0),
                    child: FilterChip(
                      avatar: CircleAvatar(
                        radius: 5,
                        backgroundColor: Color(rule.colorHex),
                      ),
                      label: Text('${rule.name} ($count)'),
                      selected: isSelected,
                      onSelected: (_) => vm.toggleSenderPill(rule.filterKey),
                      tooltip: 'Source: ${rule.displayName}',
                    ),
                  );
                }),

                // Add Source Chip Button
                Padding(
                  padding: const EdgeInsets.only(right: 6.0),
                  child: ActionChip(
                    avatar: const Icon(Icons.add, size: 14),
                    label: const Text('Add Source'),
                    tooltip: 'Add new device to Source library',
                    onPressed: () async {
                      final newRule = await showDialog<EndpointRule>(
                        context: context,
                        builder: (ctx) => const AddEndpointDialog(type: EndpointType.sender),
                      );
                      if (newRule != null) {
                        vm.addSender(newRule);
                      }
                    },
                  ),
                ),

                if (senders.isNotEmpty && discoveredEntries.isNotEmpty) ...[
                  const SizedBox(width: 4),
                  Container(
                    height: 18,
                    width: 1,
                    color: Theme.of(context).dividerColor.withValues(alpha: 0.3),
                  ),
                  const SizedBox(width: 8),
                ],

                // Discovered Source IP Pills
                ...discoveredEntries.map((entry) {
                  final ip = entry.key;
                  final count = entry.value;
                  final isSelected = vm.selectedSenderKeys.contains(ip);

                  return Padding(
                    padding: const EdgeInsets.only(right: 6.0),
                    child: FilterChip(
                      label: Text('$ip ($count)'),
                      selected: isSelected,
                      onSelected: (_) => vm.toggleSenderPill(ip),
                    ),
                  );
                }),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildReceiverFilterRow(BuildContext context, InspectorViewModel vm) {
    final receivers = vm.receivers.where((r) => r.isVisible).toList();
    final receiverCounts = vm.receiverCounts;
    final receiverLibraryKeys = vm.receivers.map((r) => r.filterKey).toSet();
    final receiverLibraryIps = vm.receivers.map((r) => r.ipAddress).toSet();

    final discoveredEntries = vm.showAutoDetected
        ? receiverCounts.entries
            .where((e) => !receiverLibraryKeys.contains(e.key) && !receiverLibraryIps.contains(e.key))
            .toList()
        : const <MapEntry<String, int>>[];

    return Row(
      children: [
        const Padding(
          padding: EdgeInsets.only(right: 8.0),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.arrow_downward, size: 14, color: Colors.greenAccent),
              SizedBox(width: 4),
              Text('Destinations', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
            ],
          ),
        ),
        Expanded(
          child: SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: [
                // Destination Library Pills
                ...receivers.map((rule) {
                  final count = receiverCounts[rule.filterKey] ?? 0;
                  final isSelected = vm.selectedReceiverKeys.contains(rule.filterKey);

                  return Padding(
                    padding: const EdgeInsets.only(right: 6.0),
                    child: FilterChip(
                      avatar: CircleAvatar(
                        radius: 5,
                        backgroundColor: Color(rule.colorHex),
                      ),
                      label: Text('${rule.name} ($count)'),
                      selected: isSelected,
                      onSelected: (_) => vm.toggleReceiverPill(rule.filterKey),
                      tooltip: 'Destination: ${rule.displayName}',
                    ),
                  );
                }),

                // Add Destination Chip Button
                Padding(
                  padding: const EdgeInsets.only(right: 6.0),
                  child: ActionChip(
                    avatar: const Icon(Icons.add, size: 14),
                    label: const Text('Add Destination'),
                    tooltip: 'Add new device / multicast group to Destination library',
                    onPressed: () async {
                      final newRule = await showDialog<EndpointRule>(
                        context: context,
                        builder: (ctx) => const AddEndpointDialog(type: EndpointType.receiver),
                      );
                      if (newRule != null) {
                        vm.addReceiver(newRule);
                      }
                    },
                  ),
                ),

                if (receivers.isNotEmpty && discoveredEntries.isNotEmpty) ...[
                  const SizedBox(width: 4),
                  Container(
                    height: 18,
                    width: 1,
                    color: Theme.of(context).dividerColor.withValues(alpha: 0.3),
                  ),
                  const SizedBox(width: 8),
                ],

                // Discovered Dest IP Pills
                ...discoveredEntries.map((entry) {
                  final ip = entry.key;
                  final count = entry.value;
                  final isSelected = vm.selectedReceiverKeys.contains(ip);

                  return Padding(
                    padding: const EdgeInsets.only(right: 6.0),
                    child: FilterChip(
                      label: Text('$ip ($count)'),
                      selected: isSelected,
                      onSelected: (_) => vm.toggleReceiverPill(ip),
                    ),
                  );
                }),
              ],
            ),
          ),
        ),
      ],
    );
  }
}
