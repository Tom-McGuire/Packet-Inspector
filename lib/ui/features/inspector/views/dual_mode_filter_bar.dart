import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../../../domain/models/packet_record.dart';
import '../view_models/inspector_view_model.dart';

class DualModeFilterBar extends StatelessWidget {
  const DualModeFilterBar({super.key});

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<InspectorViewModel>();
    final isTriage = vm.isTriageMode;

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
      child: Row(
        children: [
          // Mode Toggle Switch
          Container(
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
          ),

          const SizedBox(width: 16),
          const VerticalDivider(width: 1, indent: 6, endIndent: 6),
          const SizedBox(width: 16),

          // Dynamic Section based on Active Mode
          Expanded(
            child: isTriage
                ? _buildTriageControls(context, vm)
                : _buildQuickFilterPills(context, vm),
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

  Widget _buildQuickFilterPills(BuildContext context, InspectorViewModel vm) {
    final protocols = vm.protocolCounts.entries.toList();

    return Row(
      children: [
        if (vm.selectedProtocolPills.isNotEmpty) ...[
          ActionChip(
            avatar: const Icon(Icons.close, size: 14),
            label: const Text('Clear All'),
            onPressed: () => vm.clearProtocolPills(),
          ),
          const SizedBox(width: 8),
        ],

        Expanded(
          child: SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: protocols.map((entry) {
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
              }).toList(),
            ),
          ),
        ),
      ],
    );
  }
}
