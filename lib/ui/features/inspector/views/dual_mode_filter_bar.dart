import 'package:material_ui/material_ui.dart';
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
  late final TextEditingController _srcSearchController;
  late final TextEditingController _dstSearchController;

  @override
  void initState() {
    super.initState();
    final vm = context.read<InspectorViewModel>();
    _srcSearchController = TextEditingController(text: vm.sourceSearch);
    _dstSearchController = TextEditingController(text: vm.destSearch);
  }

  @override
  void dispose() {
    _srcSearchController.dispose();
    _dstSearchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<InspectorViewModel>();

    // Keep controllers in sync when filters are cleared externally
    if (vm.sourceSearch.isEmpty && _srcSearchController.text.isNotEmpty) {
      _srcSearchController.clear();
    }
    if (vm.destSearch.isEmpty && _dstSearchController.text.isNotEmpty) {
      _dstSearchController.clear();
    }

    final hasActiveFilters = vm.hasActiveFilters;

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
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Top control bar: Search Boxes + Controls (always shown when collapsed & expanded)
          Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              Expanded(
                child: SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.center,
                    children: [
                      // Source IP Search Box
                      _buildSearchBox(
                        context: context,
                        label: 'Source IP',
                        icon: Icons.arrow_upward,
                        iconColor: Colors.blueAccent,
                        controller: _srcSearchController,
                        isNot: vm.isSourceSearchNot,
                        onNotChanged: (val) => vm.setSourceSearchNot(val),
                        onChanged: (val) => vm.setSourceSearch(val),
                      ),
                      const SizedBox(width: 10),

                      // Destination IP Search Box
                      _buildSearchBox(
                        context: context,
                        label: 'Destination IP',
                        icon: Icons.arrow_downward,
                        iconColor: Colors.greenAccent,
                        controller: _dstSearchController,
                        isNot: vm.isDestSearchNot,
                        onNotChanged: (val) => vm.setDestSearchNot(val),
                        onChanged: (val) => vm.setDestSearch(val),
                      ),
                      const SizedBox(width: 12),

                      // Auto-Detected Switch
                      _buildAutoDetectedSwitch(context, vm),
                      const SizedBox(width: 8),

                      // Silence LAN Chatter Switch
                      _buildSilenceLanToggle(context, vm),
                      const SizedBox(width: 8),

                      if (hasActiveFilters) ...[
                        ActionChip(
                          avatar: const Icon(Icons.close, size: 14),
                          label: const Text('Clear All Filters'),
                          onPressed: () {
                            _srcSearchController.clear();
                            _dstSearchController.clear();
                            vm.clearAllFilters();
                          },
                        ),
                        const SizedBox(width: 8),
                      ],
                    ],
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Tooltip(
                message: _isExpanded ? 'Collapse filter rows' : 'Expand all filter rows',
                child: IconButton(
                  icon: Icon(_isExpanded ? Icons.unfold_less : Icons.unfold_more, size: 18),
                  onPressed: () => setState(() => _isExpanded = !_isExpanded),
                ),
              ),
            ],
          ),

          // Detailed Filter Rows (shown when expanded)
          if (_isExpanded) ...[
            const SizedBox(height: 8),

            // Row 2: Baseline Triage (Expected, Unassigned, Unexpected, Silence LAN Chatter)
            _buildTriageFilterRow(context, vm),
            const SizedBox(height: 6),

            // Row 3: Protocols
            _buildProtocolFilterRow(context, vm),
            const SizedBox(height: 6),

            // Row 4: Sources
            _buildSenderFilterRow(context, vm),
            const SizedBox(height: 6),

            // Row 5: Destinations
            _buildReceiverFilterRow(context, vm),
          ],
        ],
      ),
    );
  }

  Widget _buildSearchBox({
    required BuildContext context,
    required String label,
    required IconData icon,
    required Color iconColor,
    required TextEditingController controller,
    required bool isNot,
    required ValueChanged<bool> onNotChanged,
    required ValueChanged<String> onChanged,
  }) {
    final theme = Theme.of(context);
    return Row(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        AndNotToggle(
          isNot: isNot,
          onChanged: onNotChanged,
        ),
        const SizedBox(width: 6),
        Container(
          width: 175,
          height: 32,
          padding: const EdgeInsets.symmetric(horizontal: 8),
          decoration: BoxDecoration(
            color: theme.colorScheme.surface,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(
              color: isNot
                  ? Colors.redAccent.withValues(alpha: 0.8)
                  : theme.colorScheme.outlineVariant,
              width: isNot ? 1.5 : 1.0,
            ),
          ),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              Icon(icon, size: 14, color: iconColor),
              const SizedBox(width: 6),
              Expanded(
                child: TextField(
                  controller: controller,
                  onChanged: onChanged,
                  textAlignVertical: TextAlignVertical.center,
                  style: const TextStyle(fontSize: 12),
                  decoration: InputDecoration(
                    isDense: true,
                    contentPadding: EdgeInsets.zero,
                    hintText: label,
                    hintStyle: TextStyle(
                      fontSize: 12,
                      color: theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.6),
                    ),
                    border: InputBorder.none,
                    enabledBorder: InputBorder.none,
                    focusedBorder: InputBorder.none,
                  ),
                ),
              ),
              if (controller.text.isNotEmpty)
                IconButton(
                  icon: const Icon(Icons.clear, size: 14),
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(minWidth: 20, minHeight: 20),
                  splashRadius: 12,
                  onPressed: () {
                    controller.clear();
                    onChanged('');
                  },
                ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildRowHeader({
    required BuildContext context,
    required IconData icon,
    required Color iconColor,
    required String title,
    required bool isNot,
    required ValueChanged<bool> onNotChanged,
  }) {
    return SizedBox(
      width: 175,
      child: Row(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          AndNotToggle(
            isNot: isNot,
            onChanged: onNotChanged,
          ),
          const SizedBox(width: 8),
          Icon(icon, size: 14, color: iconColor),
          const SizedBox(width: 4),
          Expanded(
            child: Text(
              title,
              style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold),
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildAutoDetectedSwitch(BuildContext context, InspectorViewModel vm) {
    return Container(
      height: 32,
      padding: const EdgeInsets.only(left: 8, right: 4),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: Theme.of(context).colorScheme.outlineVariant,
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Icon(
            Icons.sensors,
            size: 14,
            color: vm.showAutoDetected
                ? Theme.of(context).colorScheme.primary
                : Theme.of(context).colorScheme.onSurfaceVariant,
          ),
          const SizedBox(width: 5),
          const Text(
            'Auto-Detected',
            style: TextStyle(fontWeight: FontWeight.w600, fontSize: 11.5),
          ),
          const SizedBox(width: 4),
          Transform.scale(
            scale: 0.7,
            child: Switch(
              value: vm.showAutoDetected,
              onChanged: (val) => vm.setShowAutoDetected(val),
              materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTriageFilterRow(BuildContext context, InspectorViewModel vm) {
    final counts = vm.triageCounts;
    final expectedCount = counts[TriageStatus.expected] ?? 0;
    final unclassifiedCount = counts[TriageStatus.unclassified] ?? 0;
    final unexpectedCount = counts[TriageStatus.unexpected] ?? 0;

    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        _buildRowHeader(
          context: context,
          icon: Icons.shield_outlined,
          iconColor: Theme.of(context).colorScheme.primary,
          title: 'Triage',
          isNot: vm.isTriageNot,
          onNotChanged: (val) => vm.setTriageNot(val),
        ),
        Expanded(
          child: SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.center,
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

                // Unassigned Chip
                FilterChip(
                  avatar: const CircleAvatar(
                    backgroundColor: Colors.amber,
                    radius: 5,
                  ),
                  label: Text('Unassigned ($unclassifiedCount)'),
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
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildSilenceLanToggle(BuildContext context, InspectorViewModel vm) {
    return Container(
      height: 32,
      padding: const EdgeInsets.only(left: 8, right: 4),
      decoration: BoxDecoration(
        color: vm.silenceLanChatter
            ? Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.45)
            : Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: Theme.of(context).colorScheme.outlineVariant,
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Icon(
            vm.silenceLanChatter ? Icons.volume_off : Icons.volume_up,
            size: 14,
            color: vm.silenceLanChatter
                ? Theme.of(context).colorScheme.primary
                : Theme.of(context).colorScheme.onSurfaceVariant,
          ),
          const SizedBox(width: 5),
          const Text(
            'Silence LAN Chatter',
            style: TextStyle(fontSize: 11.5, fontWeight: FontWeight.w600),
          ),
          const SizedBox(width: 3),
          Tooltip(
            message: 'Auto-hides ARP, mDNS, SSDP, NBNS & DHCP noise from view',
            child: Icon(Icons.info_outline, size: 13, color: Theme.of(context).colorScheme.outline),
          ),
          const SizedBox(width: 3),
          Transform.scale(
            scale: 0.7,
            child: Switch(
              value: vm.silenceLanChatter,
              onChanged: (val) => vm.setSilenceLanChatter(val),
              materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
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
            .where((e) => !customRuleNames.contains(e.key) && (e.value > 0 || vm.selectedProtocolPills.contains(e.key)))
            .toList()
        : const <MapEntry<String, int>>[];

    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        _buildRowHeader(
          context: context,
          icon: Icons.tune,
          iconColor: Colors.indigoAccent,
          title: 'Protocols',
          isNot: vm.isProtocolNot,
          onNotChanged: (val) => vm.setProtocolNot(val),
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
            .where((e) => !senderLibraryKeys.contains(e.key) && !senderLibraryIps.contains(e.key) && (e.value > 0 || vm.selectedSenderKeys.contains(e.key)))
            .toList()
        : const <MapEntry<String, int>>[];

    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        _buildRowHeader(
          context: context,
          icon: Icons.arrow_upward,
          iconColor: Colors.blueAccent,
          title: 'Sources',
          isNot: vm.isSenderNot,
          onNotChanged: (val) => vm.setSenderNot(val),
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
            .where((e) => !receiverLibraryKeys.contains(e.key) && !receiverLibraryIps.contains(e.key) && (e.value > 0 || vm.selectedReceiverKeys.contains(e.key)))
            .toList()
        : const <MapEntry<String, int>>[];

    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        _buildRowHeader(
          context: context,
          icon: Icons.arrow_downward,
          iconColor: Colors.greenAccent,
          title: 'Destinations',
          isNot: vm.isReceiverNot,
          onNotChanged: (val) => vm.setReceiverNot(val),
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

class AndNotToggle extends StatelessWidget {
  const AndNotToggle({
    super.key,
    required this.isNot,
    required this.onChanged,
  });

  final bool isNot;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Tooltip(
      message: isNot ? 'Inverted (excludes matching items)' : 'Normal (includes matching items)',
      child: Container(
        height: 32,
        decoration: BoxDecoration(
          color: theme.colorScheme.surface,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: isNot
                ? Colors.redAccent.withValues(alpha: 0.8)
                : theme.colorScheme.outlineVariant,
            width: isNot ? 1.5 : 1.0,
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            InkWell(
              onTap: () => onChanged(false),
              borderRadius: const BorderRadius.horizontal(left: Radius.circular(7)),
              child: Container(
                height: 32,
                alignment: Alignment.center,
                padding: const EdgeInsets.symmetric(horizontal: 7),
                decoration: BoxDecoration(
                  color: !isNot
                      ? theme.colorScheme.primaryContainer
                      : Colors.transparent,
                  borderRadius: const BorderRadius.horizontal(left: Radius.circular(7)),
                ),
                child: Text(
                  'AND',
                  style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                    color: !isNot
                        ? theme.colorScheme.onPrimaryContainer
                        : theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.7),
                  ),
                ),
              ),
            ),
            InkWell(
              onTap: () => onChanged(true),
              borderRadius: const BorderRadius.horizontal(right: Radius.circular(7)),
              child: Container(
                height: 32,
                alignment: Alignment.center,
                padding: const EdgeInsets.symmetric(horizontal: 7),
                decoration: BoxDecoration(
                  color: isNot
                      ? Colors.redAccent.withValues(alpha: 0.25)
                      : Colors.transparent,
                  borderRadius: const BorderRadius.horizontal(right: Radius.circular(7)),
                ),
                child: Text(
                  'NOT',
                  style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                    color: isNot
                        ? Colors.redAccent
                        : theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.7),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
