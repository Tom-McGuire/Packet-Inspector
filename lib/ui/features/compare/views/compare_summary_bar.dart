import 'package:material_ui/material_ui.dart';
import 'package:provider/provider.dart';

import '../../../../core/theme/app_theme.dart';
import '../../../../domain/models/packet_diff_record.dart';
import '../view_models/capture_compare_view_model.dart';

class CompareSummaryBar extends StatelessWidget {
  const CompareSummaryBar({super.key});

  Color get _accentColor =>
      AppTheme.isDark ? const Color(0xFF38BDF8) : AppTheme.accent;

  Color get _sourceGapColor =>
      AppTheme.isDark ? const Color(0xFFF43F5E) : const Color(0xFFE11D48);

  Color get _oooColor =>
      AppTheme.isDark ? const Color(0xFFA855F7) : const Color(0xFF9333EA);

  Color get _mutatedColor =>
      AppTheme.isDark ? AppTheme.warning : const Color(0xFFB45309);

  Color get _spikeColor =>
      AppTheme.isDark ? const Color(0xFFFB923C) : const Color(0xFFC2410C);

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<CaptureCompareViewModel>();
    final slots = vm.slots;
    if (slots.isEmpty) return const SizedBox.shrink();

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: AppTheme.surface,
        border: Border(
          bottom: BorderSide(color: AppTheme.border),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Wrap(
            spacing: 12,
            runSpacing: 8,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              _buildMetricPill(
                label: 'Correlated',
                value: '${vm.totalModePacketCount}',
                color: _accentColor,
              ),
              for (final slot in slots)
                _buildHopBadge(
                  index: slot.captureIndex,
                  label: slot.label,
                  deliveryPercent: vm.deliveryPercentForHop(slot.captureIndex),
                  clockOffset: slot.formattedClockOffset,
                ),
              const SizedBox(width: 4),
              _buildFilterModeDropdown(vm),
              if (vm.flowSummaries.isNotEmpty) _buildFlowDropdown(vm),
              _buildLatencyDropdown(vm),
              if (vm.droppedCount > 0)
                ElevatedButton.icon(
                  onPressed: vm.jumpToFirstDrop,
                  icon: const Icon(Icons.south_east_rounded, size: 14),
                  label: const Text('Jump to First Drop'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppTheme.error,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(
                      horizontal: 10,
                      vertical: 6,
                    ),
                    minimumSize: const Size(0, 28),
                    textStyle: const TextStyle(
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
            ],
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 6,
            children: [
              _buildStatusChip(
                vm: vm,
                filter: DiffStatusFilter.all,
                label: 'All (${vm.totalModePacketCount})',
                color: AppTheme.textSecondary,
              ),
              _buildStatusChip(
                vm: vm,
                filter: DiffStatusFilter.droppedOnly,
                label: 'Dropped (${vm.droppedCount})',
                color: AppTheme.error,
              ),
              _buildStatusChip(
                vm: vm,
                filter: DiffStatusFilter.sourceGaps,
                label: 'Source Gaps (${vm.sourceGapCount})',
                color: _sourceGapColor,
              ),
              _buildStatusChip(
                vm: vm,
                filter: DiffStatusFilter.outOfOrder,
                label: 'Out of Order (${vm.outOfOrderCount})',
                color: _oooColor,
              ),
              _buildStatusChip(
                vm: vm,
                filter: DiffStatusFilter.mutated,
                label: 'QoS / VLAN Mutated (${vm.mutatedCount})',
                color: _mutatedColor,
              ),
              _buildStatusChip(
                vm: vm,
                filter: DiffStatusFilter.latencySpikes,
                label: 'Latency Spikes (${vm.spikeCount})',
                color: _spikeColor,
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildMetricPill({
    required String label,
    required String value,
    required Color color,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: color.withValues(alpha: 0.35)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            '$label: ',
            style: TextStyle(fontSize: 11, color: AppTheme.textSecondary),
          ),
          Text(
            value,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w700,
              color: color,
              fontFamily: 'monospace',
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildHopBadge({
    required int index,
    required String label,
    required double deliveryPercent,
    required String clockOffset,
  }) {
    final isHealthy = deliveryPercent >= 99.9;
    final color = index == 0
        ? _accentColor
        : (isHealthy ? AppTheme.success : _mutatedColor);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: AppTheme.scaffoldBg,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: AppTheme.border),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            '${String.fromCharCode(65 + index)}: $label',
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w600,
              color: AppTheme.textPrimary,
            ),
          ),
          const SizedBox(width: 6),
          Text(
            '${deliveryPercent.toStringAsFixed(1)}%',
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w700,
              color: color,
              fontFamily: 'monospace',
            ),
          ),
          if (index > 0) ...[
            const SizedBox(width: 6),
            Text(
              '($clockOffset)',
              style: TextStyle(
                fontSize: 10,
                color: AppTheme.textMuted,
                fontFamily: 'monospace',
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildFilterModeDropdown(CaptureCompareViewModel vm) {
    return Container(
      height: 28,
      padding: const EdgeInsets.symmetric(horizontal: 8),
      decoration: BoxDecoration(
        color: AppTheme.scaffoldBg,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: AppTheme.border),
      ),
      child: DropdownButtonHideUnderline(
        child: DropdownButton<DiffFilterMode>(
          value: vm.filterMode,
          dropdownColor: AppTheme.surface,
          iconEnabledColor: AppTheme.textSecondary,
          style: TextStyle(fontSize: 11, color: AppTheme.textPrimary),
          isDense: true,
          onChanged: (mode) {
            if (mode != null) vm.setFilterMode(mode);
          },
          items: const [
            DropdownMenuItem(
              value: DiffFilterMode.sharedFlowsOnly,
              child: Text('Shared Flows Only'),
            ),
            DropdownMenuItem(
              value: DiffFilterMode.selectedFlow,
              child: Text('Selected Flow'),
            ),
            DropdownMenuItem(
              value: DiffFilterMode.fullDiff,
              child: Text('Full Diff (Include Noise)'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFlowDropdown(CaptureCompareViewModel vm) {
    final selectedValue = vm.selectedFlowHash ?? vm.flowSummaries.first.flowHash;
    return Container(
      height: 28,
      padding: const EdgeInsets.symmetric(horizontal: 8),
      decoration: BoxDecoration(
        color: AppTheme.scaffoldBg,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: AppTheme.border),
      ),
      child: DropdownButtonHideUnderline(
        child: DropdownButton<int>(
          value: vm.flowSummaries.any((f) => f.flowHash == selectedValue)
              ? selectedValue
              : vm.flowSummaries.first.flowHash,
          dropdownColor: AppTheme.surface,
          iconEnabledColor: AppTheme.textSecondary,
          style: TextStyle(fontSize: 11, color: AppTheme.textPrimary),
          isDense: true,
          onChanged: (hash) {
            if (hash == null) return;
            vm.setSelectedFlowHash(hash);
            if (vm.filterMode != DiffFilterMode.selectedFlow) {
              vm.setFilterMode(DiffFilterMode.selectedFlow);
            }
          },
          items: vm.flowSummaries.map((f) {
            final src = f.srcPort != null ? '${f.srcIp}:${f.srcPort}' : f.srcIp;
            final dst = f.dstPort != null ? '${f.dstIp}:${f.dstPort}' : f.dstIp;
            return DropdownMenuItem<int>(
              value: f.flowHash,
              child: Text(
                '${f.protocolName} $src -> $dst (${f.totalSent})',
                overflow: TextOverflow.ellipsis,
              ),
            );
          }).toList(),
        ),
      ),
    );
  }

  Widget _buildLatencyDropdown(CaptureCompareViewModel vm) {
    const thresholds = [2.0, 5.0, 10.0, 25.0, 50.0];
    return Container(
      height: 28,
      padding: const EdgeInsets.symmetric(horizontal: 8),
      decoration: BoxDecoration(
        color: AppTheme.scaffoldBg,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: AppTheme.border),
      ),
      child: DropdownButtonHideUnderline(
        child: DropdownButton<double>(
          value: thresholds.contains(vm.latencyThresholdMs)
              ? vm.latencyThresholdMs
              : 10.0,
          dropdownColor: AppTheme.surface,
          iconEnabledColor: AppTheme.textSecondary,
          style: TextStyle(fontSize: 11, color: AppTheme.textPrimary),
          isDense: true,
          onChanged: (val) {
            if (val != null) vm.setLatencyThresholdMs(val);
          },
          items: thresholds
              .map(
                (t) => DropdownMenuItem<double>(
                  value: t,
                  child: Text('Spike > ${t.toInt()} ms'),
                ),
              )
              .toList(),
        ),
      ),
    );
  }

  Widget _buildStatusChip({
    required CaptureCompareViewModel vm,
    required DiffStatusFilter filter,
    required String label,
    required Color color,
  }) {
    final isSelected = vm.statusFilter == filter;
    return InkWell(
      onTap: () => vm.setStatusFilter(filter),
      borderRadius: BorderRadius.circular(14),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
        decoration: BoxDecoration(
          color: isSelected
              ? color.withValues(alpha: 0.22)
              : AppTheme.scaffoldBg,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(
            color: isSelected ? color : AppTheme.border,
          ),
        ),
        child: Text(
          label,
          style: TextStyle(
            fontSize: 11,
            fontWeight: isSelected ? FontWeight.w700 : FontWeight.w500,
            color: isSelected ? color : AppTheme.textSecondary,
          ),
        ),
      ),
    );
  }
}
