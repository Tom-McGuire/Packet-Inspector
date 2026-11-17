import 'package:material_ui/material_ui.dart';
import 'package:provider/provider.dart';

import '../../../../core/theme/app_theme.dart';
import '../../../../domain/models/capture_slot.dart';
import '../../../../domain/models/packet_diff_record.dart';
import '../view_models/capture_compare_view_model.dart';

class DiffPacketTable extends StatefulWidget {
  const DiffPacketTable({super.key});

  @override
  State<DiffPacketTable> createState() => _DiffPacketTableState();
}

class _DiffPacketTableState extends State<DiffPacketTable> {
  static const double _rowHeight = 34.0;
  final ScrollController _scrollController = ScrollController();

  Color get _accentColor =>
      AppTheme.isDark ? const Color(0xFF38BDF8) : AppTheme.accent;

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  void _maybeScrollToRequested(CaptureCompareViewModel vm) {
    final target = vm.requestScrollToRowIndex;
    if (target == null) return;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      vm.consumeScrollRequest();
      if (_scrollController.hasClients) {
        final offset = (target * _rowHeight).clamp(
          0.0,
          _scrollController.position.maxScrollExtent,
        );
        _scrollController.animateTo(
          offset,
          duration: const Duration(milliseconds: 220),
          curve: Curves.easeOutCubic,
        );
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<CaptureCompareViewModel>();
    _maybeScrollToRequested(vm);

    final records = vm.visibleRecords;
    final slots = vm.slots;

    if (vm.isLoading) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircularProgressIndicator(color: _accentColor),
            const SizedBox(height: 12),
            Text(
              'Correlating captures across hops...',
              style: TextStyle(color: AppTheme.textSecondary, fontSize: 13),
            ),
          ],
        ),
      );
    }

    if (records.isEmpty) {
      return Center(
        child: Text(
          'No packets match the current diff filter.',
          style: TextStyle(color: AppTheme.textSecondary, fontSize: 13),
        ),
      );
    }

    return Column(
      children: [
        _buildHeader(slots),
        Expanded(
          child: ListView.builder(
            controller: _scrollController,
            itemCount: records.length,
            itemExtent: _rowHeight,
            itemBuilder: (context, index) {
              final record = records[index];
              final isSelected = vm.selectedRecord == record;
              return _buildRow(
                vm: vm,
                record: record,
                slots: slots,
                isSelected: isSelected,
                isEven: index.isEven,
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _buildHeader(List<CaptureSlot> slots) {
    return Container(
      height: 30,
      padding: const EdgeInsets.symmetric(horizontal: 10),
      decoration: BoxDecoration(
        color: AppTheme.surface,
        border: Border(
          bottom: BorderSide(color: AppTheme.border),
        ),
      ),
      child: Row(
        children: [
          const SizedBox(width: 54, child: _HeaderText('#')),
          const SizedBox(width: 82, child: _HeaderText('Protocol')),
          const Expanded(flex: 3, child: _HeaderText('Flow (Src -> Dst)')),
          const SizedBox(width: 68, child: _HeaderText('Seq')),
          for (final slot in slots)
            Expanded(
              flex: 2,
              child: _HeaderText(
                '${String.fromCharCode(65 + slot.captureIndex)}: ${slot.label}',
              ),
            ),
          const SizedBox(width: 86, child: _HeaderText('Transit Δt')),
          const SizedBox(width: 148, child: _HeaderText('Status')),
        ],
      ),
    );
  }

  Widget _buildRow({
    required CaptureCompareViewModel vm,
    required PacketDiffRecord record,
    required List<CaptureSlot> slots,
    required bool isSelected,
    required bool isEven,
  }) {
    final statusColor = _statusColor(record.primaryStatus);
    final bgColor = isSelected
        ? _accentColor.withValues(alpha: 0.16)
        : (record.primaryStatus != DiffStatus.ok
            ? statusColor.withValues(alpha: 0.06)
            : (isEven ? AppTheme.scaffoldBg : AppTheme.surfaceHigh));

    return InkWell(
      onTap: () => vm.selectRecord(record),
      child: Container(
        height: _rowHeight,
        padding: const EdgeInsets.symmetric(horizontal: 10),
        decoration: BoxDecoration(
          color: bgColor,
          border: Border(
            left: BorderSide(
              color: isSelected ? _accentColor : Colors.transparent,
              width: 3,
            ),
            bottom: BorderSide(color: AppTheme.border),
          ),
        ),
        child: Row(
          children: [
            SizedBox(
              width: 54,
              child: Text(
                '${record.rowIndex + 1}',
                style: TextStyle(
                  fontSize: 11,
                  color: AppTheme.textMuted,
                  fontFamily: 'monospace',
                ),
              ),
            ),
            SizedBox(
              width: 82,
              child: Text(
                record.protocolName,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  color: _accentColor,
                ),
              ),
            ),
            Expanded(
              flex: 3,
              child: Text(
                record.flowDisplay,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontSize: 11,
                  color: AppTheme.textPrimary,
                  fontFamily: 'monospace',
                ),
              ),
            ),
            SizedBox(
              width: 68,
              child: Text(
                record.extractedSeq?.toString() ?? '—',
                style: TextStyle(
                  fontSize: 11,
                  color: AppTheme.textSecondary,
                  fontFamily: 'monospace',
                ),
              ),
            ),
            for (final slot in slots)
              Expanded(
                flex: 2,
                child: _buildHopCell(record, record.hopMatches[slot.captureIndex]),
              ),
            SizedBox(
              width: 86,
              child: Text(
                _formatDelta(record.maxTransitDeltaUs),
                style: TextStyle(
                  fontSize: 11,
                  color: record.primaryStatus == DiffStatus.latencySpike
                      ? (AppTheme.isDark
                          ? const Color(0xFFFB923C)
                          : const Color(0xFFC2410C))
                      : AppTheme.textSecondary,
                  fontFamily: 'monospace',
                ),
              ),
            ),
            SizedBox(
              width: 148,
              child: Align(
                alignment: Alignment.centerLeft,
                child: Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 7,
                    vertical: 2,
                  ),
                  decoration: BoxDecoration(
                    color: statusColor.withValues(alpha: 0.16),
                    borderRadius: BorderRadius.circular(4),
                    border: Border.all(
                      color: statusColor.withValues(alpha: 0.45),
                    ),
                  ),
                  child: Text(
                    _statusLabel(record.primaryStatus),
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      fontSize: 10,
                      fontWeight: FontWeight.w700,
                      color: statusColor,
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildHopCell(PacketDiffRecord record, HopMatch? match) {
    if (match == null) {
      return Text(
        'MISSING',
        style: TextStyle(
          fontSize: 10,
          fontWeight: FontWeight.w700,
          color: AppTheme.error,
          fontFamily: 'monospace',
        ),
      );
    }
    final hasMutation = match.dscpValue != record.baselineDscp ||
        match.vlanId != record.baselineVlanId;
    return Text(
      'Frame #${match.frameNumber}',
      overflow: TextOverflow.ellipsis,
      style: TextStyle(
        fontSize: 11,
        color: hasMutation
            ? (AppTheme.isDark ? AppTheme.warning : const Color(0xFFB45309))
            : AppTheme.textSecondary,
        fontFamily: 'monospace',
      ),
    );
  }

  String _formatDelta(int? us) {
    if (us == null) return '—';
    final ms = us / 1000.0;
    return '${ms >= 0 ? '+' : ''}${ms.toStringAsFixed(2)} ms';
  }

  String _statusLabel(DiffStatus status) {
    return switch (status) {
      DiffStatus.ok => 'OK',
      DiffStatus.dropped => 'DROPPED',
      DiffStatus.sourceGap => 'SOURCE GAP',
      DiffStatus.outOfOrder => 'OUT OF ORDER',
      DiffStatus.qosVlanMutated => 'QOS / VLAN MUTATED',
      DiffStatus.latencySpike => 'LATENCY SPIKE',
      DiffStatus.injected => 'INJECTED',
    };
  }

  Color _statusColor(DiffStatus status) {
    return switch (status) {
      DiffStatus.ok => AppTheme.success,
      DiffStatus.dropped => AppTheme.error,
      DiffStatus.sourceGap =>
        AppTheme.isDark ? const Color(0xFFF43F5E) : const Color(0xFFE11D48),
      DiffStatus.outOfOrder =>
        AppTheme.isDark ? const Color(0xFFA855F7) : const Color(0xFF9333EA),
      DiffStatus.qosVlanMutated =>
        AppTheme.isDark ? AppTheme.warning : const Color(0xFFB45309),
      DiffStatus.latencySpike =>
        AppTheme.isDark ? const Color(0xFFFB923C) : const Color(0xFFC2410C),
      DiffStatus.injected => _accentColor,
    };
  }
}

class _HeaderText extends StatelessWidget {
  const _HeaderText(this.text);

  final String text;

  @override
  Widget build(BuildContext context) {
    return Text(
      text,
      overflow: TextOverflow.ellipsis,
      style: TextStyle(
        fontSize: 11,
        fontWeight: FontWeight.w700,
        color: AppTheme.textSecondary,
      ),
    );
  }
}
