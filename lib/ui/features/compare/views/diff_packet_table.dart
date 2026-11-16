import 'package:material_ui/material_ui.dart';
import 'package:provider/provider.dart';

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
      return const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircularProgressIndicator(color: Color(0xFF38BDF8)),
            SizedBox(height: 12),
            Text(
              'Correlating captures across hops...',
              style: TextStyle(color: Colors.white70, fontSize: 13),
            ),
          ],
        ),
      );
    }

    if (records.isEmpty) {
      return const Center(
        child: Text(
          'No packets match the current diff filter.',
          style: TextStyle(color: Colors.white54, fontSize: 13),
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
        color: const Color(0xFF161B22),
        border: Border(
          bottom: BorderSide(color: Colors.white.withValues(alpha: 0.1)),
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
        ? const Color(0xFF38BDF8).withValues(alpha: 0.16)
        : (record.primaryStatus != DiffStatus.ok
            ? statusColor.withValues(alpha: 0.06)
            : (isEven ? const Color(0xFF0D1117) : const Color(0xFF11161E)));

    return InkWell(
      onTap: () => vm.selectRecord(record),
      child: Container(
        height: _rowHeight,
        padding: const EdgeInsets.symmetric(horizontal: 10),
        decoration: BoxDecoration(
          color: bgColor,
          border: Border(
            left: BorderSide(
              color: isSelected ? const Color(0xFF38BDF8) : Colors.transparent,
              width: 3,
            ),
            bottom: BorderSide(color: Colors.white.withValues(alpha: 0.05)),
          ),
        ),
        child: Row(
          children: [
            SizedBox(
              width: 54,
              child: Text(
                '${record.rowIndex + 1}',
                style: const TextStyle(
                  fontSize: 11,
                  color: Colors.white54,
                  fontFamily: 'monospace',
                ),
              ),
            ),
            SizedBox(
              width: 82,
              child: Text(
                record.protocolName,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  color: Color(0xFF38BDF8),
                ),
              ),
            ),
            Expanded(
              flex: 3,
              child: Text(
                record.flowDisplay,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(
                  fontSize: 11,
                  color: Colors.white,
                  fontFamily: 'monospace',
                ),
              ),
            ),
            SizedBox(
              width: 68,
              child: Text(
                record.extractedSeq?.toString() ?? '—',
                style: const TextStyle(
                  fontSize: 11,
                  color: Colors.white70,
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
                      ? const Color(0xFFFB923C)
                      : Colors.white70,
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
      return const Text(
        'MISSING',
        style: TextStyle(
          fontSize: 10,
          fontWeight: FontWeight.w700,
          color: Color(0xFFEF4444),
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
        color: hasMutation ? const Color(0xFFF59E0B) : Colors.white70,
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
      DiffStatus.ok => const Color(0xFF10B981),
      DiffStatus.dropped => const Color(0xFFEF4444),
      DiffStatus.sourceGap => const Color(0xFFF43F5E),
      DiffStatus.outOfOrder => const Color(0xFFA855F7),
      DiffStatus.qosVlanMutated => const Color(0xFFF59E0B),
      DiffStatus.latencySpike => const Color(0xFFFB923C),
      DiffStatus.injected => const Color(0xFF38BDF8),
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
      style: const TextStyle(
        fontSize: 11,
        fontWeight: FontWeight.w700,
        color: Colors.white60,
      ),
    );
  }
}
