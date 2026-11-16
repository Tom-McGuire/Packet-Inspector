import 'package:material_ui/material_ui.dart';
import 'package:provider/provider.dart';

import '../../../../domain/models/packet_diff_record.dart';
import '../view_models/capture_compare_view_model.dart';

class DiffTimelineScrubber extends StatelessWidget {
  const DiffTimelineScrubber({super.key});

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<CaptureCompareViewModel>();
    final records = vm.visibleRecords;

    if (records.isEmpty) {
      return const SizedBox.shrink();
    }

    return Container(
      height: 36,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: const Color(0xFF0D1117),
        border: Border(
          bottom: BorderSide(color: Colors.white.withValues(alpha: 0.08)),
        ),
      ),
      child: Row(
        children: [
          const Text(
            'DIFF TIMELINE',
            style: TextStyle(
              fontSize: 10,
              fontWeight: FontWeight.w700,
              color: Colors.white54,
              letterSpacing: 0.6,
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: LayoutBuilder(
              builder: (context, constraints) {
                final width = constraints.maxWidth.clamp(1.0, 4000.0);
                final bucketCount =
                    (width / 6).floor().clamp(1, records.length);

                return GestureDetector(
                  behavior: HitTestBehavior.opaque,
                  onTapDown: (details) {
                    final ratio =
                        (details.localPosition.dx / width).clamp(0.0, 0.9999);
                    final targetIdx = (ratio * records.length).floor();
                    vm.jumpToRowIndex(targetIdx);
                  },
                  child: CustomPaint(
                    size: Size(width, 24),
                    painter: _DiffScrubberPainter(
                      records: records,
                      bucketCount: bucketCount,
                      selectedRowIndex: vm.selectedRecord != null
                          ? records.indexOf(vm.selectedRecord!)
                          : -1,
                    ),
                  ),
                );
              },
            ),
          ),
          const SizedBox(width: 10),
          _legendDot(const Color(0xFF10B981), 'OK'),
          const SizedBox(width: 8),
          _legendDot(const Color(0xFFEF4444), 'Drop'),
          const SizedBox(width: 8),
          _legendDot(const Color(0xFFF59E0B), 'Mutated'),
          const SizedBox(width: 8),
          _legendDot(const Color(0xFFA855F7), 'OOO'),
          const SizedBox(width: 8),
          _legendDot(const Color(0xFFFB923C), 'Spike'),
        ],
      ),
    );
  }

  Widget _legendDot(Color color, String label) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 7,
          height: 7,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
        const SizedBox(width: 4),
        Text(
          label,
          style: const TextStyle(fontSize: 10, color: Colors.white54),
        ),
      ],
    );
  }
}

class _DiffScrubberPainter extends CustomPainter {
  _DiffScrubberPainter({
    required this.records,
    required this.bucketCount,
    required this.selectedRowIndex,
  });

  final List<PacketDiffRecord> records;
  final int bucketCount;
  final int selectedRowIndex;

  @override
  void paint(Canvas canvas, Size size) {
    final bgPaint = Paint()..color = const Color(0xFF161B22);
    canvas.drawRRect(
      RRect.fromRectAndRadius(
        Offset.zero & size,
        const Radius.circular(4),
      ),
      bgPaint,
    );

    if (records.isEmpty || bucketCount <= 0) return;

    final barWidth = size.width / bucketCount;
    for (var b = 0; b < bucketCount; b++) {
      final start = (b * records.length / bucketCount).floor();
      final end = (((b + 1) * records.length) / bucketCount)
          .ceil()
          .clamp(start + 1, records.length);

      var severity = 0; // 0=ok, 1=spike, 2=mutated, 3=ooo, 4=drop/gap
      for (var i = start; i < end; i++) {
        final s = _severityOf(records[i].primaryStatus);
        if (s > severity) severity = s;
        if (severity == 4) break;
      }

      final color = switch (severity) {
        4 => const Color(0xFFEF4444),
        3 => const Color(0xFFA855F7),
        2 => const Color(0xFFF59E0B),
        1 => const Color(0xFFFB923C),
        _ => const Color(0xFF10B981).withValues(alpha: 0.45),
      };

      final heightFactor = severity == 0 ? 0.35 : 0.85;
      final barHeight = size.height * heightFactor;
      final rect = Rect.fromLTWH(
        b * barWidth + 0.5,
        size.height - barHeight,
        (barWidth - 1.0).clamp(1.0, barWidth),
        barHeight,
      );
      canvas.drawRect(rect, Paint()..color = color);
    }

    if (selectedRowIndex >= 0 && selectedRowIndex < records.length) {
      final x = ((selectedRowIndex + 0.5) / records.length) * size.width;
      canvas.drawLine(
        Offset(x, 0),
        Offset(x, size.height),
        Paint()
          ..color = const Color(0xFF38BDF8)
          ..strokeWidth = 2,
      );
    }
  }

  int _severityOf(DiffStatus status) {
    return switch (status) {
      DiffStatus.dropped || DiffStatus.sourceGap => 4,
      DiffStatus.outOfOrder => 3,
      DiffStatus.qosVlanMutated => 2,
      DiffStatus.latencySpike => 1,
      DiffStatus.injected => 2,
      DiffStatus.ok => 0,
    };
  }

  @override
  bool shouldRepaint(covariant _DiffScrubberPainter oldDelegate) {
    return oldDelegate.records != records ||
        oldDelegate.bucketCount != bucketCount ||
        oldDelegate.selectedRowIndex != selectedRowIndex;
  }
}
