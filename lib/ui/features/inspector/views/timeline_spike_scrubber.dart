import 'package:flutter/material.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:provider/provider.dart';
import '../view_models/inspector_view_model.dart';

enum TimelineMetricMode {
  burstRate, // Packet bursts / Traffic rate
  streamLatency, // Max stream delta (ms)
}

class TimelineSpikeScrubber extends StatefulWidget {
  const TimelineSpikeScrubber({super.key});

  @override
  State<TimelineSpikeScrubber> createState() => _TimelineSpikeScrubberState();
}

class _TimelineSpikeScrubberState extends State<TimelineSpikeScrubber> {
  TimelineMetricMode _metricMode = TimelineMetricMode.burstRate;

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<InspectorViewModel>();
    final buckets = vm.timelineBuckets;
    final isZoomed = vm.timeWindowStartUs != null || vm.timeWindowEndUs != null;

    if (buckets.isEmpty) {
      return const SizedBox.shrink();
    }

    return Container(
      height: 120,
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        border: Border(
          bottom: BorderSide(
            color: Theme.of(context).dividerColor.withValues(alpha: 0.3),
          ),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Header controls
          Row(
            children: [
              const Icon(Icons.show_chart, size: 16),
              const SizedBox(width: 6),
              const Text(
                'Delta-Time & Spike Timeline',
                style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12),
              ),
              const SizedBox(width: 16),

              // Metric view toggle
              SegmentedButton<TimelineMetricMode>(
                segments: const [
                  ButtonSegment(
                    value: TimelineMetricMode.burstRate,
                    label: Text('Traffic Bursts', style: TextStyle(fontSize: 11)),
                  ),
                  ButtonSegment(
                    value: TimelineMetricMode.streamLatency,
                    label: Text('Stream Latency (Stalls)', style: TextStyle(fontSize: 11)),
                  ),
                ],
                selected: {_metricMode},
                onSelectionChanged: (set) {
                  setState(() {
                    _metricMode = set.first;
                  });
                },
                style: const ButtonStyle(
                  visualDensity: VisualDensity.compact,
                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                ),
              ),

              const Spacer(),

              if (isZoomed)
                ActionChip(
                  avatar: const Icon(Icons.zoom_out, size: 14),
                  label: Text(
                    'Reset Zoom (${((vm.timeWindowStartUs ?? 0) / 1000000.0).toStringAsFixed(2)}s – ${((vm.timeWindowEndUs ?? 0) / 1000000.0).toStringAsFixed(2)}s)',
                    style: const TextStyle(fontSize: 11),
                  ),
                  onPressed: () => vm.resetTimeRange(),
                ),
            ],
          ),

          const SizedBox(height: 6),

          // Chart
          Expanded(
            child: BarChart(
              BarChartData(
                alignment: BarChartAlignment.spaceAround,
                barTouchData: BarTouchData(
                  touchTooltipData: BarTouchTooltipData(
                    getTooltipColor: (_) => Theme.of(context).colorScheme.inverseSurface,
                    getTooltipItem: (group, groupIndex, rod, rodIndex) {
                      if (groupIndex >= buckets.length) return null;
                      final b = buckets[groupIndex];
                      final metricTitle = _metricMode == TimelineMetricMode.burstRate
                          ? '${b.packetCount} pkts'
                          : '${b.maxStreamDeltaMs.toStringAsFixed(1)} ms stall';
                      return BarTooltipItem(
                        'Time: ${b.startSeconds.toStringAsFixed(2)}s\n$metricTitle\n${b.unexpectedCount} unexpected\n(Click to zoom)',
                        TextStyle(
                          color: Theme.of(context).colorScheme.onInverseSurface,
                          fontSize: 11,
                        ),
                      );
                    },
                  ),
                  touchCallback: (event, response) {
                    if (event is FlTapUpEvent && response != null && response.spot != null) {
                      final idx = response.spot!.touchedBarGroupIndex;
                      if (idx >= 0 && idx < buckets.length) {
                        final b = buckets[idx];
                        vm.setTimeRange(b.bucketStartUs, b.bucketEndUs);
                      }
                    }
                  },
                ),
                titlesData: const FlTitlesData(
                  topTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
                  rightTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
                  leftTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
                  bottomTitles: AxisTitles(
                    sideTitles: SideTitles(
                      showTitles: true,
                      reservedSize: 14,
                      interval: 1,
                    ),
                  ),
                ),
                borderData: FlBorderData(show: false),
                gridData: const FlGridData(show: false),
                barGroups: [
                  for (int i = 0; i < buckets.length; i++)
                    BarChartGroupData(
                      x: i,
                      barRods: [
                        BarChartRodData(
                          toY: _metricMode == TimelineMetricMode.burstRate
                              ? buckets[i].packetCount.toDouble()
                              : buckets[i].maxStreamDeltaMs,
                          color: buckets[i].unexpectedCount > 0
                              ? Colors.redAccent
                              : (_metricMode == TimelineMetricMode.burstRate
                                  ? Theme.of(context).colorScheme.primary
                                  : Colors.orangeAccent),
                          width: 4,
                          borderRadius: BorderRadius.circular(2),
                        ),
                      ],
                    ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
