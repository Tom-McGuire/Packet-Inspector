import 'package:material_ui/material_ui.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:provider/provider.dart';
import '../view_models/inspector_view_model.dart';

enum TimelineMetricMode {
  burstRate, // Packet bursts / Traffic rate
  streamLatency, // Max stream delta (ms)
  bandwidth, // Bandwidth throughput (Kbps / Mbps)
}

class TimelineSpikeScrubber extends StatefulWidget {
  const TimelineSpikeScrubber({super.key});

  @override
  State<TimelineSpikeScrubber> createState() => _TimelineSpikeScrubberState();
}

class _TimelineSpikeScrubberState extends State<TimelineSpikeScrubber> {
  TimelineMetricMode _metricMode = TimelineMetricMode.burstRate;
  Offset? _pointerDownPos;
  int? _dragStartIdx;
  int? _dragEndIdx;

  int _bucketIndexForDx(double dx, double width, int bucketCount) {
    if (bucketCount <= 0 || width <= 0) return 0;
    final clamped = dx.clamp(0.0, width - 0.001);
    return ((clamped / width) * bucketCount).floor().clamp(0, bucketCount - 1);
  }

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
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
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
                      label: Text('Bursts', style: TextStyle(fontSize: 11)),
                    ),
                    ButtonSegment(
                      value: TimelineMetricMode.streamLatency,
                      label: Text('Latency (Stalls)', style: TextStyle(fontSize: 11)),
                    ),
                    ButtonSegment(
                      value: TimelineMetricMode.bandwidth,
                      label: Text('Bandwidth', style: TextStyle(fontSize: 11)),
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
                const SizedBox(width: 12),

                // Bandwidth summary indicator
                Tooltip(
                  message: vm.portBandwidths.isNotEmpty
                      ? 'Top Ports by Bandwidth:\n${vm.portBandwidths.entries.take(5).map((e) => 'Port ${e.key}: ${InspectorViewModel.formatBandwidth(e.value)}').join('\n')}'
                      : 'Average and peak throughput across capture',
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                    decoration: BoxDecoration(
                      color: Colors.teal.withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(6),
                      border: Border.all(color: Colors.teal.withValues(alpha: 0.3)),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.speed, size: 13, color: Colors.teal),
                        const SizedBox(width: 4),
                        Text(
                          'Bandwidth: Avg ${vm.formattedAvgBandwidth} • Peak ${vm.formattedPeakBandwidth}',
                          style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.teal),
                        ),
                      ],
                    ),
                  ),
                ),

                if (isZoomed) ...[
                  const SizedBox(width: 12),
                  ActionChip(
                    avatar: const Icon(Icons.zoom_out, size: 14),
                    label: Text(
                      'Reset Zoom (${((vm.timeWindowStartUs ?? 0) / 1000000.0).toStringAsFixed(2)}s – ${((vm.timeWindowEndUs ?? 0) / 1000000.0).toStringAsFixed(2)}s)',
                      style: const TextStyle(fontSize: 11),
                    ),
                    onPressed: () => vm.resetTimeRange(),
                  ),
                ],
              ],
            ),
          ),

          const SizedBox(height: 6),

          // Chart
          Expanded(
            child: LayoutBuilder(
              builder: (context, constraints) {
                final chartWidth = constraints.maxWidth;
                final hasBrush = _dragStartIdx != null && _dragEndIdx != null;
                final minIdx = hasBrush
                    ? (_dragStartIdx! < _dragEndIdx! ? _dragStartIdx! : _dragEndIdx!)
                    : 0;
                final maxIdx = hasBrush
                    ? (_dragStartIdx! > _dragEndIdx! ? _dragStartIdx! : _dragEndIdx!)
                    : 0;
                final brushLeft = hasBrush && buckets.isNotEmpty
                    ? (minIdx / buckets.length) * chartWidth
                    : 0.0;
                final brushWidth = hasBrush && buckets.isNotEmpty
                    ? (((maxIdx - minIdx + 1) / buckets.length) * chartWidth)
                        .clamp(2.0, chartWidth - brushLeft)
                    : 0.0;

                return Listener(
                  behavior: HitTestBehavior.translucent,
                  onPointerDown: (event) {
                    _pointerDownPos = event.localPosition;
                  },
                  onPointerMove: (event) {
                    if (_pointerDownPos == null) return;
                    if (_dragStartIdx == null &&
                        (event.localPosition.dx - _pointerDownPos!.dx).abs() > 8.0) {
                      final startIdx = _bucketIndexForDx(
                        _pointerDownPos!.dx,
                        chartWidth,
                        buckets.length,
                      );
                      final endIdx = _bucketIndexForDx(
                        event.localPosition.dx,
                        chartWidth,
                        buckets.length,
                      );
                      setState(() {
                        _dragStartIdx = startIdx;
                        _dragEndIdx = endIdx;
                      });
                    } else if (_dragStartIdx != null) {
                      final idx = _bucketIndexForDx(
                        event.localPosition.dx,
                        chartWidth,
                        buckets.length,
                      );
                      if (idx != _dragEndIdx) {
                        setState(() => _dragEndIdx = idx);
                      }
                    }
                  },
                  onPointerUp: (_) {
                    _pointerDownPos = null;
                    if (_dragStartIdx != null && _dragEndIdx != null && buckets.isNotEmpty) {
                      final sIdx = _dragStartIdx! < _dragEndIdx! ? _dragStartIdx! : _dragEndIdx!;
                      final eIdx = _dragStartIdx! > _dragEndIdx! ? _dragStartIdx! : _dragEndIdx!;
                      final startBucket = buckets[sIdx];
                      final endBucket = buckets[eIdx];
                      setState(() {
                        _dragStartIdx = null;
                        _dragEndIdx = null;
                      });
                      vm.setTimeRange(startBucket.bucketStartUs, endBucket.bucketEndUs);
                    } else {
                      setState(() {
                        _dragStartIdx = null;
                        _dragEndIdx = null;
                      });
                    }
                  },
                  onPointerCancel: (_) {
                    _pointerDownPos = null;
                    setState(() {
                      _dragStartIdx = null;
                      _dragEndIdx = null;
                    });
                  },
                  child: Stack(
                    children: [
                      BarChart(
                        BarChartData(
                          alignment: BarChartAlignment.spaceAround,
                          barTouchData: BarTouchData(
                            touchTooltipData: BarTouchTooltipData(
                              getTooltipColor: (_) => Theme.of(context).colorScheme.inverseSurface,
                              getTooltipItem: (group, groupIndex, rod, rodIndex) {
                                if (groupIndex >= buckets.length) return null;
                                final b = buckets[groupIndex];
                                final String metricTitle;
                                if (_metricMode == TimelineMetricMode.burstRate) {
                                  metricTitle = '${b.packetCount} pkts';
                                } else if (_metricMode == TimelineMetricMode.streamLatency) {
                                  metricTitle = '${b.maxStreamDeltaMs.toStringAsFixed(1)} ms stall';
                                } else {
                                  metricTitle = 'Bandwidth: ${b.formattedBandwidth}\nRate: ${(b.bytesPerSecond / 1024.0).toStringAsFixed(1)} KB/s (${b.totalBytes} B)';
                                }
                                return BarTooltipItem(
                                  'Time: ${b.formattedDateTime}\n$metricTitle\n${b.unexpectedCount} unexpected\n(Click or drag to zoom)',
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
                                        : (_metricMode == TimelineMetricMode.streamLatency
                                            ? buckets[i].maxStreamDeltaMs
                                            : (vm.peakBucketBandwidthBps >= 1000000.0 ? buckets[i].mbps : buckets[i].kbps)),
                                    color: buckets[i].unexpectedCount > 0
                                        ? Colors.redAccent
                                        : (_metricMode == TimelineMetricMode.burstRate
                                            ? Theme.of(context).colorScheme.primary
                                            : (_metricMode == TimelineMetricMode.streamLatency
                                                ? Colors.orangeAccent
                                                : Colors.teal)),
                                    width: 4,
                                    borderRadius: BorderRadius.circular(2),
                                  ),
                                ],
                              ),
                          ],
                        ),
                      ),
                      if (hasBrush)
                        Positioned(
                          key: const Key('timeline_brush_overlay'),
                          left: brushLeft,
                          top: 0,
                          bottom: 14,
                          width: brushWidth,
                          child: IgnorePointer(
                            child: Container(
                              decoration: BoxDecoration(
                                color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.18),
                                border: Border.symmetric(
                                  vertical: BorderSide(
                                    color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.7),
                                    width: 1.5,
                                  ),
                                ),
                              ),
                            ),
                          ),
                        ),
                    ],
                  ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}
