/// Per-5-tuple flow loss, reordering, mutation, and latency summary across captures.
class FlowDiffSummary {
  const FlowDiffSummary({
    required this.flowHash,
    required this.srcIp,
    required this.dstIp,
    this.srcPort,
    this.dstPort,
    required this.protocolName,
    required this.totalSent,
    required this.hopDeliveredCounts,
    required this.droppedCount,
    required this.sourceGapCount,
    required this.outOfOrderCount,
    required this.mutatedCount,
    required this.spikeCount,
    required this.avgTransitDeltaUs,
    required this.maxTransitDeltaUs,
  });

  final int flowHash;
  final String srcIp;
  final String dstIp;
  final int? srcPort;
  final int? dstPort;
  final String protocolName;
  final int totalSent;
  final Map<int, int> hopDeliveredCounts;
  final int droppedCount;
  final int sourceGapCount;
  final int outOfOrderCount;
  final int mutatedCount;
  final int spikeCount;
  final double avgTransitDeltaUs;
  final int maxTransitDeltaUs;

  String get flowDisplay {
    final src = srcPort != null ? '$srcIp:$srcPort' : srcIp;
    final dst = dstPort != null ? '$dstIp:$dstPort' : dstIp;
    return '$protocolName • $src -> $dst';
  }

  double deliveryRateForHop(int captureIndex) {
    if (totalSent <= 0) return 0.0;
    final delivered = hopDeliveredCounts[captureIndex] ?? 0;
    return (delivered / totalSent) * 100.0;
  }
}
