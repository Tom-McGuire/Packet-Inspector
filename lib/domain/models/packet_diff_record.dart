import 'dart:typed_data';

/// Fault / correlation classification for a packet across captures.
enum DiffStatus {
  ok,
  dropped,
  sourceGap,
  outOfOrder,
  qosVlanMutated,
  latencySpike,
  injected,
}

/// Filter modes for multi-capture background noise suppression.
enum DiffFilterMode {
  sharedFlowsOnly,
  selectedFlow,
  fullDiff,
}

/// Status filter chips for the Diff summary bar.
enum DiffStatusFilter {
  all,
  droppedOnly,
  sourceGaps,
  outOfOrder,
  mutated,
  latencySpikes,
}

/// Match information for a single packet within a downstream capture hop.
class HopMatch {
  const HopMatch({
    required this.captureIndex,
    required this.frameNumber,
    required this.timestampUs,
    required this.transitDeltaUs,
    this.dscpValue,
    this.vlanId,
    this.rawBytes,
  });

  final int captureIndex;
  final int frameNumber;
  final int timestampUs;
  final int transitDeltaUs;
  final int? dscpValue;
  final int? vlanId;
  final Uint8List? rawBytes;

  double get transitDeltaMs => transitDeltaUs / 1000.0;
}

/// A unified correlated packet row spanning Baseline Capture 0 and hops 1..N.
class PacketDiffRecord {
  const PacketDiffRecord({
    required this.rowIndex,
    required this.flowHash,
    required this.fingerprintHash,
    required this.occurrenceIndex,
    required this.srcIp,
    required this.dstIp,
    this.srcPort,
    this.dstPort,
    required this.protocolName,
    this.extractedSeq,
    required this.baselineCaptureIndex,
    required this.baselineFrameNumber,
    required this.baselineTimestampUs,
    this.baselineDscp,
    this.baselineVlanId,
    required this.packetLength,
    required this.hopMatches,
    required this.statuses,
    required this.primaryStatus,
    this.maxTransitDeltaUs,
    required this.statusDetail,
    this.baselineRawBytes,
  });

  final int rowIndex;
  final int flowHash;
  final int fingerprintHash;
  final int occurrenceIndex;
  final String srcIp;
  final String dstIp;
  final int? srcPort;
  final int? dstPort;
  final String protocolName;
  final int? extractedSeq;
  final int baselineCaptureIndex;
  final int baselineFrameNumber;
  final int baselineTimestampUs;
  final int? baselineDscp;
  final int? baselineVlanId;
  final int packetLength;
  final Map<int, HopMatch> hopMatches;
  final Set<DiffStatus> statuses;
  final DiffStatus primaryStatus;
  final int? maxTransitDeltaUs;
  final String statusDetail;
  final Uint8List? baselineRawBytes;

  String get flowDisplay {
    final src = srcPort != null ? '$srcIp:$srcPort' : srcIp;
    final dst = dstPort != null ? '$dstIp:$dstPort' : dstIp;
    return '$src -> $dst';
  }

  String get formattedTransitDelta {
    if (maxTransitDeltaUs == null) return '—';
    final ms = maxTransitDeltaUs! / 1000.0;
    final sign = ms >= 0 ? '+' : '';
    return '$sign${ms.toStringAsFixed(2)} ms';
  }

  static String dscpLabel(int? dscp) {
    if (dscp == null) return '—';
    switch (dscp) {
      case 46:
        return 'EF (46)';
      case 34:
        return 'AF41 (34)';
      case 26:
        return 'AF31 (26)';
      case 18:
        return 'AF21 (18)';
      case 10:
        return 'AF11 (10)';
      case 0:
        return 'CS0 (0)';
      default:
        return 'DSCP $dscp';
    }
  }
}
