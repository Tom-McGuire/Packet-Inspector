/// Represents a loaded capture file participating in a multi-capture diff session.
class CaptureSlot {
  const CaptureSlot({
    required this.captureIndex,
    required this.label,
    required this.filePath,
    required this.packetCount,
    this.clockOffsetUs = 0,
  });

  final int captureIndex;
  final String label;
  final String filePath;
  final int packetCount;
  final int clockOffsetUs;

  double get clockOffsetMs => clockOffsetUs / 1000.0;

  String get formattedClockOffset {
    if (captureIndex == 0) return 'Baseline (0.0 ms)';
    final ms = clockOffsetMs;
    final sign = ms >= 0 ? '+' : '';
    return '$sign${ms.toStringAsFixed(2)} ms';
  }

  CaptureSlot copyWith({
    int? captureIndex,
    String? label,
    String? filePath,
    int? packetCount,
    int? clockOffsetUs,
  }) {
    return CaptureSlot(
      captureIndex: captureIndex ?? this.captureIndex,
      label: label ?? this.label,
      filePath: filePath ?? this.filePath,
      packetCount: packetCount ?? this.packetCount,
      clockOffsetUs: clockOffsetUs ?? this.clockOffsetUs,
    );
  }
}
