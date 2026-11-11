class TimelineBucket {
  const TimelineBucket({
    required this.bucketIndex,
    required this.bucketStartUs,
    required this.bucketEndUs,
    required this.packetCount,
    required this.totalBytes,
    required this.minGlobalDeltaUs,
    required this.maxStreamDeltaUs,
    required this.avgStreamDeltaUs,
    required this.unexpectedCount,
  });

  final int bucketIndex;
  final int bucketStartUs;
  final int bucketEndUs;
  final int packetCount;
  final int totalBytes;
  final int minGlobalDeltaUs;
  final int maxStreamDeltaUs;
  final double avgStreamDeltaUs;
  final int unexpectedCount;

  double get startSeconds => bucketStartUs / 1000000.0;
  double get endSeconds => bucketEndUs / 1000000.0;
  double get minGlobalDeltaMs => minGlobalDeltaUs / 1000.0;
  double get maxStreamDeltaMs => maxStreamDeltaUs / 1000.0;

  DateTime get dateTime => DateTime.fromMicrosecondsSinceEpoch(bucketStartUs);

  String get formattedDateTime {
    final dt = DateTime.fromMicrosecondsSinceEpoch(bucketStartUs);
    final y = dt.year.toString().padLeft(4, '0');
    final m = dt.month.toString().padLeft(2, '0');
    final d = dt.day.toString().padLeft(2, '0');
    final h = dt.hour.toString().padLeft(2, '0');
    final min = dt.minute.toString().padLeft(2, '0');
    final s = dt.second.toString().padLeft(2, '0');
    final ms = dt.millisecond.toString().padLeft(3, '0');
    return '$y-$m-$d $h:$min:$s.$ms';
  }

  double get durationSeconds {
    final diff = bucketEndUs - bucketStartUs;
    return diff > 0 ? diff / 1000000.0 : 1.0;
  }

  double get bytesPerSecond => durationSeconds > 0 ? totalBytes / durationSeconds : 0.0;
  double get bitsPerSecond => bytesPerSecond * 8.0;
  double get kbps => bitsPerSecond / 1000.0;
  double get mbps => bitsPerSecond / 1000000.0;

  String get formattedBandwidth {
    if (mbps >= 1.0) {
      return '${mbps.toStringAsFixed(2)} Mbps';
    } else if (kbps >= 1.0) {
      return '${kbps.toStringAsFixed(1)} Kbps';
    } else {
      return '${bitsPerSecond.toStringAsFixed(0)} bps';
    }
  }

  Map<String, dynamic> toMap() => {
        'bucket_index': bucketIndex,
        'bucket_start_us': bucketStartUs,
        'bucket_end_us': bucketEndUs,
        'packet_count': packetCount,
        'total_bytes': totalBytes,
        'min_global_delta_us': minGlobalDeltaUs,
        'max_stream_delta_us': maxStreamDeltaUs,
        'avg_stream_delta_us': avgStreamDeltaUs,
        'unexpected_count': unexpectedCount,
      };

  factory TimelineBucket.fromMap(Map<String, dynamic> map) => TimelineBucket(
        bucketIndex: map['bucket_index'] as int,
        bucketStartUs: map['bucket_start_us'] as int,
        bucketEndUs: map['bucket_end_us'] as int,
        packetCount: map['packet_count'] as int? ?? 0,
        totalBytes: map['total_bytes'] as int? ?? 0,
        minGlobalDeltaUs: map['min_global_delta_us'] as int? ?? 0,
        maxStreamDeltaUs: map['max_stream_delta_us'] as int? ?? 0,
        avgStreamDeltaUs: (map['avg_stream_delta_us'] as num?)?.toDouble() ?? 0.0,
        unexpectedCount: map['unexpected_count'] as int? ?? 0,
      );
}
