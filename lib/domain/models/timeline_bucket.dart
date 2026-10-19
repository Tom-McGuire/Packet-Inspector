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
