import 'package:sqlite3/sqlite3.dart';

/// Estimates clock skew between Baseline Capture 0 and downstream Capture N
/// by taking the median timestamp delta of the first 100 matched packet pairs.
class ClockSkewEstimator {
  static int estimateClockOffsetUs(
    Database db, {
    required int targetCaptureIndex,
    int sampleLimit = 100,
  }) {
    if (targetCaptureIndex == 0) return 0;

    final result = db.select(
      '''
      SELECT (b.timestamp_us - a.timestamp_us) AS raw_delta_us
      FROM diff_packets a
      INNER JOIN diff_packets b
        ON a.flow_hash = b.flow_hash
        AND a.fingerprint_hash = b.fingerprint_hash
        AND a.occurrence_index = b.occurrence_index
      WHERE a.capture_index = 0
        AND b.capture_index = ?
      ORDER BY a.frame_number ASC
      LIMIT ?
      ''',
      [targetCaptureIndex, sampleLimit],
    );

    if (result.isEmpty) return 0;

    final deltas = result
        .map((row) => row['raw_delta_us'] as int)
        .toList()
      ..sort();

    final mid = deltas.length ~/ 2;
    if (deltas.length.isOdd) {
      return deltas[mid];
    } else {
      return ((deltas[mid - 1] + deltas[mid]) / 2).round();
    }
  }
}
