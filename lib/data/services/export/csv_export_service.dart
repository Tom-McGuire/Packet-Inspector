import 'package:csv/csv.dart';
import '../../../domain/models/packet_record.dart';
import '../database/packet_database_service.dart';

class CsvExportService {
  static String exportPacketsToCsv(List<PacketRecord> packets) {
    final rows = <List<dynamic>>[
      [
        'Packet No',
        'Time (s)',
        'Global Delta (s)',
        'Stream Delta (s)',
        'Source IP',
        'Dest IP',
        'Protocol',
        'Source Port',
        'Dest Port',
        'Length',
        'Triage Status',
        'LAN Noise',
        'Summary',
      ],
      ...packets.map((p) => [
            p.packetNo,
            p.timestampSeconds.toStringAsFixed(6),
            p.globalDeltaSeconds.toStringAsFixed(6),
            p.streamDeltaSeconds.toStringAsFixed(6),
            p.srcIp,
            p.dstIp,
            p.detectedProtocol,
            p.srcPort ?? '',
            p.dstPort ?? '',
            p.capturedLength,
            p.triageStatus.displayName,
            p.isLanNoise ? 'Yes' : 'No',
            p.summary,
          ]),
    ];

    return Csv().encode(rows);
  }

  static String exportFlowsToCsv(List<FlowSummary> flows) {
    final rows = <List<dynamic>>[
      [
        'Flow Hash',
        'Source IP',
        'Dest IP',
        'Source Port',
        'Dest Port',
        'Protocol',
        'Packet Count',
        'Total Bytes',
        'Min Delta (ms)',
        'Max Delta (ms)',
        'Avg Delta (ms)',
        'First Seen (s)',
        'Last Seen (s)',
      ],
      ...flows.map((f) => [
            f.flowHash,
            f.srcIp,
            f.dstIp,
            f.srcPort ?? '',
            f.dstPort ?? '',
            f.protocol,
            f.packetCount,
            f.totalBytes,
            (f.minDeltaUs / 1000.0).toStringAsFixed(3),
            (f.maxDeltaUs / 1000.0).toStringAsFixed(3),
            (f.avgDeltaUs / 1000.0).toStringAsFixed(3),
            (f.firstSeenUs / 1000000.0).toStringAsFixed(6),
            (f.lastSeenUs / 1000000.0).toStringAsFixed(6),
          ]),
    ];

    return Csv().encode(rows);
  }

  static String exportTableToCsv({
    required List<String> headers,
    required List<List<dynamic>> dataRows,
  }) {
    final rows = <List<dynamic>>[
      headers,
      ...dataRows,
    ];
    return Csv().encode(rows);
  }
}
