import 'package:flutter_test/flutter_test.dart';
import 'package:packet_inspector/domain/models/packet_record.dart';
import 'package:packet_inspector/data/services/database/packet_database_service.dart';
import 'package:packet_inspector/data/services/export/csv_export_service.dart';

void main() {
  group('CsvExportService Tests', () {
    test('exportPacketsToCsv exports headers and formatted rows', () {
      final packets = [
        const PacketRecord(
          packetNo: 1,
          timestampUs: 1000000,
          globalDeltaUs: 1500,
          streamDeltaUs: 2500,
          flowHash: 111,
          ethType: 0x0800,
          srcIp: '192.168.1.5',
          dstIp: '8.8.8.8',
          ipProto: 17,
          srcPort: 54321,
          dstPort: 53,
          detectedProtocol: 'DNS',
          capturedLength: 72,
          originalLength: 72,
          fileByteOffset: 0,
          payloadFileOffset: 42,
          payloadLength: 30,
          payloadPreview: [0x01, 0x02],
          summary: 'Standard query "google.com", type A',
          triageStatus: TriageStatus.expected,
          isLanNoise: false,
        ),
      ];

      final csv = CsvExportService.exportPacketsToCsv(packets);
      expect(csv, contains('Packet No'));
      expect(csv, contains('Time (s)'));
      expect(csv, contains('192.168.1.5'));
      expect(csv, contains('8.8.8.8'));
      expect(csv, contains('DNS'));
      expect(csv, contains('54321'));
      expect(csv, contains('53'));
      expect(csv, contains('Expected'));
      expect(csv, contains('No'));
      expect(csv, contains('Standard query ""google.com"", type A'));
    });

    test('exportFlowsToCsv exports aggregated flows correctly', () {
      final flows = [
        const FlowSummary(
          flowHash: 999,
          srcIp: '10.0.0.1',
          dstIp: '10.0.0.2',
          srcPort: 8080,
          dstPort: 443,
          ipProto: 6,
          protocol: 'TCP',
          packetCount: 42,
          totalBytes: 15000,
          minDeltaUs: 200,
          maxDeltaUs: 8000,
          avgDeltaUs: 1500.5,
          firstSeenUs: 1000000,
          lastSeenUs: 2000000,
        ),
      ];

      final csv = CsvExportService.exportFlowsToCsv(flows);
      expect(csv, contains('Flow Hash'));
      expect(csv, contains('Packet Count'));
      expect(csv, contains('Total Bytes'));
      expect(csv, contains('999'));
      expect(csv, contains('10.0.0.1'));
      expect(csv, contains('10.0.0.2'));
      expect(csv, contains('8080'));
      expect(csv, contains('443'));
      expect(csv, contains('42'));
      expect(csv, contains('15000'));
      expect(csv, contains('0.200')); // minDelta in ms
      expect(csv, contains('8.000')); // maxDelta in ms
    });

    test('exportTableToCsv exports arbitrary tabular data', () {
      final headers = ['ColA', 'ColB', 'ColC'];
      final rows = [
        ['val1', 123, 45.6],
        ['comma, test', 'quote "test"', 'newline\ntest'],
      ];

      final csv = CsvExportService.exportTableToCsv(
        headers: headers,
        dataRows: rows,
      );

      expect(csv, contains('ColA,ColB,ColC'));
      expect(csv, contains('val1,123,45.6'));
      expect(csv, contains('"comma, test"'));
      expect(csv, contains('"quote ""test"""'));
    });

    test('exports gracefully handle empty collections', () {
      final emptyPacketsCsv = CsvExportService.exportPacketsToCsv(<PacketRecord>[]);
      expect(emptyPacketsCsv, contains('Packet No'));

      final emptyFlowsCsv = CsvExportService.exportFlowsToCsv(<FlowSummary>[]);
      expect(emptyFlowsCsv, contains('Flow Hash'));

      final emptyTableCsv = CsvExportService.exportTableToCsv(
        headers: ['Header1'],
        dataRows: [],
      );
      expect(emptyTableCsv, equals('Header1'));
    });
  });
}
