import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:packet_inspector/domain/models/packet_record.dart';
import 'package:packet_inspector/domain/models/custom_protocol_rule.dart';
import 'package:packet_inspector/domain/models/endpoint_rule.dart';
import 'package:packet_inspector/data/services/database/packet_database_service.dart';
import 'package:packet_inspector/data/services/storage/protocol_library_service.dart';
import 'package:packet_inspector/data/services/export/csv_export_service.dart';
import 'package:packet_inspector/data/repositories/packet_repository.dart';

void main() {
  group('PacketDatabaseService & Analytical Queries', () {
    late PacketDatabaseService dbService;

    setUp(() {
      dbService = PacketDatabaseService();
    });

    tearDown(() {
      dbService.close();
    });

    test('Batch insertion, flow rollups, and timeline bucket calculation', () {
      final packets = [
        PacketRecord(
          packetNo: 1,
          timestampUs: 1000000,
          globalDeltaUs: 0,
          streamDeltaUs: 0,
          flowHash: 111,
          ethType: 0x0800,
          srcIp: '192.168.1.10',
          dstIp: '8.8.8.8',
          ipProto: 17,
          srcPort: 54321,
          dstPort: 53,
          detectedProtocol: 'DNS',
          capturedLength: 60,
          originalLength: 60,
          fileByteOffset: 0,
          payloadFileOffset: 42,
          payloadLength: 18,
          payloadPreview: [0x12, 0x34],
          summary: 'DNS Query',
          triageStatus: TriageStatus.expected,
          isLanNoise: false,
        ),
        PacketRecord(
          packetNo: 2,
          timestampUs: 1010000,
          globalDeltaUs: 10000,
          streamDeltaUs: 10000,
          flowHash: 111,
          ethType: 0x0800,
          srcIp: '8.8.8.8',
          dstIp: '192.168.1.10',
          ipProto: 17,
          srcPort: 53,
          dstPort: 54321,
          detectedProtocol: 'DNS',
          capturedLength: 90,
          originalLength: 90,
          fileByteOffset: 60,
          payloadFileOffset: 102,
          payloadLength: 48,
          payloadPreview: [0x12, 0x34],
          summary: 'DNS Response',
          triageStatus: TriageStatus.expected,
          isLanNoise: false,
        ),
        PacketRecord(
          packetNo: 3,
          timestampUs: 1020000,
          globalDeltaUs: 10000,
          streamDeltaUs: 0,
          flowHash: 222,
          ethType: 0x0806,
          srcIp: '192.168.1.50',
          dstIp: '192.168.1.1',
          ipProto: 0,
          srcPort: null,
          dstPort: null,
          detectedProtocol: 'ARP',
          capturedLength: 42,
          originalLength: 42,
          fileByteOffset: 150,
          payloadFileOffset: 164,
          payloadLength: 28,
          payloadPreview: const [],
          summary: 'ARP Request',
          triageStatus: TriageStatus.expected,
          isLanNoise: true,
        ),
      ];

      dbService.insertPacketsBatch(packets);
      dbService.buildFlowsAndBuckets(bucketCount: 10);

      expect(dbService.getPacketCount(), equals(2)); // Default silenceLanChatter=true excludes ARP (packet 3)
      expect(dbService.getPacketCount(silenceLanChatter: false), equals(3));

      final flows = dbService.queryFlows();
      expect(flows.length, equals(2)); // 1 DNS flow, 1 ARP flow
      final dnsFlow = flows.firstWhere((f) => f.flowHash == 111);
      expect(dnsFlow.packetCount, equals(2));
      expect(dnsFlow.totalBytes, equals(150));

      final buckets = dbService.queryTimelineBuckets();
      expect(buckets.isNotEmpty, isTrue);
      expect(buckets.first.packetCount, greaterThan(0));
    });

    test('Quick-Filter Protocol Pill queries filter packets precisely', () {
      final packets = [
        PacketRecord(
          packetNo: 1,
          timestampUs: 1000,
          globalDeltaUs: 0,
          streamDeltaUs: 0,
          flowHash: 1,
          ethType: 0x0800,
          srcIp: '1.1.1.1',
          dstIp: '2.2.2.2',
          ipProto: 6,
          srcPort: 100,
          dstPort: 80,
          detectedProtocol: 'HTTP',
          capturedLength: 100,
          originalLength: 100,
          fileByteOffset: 0,
          payloadFileOffset: 54,
          payloadLength: 46,
          payloadPreview: const [],
          summary: 'HTTP GET',
          triageStatus: TriageStatus.expected,
          isLanNoise: false,
        ),
        PacketRecord(
          packetNo: 2,
          timestampUs: 2000,
          globalDeltaUs: 1000,
          streamDeltaUs: 0,
          flowHash: 2,
          ethType: 0x0800,
          srcIp: '1.1.1.1',
          dstIp: '8.8.8.8',
          ipProto: 17,
          srcPort: 54321,
          dstPort: 53,
          detectedProtocol: 'DNS',
          capturedLength: 50,
          originalLength: 50,
          fileByteOffset: 100,
          payloadFileOffset: 142,
          payloadLength: 8,
          payloadPreview: const [],
          summary: 'DNS Query',
          triageStatus: TriageStatus.expected,
          isLanNoise: false,
        ),
      ];

      dbService.insertPacketsBatch(packets);

      // In quick filter mode, selecting protocol 'DNS' returns only DNS packet
      final dnsResults = dbService.queryPackets(
        isTriageMode: false,
        protocolPills: {'DNS'},
      );
      expect(dnsResults.length, equals(1));
      expect(dnsResults.first.detectedProtocol, equals('DNS'));

      // Selecting protocol 'HTTP' returns only HTTP packet
      final httpResults = dbService.queryPackets(
        isTriageMode: false,
        protocolPills: {'HTTP'},
      );
      expect(httpResults.length, equals(1));
      expect(httpResults.first.detectedProtocol, equals('HTTP'));
    });

    test('Retroactive Custom Protocol re-labeling in SQLite', () {
      final packet = PacketRecord(
        packetNo: 1,
        timestampUs: 1000,
        globalDeltaUs: 0,
        streamDeltaUs: 0,
        flowHash: 123,
        ethType: 0x0800,
        srcIp: '192.168.1.10',
        dstIp: '192.168.1.200',
        ipProto: 17, // UDP
        srcPort: 45820,
        dstPort: 45820,
        detectedProtocol: 'UDP',
        capturedLength: 50,
        originalLength: 50,
        fileByteOffset: 0,
        payloadFileOffset: 42,
        payloadLength: 8,
        payloadPreview: [0x41, 0x43, 0x4D, 0x45, 0x00, 0x65], // 'ACME' + 101
        summary: '45820 -> 45820 Len=8',
        triageStatus: TriageStatus.unclassified,
        isLanNoise: false,
      );

      dbService.insertPacketsBatch([packet]);

      final before = dbService.queryPackets(isTriageMode: false);
      expect(before.first.detectedProtocol, equals('UDP'));

      // Define custom rule
      final rule = const CustomProtocolRule(
        id: 'acme_proto',
        name: 'ACME Telemetry',
        colorHex: 0xFF9C27B0,
        defaultTriageStatus: TriageStatus.expected,
        ipProtocol: 17,
        port: 45820,
        magicBytesOffset: 0,
        magicBytesHex: [0x41, 0x43, 0x4D, 0x45],
      );

      final updatedCount = dbService.relabelCustomProtocol(rule);
      expect(updatedCount, equals(1));

      final after = dbService.queryPackets(isTriageMode: false);
      expect(after.first.detectedProtocol, equals('ACME Telemetry'));
      expect(after.first.customProtocolId, equals('acme_proto'));
      expect(after.first.triageStatus, equals(TriageStatus.expected));
    });
  });

  group('CsvExportService Tests', () {
    test('Exports packets to valid CSV string', () {
      final packet = PacketRecord(
        packetNo: 1,
        timestampUs: 1500000,
        globalDeltaUs: 1200,
        streamDeltaUs: 3400,
        flowHash: 1,
        ethType: 0x0800,
        srcIp: '192.168.1.10',
        dstIp: '8.8.8.8',
        ipProto: 17,
        srcPort: 54321,
        dstPort: 53,
        detectedProtocol: 'DNS',
        capturedLength: 64,
        originalLength: 64,
        fileByteOffset: 0,
        payloadFileOffset: 42,
        payloadLength: 22,
        payloadPreview: const [],
        summary: 'DNS Query',
        triageStatus: TriageStatus.expected,
        isLanNoise: false,
      );

      final csv = CsvExportService.exportPacketsToCsv([packet]);
      expect(csv, contains('Packet No,Time (s),Global Delta (s)'));
      expect(csv, contains('192.168.1.10,8.8.8.8,DNS'));
    });
  });

  group('PacketRepository Tests', () {
    test('Loads Demo Capture and performs live queries and byte reading', () {
      final repo = PacketRepository();
      repo.loadDemoCapture();

      expect(repo.loadedFilePath, equals('demo_capture.pcap'));
      final totalPackets = repo.getPacketCount(silenceLanChatter: false);
      expect(totalPackets, greaterThanOrEqualTo(18));

      final protocolCounts = repo.getProtocolCounts();
      expect(protocolCounts.containsKey('DNS'), isTrue);
      expect(protocolCounts.containsKey('HTTP'), isTrue);
      expect(protocolCounts.containsKey('ARP'), isTrue);

      final timingSpikes = repo.getTimingAnomalies(isBurst: true, thresholdUs: 100);
      expect(timingSpikes.isNotEmpty, isTrue);

      // Verify on-demand raw byte reading
      final firstPacket = repo.queryPackets(limit: 1, silenceLanChatter: false).first;
      final rawBytes = repo.readRawPacketBytes(firstPacket);
      expect(rawBytes.length, equals(firstPacket.capturedLength));

      // Test column sorting in queryPackets
      final sortedDesc = repo.queryPackets(
        sortColumn: 'packet_no',
        sortAscending: false,
        silenceLanChatter: false,
      );
      expect(sortedDesc.first.packetNo, greaterThan(sortedDesc.last.packetNo));

      final sortedByLenAsc = repo.queryPackets(
        sortColumn: 'captured_length',
        sortAscending: true,
        silenceLanChatter: false,
      );
      expect(sortedByLenAsc.first.capturedLength, lessThanOrEqualTo(sortedByLenAsc.last.capturedLength));

      // Test baseline triage reclassification
      // Flag 10.99.88.77 as unexpected
      final updatedProfile = repo.baselineProfile.copyWith(
        unexpectedIps: {'10.99.88.77'},
      );
      repo.updateBaselineProfile(updatedProfile);

      final unexpectedCounts = repo.getTriageCounts(silenceLanChatter: false);
      expect(unexpectedCounts[TriageStatus.unexpected], greaterThanOrEqualTo(10));

      final unexpectedPackets = repo.queryPackets(
        isTriageMode: true,
        triageStatuses: {TriageStatus.unexpected},
        silenceLanChatter: false,
      );
      expect(unexpectedPackets.any((p) => p.srcIp == '10.99.88.77'), isTrue);
      expect(unexpectedPackets.first.triageStatus, equals(TriageStatus.unexpected));

      // Test direct packet triage assignment
      final targetPacketNo = unexpectedPackets.first.packetNo;
      repo.setPacketTriage(targetPacketNo, TriageStatus.expected);
      final reloadedPacket = repo.queryPackets(silenceLanChatter: false).firstWhere((p) => p.packetNo == targetPacketNo);
      expect(reloadedPacket.triageStatus, equals(TriageStatus.expected));

      // Test batch pagination query
      final page1 = repo.queryPackets(offset: 0, limit: 5, silenceLanChatter: false);
      expect(page1.length, equals(5));
      final page2 = repo.queryPackets(offset: 5, limit: 5, silenceLanChatter: false);
      expect(page2.length, equals(5));
      expect(page1.first.packetNo, isNot(equals(page2.first.packetNo)));

      repo.dispose();
    });

    test('Bandwidth throughput queries calculate bps and top ports', () {
      final repo = PacketRepository();
      repo.loadDemoCapture();

      final bps = repo.getCaptureBandwidthBps();
      expect(bps, greaterThan(0));

      final portBandwidths = repo.getPortBandwidth(limit: 5);
      expect(portBandwidths.isNotEmpty, isTrue);
      expect(portBandwidths.keys.first, isNotNull);
      expect(portBandwidths.values.first, greaterThan(0));

      repo.dispose();
    });

    test('Custom library bundle export and import round-trip', () {
      final tempDir1 = Directory.systemTemp.createTempSync('lib_test_1_');
      final tempDir2 = Directory.systemTemp.createTempSync('lib_test_2_');
      final repo = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir1),
      );
      repo.addCustomProtocol(const CustomProtocolRule(
        id: 'bundle_proto_1',
        name: 'ArtNet Broadcast',
        port: 6454,
        colorHex: 0xFF2196F3,
        defaultTriageStatus: TriageStatus.expected,
        ipProtocol: 17,
      ));
      repo.addSource(const EndpointRule(
        id: 'bundle_src_1',
        name: 'Console A',
        ipAddress: '10.0.0.100',
        port: 6454,
      ));
      repo.addDestination(const EndpointRule(
        id: 'bundle_dst_1',
        name: 'Node 1',
        ipAddress: '10.0.0.200',
        port: 6454,
        type: EndpointType.receiver,
      ));

      final exportedJson = repo.exportLibraryBundle();
      expect(exportedJson, contains('packet_inspector_library'));
      expect(exportedJson, contains('ArtNet Broadcast'));
      expect(exportedJson, contains('Console A'));
      expect(exportedJson, contains('Node 1'));

      final freshRepo = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir2),
      );
      final counts = freshRepo.importLibraryBundle(exportedJson);
      expect(counts['protocols'], equals(1));
      expect(counts['sources'], equals(1));
      expect(counts['destinations'], equals(1));
      expect(freshRepo.customRules.any((p) => p.name == 'ArtNet Broadcast'), isTrue);
      expect(freshRepo.sources.any((s) => s.name == 'Console A'), isTrue);
      expect(freshRepo.destinations.any((d) => d.name == 'Node 1'), isTrue);

      repo.dispose();
      freshRepo.dispose();
      try {
        tempDir1.deleteSync(recursive: true);
        tempDir2.deleteSync(recursive: true);
      } catch (_) {}
    });
  });
}
