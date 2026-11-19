import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:packet_inspector/domain/models/packet_record.dart';
import 'package:packet_inspector/domain/models/custom_protocol_rule.dart';
import 'package:packet_inspector/domain/models/baseline_profile.dart';
import 'package:packet_inspector/domain/models/endpoint_rule.dart';
import 'package:packet_inspector/data/services/database/packet_database_service.dart';
import 'package:packet_inspector/data/services/parser/demo_pcap_generator.dart';
import 'package:packet_inspector/data/services/storage/ai_settings_storage_service.dart';
import 'package:packet_inspector/data/services/storage/protocol_library_service.dart';
import 'package:packet_inspector/data/services/storage/shared_device_database.dart';
import 'package:packet_inspector/data/services/ai/llm_provider_service.dart';
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
        protocolPills: {'DNS'},
      );
      expect(dnsResults.length, equals(1));
      expect(dnsResults.first.detectedProtocol, equals('DNS'));

      // Selecting protocol 'HTTP' returns only HTTP packet
      final httpResults = dbService.queryPackets(
        protocolPills: {'HTTP'},
      );
      expect(httpResults.length, equals(1));
      expect(httpResults.first.detectedProtocol, equals('HTTP'));

      // Test combining triage with protocol and NOT inversion
      final combinedExpectedHttp = dbService.queryPackets(
        triageStatuses: {TriageStatus.expected},
        protocolPills: {'HTTP'},
      );
      expect(combinedExpectedHttp.length, equals(1));

      // Inverted protocol: NOT HTTP (returns DNS)
      final notHttp = dbService.queryPackets(
        protocolPills: {'HTTP'},
        isProtocolNot: true,
      );
      expect(notHttp.length, equals(1));
      expect(notHttp.first.detectedProtocol, equals('DNS'));

      // Source Search Box: positive and NOT
      final srcSearchMatch = dbService.queryPackets(
        sourceSearch: '1.1.1.1:100',
      );
      expect(srcSearchMatch.length, equals(1));
      expect(srcSearchMatch.first.srcIp, equals('1.1.1.1'));
      expect(srcSearchMatch.first.srcPort, equals(100));

      final srcSearchNot = dbService.queryPackets(
        sourceSearch: '1.1.1.1:100',
        isSourceSearchNot: true,
      );
      expect(srcSearchNot.length, equals(1));
      expect(srcSearchNot.first.detectedProtocol, equals('DNS'));

      // Destination Search Box: positive and NOT
      final dstSearchMatch = dbService.queryPackets(
        destSearch: '8.8.8.8',
      );
      expect(dstSearchMatch.length, equals(1));
      expect(dstSearchMatch.first.dstIp, equals('8.8.8.8'));

      final dstSearchNot = dbService.queryPackets(
        destSearch: '8.8.8.8',
        isDestSearchNot: true,
      );
      expect(dstSearchNot.length, equals(1));
      expect(dstSearchNot.first.dstIp, equals('2.2.2.2'));
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

      final before = dbService.queryPackets();
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

      final updatedCount = dbService.relabelAllCustomProtocols([rule]);
      expect(updatedCount, equals(1));

      final after = dbService.queryPackets();
      expect(after.first.detectedProtocol, equals('ACME Telemetry'));
      expect(after.first.customProtocolId, equals('acme_proto'));
      expect(after.first.triageStatus, equals(TriageStatus.expected));
      expect(after.first.baseProtocol, equals('UDP'));
      expect(after.first.baseSummary, equals('45820 -> 45820 Len=8'));
      expect(after.first.summary, contains('Len=8'));
    });

    test('customFields persist in SQLite and stale [Field=...] clears on rule edit (F4)', () {
      final packet = PacketRecord(
        packetNo: 1,
        timestampUs: 1000,
        globalDeltaUs: 0,
        streamDeltaUs: 0,
        flowHash: 123,
        ethType: 0x0800,
        srcIp: '192.168.1.10',
        dstIp: '192.168.1.200',
        ipProto: 17,
        srcPort: 45820,
        dstPort: 45820,
        detectedProtocol: 'ACME Telemetry',
        capturedLength: 58,
        originalLength: 58,
        fileByteOffset: 0,
        payloadFileOffset: 42,
        payloadLength: 16,
        payloadPreview: const [0x41, 0x43, 0x4D, 0x45, 0x00, 0x65, 0x00, 0x0D, 0x7C, 0x07],
        summary: 'ACME Telemetry [CommandID=101]',
        triageStatus: TriageStatus.expected,
        isLanNoise: false,
        customProtocolId: 'acme_proto',
        customFields: const {'CommandID': 101},
        baseProtocol: 'UDP',
        baseSummary: '45820 → 45820 Len=16',
      );

      dbService.insertPacketsBatch([packet]);

      final loaded = dbService.queryPackets();
      expect(loaded.first.customFields['CommandID'], equals(101));
      expect(loaded.first.baseProtocol, equals('UDP'));
      expect(loaded.first.baseSummary, equals('45820 → 45820 Len=16'));

      // Edit rule to remove fieldSlices -> stale [CommandID=101] must clear and Len=16 must be used
      const fieldlessRule = CustomProtocolRule(
        id: 'acme_proto',
        name: 'ACME Telemetry',
        colorHex: 0xFF9C27B0,
        defaultTriageStatus: TriageStatus.expected,
        ipProtocol: 17,
        port: 45820,
        magicBytesOffset: 0,
        magicBytesHex: [0x41, 0x43, 0x4D, 0x45],
      );

      final editedCount = dbService.relabelAllCustomProtocols([fieldlessRule]);
      expect(editedCount, equals(1));

      final afterEdit = dbService.queryPackets();
      expect(afterEdit.first.customFields, isEmpty);
      expect(afterEdit.first.summary, isNot(contains('CommandID')));
      expect(afterEdit.first.summary, contains('Len=16'));

      // Re-add fieldSlices -> customFields and summary restore
      const withSliceRule = CustomProtocolRule(
        id: 'acme_proto',
        name: 'ACME Telemetry',
        colorHex: 0xFF9C27B0,
        defaultTriageStatus: TriageStatus.expected,
        ipProtocol: 17,
        port: 45820,
        magicBytesOffset: 0,
        magicBytesHex: [0x41, 0x43, 0x4D, 0x45],
        fieldSlices: [
          ProtocolFieldSlice(
            name: 'CommandID',
            byteOffset: 4,
            byteLength: 2,
            dataType: FieldDataType.uint16Be,
          ),
        ],
      );
      expect(dbService.relabelAllCustomProtocols([withSliceRule]), equals(1));
      final afterReAdd = dbService.queryPackets();
      expect(afterReAdd.first.customFields['CommandID'], equals(101));
      expect(afterReAdd.first.summary, contains('CommandID=101'));
    });

    test('relabelAllCustomProtocols restores base L7 protocol, summary, and triage when rules are deleted or narrowed (F4)', () {
      final dnsPacket = PacketRecord(
        packetNo: 1,
        timestampUs: 1000,
        globalDeltaUs: 0,
        streamDeltaUs: 0,
        flowHash: 1,
        ethType: 0x0800,
        srcIp: '192.168.1.10',
        dstIp: '8.8.8.8',
        ipProto: 17,
        srcPort: 54321,
        dstPort: 53,
        detectedProtocol: 'CustomDNS',
        capturedLength: 64,
        originalLength: 64,
        fileByteOffset: 0,
        payloadFileOffset: 42,
        payloadLength: 22,
        payloadPreview: const [0x12, 0x34, 0x01, 0x00],
        summary: 'CustomDNS [TxID=4660]',
        triageStatus: TriageStatus.unexpected,
        isLanNoise: false,
        customProtocolId: 'custom_dns',
        customFields: const {'TxID': 4660},
        baseProtocol: 'DNS',
        baseSummary: 'DNS Standard query, 1 questions',
      );
      final acmePacket = PacketRecord(
        packetNo: 2,
        timestampUs: 2000,
        globalDeltaUs: 1000,
        streamDeltaUs: 0,
        flowHash: 2,
        ethType: 0x0800,
        srcIp: '192.168.1.10',
        dstIp: '192.168.1.200',
        ipProto: 17,
        srcPort: 45820,
        dstPort: 45820,
        detectedProtocol: 'ACME',
        capturedLength: 58,
        originalLength: 58,
        fileByteOffset: 64,
        payloadFileOffset: 106,
        payloadLength: 16,
        payloadPreview: const [0x41, 0x43, 0x4D, 0x45],
        summary: '45820 → 45820 [ACME] Len=16',
        triageStatus: TriageStatus.expected,
        isLanNoise: false,
        customProtocolId: 'acme_rule',
        baseProtocol: 'UDP',
        baseSummary: '45820 → 45820 Len=16',
      );

      dbService.insertPacketsBatch([dnsPacket, acmePacket]);

      const baseline = BaselineProfile(
        id: 'b1',
        name: 'Strict',
        expectedProtocols: {'DNS'},
        silenceLanChatter: false,
      );
      const acmeRule = CustomProtocolRule(
        id: 'acme_rule',
        name: 'ACME',
        colorHex: 0xFF9C27B0,
        defaultTriageStatus: TriageStatus.expected,
        ipProtocol: 17,
        port: 45820,
        magicBytesOffset: 0,
        magicBytesHex: [0x41, 0x43, 0x4D, 0x45],
      );

      // Partial rule deletion: remove custom_dns while keeping acmeRule -> packet 1 must restore to DNS
      final partialUpdated = dbService.relabelAllCustomProtocols(
        [acmeRule],
        baselineProfile: baseline,
      );
      expect(partialUpdated, equals(1));

      final afterPartial = dbService.queryPackets();
      expect(afterPartial[0].detectedProtocol, equals('DNS'));
      expect(afterPartial[0].summary, equals('DNS Standard query, 1 questions'));
      expect(afterPartial[0].customProtocolId, isNull);
      expect(afterPartial[0].customFields, isEmpty);
      expect(afterPartial[0].triageStatus, equals(TriageStatus.expected));
      expect(afterPartial[1].detectedProtocol, equals('ACME'));

      // Full rule deletion: rules.isEmpty -> packet 2 must restore to UDP & unclassified
      final emptyUpdated = dbService.relabelAllCustomProtocols(
        const [],
        baselineProfile: baseline,
      );
      expect(emptyUpdated, equals(1));

      final afterEmpty = dbService.queryPackets();
      expect(afterEmpty[1].detectedProtocol, equals('UDP'));
      expect(afterEmpty[1].summary, equals('45820 → 45820 Len=16'));
      expect(afterEmpty[1].customProtocolId, isNull);
      expect(afterEmpty[1].customFields, isEmpty);
      expect(afterEmpty[1].triageStatus, equals(TriageStatus.unclassified));
    });

    test('Parameterized queries return accurate buckets, top endpoints, bandwidth, and triage filters (F22)', () {
      final packets = [
        PacketRecord(
          packetNo: 1,
          timestampUs: 1000000,
          globalDeltaUs: 0,
          streamDeltaUs: 0,
          flowHash: 1,
          ethType: 0x0800,
          srcIp: '10.0.0.1',
          dstIp: '10.0.0.2',
          ipProto: 17,
          srcPort: 5000,
          dstPort: 53,
          detectedProtocol: 'DNS',
          capturedLength: 100,
          originalLength: 100,
          fileByteOffset: 0,
          payloadFileOffset: 42,
          payloadLength: 58,
          payloadPreview: const [],
          summary: 'DNS',
          triageStatus: TriageStatus.expected,
          isLanNoise: false,
        ),
        PacketRecord(
          packetNo: 2,
          timestampUs: 2000000,
          globalDeltaUs: 1000000,
          streamDeltaUs: 1000000,
          flowHash: 2,
          ethType: 0x0800,
          srcIp: '10.0.0.3',
          dstIp: '10.0.0.4',
          ipProto: 6,
          srcPort: 40000,
          dstPort: 443,
          detectedProtocol: 'TLS',
          capturedLength: 200,
          originalLength: 200,
          fileByteOffset: 100,
          payloadFileOffset: 154,
          payloadLength: 146,
          payloadPreview: const [],
          summary: 'TLS',
          triageStatus: TriageStatus.unexpected,
          isLanNoise: false,
        ),
        PacketRecord(
          packetNo: 3,
          timestampUs: 3000000,
          globalDeltaUs: 1000000,
          streamDeltaUs: 1000000,
          flowHash: 2,
          ethType: 0x0800,
          srcIp: '10.0.0.3',
          dstIp: '10.0.0.4',
          ipProto: 6,
          srcPort: 40000,
          dstPort: 443,
          detectedProtocol: 'TLS',
          capturedLength: 300,
          originalLength: 300,
          fileByteOffset: 300,
          payloadFileOffset: 354,
          payloadLength: 246,
          payloadPreview: const [],
          summary: 'TLS',
          triageStatus: TriageStatus.unclassified,
          isLanNoise: false,
        ),
      ];

      dbService.insertPacketsBatch(packets);
      dbService.buildFlowsAndBuckets(bucketCount: 4);

      final buckets = dbService.queryTimelineBuckets();
      expect(buckets.isNotEmpty, isTrue);
      expect(buckets.fold<int>(0, (sum, b) => sum + b.packetCount), equals(3));

      final topSenders = dbService.queryTopSenders(limit: 1);
      expect(topSenders.length, equals(1));
      expect(topSenders['10.0.0.3'], equals(2));

      final topReceivers = dbService.queryTopReceivers(limit: 1);
      expect(topReceivers.length, equals(1));
      expect(topReceivers['10.0.0.4'], equals(2));

      final portBw = dbService.queryPortBandwidth(limit: 1);
      expect(portBw.length, equals(1));
      expect(portBw.containsKey(443), isTrue);

      final filteredTriage = dbService.queryPackets(
        triageStatuses: {TriageStatus.expected, TriageStatus.unexpected},
      );
      expect(filteredTriage.map((p) => p.packetNo).toList(), equals([1, 2]));
    });

    test('countPacketsForEndpoints matches countPacketsForEndpoint across IP, IP:port, and overlapping keys (F19)', () {
      final packets = [
        PacketRecord(
          packetNo: 1,
          timestampUs: 1000,
          globalDeltaUs: 0,
          streamDeltaUs: 0,
          flowHash: 1,
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
          payloadPreview: const [],
          summary: 'DNS',
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
          srcIp: '192.168.1.10',
          dstIp: '1.1.1.1',
          ipProto: 6,
          srcPort: 55000,
          dstPort: 443,
          detectedProtocol: 'TLS',
          capturedLength: 100,
          originalLength: 100,
          fileByteOffset: 60,
          payloadFileOffset: 114,
          payloadLength: 46,
          payloadPreview: const [],
          summary: 'TLS',
          triageStatus: TriageStatus.expected,
          isLanNoise: false,
        ),
        PacketRecord(
          packetNo: 3,
          timestampUs: 3000,
          globalDeltaUs: 1000,
          streamDeltaUs: 0,
          flowHash: 3,
          ethType: 0x0800,
          srcIp: '192.168.1.20',
          dstIp: '8.8.8.8',
          ipProto: 17,
          srcPort: 60000,
          dstPort: 53,
          detectedProtocol: 'DNS',
          capturedLength: 60,
          originalLength: 60,
          fileByteOffset: 160,
          payloadFileOffset: 202,
          payloadLength: 18,
          payloadPreview: const [],
          summary: 'DNS',
          triageStatus: TriageStatus.expected,
          isLanNoise: false,
        ),
      ];
      dbService.insertPacketsBatch(packets);

      expect(
        dbService.countPacketsForEndpoints(endpointKeys: const [], isSender: true),
        isEmpty,
      );

      final senderKeys = [
        '192.168.1.10',
        '192.168.1.10:54321',
        '192.168.1.10:9999',
        '192.168.1.20:60000',
      ];
      final batchedSenders = dbService.countPacketsForEndpoints(
        endpointKeys: senderKeys,
        isSender: true,
      );
      expect(batchedSenders['192.168.1.10'], equals(dbService.countPacketsForEndpoint(ip: '192.168.1.10', isSender: true)));
      expect(batchedSenders['192.168.1.10:54321'], equals(dbService.countPacketsForEndpoint(ip: '192.168.1.10', port: 54321, isSender: true)));
      expect(batchedSenders['192.168.1.10:9999'], equals(0));
      expect(batchedSenders['192.168.1.20:60000'], equals(dbService.countPacketsForEndpoint(ip: '192.168.1.20', port: 60000, isSender: true)));

      final receiverKeys = ['8.8.8.8', '8.8.8.8:53', '1.1.1.1:443'];
      final batchedReceivers = dbService.countPacketsForEndpoints(
        endpointKeys: receiverKeys,
        isSender: false,
      );
      expect(batchedReceivers['8.8.8.8'], equals(2));
      expect(batchedReceivers['8.8.8.8:53'], equals(2));
      expect(batchedReceivers['1.1.1.1:443'], equals(1));
    });

    test('IPv6 endpoint keys with numeric hextets, EndpointRule.filterKey, [ipv6]:port, and search filters count and filter accurately', () {
      const linkLocal = 'fe80:0:0:0:1234:5678:9abc:def0';
      const multicast = 'ff02:0:0:0:0:0:0:1';
      const compressed = '2001:db8::1';

      final packets = [
        PacketRecord(
          packetNo: 1,
          timestampUs: 1000,
          globalDeltaUs: 0,
          streamDeltaUs: 0,
          flowHash: 10,
          ethType: 0x86DD,
          srcIp: linkLocal,
          dstIp: multicast,
          ipProto: 17,
          srcPort: 5353,
          dstPort: 5353,
          detectedProtocol: 'mDNS',
          capturedLength: 80,
          originalLength: 80,
          fileByteOffset: 0,
          payloadFileOffset: 62,
          payloadLength: 18,
          payloadPreview: const [],
          summary: 'mDNS IPv6',
          triageStatus: TriageStatus.expected,
          isLanNoise: false,
        ),
        PacketRecord(
          packetNo: 2,
          timestampUs: 2000,
          globalDeltaUs: 1000,
          streamDeltaUs: 0,
          flowHash: 11,
          ethType: 0x86DD,
          srcIp: linkLocal,
          dstIp: compressed,
          ipProto: 6,
          srcPort: 54000,
          dstPort: 443,
          detectedProtocol: 'TLS',
          capturedLength: 100,
          originalLength: 100,
          fileByteOffset: 80,
          payloadFileOffset: 154,
          payloadLength: 26,
          payloadPreview: const [],
          summary: 'TLS IPv6',
          triageStatus: TriageStatus.expected,
          isLanNoise: false,
        ),
      ];
      dbService.insertPacketsBatch(packets);

      const rulePortless = EndpointRule(
        id: 'v6_plain',
        name: 'LinkLocal',
        ipAddress: linkLocal,
      );
      const ruleWithPort = EndpointRule(
        id: 'v6_port',
        name: 'LinkLocal mDNS',
        ipAddress: linkLocal,
        port: 5353,
      );

      final senderCounts = dbService.countPacketsForEndpoints(
        endpointKeys: [
          rulePortless.filterKey,
          ruleWithPort.filterKey,
          '[$linkLocal]:5353',
          '$linkLocal:9999',
        ],
        isSender: true,
      );
      expect(senderCounts[linkLocal], equals(dbService.countPacketsForEndpoint(ip: linkLocal, isSender: true)));
      expect(senderCounts[linkLocal], equals(2));
      expect(senderCounts[ruleWithPort.filterKey], equals(dbService.countPacketsForEndpoint(ip: linkLocal, port: 5353, isSender: true)));
      expect(senderCounts[ruleWithPort.filterKey], equals(1));
      expect(senderCounts['[$linkLocal]:5353'], equals(1));
      expect(senderCounts['$linkLocal:9999'], equals(0));

      final receiverCounts = dbService.countPacketsForEndpoints(
        endpointKeys: [multicast, compressed, '[$compressed]:443'],
        isSender: false,
      );
      expect(receiverCounts[multicast], equals(1));
      expect(receiverCounts[compressed], equals(1));
      expect(receiverCounts['[$compressed]:443'], equals(1));

      expect(dbService.queryPackets(senderFilters: {linkLocal}).length, equals(2));
      expect(dbService.queryPackets(senderFilters: {ruleWithPort.filterKey}).map((p) => p.packetNo), equals([1]));
      expect(dbService.queryPackets(senderFilters: {'[$linkLocal]:5353'}).map((p) => p.packetNo), equals([1]));
      expect(dbService.queryPackets(receiverFilters: {multicast}).map((p) => p.packetNo), equals([1]));
      expect(dbService.queryPackets(receiverFilters: {compressed}, isReceiverNot: true).map((p) => p.packetNo), equals([1]));
      expect(dbService.queryPackets(sourceSearch: 'fe80:0:0:0').length, equals(2));
      expect(dbService.queryPackets(destSearch: 'ff02:0:0:0').map((p) => p.packetNo), equals([1]));
      expect(dbService.queryPackets(sourceSearch: '[$linkLocal]:5353').map((p) => p.packetNo), equals([1]));
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
      final tempDir = Directory.systemTemp.createTempSync('db_test_demo_');
      addTearDown(() {
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      });
      final repo = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir),
      );
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
      final tempDir = Directory.systemTemp.createTempSync('db_test_bw_');
      addTearDown(() {
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      });
      final repo = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir),
      );
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

    test('Contextual filter counts update dynamically based on active filter criteria', () {
      final tempDir = Directory.systemTemp.createTempSync('db_test_ctx_');
      addTearDown(() {
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      });
      final repo = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir),
      );
      repo.loadDemoCapture();

      // Overall capture counts
      final allProtocols = repo.getProtocolCounts(silenceLanChatter: false);
      expect(allProtocols.containsKey('DNS'), isTrue);
      expect(allProtocols.containsKey('HTTP'), isTrue);

      // Filter contextual counts for a specific source IP
      final dnsSenderCounts = repo.getProtocolCounts(
        sourceSearch: '192.168.1.10',
        silenceLanChatter: false,
      );
      // Under this source, HTTP and DNS counts match only packets from 192.168.1.10
      expect(dnsSenderCounts['DNS'], isNotNull);

      // Contextual top senders given destination 8.8.8.8
      final sendersToDns = repo.getTopSenders(
        destSearch: '8.8.8.8',
        silenceLanChatter: false,
      );
      expect(sendersToDns.containsKey('192.168.1.10'), isTrue);

      repo.dispose();
    });

    test('Ingest vs relabelAllCustomProtocols produce identical triage, protocol, summary, and customFields (F4)', () {
      final tempDirA = Directory.systemTemp.createTempSync('f4_ingest_');
      final tempDirB = Directory.systemTemp.createTempSync('f4_relabel_');
      addTearDown(() {
        if (tempDirA.existsSync()) tempDirA.deleteSync(recursive: true);
        if (tempDirB.existsSync()) tempDirB.deleteSync(recursive: true);
      });

      const acmeRule = CustomProtocolRule(
        id: 'acme_proto',
        name: 'ACME Telemetry',
        colorHex: 0xFF9C27B0,
        defaultTriageStatus: TriageStatus.unexpected,
        ipProtocol: 17,
        port: 45820,
        magicBytesOffset: 0,
        magicBytesHex: [0x41, 0x43, 0x4D, 0x45],
        fieldSlices: [
          ProtocolFieldSlice(
            name: 'CommandID',
            byteOffset: 4,
            byteLength: 2,
            dataType: FieldDataType.uint16Be,
          ),
        ],
      );

      final storageA = ProtocolLibraryService(storageDirectory: tempDirA);
      storageA.saveCustomProtocols([acmeRule]);
      final repoA = PacketRepository(storageService: storageA);
      repoA.loadDemoCapture();

      final repoB = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDirB),
      );
      repoB.loadDemoCapture();
      repoB.addCustomProtocol(acmeRule);

      final acmeA = repoA.queryPackets(silenceLanChatter: false).last;
      final acmeB = repoB.queryPackets(silenceLanChatter: false).last;

      expect(acmeA.detectedProtocol, equals('ACME Telemetry'));
      expect(acmeA.triageStatus, equals(TriageStatus.unexpected));
      expect(acmeB.detectedProtocol, equals(acmeA.detectedProtocol));
      expect(acmeB.triageStatus, equals(acmeA.triageStatus));
      expect(acmeB.summary, equals(acmeA.summary));
      expect(acmeB.customFields, equals(acmeA.customFields));

      // Deleting the custom rule on repoB restores UDP + baseSummary + unclassified
      repoB.deleteCustomProtocol('acme_proto');
      final restored = repoB.queryPackets(silenceLanChatter: false).last;
      expect(restored.detectedProtocol, equals('UDP'));
      expect(restored.customProtocolId, isNull);
      expect(restored.customFields, isEmpty);
      expect(restored.summary, equals(acmeA.baseSummary));
      expect(restored.triageStatus, equals(TriageStatus.expected)); // UDP is in default expectedProtocols

      repoA.dispose();
      repoB.dispose();
    });

    test('readRawPacketBytes returns exact frame and L4 payload bytes for classic PCAP & PCAPNG (F1)', () {
      final tempDir = Directory.systemTemp.createTempSync('f1_bytes_');
      addTearDown(() {
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      });

      final classicBytes = DemoPcapGenerator.generateClassicPcap();
      final classicFile = File(p.join(tempDir.path, 'classic.pcap'))..writeAsBytesSync(classicBytes);

      final repoMem = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir),
      )..loadFromBytes(classicBytes, 'classic.pcap');

      final repoDisk = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir),
      )..loadFromFile(classicFile);

      for (final repo in [repoMem, repoDisk]) {
        final packets = repo.queryPackets(silenceLanChatter: false, limit: 100);
        final arp = packets.first;
        final arpFrame = repo.readRawPacketBytes(arp, payloadOnly: false);
        expect(arpFrame.length, equals(arp.capturedLength));
        expect(arpFrame.sublist(0, 6), equals([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]));

        final acme = packets.last;
        final acmeFrame = repo.readRawPacketBytes(acme, payloadOnly: false);
        expect(acmeFrame.length, equals(acme.capturedLength));
        expect(acmeFrame.sublist(0, 6), equals([0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]));

        final acmePayload = repo.readRawPacketBytes(acme, payloadOnly: true);
        expect(acmePayload.length, equals(acme.payloadLength));
        expect(acmePayload.sublist(0, 4), equals([0x41, 0x43, 0x4D, 0x45])); // "ACME"
      }

      // PCAPNG disk path
      final ngBytes = DemoPcapGenerator.generatePcapNg();
      final ngFile = File(p.join(tempDir.path, 'capture.pcapng'))..writeAsBytesSync(ngBytes);
      final repoNg = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir),
      )..loadFromFile(ngFile);
      final ngPkt = repoNg.queryPackets(silenceLanChatter: false).first;
      final ngFrame = repoNg.readRawPacketBytes(ngPkt, payloadOnly: false);
      expect(ngFrame.length, equals(48));
      expect(ngFrame.sublist(0, 6), equals([0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]));
      final ngPayload = repoNg.readRawPacketBytes(ngPkt, payloadOnly: true);
      expect(ngPayload, equals([0x12, 0x34, 0x01, 0x00, 0x00, 0x01]));

      repoMem.dispose();
      repoDisk.dispose();
      repoNg.dispose();
    });

    test('readRawPacketBytes returns exact unpadded frame and L4 payload bytes for non-4B-aligned PCAPNG SPB (F1)', () {
      final tempDir = Directory.systemTemp.createTempSync('f1_spb_unaligned_');
      addTearDown(() {
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      });

      final frame55 = Uint8List(55);
      frame55.setRange(0, 6, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
      frame55.setRange(6, 12, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
      frame55[12] = 0x08;
      frame55[13] = 0x00;
      final ipBd = ByteData.sublistView(frame55, 14, 34);
      ipBd.setUint8(0, 0x45);
      ipBd.setUint16(2, 41, Endian.big);
      ipBd.setUint8(8, 64);
      ipBd.setUint8(9, 6);
      frame55.setRange(26, 30, [192, 168, 1, 10]);
      frame55.setRange(30, 34, [192, 168, 1, 20]);
      final tcpBd = ByteData.sublistView(frame55, 34, 54);
      tcpBd.setUint16(0, 12345, Endian.big);
      tcpBd.setUint16(2, 80, Endian.big);
      tcpBd.setUint32(4, 1, Endian.big);
      tcpBd.setUint32(8, 1, Endian.big);
      tcpBd.setUint8(12, 5 << 4);
      tcpBd.setUint8(13, 0x18);
      tcpBd.setUint16(14, 65535, Endian.big);
      frame55[54] = 0x42;

      final shb = ByteData(28)
        ..setUint32(0, 0x0A0D0D0A, Endian.little)
        ..setUint32(4, 28, Endian.little)
        ..setUint32(8, 0x1A2B3C4D, Endian.little)
        ..setUint16(12, 1, Endian.little)
        ..setUint16(14, 0, Endian.little)
        ..setInt64(16, -1, Endian.little)
        ..setUint32(24, 28, Endian.little);

      final idb = ByteData(20)
        ..setUint32(0, 0x00000001, Endian.little)
        ..setUint32(4, 20, Endian.little)
        ..setUint16(8, 1, Endian.little)
        ..setUint16(10, 0, Endian.little)
        ..setUint32(12, 65535, Endian.little)
        ..setUint32(16, 20, Endian.little);

      final paddedCap = (frame55.length + 3) & ~3; // 56
      final spbTotalLen = 16 + paddedCap; // 72
      final spb = Uint8List(spbTotalLen);
      final spbBd = ByteData.sublistView(spb);
      spbBd.setUint32(0, 0x00000003, Endian.little);
      spbBd.setUint32(4, spbTotalLen, Endian.little);
      spbBd.setUint32(8, 55, Endian.little);
      spb.setRange(12, 12 + frame55.length, frame55);
      spbBd.setUint32(spbTotalLen - 4, spbTotalLen, Endian.little);

      final ngBytes = (BytesBuilder()
            ..add(shb.buffer.asUint8List())
            ..add(idb.buffer.asUint8List())
            ..add(spb))
          .toBytes();

      final spbFile = File(p.join(tempDir.path, 'spb_unaligned.pcapng'))
        ..writeAsBytesSync(ngBytes);

      final repoMem = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir),
      )..loadFromBytes(ngBytes, 'spb.pcapng');
      final repoDisk = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir),
      )..loadFromFile(spbFile);

      for (final repo in [repoMem, repoDisk]) {
        final pkt = repo.queryPackets(silenceLanChatter: false).single;
        expect(pkt.capturedLength, equals(55));
        expect(pkt.originalLength, equals(55));
        expect(pkt.payloadLength, equals(1));
        expect(repo.readRawPacketBytes(pkt, payloadOnly: false), equals(frame55));
        expect(repo.readRawPacketBytes(pkt, payloadOnly: true), equals([0x42]));
      }

      repoMem.dispose();
      repoDisk.dispose();
    });

    test('readRawPacketBytes uses RandomAccessFile slice I/O without readAsBytesSync and guards bounds (F18)', () {
      final tempDir = Directory.systemTemp.createTempSync('f18_raf_');
      addTearDown(() {
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      });

      final classicBytes = DemoPcapGenerator.generateClassicPcap();
      final pcapFile = File(p.join(tempDir.path, 'disk.pcap'))..writeAsBytesSync(classicBytes);

      final repo = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir),
      )..loadFromFile(pcapFile);
      final acme = repo.queryPackets(silenceLanChatter: false, limit: 100).last;

      // Capture real File outside IOOverrides zone to avoid recursion
      final realFile = File(pcapFile.path);
      final spyLog = _RafSpyLog();

      IOOverrides.runZoned(
        () {
          final frameBytes = repo.readRawPacketBytes(acme, payloadOnly: false);
          expect(frameBytes.sublist(0, 6), equals([0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]));
          final payloadBytes = repo.readRawPacketBytes(acme, payloadOnly: true);
          expect(payloadBytes.sublist(0, 4), equals([0x41, 0x43, 0x4D, 0x45]));
        },
        createFile: (path) => _SpyFile(realFile, spyLog),
      );

      expect(spyLog.readAsBytesSyncCalls, equals(0));
      expect(spyLog.seekOffsets, equals([acme.fileByteOffset, acme.payloadFileOffset]));
      expect(spyLog.readLengths, equals([acme.capturedLength, acme.payloadLength]));
      expect(spyLog.readLengths.every((len) => len < classicBytes.length), isTrue);
      expect(spyLog.closeCalls, equals(2));

      // Out-of-bounds & zero-length checks (disk + memory)
      final repoMem = PacketRepository(
        storageService: ProtocolLibraryService(storageDirectory: tempDir),
      )..loadFromBytes(classicBytes, 'mem.pcap');

      for (final r in [repo, repoMem]) {
        expect(r.readRawPacketBytes(acme.copyWith(fileByteOffset: -1), payloadOnly: false), isEmpty);
        expect(r.readRawPacketBytes(acme.copyWith(fileByteOffset: classicBytes.length + 10), payloadOnly: false), isEmpty);
        expect(r.readRawPacketBytes(acme.copyWith(capturedLength: 0), payloadOnly: false), isEmpty);
        expect(r.readRawPacketBytes(acme.copyWith(payloadFileOffset: -5), payloadOnly: true), isEmpty);
        expect(r.readRawPacketBytes(acme.copyWith(payloadFileOffset: classicBytes.length), payloadOnly: true), isEmpty);
        expect(r.readRawPacketBytes(acme.copyWith(payloadLength: 0), payloadOnly: true), isEmpty);
      }

      // Truncated file mid-packet -> returns remaining bytes cleanly without RangeError
      pcapFile.writeAsBytesSync(classicBytes.sublist(0, acme.fileByteOffset + 10));
      final partial = repo.readRawPacketBytes(acme, payloadOnly: false);
      expect(partial.length, equals(10));

      // Empty file -> returns empty
      pcapFile.writeAsBytesSync(const []);
      expect(repo.readRawPacketBytes(acme, payloadOnly: false), isEmpty);

      // Deleted file -> returns empty
      pcapFile.deleteSync();
      expect(repo.readRawPacketBytes(acme, payloadOnly: false), isEmpty);

      repo.dispose();
      repoMem.dispose();
    });
  });

  group('Storage Services Fallback & Directory Creation (F21)', () {
    test('Default fallback path uses SharedDeviceDatabase.getDefaultDirectoryPath', () {
      final defaultDir = SharedDeviceDatabase.getDefaultDirectoryPath();
      expect(
        AiSettingsStorageService().resolvedFilePath,
        equals(p.join(defaultDir, 'ai_settings.json')),
      );
      final lib = ProtocolLibraryService();
      expect(
        lib.resolveWritePath('custom_protocols.json'),
        equals(p.join(defaultDir, 'custom_protocols.json')),
      );
      expect(
        lib.resolveWritePath('baseline_profiles.json'),
        equals(p.join(defaultDir, 'baseline_profiles.json')),
      );
      expect(
        lib.resolveWritePath('sender_library.json'),
        equals(p.join(defaultDir, 'sender_library.json')),
      );
      expect(
        lib.resolveWritePath('receiver_library.json'),
        equals(p.join(defaultDir, 'receiver_library.json')),
      );
    });

    test('AiSettingsStorageService creates missing nested parent directories and round-trips', () {
      final tempDir = Directory.systemTemp.createTempSync('ai_storage_f21_');
      addTearDown(() {
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      });
      final nestedDir = Directory(p.join(tempDir.path, 'nested', 'cfg'));
      expect(nestedDir.existsSync(), isFalse);

      final service = AiSettingsStorageService(storageDirectory: nestedDir);
      service.saveSettings(
        const AiSettings(
          backendMode: LlmBackendMode.claudeCodeCli,
          geminiApiKey: 'test-secret-123',
          claudeModel: 'sonnet',
        ),
      );

      expect(File(p.join(nestedDir.path, 'ai_settings.json')).existsSync(), isTrue);
      final loaded = service.loadSettings();
      expect(loaded.backendMode, equals(LlmBackendMode.claudeCodeCli));
      expect(loaded.geminiApiKey, equals('test-secret-123'));
      expect(loaded.claudeModel, equals('sonnet'));
    });

    test('ProtocolLibraryService creates missing nested parent directories for all 4 save methods', () {
      final tempDir = Directory.systemTemp.createTempSync('lib_storage_f21_');
      addTearDown(() {
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      });
      final nestedDir = Directory(p.join(tempDir.path, 'nested', 'lib'));
      expect(nestedDir.existsSync(), isFalse);

      final service = ProtocolLibraryService(storageDirectory: nestedDir);
      service.saveCustomProtocols(const [
        CustomProtocolRule(
          id: 'p1',
          name: 'TestProto',
          colorHex: 0xFF2196F3,
          defaultTriageStatus: TriageStatus.expected,
          port: 1234,
        ),
      ]);
      service.saveBaselineProfile(const BaselineProfile(
        id: 'b1',
        name: 'Custom Baseline',
        expectedIps: {'10.0.0.1'},
      ));
      service.saveSenders(const [
        EndpointRule(id: 's1', name: 'Sender1', ipAddress: '10.0.0.1'),
      ]);
      service.saveReceivers(const [
        EndpointRule(
          id: 'r1',
          name: 'Receiver1',
          ipAddress: '10.0.0.2',
          type: EndpointType.receiver,
        ),
      ]);

      expect(File(p.join(nestedDir.path, 'custom_protocols.json')).existsSync(), isTrue);
      expect(File(p.join(nestedDir.path, 'baseline_profiles.json')).existsSync(), isTrue);
      expect(File(p.join(nestedDir.path, 'sender_library.json')).existsSync(), isTrue);
      expect(File(p.join(nestedDir.path, 'receiver_library.json')).existsSync(), isTrue);

      expect(service.loadCustomProtocols().first.name, equals('TestProto'));
      expect(service.loadBaselineProfile().expectedIps, contains('10.0.0.1'));
      expect(service.loadSenders().first.name, equals('Sender1'));
      expect(service.loadReceivers().first.name, equals('Receiver1'));
    });

    test('Storage services enforce strict storageDirectory isolation', () {
      final emptyDir = Directory.systemTemp.createTempSync('empty_isolation_f21_');
      addTearDown(() {
        if (emptyDir.existsSync()) emptyDir.deleteSync(recursive: true);
      });

      final ai = AiSettingsStorageService(storageDirectory: emptyDir);
      final lib = ProtocolLibraryService(storageDirectory: emptyDir);

      expect(ai.loadSettings().geminiApiKey, isEmpty);
      expect(lib.loadCustomProtocols(), isEmpty);
      expect(lib.loadSenders(), isEmpty);
      expect(lib.loadReceivers(), isEmpty);
    });
  });
}

class _RafSpyLog {
  int readAsBytesSyncCalls = 0;
  int closeCalls = 0;
  final List<int> seekOffsets = [];
  final List<int> readLengths = [];
}

class _SpyFile implements File {
  _SpyFile(this._delegate, this._log);

  final File _delegate;
  final _RafSpyLog _log;

  @override
  bool existsSync() => _delegate.existsSync();

  @override
  RandomAccessFile openSync({FileMode mode = FileMode.read}) {
    return _SpyRandomAccessFile(_delegate.openSync(mode: mode), _log);
  }

  @override
  Uint8List readAsBytesSync() {
    _log.readAsBytesSyncCalls++;
    throw StateError('readAsBytesSync must not be called');
  }

  @override
  Future<Uint8List> readAsBytes() {
    _log.readAsBytesSyncCalls++;
    throw StateError('readAsBytes must not be called');
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _SpyRandomAccessFile implements RandomAccessFile {
  _SpyRandomAccessFile(this._delegate, this._log);

  final RandomAccessFile _delegate;
  final _RafSpyLog _log;

  @override
  int lengthSync() => _delegate.lengthSync();

  @override
  void setPositionSync(int position) {
    _log.seekOffsets.add(position);
    _delegate.setPositionSync(position);
  }

  @override
  Uint8List readSync(int count) {
    _log.readLengths.add(count);
    return _delegate.readSync(count);
  }

  @override
  void closeSync() {
    _log.closeCalls++;
    _delegate.closeSync();
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}
