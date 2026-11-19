import 'package:flutter_test/flutter_test.dart';
import 'package:packet_inspector/domain/models/packet_record.dart';
import 'package:packet_inspector/domain/models/custom_protocol_rule.dart';
import 'package:packet_inspector/domain/models/baseline_profile.dart';
import 'package:packet_inspector/domain/models/timeline_bucket.dart';

void main() {
  group('PacketRecord Model Tests', () {
    test('toMap and fromMap should round-trip correctly', () {
      final packet = PacketRecord(
        packetNo: 1,
        timestampUs: 1500000,
        globalDeltaUs: 1200,
        streamDeltaUs: 3400,
        flowHash: 987654321,
        ethType: 0x0800,
        srcIp: '192.168.1.10',
        dstIp: '8.8.8.8',
        ipProto: 17,
        srcPort: 54321,
        dstPort: 53,
        detectedProtocol: 'DNS',
        capturedLength: 64,
        originalLength: 64,
        fileByteOffset: 128,
        payloadFileOffset: 170,
        payloadLength: 22,
        payloadPreview: [0x12, 0x34, 0x56, 0x78],
        summary: 'Standard query 0x1234 A google.com',
        triageStatus: TriageStatus.expected,
        isLanNoise: false,
      );

      expect(packet.timestampSeconds, closeTo(1.5, 0.0001));
      expect(packet.globalDeltaSeconds, closeTo(0.0012, 0.00001));
      expect(packet.streamDeltaSeconds, closeTo(0.0034, 0.00001));
      expect(packet.formattedGlobalDeltaSeconds, equals('0.001200s'));
      expect(packet.formattedStreamDeltaSeconds, equals('0.003400s'));
      expect(packet.globalDeltaMs, closeTo(1.2, 0.0001));
      expect(packet.streamDeltaMs, closeTo(3.4, 0.0001));
      expect(packet.formattedDateTime, isNotEmpty);
      expect(packet.dateTime.millisecondsSinceEpoch, equals(1500));

      final map = packet.toMap();
      expect(map['custom_fields_json'], isNull);
      final reconstructed = PacketRecord.fromMap(map);

      expect(reconstructed.packetNo, equals(1));
      expect(reconstructed.timestampUs, equals(1500000));
      expect(reconstructed.detectedProtocol, equals('DNS'));
      expect(reconstructed.triageStatus, equals(TriageStatus.expected));
      expect(reconstructed.payloadPreview, equals([0x12, 0x34, 0x56, 0x78]));
      expect(reconstructed.isLanNoise, isFalse);
      expect(reconstructed.customFields, isEmpty);
      expect(reconstructed.baseProtocol, isNull);
      expect(reconstructed.baseSummary, isNull);
    });

    test('toMap and fromMap preserve customFields, baseProtocol, and baseSummary', () {
      final packet = PacketRecord(
        packetNo: 2,
        timestampUs: 2000000,
        globalDeltaUs: 500,
        streamDeltaUs: 500,
        flowHash: 42,
        ethType: 0x0800,
        srcIp: '10.0.0.1',
        dstIp: '10.0.0.2',
        ipProto: 17,
        srcPort: 45820,
        dstPort: 45820,
        detectedProtocol: 'ACME Telemetry',
        capturedLength: 58,
        originalLength: 58,
        fileByteOffset: 100,
        payloadFileOffset: 142,
        payloadLength: 16,
        payloadPreview: const [0x41, 0x43, 0x4D, 0x45],
        summary: 'ACME Telemetry [CommandID=101, Tag=PROD]',
        triageStatus: TriageStatus.expected,
        isLanNoise: false,
        customProtocolId: 'acme_proto',
        customFields: const {'CommandID': 101, 'Tag': 'PROD'},
        baseProtocol: 'UDP',
        baseSummary: '45820 → 45820 Len=16',
      );

      final map = packet.toMap();
      expect(map['custom_fields_json'], isA<String>());
      expect(map['base_protocol'], equals('UDP'));
      expect(map['base_summary'], equals('45820 → 45820 Len=16'));

      final restored = PacketRecord.fromMap(map);
      expect(restored.baseProtocol, equals('UDP'));
      expect(restored.baseSummary, equals('45820 → 45820 Len=16'));
      expect(restored.customFields['CommandID'], equals(101));
      expect(restored.customFields['Tag'], equals('PROD'));

      final copied = restored.copyWith(
        baseProtocol: 'TCP',
        baseSummary: 'updated base',
      );
      expect(copied.baseProtocol, equals('TCP'));
      expect(copied.baseSummary, equals('updated base'));
    });

    test('copyWith updates specified fields', () {
      final original = PacketRecord(
        packetNo: 1,
        timestampUs: 1000,
        globalDeltaUs: 0,
        streamDeltaUs: 0,
        flowHash: 1,
        ethType: 0x0800,
        srcIp: '1.1.1.1',
        dstIp: '2.2.2.2',
        ipProto: 6,
        srcPort: 1234,
        dstPort: 80,
        detectedProtocol: 'HTTP',
        capturedLength: 50,
        originalLength: 50,
        fileByteOffset: 0,
        payloadFileOffset: 40,
        payloadLength: 10,
        payloadPreview: const [],
        summary: 'GET / HTTP/1.1',
        triageStatus: TriageStatus.unclassified,
        isLanNoise: false,
      );

      final updated = original.copyWith(
        triageStatus: TriageStatus.unexpected,
        detectedProtocol: 'SuspiciousHTTP',
      );

      expect(updated.triageStatus, equals(TriageStatus.unexpected));
      expect(updated.detectedProtocol, equals('SuspiciousHTTP'));
      expect(updated.srcIp, equals('1.1.1.1'));
    });
  });

  group('CustomProtocolRule & FieldSlice Tests', () {
    test('ProtocolFieldSlice extracts various data types accurately', () {
      // Byte buffer:
      // Byte 0: 0x42 (UInt8)
      // Bytes 1..2: 0x01, 0x02 -> UInt16 BE: 258, LE: 513
      // Bytes 3..6: 0x00, 0x00, 0x03, 0xE8 -> UInt32 BE: 1000, LE: 0xE8030000
      // Bytes 7..10: "ACME" (ASCII)
      final payload = <int>[
        0x42,
        0x01, 0x02,
        0x00, 0x00, 0x03, 0xE8,
        0x41, 0x43, 0x4D, 0x45,
      ];

      final uint8Slice = const ProtocolFieldSlice(
        name: 'Type',
        byteOffset: 0,
        byteLength: 1,
        dataType: FieldDataType.uint8,
      );
      expect(uint8Slice.extractValue(payload), equals(0x42));

      final uint16BeSlice = const ProtocolFieldSlice(
        name: 'SeqBE',
        byteOffset: 1,
        byteLength: 2,
        dataType: FieldDataType.uint16Be,
      );
      expect(uint16BeSlice.extractValue(payload), equals(258));

      final uint16LeSlice = const ProtocolFieldSlice(
        name: 'SeqLE',
        byteOffset: 1,
        byteLength: 2,
        dataType: FieldDataType.uint16Le,
      );
      expect(uint16LeSlice.extractValue(payload), equals(513));

      final uint32BeSlice = const ProtocolFieldSlice(
        name: 'ValueBE',
        byteOffset: 3,
        byteLength: 4,
        dataType: FieldDataType.uint32Be,
      );
      expect(uint32BeSlice.extractValue(payload), equals(1000));

      final asciiSlice = const ProtocolFieldSlice(
        name: 'Tag',
        byteOffset: 7,
        byteLength: 4,
        dataType: FieldDataType.asciiString,
      );
      expect(asciiSlice.extractValue(payload), equals('ACME'));

      final hexSlice = const ProtocolFieldSlice(
        name: 'Hex',
        byteOffset: 1,
        byteLength: 2,
        dataType: FieldDataType.hexBytes,
      );
      expect(hexSlice.extractValue(payload), equals('01 02'));
    });

    test('CustomProtocolRule matches port, IP, and magic bytes', () {
      final rule = const CustomProtocolRule(
        id: 'acme_proto',
        name: 'ACME Telemetry',
        colorHex: 0xFF9C27B0,
        defaultTriageStatus: TriageStatus.expected,
        ipProtocol: 17, // UDP
        port: 45820,
        portDirection: PortMatchDirection.either,
        magicBytesOffset: 0,
        magicBytesHex: [0x41, 0x43, 0x4D, 0x45], // "ACME"
      );

      final matchingPayload = [0x41, 0x43, 0x4D, 0x45, 0x01, 0x02];
      final nonMatchingPayload = [0x50, 0x51, 0x52, 0x53, 0x01, 0x02];

      // Exact match
      expect(
        rule.matches(
          ipProto: 17,
          srcPort: 45820,
          dstPort: 50000,
          srcIp: '192.168.1.50',
          dstIp: '192.168.1.1',
          payload: matchingPayload,
        ),
        isTrue,
      );

      // Wrong port
      expect(
        rule.matches(
          ipProto: 17,
          srcPort: 80,
          dstPort: 50000,
          srcIp: '192.168.1.50',
          dstIp: '192.168.1.1',
          payload: matchingPayload,
        ),
        isFalse,
      );

      // Wrong magic bytes
      expect(
        rule.matches(
          ipProto: 17,
          srcPort: 45820,
          dstPort: 50000,
          srcIp: '192.168.1.50',
          dstIp: '192.168.1.1',
          payload: nonMatchingPayload,
        ),
        isFalse,
      );
    });

    test('CustomProtocolRule JSON serialization round-trip', () {
      final rule = const CustomProtocolRule(
        id: 'custom_1',
        name: 'Custom Sensor',
        colorHex: 0xFFFF9800,
        defaultTriageStatus: TriageStatus.unexpected,
        ipProtocol: 6,
        port: 9000,
        magicBytesOffset: 2,
        magicBytesHex: [0xDE, 0xAD],
        fieldSlices: [
          ProtocolFieldSlice(
            name: 'DeviceID',
            byteOffset: 4,
            byteLength: 2,
            dataType: FieldDataType.uint16Be,
          ),
        ],
      );

      final jsonStr = CustomProtocolRule.serializeList([rule]);
      final deserialized = CustomProtocolRule.deserializeList(jsonStr);

      expect(deserialized.length, equals(1));
      expect(deserialized[0].id, equals('custom_1'));
      expect(deserialized[0].fieldSlices.length, equals(1));
      expect(deserialized[0].fieldSlices[0].name, equals('DeviceID'));
    });
  });

  group('BaselineProfile Tests', () {
    test('Silence LAN chatter classifies LAN noise as expected', () {
      final profile = const BaselineProfile(
        id: 'default',
        name: 'Default Baseline',
        silenceLanChatter: true,
      );

      final status = profile.evaluateTriage(
        srcIp: '192.168.1.20',
        dstIp: '224.0.0.251',
        detectedProtocol: 'mDNS',
        isLanNoise: true,
      );

      expect(status, equals(TriageStatus.expected));
    });

    test('Unexpected IP flags traffic as unexpected', () {
      final profile = const BaselineProfile(
        id: 'strict',
        name: 'Strict Profile',
        unexpectedIps: {'10.99.88.77'},
        silenceLanChatter: false,
      );

      final status = profile.evaluateTriage(
        srcIp: '10.99.88.77',
        dstIp: '192.168.1.10',
        detectedProtocol: 'TCP',
        isLanNoise: false,
      );

      expect(status, equals(TriageStatus.unexpected));
    });

    test('expectedSubnets classifies packet as expected when only srcIp matches', () {
      const profile = BaselineProfile(
        id: 'sub1',
        name: 'Subnet',
        expectedSubnets: ['192.168.1.'],
        expectedProtocols: {},
        silenceLanChatter: false,
      );

      final status = profile.evaluateTriage(
        srcIp: '192.168.1.10',
        dstIp: '8.8.8.8',
        detectedProtocol: 'CUSTOM',
        isLanNoise: false,
      );
      expect(status, equals(TriageStatus.expected));
    });

    test('expectedSubnets classifies packet as expected when only dstIp matches', () {
      const profile = BaselineProfile(
        id: 'sub1',
        name: 'Subnet',
        expectedSubnets: ['192.168.1.'],
        expectedProtocols: {},
        silenceLanChatter: false,
      );

      final status = profile.evaluateTriage(
        srcIp: '8.8.8.8',
        dstIp: '192.168.1.50',
        detectedProtocol: 'CUSTOM',
        isLanNoise: false,
      );
      expect(status, equals(TriageStatus.expected));
    });

    test('expectedSubnets matches traffic across two different expected subnets', () {
      const profile = BaselineProfile(
        id: 'sub2',
        name: 'Multi Subnet',
        expectedSubnets: ['192.168.1.', '10.0.0.'],
        expectedProtocols: {},
        silenceLanChatter: false,
      );

      final status = profile.evaluateTriage(
        srcIp: '192.168.1.10',
        dstIp: '10.0.0.5',
        detectedProtocol: 'CUSTOM',
        isLanNoise: false,
      );
      expect(status, equals(TriageStatus.expected));
    });

    test('expectedSubnets skips non-matching traffic and respects unexpected precedence', () {
      const profile = BaselineProfile(
        id: 'sub3',
        name: 'Strict Subnet',
        expectedSubnets: ['192.168.1.'],
        unexpectedIps: {'8.8.8.8'},
        expectedProtocols: {},
        silenceLanChatter: false,
      );

      expect(
        profile.evaluateTriage(
          srcIp: '172.16.0.1',
          dstIp: '172.16.0.2',
          detectedProtocol: 'CUSTOM',
          isLanNoise: false,
          defaultRuleStatus: TriageStatus.unclassified,
        ),
        equals(TriageStatus.unclassified),
      );

      expect(
        profile.evaluateTriage(
          srcIp: '192.168.1.10',
          dstIp: '8.8.8.8',
          detectedProtocol: 'CUSTOM',
          isLanNoise: false,
        ),
        equals(TriageStatus.unexpected),
      );
    });

    test('BaselineProfile serialization round-trip', () {
      final profile = const BaselineProfile(
        id: 'office',
        name: 'Office Network',
        expectedIps: {'192.168.1.1'},
        unexpectedSubnets: ['10.99.'],
        silenceLanChatter: true,
      );

      final json = BaselineProfile.serialize(profile);
      final restored = BaselineProfile.deserialize(json);

      expect(restored.id, equals('office'));
      expect(restored.expectedIps.contains('192.168.1.1'), isTrue);
      expect(restored.unexpectedSubnets, contains('10.99.'));
      expect(restored.silenceLanChatter, isTrue);
    });
  });

  group('TimelineBucket Tests', () {
    test('toMap and fromMap should preserve bucket statistics', () {
      final bucket = const TimelineBucket(
        bucketIndex: 5,
        bucketStartUs: 5000000,
        bucketEndUs: 6000000,
        packetCount: 150,
        totalBytes: 75000,
        minGlobalDeltaUs: 12,
        maxStreamDeltaUs: 85000,
        avgStreamDeltaUs: 450.5,
        unexpectedCount: 3,
      );

      expect(bucket.startSeconds, equals(5.0));
      expect(bucket.endSeconds, equals(6.0));
      expect(bucket.minGlobalDeltaMs, equals(0.012));
      expect(bucket.maxStreamDeltaMs, equals(85.0));

      final map = bucket.toMap();
      final restored = TimelineBucket.fromMap(map);

      expect(restored.bucketIndex, equals(5));
      expect(restored.packetCount, equals(150));
      expect(restored.unexpectedCount, equals(3));
      expect(restored.avgStreamDeltaUs, closeTo(450.5, 0.01));
    });
  });
}
