import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:packet_inspector/core/theme/app_theme.dart';
import 'package:packet_inspector/data/repositories/packet_repository.dart';
import 'package:packet_inspector/data/services/ai/llm_provider_service.dart';
import 'package:packet_inspector/data/services/database/packet_database_service.dart';
import 'package:packet_inspector/data/services/parser/packet_dissector.dart';
import 'package:packet_inspector/data/services/parser/pcap_binary_reader.dart';
import 'package:packet_inspector/data/services/storage/ai_settings_storage_service.dart';
import 'package:packet_inspector/data/services/storage/protocol_library_service.dart';
import 'package:packet_inspector/data/services/storage/shared_device_database.dart';
import 'package:packet_inspector/domain/models/baseline_profile.dart';
import 'package:packet_inspector/domain/models/capture_slot.dart';
import 'package:packet_inspector/domain/models/custom_protocol_rule.dart';
import 'package:packet_inspector/domain/models/endpoint_rule.dart';
import 'package:packet_inspector/domain/models/flow_diff_summary.dart';
import 'package:packet_inspector/domain/models/packet_diff_record.dart';
import 'package:packet_inspector/domain/models/packet_record.dart';
import 'package:path/path.dart' as p;

import 'helpers/e2e_test_harness.dart';
import 'helpers/pcap_fixture_builder.dart';

void main() {
  CustomProtocolRule buildAcmeRule({
    String id = 'rule_acme',
    String name = 'ACME',
    int? port = 45820,
    String? ipAddressFilter,
    List<int>? magicBytesHex,
    int? magicBytesOffset,
    TriageStatus defaultTriageStatus = TriageStatus.unclassified,
    List<ProtocolFieldSlice> fieldSlices = const [
      ProtocolFieldSlice(
        name: 'CommandID',
        byteOffset: 4,
        byteLength: 2,
        dataType: FieldDataType.uint16Be,
      ),
      ProtocolFieldSlice(
        name: 'Serial',
        byteOffset: 6,
        byteLength: 4,
        dataType: FieldDataType.uint32Be,
      ),
      ProtocolFieldSlice(
        name: 'Status',
        byteOffset: 10,
        byteLength: 1,
        dataType: FieldDataType.uint8,
      ),
      ProtocolFieldSlice(
        name: 'Tag',
        byteOffset: 11,
        byteLength: 4,
        dataType: FieldDataType.asciiString,
      ),
    ],
  }) {
    return CustomProtocolRule(
      id: id,
      name: name,
      colorHex: 0xFF00BCD4,
      defaultTriageStatus: defaultTriageStatus,
      ipProtocol: 17,
      port: port,
      portDirection: PortMatchDirection.either,
      ipAddressFilter: ipAddressFilter,
      magicBytesOffset: magicBytesOffset,
      magicBytesHex: magicBytesHex,
      fieldSlices: fieldSlices,
    );
  }

  PacketRepository createIsolatedRepo(
    E2eTestHarness harness, {
    String? subDirName,
  }) {
    final dir = subDirName == null
        ? harness.tempDir
        : harness.createSubDir(subDirName);
    final storage = ProtocolLibraryService(storageDirectory: dir);
    final repo = PacketRepository(storageService: storage);
    addTearDown(repo.dispose);
    return repo;
  }

  group('Tier 1 — Feature Coverage', () {
    group('F1 — Exact Frame & L4 Payload Byte Offsets', () {
      test(
        '[F1][T1] Classic PCAP LE microsecond & nanosecond exact frame and L4 payload byte slices',
        () {
          for (final nanosecond in [false, true]) {
            final harness = E2eTestHarness.create();
            final fixture = PcapFixtureBuilder.buildRichInspectorCapture(
              endian: Endian.little,
              nanosecond: nanosecond,
            );
            final file = harness.writeTempCaptureFile(
              nanosecond ? 'rich_le_ns.pcap' : 'rich_le_us.pcap',
              fixture.bytes,
            );
            harness.repository.loadFromFile(file);

            final packets = harness.repository.queryPackets(
              limit: 100,
              silenceLanChatter: false,
            );
            expect(packets.length, equals(fixture.expectations.length));

            for (int i = 0; i < packets.length; i++) {
              final pkt = packets[i];
              final exp = fixture.expectations[i];

              expect(pkt.timestampUs, equals(exp.timestampUs));
              expect(pkt.fileByteOffset, equals(exp.expectedFrameFileOffset));
              expect(
                pkt.payloadFileOffset,
                equals(exp.expectedPayloadFileOffset),
              );

              final fullFrame = harness.repository.readRawPacketBytes(
                pkt,
                payloadOnly: false,
              );
              final l4Payload = harness.repository.readRawPacketBytes(
                pkt,
                payloadOnly: true,
              );

              expect(fullFrame, equals(exp.frameBytes));
              expect(fullFrame.first, anyOf(equals(0xAA), equals(0xFF)));
              expect(l4Payload, equals(exp.l4PayloadBytes));
            }

            final acmePkt = packets.firstWhere(
              (p) => p.srcPort == 45820 && p.dstPort == 45820,
            );
            final acmePayload = harness.repository.readRawPacketBytes(
              acmePkt,
              payloadOnly: true,
            );
            expect(
              String.fromCharCodes(acmePayload.take(4)),
              equals('ACME'),
            );

            final bulkPkt = packets.firstWhere((p) => p.payloadLength == 1400);
            final bulkPayload = harness.repository.readRawPacketBytes(
              bulkPkt,
              payloadOnly: true,
            );
            expect(bulkPayload.length, equals(1400));
          }
        },
      );

      test(
        '[F1][T1] Classic PCAP BE microsecond & nanosecond exact frame and L4 payload byte slices',
        () {
          for (final nanosecond in [false, true]) {
            final harness = E2eTestHarness.create();
            final fixture = PcapFixtureBuilder.buildRichInspectorCapture(
              endian: Endian.big,
              nanosecond: nanosecond,
            );
            final expectedFormat = nanosecond
                ? PcapFormat.classicNanosecond
                : PcapFormat.classicMicrosecond;
            expect(
              PcapBinaryReader.detectFormat(fixture.bytes),
              equals(expectedFormat),
            );

            final file = harness.writeTempCaptureFile(
              nanosecond ? 'rich_be_ns.pcap' : 'rich_be_us.pcap',
              fixture.bytes,
            );
            harness.repository.loadFromFile(file);

            final packets = harness.repository.queryPackets(
              limit: 100,
              silenceLanChatter: false,
            );
            expect(packets.length, equals(fixture.expectations.length));

            for (int i = 0; i < packets.length; i++) {
              final pkt = packets[i];
              final exp = fixture.expectations[i];
              expect(pkt.timestampUs, equals(exp.timestampUs));
              expect(pkt.fileByteOffset, equals(exp.expectedFrameFileOffset));
              expect(
                pkt.payloadFileOffset,
                equals(exp.expectedPayloadFileOffset),
              );
              expect(
                harness.repository.readRawPacketBytes(pkt, payloadOnly: false),
                equals(exp.frameBytes),
              );
              expect(
                harness.repository.readRawPacketBytes(pkt, payloadOnly: true),
                equals(exp.l4PayloadBytes),
              );
            }
          }
        },
      );

      test(
        '[F1][T1] LinkTypes 1 (Ethernet), 113 (Linux SLL), 0 (Loopback), and 101 (Raw IP) offsets',
        () {
          final payload = Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02]);
          final cases = <({int linkType, BuiltFrame frame, int expectedOffset})>[
            (
              linkType: 1,
              frame: PcapFrameFactory.ethernetUdp(
                srcIp: '10.0.0.1',
                dstIp: '10.0.0.2',
                srcPort: 1111,
                dstPort: 2222,
                payload: payload,
              ),
              expectedOffset: 42,
            ),
            (
              linkType: 113,
              frame: PcapFrameFactory.linuxSllUdp(
                srcIp: '10.0.0.1',
                dstIp: '10.0.0.2',
                srcPort: 1111,
                dstPort: 2222,
                payload: payload,
              ),
              expectedOffset: 44,
            ),
            (
              linkType: 0,
              frame: PcapFrameFactory.loopbackUdp(
                srcIp: '10.0.0.1',
                dstIp: '10.0.0.2',
                srcPort: 1111,
                dstPort: 2222,
                payload: payload,
              ),
              expectedOffset: 32,
            ),
            (
              linkType: 101,
              frame: PcapFrameFactory.rawIpUdp(
                srcIp: '10.0.0.1',
                dstIp: '10.0.0.2',
                srcPort: 1111,
                dstPort: 2222,
                payload: payload,
              ),
              expectedOffset: 28,
            ),
          ];

          for (final c in cases) {
            final harness = E2eTestHarness.create();
            final builder = ClassicPcapBuilder(linkType: c.linkType);
            builder.addBuiltFrame(
              c.frame,
              timestampUs: PcapFixtureBuilder.defaultStartEpochUs,
            );
            final fixture = builder.buildWithExpectations();
            final file = harness.writeTempCaptureFile(
              'lt_${c.linkType}.pcap',
              fixture.bytes,
            );
            harness.repository.loadFromFile(file);

            final packets = harness.repository.queryPackets(limit: 10);
            expect(packets.length, equals(1));
            final pkt = packets.single;
            final exp = fixture.expectations.single;

            expect(pkt.fileByteOffset, equals(exp.expectedFrameFileOffset));
            expect(pkt.payloadFileOffset, equals(exp.expectedPayloadFileOffset));
            expect(
              pkt.payloadFileOffset - pkt.fileByteOffset,
              equals(c.expectedOffset),
            );
            expect(
              harness.repository.readRawPacketBytes(pkt, payloadOnly: false),
              equals(exp.frameBytes),
            );
            expect(
              harness.repository.readRawPacketBytes(pkt, payloadOnly: true),
              equals(payload),
            );
          }
        },
      );

      test(
        '[F1][T1] 802.1Q VLAN-tagged Ethernet IPv4 and ARP frame/payload offsets',
        () {
          final harness = E2eTestHarness.create();
          final udpPayload = Uint8List.fromList('VLAN_TEST'.codeUnits);
          final builder = ClassicPcapBuilder(linkType: 1);
          builder.addBuiltFrame(
            PcapFrameFactory.ethernetUdp(
              srcIp: '192.168.10.1',
              dstIp: '192.168.10.2',
              srcPort: 4000,
              dstPort: 5000,
              vlanId: 42,
              payload: udpPayload,
            ),
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs,
          );
          builder.addBuiltFrame(
            PcapFrameFactory.ethernetArp(
              senderIp: '192.168.10.1',
              targetIp: '192.168.10.2',
              vlanId: 100,
            ),
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs + 1000,
          );

          final fixture = builder.buildWithExpectations();
          final file = harness.writeTempCaptureFile('vlan.pcap', fixture.bytes);
          harness.repository.loadFromFile(file);

          final packets = harness.repository.queryPackets(
            limit: 10,
            silenceLanChatter: false,
          );
          expect(packets.length, equals(2));

          // VLAN + IPv4 + UDP => 18 + 20 + 8 = 46 bytes offset
          expect(
            packets[0].payloadFileOffset - packets[0].fileByteOffset,
            equals(46),
          );
          expect(
            harness.repository.readRawPacketBytes(packets[0], payloadOnly: false),
            equals(fixture.expectations[0].frameBytes),
          );
          expect(
            harness.repository.readRawPacketBytes(packets[0], payloadOnly: true),
            equals(udpPayload),
          );

          // VLAN + ARP => 18 bytes offset, 28 bytes ARP payload
          expect(packets[1].detectedProtocol, equals('ARP'));
          expect(
            packets[1].payloadFileOffset - packets[1].fileByteOffset,
            equals(18),
          );
          expect(
            harness.repository.readRawPacketBytes(packets[1], payloadOnly: false),
            equals(fixture.expectations[1].frameBytes),
          );
          expect(
            harness.repository.readRawPacketBytes(packets[1], payloadOnly: true),
            equals(fixture.expectations[1].l4PayloadBytes),
          );
        },
      );

      test(
        '[F1][T1] PCAPNG EPB & SPB exact dataOffset frame and L4 payload byte slices',
        () {
          final harness = E2eTestHarness.create();
          final ng = PcapNgBuilder(initialEndian: Endian.little);
          final ethIf = ng.addInterface(linkType: 1, tsResolCode: 6);
          final sllIf = ng.addInterface(linkType: 113, tsResolCode: 6);

          final epbEthFrame = PcapFrameFactory.ethernetUdp(
            srcIp: '10.1.1.1',
            dstIp: '10.1.1.2',
            srcPort: 7000,
            dstPort: 8000,
            payload: Uint8List.fromList('EPB_ETH_DATA'.codeUnits),
          );
          // 4-byte aligned frame (56 bytes) for SPB so no padding ambiguity
          final spbEthFrame = PcapFrameFactory.ethernetUdp(
            srcIp: '10.1.1.3',
            dstIp: '10.1.1.4',
            srcPort: 7001,
            dstPort: 8001,
            payload: Uint8List.fromList('SPB_ALIGNED_14'.codeUnits), // 14+20+8+14 = 56B
          );
          final epbSllFrame = PcapFrameFactory.linuxSllUdp(
            srcIp: '10.1.1.5',
            dstIp: '10.1.1.6',
            srcPort: 7002,
            dstPort: 8002,
            payload: Uint8List.fromList('EPB_SLL_DATA'.codeUnits),
          );

          ng.addEnhancedBuiltFrame(
            interfaceId: ethIf,
            built: epbEthFrame,
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs,
          );
          ng.addSimpleBuiltFrame(spbEthFrame);
          ng.addEnhancedBuiltFrame(
            interfaceId: sllIf,
            built: epbSllFrame,
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs + 2000,
          );

          final fixture = ng.buildWithExpectations();
          final file = harness.writeTempCaptureFile('epb_spb.pcapng', fixture.bytes);
          harness.repository.loadFromFile(file);

          final packets = harness.repository.queryPackets(limit: 10);
          expect(packets.length, equals(3));

          for (int i = 0; i < 3; i++) {
            final pkt = packets[i];
            final exp = fixture.expectations[i];
            expect(pkt.fileByteOffset, equals(exp.expectedFrameFileOffset));
            expect(pkt.payloadFileOffset, equals(exp.expectedPayloadFileOffset));
            expect(
              harness.repository.readRawPacketBytes(pkt, payloadOnly: false),
              equals(exp.frameBytes),
            );
            expect(
              harness.repository.readRawPacketBytes(pkt, payloadOnly: true),
              equals(exp.l4PayloadBytes),
            );
          }
        },
      );

      test(
        '[F1][T1] Ethernet IPv6 UDP and TCP/ICMP frame and L4 payload byte slices',
        () {
          final harness = E2eTestHarness.create();
          final builder = ClassicPcapBuilder();

          final v6Src = Uint8List.fromList([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
          ]);
          final v6Dst = Uint8List.fromList([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
          ]);
          final v6Payload = Uint8List.fromList('IPV6_UDP_DATA'.codeUnits);
          final tcpPayload = Uint8List.fromList('TCP_BODY_1234'.codeUnits);
          final icmpPayload = Uint8List.fromList([0xCA, 0xFE, 0xBA, 0xBE]);

          builder.addBuiltFrame(
            PcapFrameFactory.ethernetIpv6Udp(
              srcIpBytes: v6Src,
              dstIpBytes: v6Dst,
              srcPort: 5000,
              dstPort: 5001,
              payload: v6Payload,
            ),
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs,
          );
          builder.addBuiltFrame(
            PcapFrameFactory.ethernetTcp(
              srcIp: '192.168.1.10',
              dstIp: '192.168.1.20',
              srcPort: 51000,
              dstPort: 8080,
              seqNum: 100,
              ackNum: 1,
              payload: tcpPayload,
            ),
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs + 1000,
          );
          builder.addBuiltFrame(
            PcapFrameFactory.ethernetIcmp(
              srcIp: '192.168.1.10',
              dstIp: '192.168.1.20',
              payload: icmpPayload,
            ),
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs + 2000,
          );

          final fixture = builder.buildWithExpectations();
          final file = harness.writeTempCaptureFile('v6_tcp_icmp.pcap', fixture.bytes);
          harness.repository.loadFromFile(file);

          final packets = harness.repository.queryPackets(limit: 10);
          expect(packets.length, equals(3));

          // IPv6 UDP: 14 + 40 + 8 = 62
          expect(packets[0].payloadFileOffset - packets[0].fileByteOffset, equals(62));
          // IPv4 TCP: 14 + 20 + 20 = 54
          expect(packets[1].payloadFileOffset - packets[1].fileByteOffset, equals(54));
          // IPv4 ICMP: 14 + 20 + 8 = 42
          expect(packets[2].payloadFileOffset - packets[2].fileByteOffset, equals(42));

          for (int i = 0; i < 3; i++) {
            expect(
              harness.repository.readRawPacketBytes(packets[i], payloadOnly: true),
              equals(fixture.expectations[i].l4PayloadBytes),
            );
            expect(
              harness.repository.readRawPacketBytes(packets[i], payloadOnly: false),
              equals(fixture.expectations[i].frameBytes),
            );
          }
        },
      );
    });

    group('F4 — Custom Protocol Persistence, Relabeling & Triage Consistency', () {
      test(
        '[F4][T1] customFields persisted in SQLite custom_fields_json and restored on queryPackets',
        () {
          final harness = E2eTestHarness.create();
          final acmeRule = buildAcmeRule();
          harness.repository.updateCustomProtocols([acmeRule]);

          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          harness.repository.loadFromBytes(fixture.bytes, 'rich.pcap');

          final packets = harness.repository.queryPackets(
            protocolPills: {'ACME'},
            limit: 50,
          );
          expect(packets.length, equals(1));
          final acme = packets.single;

          expect(acme.detectedProtocol, equals('ACME'));
          expect(acme.customProtocolId, equals('rule_acme'));
          expect(acme.baseProtocol, equals('UDP'));
          expect(acme.baseSummary, equals('45820 → 45820 Len=16'));
          expect(acme.customFields, equals({
            'CommandID': 101,
            'Serial': 883719,
            'Status': 1,
            'Tag': 'PROD',
          }));
          expect(acme.summary, contains('CommandID=101'));
          expect(acme.summary, contains('Serial=883719'));
          expect(acme.summary, contains('Tag=PROD'));
        },
      );

      test(
        '[F4][T1] Retroactive addCustomProtocol matches packets, extracts customFields, and updates summary/triage',
        () {
          final harness = E2eTestHarness.create();
          harness.repository.updateBaselineProfile(
            const BaselineProfile(
              id: 'strict',
              name: 'Strict',
              expectedProtocols: {'DNS', 'HTTP', 'TLS'},
              silenceLanChatter: true,
            ),
          );

          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          harness.repository.loadFromBytes(fixture.bytes, 'rich.pcap');

          final before = harness.repository.queryPackets(limit: 50).firstWhere(
                (p) => p.srcPort == 45820 && p.dstPort == 45820,
              );
          expect(before.detectedProtocol, equals('UDP'));
          expect(before.triageStatus, equals(TriageStatus.unclassified));
          expect(before.customFields, isEmpty);

          final acmeRule = buildAcmeRule(
            defaultTriageStatus: TriageStatus.unexpected,
          );
          final modified = harness.repository.addCustomProtocol(acmeRule);
          expect(modified, equals(1));

          final after = harness.repository.queryPackets(
            protocolPills: {'ACME'},
            limit: 50,
          );
          expect(after.length, equals(1));
          final pkt = after.single;
          expect(pkt.detectedProtocol, equals('ACME'));
          expect(pkt.customProtocolId, equals('rule_acme'));
          expect(pkt.baseProtocol, equals('UDP'));
          expect(pkt.baseSummary, equals('45820 → 45820 Len=16'));
          expect(pkt.triageStatus, equals(TriageStatus.unexpected));
          expect(pkt.customFields['CommandID'], equals(101));
          expect(pkt.customFields['Serial'], equals(883719));
          expect(pkt.customFields['Status'], equals(1));
          expect(pkt.customFields['Tag'], equals('PROD'));
        },
      );

      test(
        '[F4][T1] Deleting a custom rule restores exact L7 base_protocol (DNS/HTTP/TLS/mDNS/SSDP/NBNS/DHCP/NTP) and base_summary',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          harness.repository.loadFromBytes(fixture.bytes, 'l7.pcap');

          final baselinePackets = harness.repository.queryPackets(
            limit: 50,
            silenceLanChatter: false,
          );
          final expectedByNo = {
            for (final p in baselinePackets)
              p.packetNo: (proto: p.detectedProtocol, summary: p.summary),
          };
          for (final l7 in ['DNS', 'HTTP', 'TLS', 'mDNS', 'SSDP', 'NBNS', 'DHCP', 'NTP']) {
            expect(
              baselinePackets.any((p) => p.detectedProtocol == l7),
              isTrue,
              reason: 'Fixture must contain $l7',
            );
          }

          final overrideRules = [
            CustomProtocolRule(
              id: 'ov_dns',
              name: 'OVR_DNS',
              colorHex: 0xFF111111,
              defaultTriageStatus: TriageStatus.unexpected,
              ipProtocol: 17,
              port: 53,
            ),
            CustomProtocolRule(
              id: 'ov_http',
              name: 'OVR_HTTP',
              colorHex: 0xFF222222,
              defaultTriageStatus: TriageStatus.unexpected,
              ipProtocol: 6,
              port: 80,
            ),
            CustomProtocolRule(
              id: 'ov_tls',
              name: 'OVR_TLS',
              colorHex: 0xFF333333,
              defaultTriageStatus: TriageStatus.unexpected,
              ipProtocol: 6,
              port: 443,
            ),
            CustomProtocolRule(
              id: 'ov_mdns',
              name: 'OVR_MDNS',
              colorHex: 0xFF444444,
              defaultTriageStatus: TriageStatus.unexpected,
              ipProtocol: 17,
              port: 5353,
            ),
            CustomProtocolRule(
              id: 'ov_ssdp',
              name: 'OVR_SSDP',
              colorHex: 0xFF555555,
              defaultTriageStatus: TriageStatus.unexpected,
              ipProtocol: 17,
              port: 1900,
            ),
            CustomProtocolRule(
              id: 'ov_nbns',
              name: 'OVR_NBNS',
              colorHex: 0xFF666666,
              defaultTriageStatus: TriageStatus.unexpected,
              ipProtocol: 17,
              port: 137,
            ),
            CustomProtocolRule(
              id: 'ov_dhcp',
              name: 'OVR_DHCP',
              colorHex: 0xFF777777,
              defaultTriageStatus: TriageStatus.unexpected,
              ipProtocol: 17,
              port: 67,
            ),
            CustomProtocolRule(
              id: 'ov_ntp',
              name: 'OVR_NTP',
              colorHex: 0xFF888888,
              defaultTriageStatus: TriageStatus.unexpected,
              ipProtocol: 17,
              port: 123,
            ),
          ];

          harness.repository.updateCustomProtocols(overrideRules);
          final overridden = harness.repository.queryPackets(limit: 50);
          for (final l7 in ['DNS', 'HTTP', 'TLS', 'mDNS', 'SSDP', 'NBNS', 'DHCP', 'NTP']) {
            expect(overridden.any((p) => p.detectedProtocol == l7), isFalse);
          }

          for (final rule in overrideRules) {
            harness.repository.deleteCustomProtocol(rule.id);
          }

          final restored = harness.repository.queryPackets(limit: 50);
          for (final pkt in restored) {
            final orig = expectedByNo[pkt.packetNo]!;
            expect(pkt.detectedProtocol, equals(orig.proto));
            expect(pkt.summary, equals(orig.summary));
            expect(pkt.customProtocolId, isNull);
            expect(pkt.customFields, isEmpty);
          }
        },
      );

      test(
        '[F4][T1] Editing a custom rule clears stale [Field=...] when fieldSlices removed and uses payload_length for Len=',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          harness.repository.loadFromBytes(fixture.bytes, 'rich.pcap');

          final withFields = CustomProtocolRule(
            id: 'rule_big_udp',
            name: 'BIGUDP',
            colorHex: 0xFF9C27B0,
            defaultTriageStatus: TriageStatus.expected,
            ipProtocol: 17,
            port: 9000,
            fieldSlices: const [
              ProtocolFieldSlice(
                name: 'Magic',
                byteOffset: 0,
                byteLength: 2,
                dataType: FieldDataType.uint16Be,
              ),
            ],
          );

          harness.repository.addCustomProtocol(withFields);
          var pkt = harness.repository
              .queryPackets(protocolPills: {'BIGUDP'}, limit: 10)
              .single;
          expect(pkt.payloadLength, equals(1400));
          expect(pkt.payloadPreview.length, equals(256));
          expect(pkt.summary, contains('[Magic='));
          expect(pkt.customFields['Magic'], isNotNull);

          // Remove fieldSlices and relabel via addCustomProtocol (replaces same ID)
          final withoutFields = withFields.copyWith(fieldSlices: const []);
          final modified = harness.repository.addCustomProtocol(withoutFields);
          expect(modified, equals(1));

          pkt = harness.repository
              .queryPackets(protocolPills: {'BIGUDP'}, limit: 10)
              .single;
          expect(pkt.customFields, isEmpty);
          expect(pkt.summary, isNot(contains('[Magic=')));
          expect(pkt.summary, equals('55000 → 9000 [BIGUDP] Len=1400'));
        },
      );

      test(
        '[F4][T1] Specificity ordering: Tier 2 magic-bytes rule overrides Tier 1 port-only rule on relabel',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();

          final portOnly = CustomProtocolRule(
            id: 'tier1_port',
            name: 'GENERIC_45820',
            colorHex: 0xFF607D8B,
            defaultTriageStatus: TriageStatus.unclassified,
            ipProtocol: 17,
            port: 45820,
          );
          final magicRule = buildAcmeRule(
            id: 'tier2_magic',
            name: 'ACME_MAGIC',
            port: 45820,
            magicBytesOffset: 0,
            magicBytesHex: [0x41, 0x43, 0x4D, 0x45], // "ACME"
            defaultTriageStatus: TriageStatus.expected,
          );
          expect(
            magicRule.specificityScore,
            greaterThan(portOnly.specificityScore),
          );

          // Put portOnly BEFORE magicRule to prove specificity sorting works
          harness.repository.updateCustomProtocols([portOnly, magicRule]);
          harness.repository.loadFromBytes(fixture.bytes, 'spec_ingest.pcap');

          var matched = harness.repository
              .queryPackets(limit: 50)
              .firstWhere((p) => p.srcPort == 45820);
          expect(matched.detectedProtocol, equals('ACME_MAGIC'));
          expect(matched.customProtocolId, equals('tier2_magic'));

          // Now reset to portOnly, then retroactively add magicRule
          harness.repository.updateCustomProtocols([portOnly]);
          matched = harness.repository
              .queryPackets(limit: 50)
              .firstWhere((p) => p.srcPort == 45820);
          expect(matched.detectedProtocol, equals('GENERIC_45820'));

          harness.repository.updateCustomProtocols([portOnly, magicRule]);
          matched = harness.repository
              .queryPackets(limit: 50)
              .firstWhere((p) => p.srcPort == 45820);
          expect(matched.detectedProtocol, equals('ACME_MAGIC'));
          expect(matched.customProtocolId, equals('tier2_magic'));
        },
      );

      test(
        '[F4][T1] Triage consistency between initial ingest and relabelAllCustomProtocols',
        () {
          final harness = E2eTestHarness.create();
          final repoA = createIsolatedRepo(harness, subDirName: 'repo_a');
          final repoB = createIsolatedRepo(harness, subDirName: 'repo_b');

          const profile = BaselineProfile(
            id: 'consistency',
            name: 'Consistency',
            expectedSubnets: ['192.168.1.'],
            unexpectedIps: {'10.99.88.77'},
            expectedProtocols: {'DNS', 'HTTP', 'TLS'},
            silenceLanChatter: true,
          );
          final rules = [
            buildAcmeRule(defaultTriageStatus: TriageStatus.unexpected),
            const CustomProtocolRule(
              id: 'rule_bulk',
              name: 'BULK_PROTO',
              colorHex: 0xFFFF5722,
              defaultTriageStatus: TriageStatus.unexpected,
              ipProtocol: 17,
              port: 9000,
            ),
          ];

          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();

          // Repo A: rules + baseline configured BEFORE ingest
          repoA.updateBaselineProfile(profile);
          repoA.updateCustomProtocols(rules);
          repoA.loadFromBytes(fixture.bytes, 'a.pcap');

          // Repo B: ingest first, then apply baseline + retroactive relabel
          repoB.loadFromBytes(fixture.bytes, 'b.pcap');
          repoB.updateBaselineProfile(profile);
          repoB.updateCustomProtocols(rules);

          final pktsA = repoA.queryPackets(limit: 100);
          final pktsB = repoB.queryPackets(limit: 100);
          expect(pktsA.length, equals(pktsB.length));

          for (int i = 0; i < pktsA.length; i++) {
            expect(pktsA[i].detectedProtocol, equals(pktsB[i].detectedProtocol));
            expect(pktsA[i].summary, equals(pktsB[i].summary));
            expect(pktsA[i].triageStatus, equals(pktsB[i].triageStatus));
            expect(pktsA[i].customFields, equals(pktsB[i].customFields));
            expect(pktsA[i].baseProtocol, equals(pktsB[i].baseProtocol));
          }
        },
      );
    });

    group('F6 — BaselineProfile.evaluateTriage & expectedSubnets', () {
      test(
        '[F6][T1] expectedSubnets matches when ONLY srcIp starts with an expected subnet',
        () {
          const profile = BaselineProfile(
            id: 'sub_src',
            name: 'Subnet Src',
            expectedSubnets: ['192.168.1.'],
            expectedProtocols: {},
            silenceLanChatter: false,
          );

          expect(
            profile.evaluateTriage(
              srcIp: '192.168.1.10',
              dstIp: '8.8.8.8',
              detectedProtocol: 'CUSTOM',
              isLanNoise: false,
            ),
            equals(TriageStatus.expected),
          );
        },
      );

      test(
        '[F6][T1] expectedSubnets matches when ONLY dstIp starts with an expected subnet',
        () {
          const profile = BaselineProfile(
            id: 'sub_dst',
            name: 'Subnet Dst',
            expectedSubnets: ['192.168.1.'],
            expectedProtocols: {},
            silenceLanChatter: false,
          );

          expect(
            profile.evaluateTriage(
              srcIp: '8.8.8.8',
              dstIp: '192.168.1.10',
              detectedProtocol: 'CUSTOM',
              isLanNoise: false,
            ),
            equals(TriageStatus.expected),
          );
        },
      );

      test(
        '[F6][T1] Cross-subnet traffic between two different expectedSubnets (192.168.1. -> 10.0.0.)',
        () {
          const profile = BaselineProfile(
            id: 'cross_sub',
            name: 'Cross Subnet',
            expectedSubnets: ['192.168.1.', '10.0.0.'],
            expectedProtocols: {},
            silenceLanChatter: false,
          );

          expect(
            profile.evaluateTriage(
              srcIp: '192.168.1.10',
              dstIp: '10.0.0.50',
              detectedProtocol: 'CUSTOM',
              isLanNoise: false,
            ),
            equals(TriageStatus.expected),
          );
        },
      );

      test(
        '[F6][T1] expectedIps, expectedProtocols, and silenceLanChatter precedence',
        () {
          const profile = BaselineProfile(
            id: 'prec',
            name: 'Precedence',
            expectedIps: {'172.16.5.5'},
            expectedProtocols: {'HTTP'},
            silenceLanChatter: true,
          );

          // expectedIps matches srcIp or dstIp
          expect(
            profile.evaluateTriage(
              srcIp: '172.16.5.5',
              dstIp: '1.1.1.1',
              detectedProtocol: 'UNKNOWN',
              isLanNoise: false,
            ),
            equals(TriageStatus.expected),
          );
          expect(
            profile.evaluateTriage(
              srcIp: '1.1.1.1',
              dstIp: '172.16.5.5',
              detectedProtocol: 'UNKNOWN',
              isLanNoise: false,
            ),
            equals(TriageStatus.expected),
          );

          // expectedProtocols
          expect(
            profile.evaluateTriage(
              srcIp: '1.1.1.1',
              dstIp: '2.2.2.2',
              detectedProtocol: 'HTTP',
              isLanNoise: false,
            ),
            equals(TriageStatus.expected),
          );

          // silenceLanChatter
          expect(
            profile.evaluateTriage(
              srcIp: '1.1.1.1',
              dstIp: '224.0.0.251',
              detectedProtocol: 'mDNS',
              isLanNoise: true,
            ),
            equals(TriageStatus.expected),
          );
        },
      );

      test(
        '[F6][T1] defaultRuleStatus fallback when no rule matches & repository updateBaselineProfile re-evaluation',
        () {
          final harness = E2eTestHarness.create();
          const p1 = BaselineProfile(
            id: 'p1',
            name: 'P1',
            expectedProtocols: {},
            silenceLanChatter: false,
          );

          expect(
            p1.evaluateTriage(
              srcIp: '1.2.3.4',
              dstIp: '5.6.7.8',
              detectedProtocol: 'ACME',
              isLanNoise: false,
            ),
            equals(TriageStatus.unclassified),
          );
          expect(
            p1.evaluateTriage(
              srcIp: '1.2.3.4',
              dstIp: '5.6.7.8',
              detectedProtocol: 'ACME',
              isLanNoise: false,
              defaultRuleStatus: TriageStatus.unexpected,
            ),
            equals(TriageStatus.unexpected),
          );

          final builder = ClassicPcapBuilder();
          builder.addBuiltFrame(
            PcapFrameFactory.ethernetUdp(
              srcIp: '192.168.1.10',
              dstIp: '8.8.8.8',
              srcPort: 50000,
              dstPort: 9999,
              payload: Uint8List.fromList([1, 2, 3, 4]),
            ),
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs,
          );
          harness.repository.loadFromBytes(builder.buildBytes(), 'triage.pcap');

          // Initially default baseline includes UDP -> expected
          var counts = harness.repository.getTriageCounts();
          expect(counts[TriageStatus.expected], equals(1));

          // Remove UDP from expectedProtocols and add 192.168.1. subnet -> still expected via srcIp subnet!
          harness.repository.updateBaselineProfile(
            const BaselineProfile(
              id: 'sub_only',
              name: 'Subnet Only',
              expectedSubnets: ['192.168.1.'],
              expectedProtocols: {},
              silenceLanChatter: false,
            ),
          );
          counts = harness.repository.getTriageCounts();
          expect(counts[TriageStatus.expected], equals(1));

          // Change expectedSubnets to 10.0.0. -> falls back to unclassified
          harness.repository.updateBaselineProfile(
            const BaselineProfile(
              id: 'other_sub',
              name: 'Other Subnet',
              expectedSubnets: ['10.0.0.'],
              expectedProtocols: {},
              silenceLanChatter: false,
            ),
          );
          counts = harness.repository.getTriageCounts();
          expect(counts[TriageStatus.unclassified], equals(1));
        },
      );
    });

    group('F7 — PCAPNG Multi-IDB Tracking & BigInt Timestamps', () {
      test(
        '[F7][T1] Multi-IDB within single SHB tracks distinct linkTypes (Ethernet=1, Linux SLL=113, Loopback=0, Raw IP=101)',
        () {
          final ng = PcapNgBuilder();
          final ifEth = ng.addInterface(linkType: 1);
          final ifSll = ng.addInterface(linkType: 113);
          final ifLoop = ng.addInterface(linkType: 0);
          final ifRaw = ng.addInterface(linkType: 101);

          final frames = [
            (
              ifId: ifRaw,
              lt: 101,
              built: PcapFrameFactory.rawIpUdp(
                srcIp: '10.0.0.1',
                dstIp: '10.0.0.2',
                srcPort: 1001,
                dstPort: 2001,
                payload: Uint8List.fromList('RAW'.codeUnits),
              ),
            ),
            (
              ifId: ifLoop,
              lt: 0,
              built: PcapFrameFactory.loopbackUdp(
                srcIp: '127.0.0.1',
                dstIp: '127.0.0.1',
                srcPort: 1002,
                dstPort: 2002,
                payload: Uint8List.fromList('LOOP'.codeUnits),
              ),
            ),
            (
              ifId: ifSll,
              lt: 113,
              built: PcapFrameFactory.linuxSllUdp(
                srcIp: '10.0.0.3',
                dstIp: '10.0.0.4',
                srcPort: 1003,
                dstPort: 2003,
                payload: Uint8List.fromList('SLL'.codeUnits),
              ),
            ),
            (
              ifId: ifEth,
              lt: 1,
              built: PcapFrameFactory.ethernetUdp(
                srcIp: '10.0.0.5',
                dstIp: '10.0.0.6',
                srcPort: 1004,
                dstPort: 2004,
                payload: Uint8List.fromList('ETH'.codeUnits),
              ),
            ),
          ];

          for (int i = 0; i < frames.length; i++) {
            ng.addEnhancedBuiltFrame(
              interfaceId: frames[i].ifId,
              built: frames[i].built,
              timestampUs: PcapFixtureBuilder.defaultStartEpochUs + i * 1000,
            );
          }

          final parsed = PcapBinaryReader.parseBytes(ng.buildBytes());
          expect(parsed.length, equals(4));
          for (int i = 0; i < 4; i++) {
            expect(parsed[i].linkType, equals(frames[i].lt));
            final info = PacketDissector.dissect(rawPacket: parsed[i]);
            expect(info.detectedProtocol, equals('UDP'));
            expect(info.srcPort, equals(1001 + i));
          }
        },
      );

      test(
        '[F7][T1] Multi-IDB with mixed tsResolutions (omitted=10^-6, 10^-6, 10^-9, 2^-32)',
        () {
          final ng = PcapNgBuilder();
          final ifDefault = ng.addInterface(linkType: 1, tsResolCode: null);
          final ifUs = ng.addInterface(linkType: 1, tsResolCode: 6);
          final ifNs = ng.addInterface(linkType: 1, tsResolCode: 9);
          final ifBin = ng.addInterface(linkType: 1, tsResolCode: 0x80 | 32);

          final frame = PcapFrameFactory.ethernetUdp(
            srcIp: '10.0.0.1',
            dstIp: '10.0.0.2',
            srcPort: 1234,
            dstPort: 5678,
            payload: Uint8List.fromList([1, 2, 3, 4]),
          );

          ng.addEnhancedPacket(
            interfaceId: ifDefault,
            frameBytes: frame.frameBytes,
            rawTimestamp: BigInt.from(1700000000123456),
          );
          ng.addEnhancedPacket(
            interfaceId: ifUs,
            frameBytes: frame.frameBytes,
            rawTimestamp: BigInt.from(1700000001654321),
          );
          ng.addEnhancedPacket(
            interfaceId: ifNs,
            frameBytes: frame.frameBytes,
            rawTimestamp: BigInt.from(1700000002) * BigInt.from(1000000000) +
                BigInt.from(250000000),
          );
          ng.addEnhancedPacket(
            interfaceId: ifBin,
            frameBytes: frame.frameBytes,
            rawTimestamp: BigInt.from(1700000003) * (BigInt.one << 32) +
                (BigInt.one << 31),
          );

          final parsed = PcapBinaryReader.parseBytes(ng.buildBytes());
          expect(parsed.length, equals(4));
          expect(parsed[0].timestampUs, equals(1700000000123456));
          expect(parsed[1].timestampUs, equals(1700000001654321));
          expect(parsed[2].timestampUs, equals(1700000002250000));
          expect(parsed[3].timestampUs, equals(1700000003500000));
        },
      );

      test(
        '[F7][T1] Multi-SHB capture resets interfaces list and switches endianness (LE -> BE)',
        () {
          final ng = PcapNgBuilder(initialEndian: Endian.little);
          ng.addInterface(linkType: 1, tsResolCode: 6);
          ng.addInterface(linkType: 1, tsResolCode: 6);
          ng.addEnhancedBuiltFrame(
            interfaceId: 0,
            built: PcapFrameFactory.ethernetUdp(
              srcIp: '10.0.0.1',
              dstIp: '10.0.0.2',
              srcPort: 1000,
              dstPort: 2000,
              payload: Uint8List.fromList([1, 2]),
            ),
            timestampUs: 1700000000000000,
          );

          // Section 2 switches to BE and resets interfaces[0] to SLL (113) + 10^-9
          ng.addSection(endian: Endian.big);
          ng.addInterface(linkType: 113, tsResolCode: 9);
          ng.addEnhancedBuiltFrame(
            interfaceId: 0,
            built: PcapFrameFactory.linuxSllUdp(
              srcIp: '172.16.1.1',
              dstIp: '172.16.1.2',
              srcPort: 3000,
              dstPort: 4000,
              payload: Uint8List.fromList([3, 4]),
            ),
            timestampUs: 1700000005123456,
          );

          final parsed = PcapBinaryReader.parseBytes(ng.buildBytes());
          expect(parsed.length, equals(2));
          expect(parsed[0].linkType, equals(1));
          expect(parsed[0].timestampUs, equals(1700000000000000));

          expect(parsed[1].linkType, equals(113));
          expect(parsed[1].timestampUs, equals(1700000005123456));
          final info = PacketDissector.dissect(rawPacket: parsed[1]);
          expect(info.srcIp, equals('172.16.1.1'));
          expect(info.dstIp, equals('172.16.1.2'));
        },
      );

      test(
        '[F7][T1] Binary 2^-32 (if_tsresol = 0x80 | 32) BigInt overflow-safe timestamp conversion',
        () {
          final ng = PcapNgBuilder();
          final ifBin = ng.addInterface(linkType: 1, tsResolCode: 0x80 | 32);
          final frame = PcapFrameFactory.ethernetUdp(
            srcIp: '10.0.0.1',
            dstIp: '10.0.0.2',
            srcPort: 4000,
            dstPort: 5000,
            payload: Uint8List.fromList([0xAA, 0xBB]),
          );

          // 1700000001.5s * 2^32 (~7.3e18); * 1,000,000 overflows int64!
          final rawTs =
              BigInt.from(1700000001) * (BigInt.one << 32) + (BigInt.one << 31);
          ng.addEnhancedPacket(
            interfaceId: ifBin,
            frameBytes: frame.frameBytes,
            rawTimestamp: rawTs,
          );

          final parsed = PcapBinaryReader.parseBytes(ng.buildBytes());
          expect(parsed.length, equals(1));
          expect(parsed.single.timestampUs, equals(1700000001500000));
        },
      );

      test(
        '[F7][T1] Simple Packet Block (SPB) uses Section interfaces[0] linkType and timestampUs == 0',
        () {
          final ng = PcapNgBuilder();
          ng.addInterface(linkType: 113);
          ng.addSimpleBuiltFrame(
            PcapFrameFactory.linuxSllUdp(
              srcIp: '10.2.2.1',
              dstIp: '10.2.2.2',
              srcPort: 5000,
              dstPort: 6000,
              payload: Uint8List.fromList([0x11, 0x22, 0x33, 0x44]),
            ),
          );

          ng.addSection(endian: Endian.big);
          ng.addInterface(linkType: 101);
          ng.addSimpleBuiltFrame(
            PcapFrameFactory.rawIpUdp(
              srcIp: '10.3.3.1',
              dstIp: '10.3.3.2',
              srcPort: 5001,
              dstPort: 6001,
              payload: Uint8List.fromList([0x55, 0x66, 0x77, 0x88]),
            ),
          );

          final parsed = PcapBinaryReader.parseBytes(ng.buildBytes());
          expect(parsed.length, equals(2));
          expect(parsed[0].linkType, equals(113));
          expect(parsed[0].timestampUs, equals(0));
          expect(parsed[1].linkType, equals(101));
          expect(parsed[1].timestampUs, equals(0));

          expect(
            PacketDissector.dissect(rawPacket: parsed[0]).srcIp,
            equals('10.2.2.1'),
          );
          expect(
            PacketDissector.dissect(rawPacket: parsed[1]).srcIp,
            equals('10.3.3.1'),
          );
        },
      );

      test(
        '[F7][T1] End-to-end PacketRepository ingest of PcapFixtureBuilder.buildMultiIdbPcapNg()',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildMultiIdbPcapNg();
          final file = harness.writeTempCaptureFile('multi_idb.pcapng', fixture.bytes);
          harness.repository.loadFromFile(file);

          final packets = harness.repository.queryPackets(limit: 10);
          expect(packets.length, equals(4));
          expect(packets[0].detectedProtocol, equals('DNS'));
          expect(packets[0].timestampUs, equals(1700000000000000));

          expect(packets[1].srcPort, equals(45820));
          expect(packets[1].timestampUs, equals(1700000001000000));

          expect(packets[2].srcIp, equals('172.16.0.10'));
          expect(packets[2].timestampUs, equals(1700000002500000));

          expect(packets[3].srcIp, equals('172.16.0.11'));
          expect(packets[3].timestampUs, equals(0));

          for (int i = 0; i < 4; i++) {
            final exp = fixture.expectations[i];
            final slicedFrame = harness.repository.readRawPacketBytes(
              packets[i],
              payloadOnly: false,
            );
            expect(
              slicedFrame.sublist(0, exp.frameBytes.length),
              equals(exp.frameBytes),
            );
          }
        },
      );
    });

    group('F18 — RandomAccessFile Slice Reads', () {
      test(
        '[F18][T1] Disk-loaded classic PCAP slices exact frame and L4 payload bytes',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          final file = harness.writeTempCaptureFile('disk_classic.pcap', fixture.bytes);
          harness.repository.loadFromFile(file);

          expect(harness.repository.loadedFilePath, equals(file.path));
          final packets = harness.repository.queryPackets(
            limit: 50,
            silenceLanChatter: false,
          );
          expect(packets.length, equals(fixture.expectations.length));

          for (int i = 0; i < packets.length; i++) {
            final exp = fixture.expectations[i];
            expect(
              harness.repository.readRawPacketBytes(packets[i], payloadOnly: false),
              equals(exp.frameBytes),
            );
            expect(
              harness.repository.readRawPacketBytes(packets[i], payloadOnly: true),
              equals(exp.l4PayloadBytes),
            );
          }
        },
      );

      test(
        '[F18][T1] Disk-loaded PCAPNG (EPB + SPB) slices exact bytes via RandomAccessFile',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildMultiIdbPcapNg();
          final file = harness.writeTempCaptureFile('disk_ng.pcapng', fixture.bytes);
          harness.repository.loadFromFile(file);

          final packets = harness.repository.queryPackets(limit: 10);
          expect(packets.length, equals(4));

          for (int i = 0; i < 4; i++) {
            final exp = fixture.expectations[i];
            final frame = harness.repository.readRawPacketBytes(
              packets[i],
              payloadOnly: false,
            );
            final payload = harness.repository.readRawPacketBytes(
              packets[i],
              payloadOnly: true,
            );
            expect(frame.sublist(0, exp.frameBytes.length), equals(exp.frameBytes));
            expect(payload, equals(exp.l4PayloadBytes));
          }
        },
      );

      test(
        '[F18][T1] Random-order / repeated reads on large (>1,500 packet) disk capture',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildBulkPcap(packetCount: 1500);
          final file = harness.writeTempCaptureFile('bulk_1500.pcap', fixture.bytes);
          harness.repository.loadFromFile(file);

          final allPackets = harness.repository.queryPackets(limit: 1500, offset: 0);
          expect(allPackets.length, equals(1500));

          for (final idx in [0, 1499, 749, 1, 1498, 749, 0]) {
            final pkt = allPackets[idx];
            final exp = fixture.expectations[idx];
            expect(
              harness.repository.readRawPacketBytes(pkt, payloadOnly: false),
              equals(exp.frameBytes),
            );
            expect(
              harness.repository.readRawPacketBytes(pkt, payloadOnly: true),
              equals(exp.l4PayloadBytes),
            );
          }
        },
      );

      test(
        '[F18][T1] In-memory loadFromBytes parity with disk loadFromFile',
        () {
          final harness = E2eTestHarness.create();
          final repoMem = createIsolatedRepo(harness, subDirName: 'mem');
          final repoDisk = createIsolatedRepo(harness, subDirName: 'disk');

          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          final file = harness.writeTempCaptureFile('parity.pcap', fixture.bytes);

          repoMem.loadFromBytes(fixture.bytes, 'parity.pcap');
          repoDisk.loadFromFile(file);

          final memPackets = repoMem.queryPackets(limit: 100);
          final diskPackets = repoDisk.queryPackets(limit: 100);
          expect(memPackets.length, equals(diskPackets.length));

          for (int i = 0; i < memPackets.length; i++) {
            expect(
              repoMem.readRawPacketBytes(memPackets[i], payloadOnly: false),
              equals(
                repoDisk.readRawPacketBytes(diskPackets[i], payloadOnly: false),
              ),
            );
            expect(
              repoMem.readRawPacketBytes(memPackets[i], payloadOnly: true),
              equals(
                repoDisk.readRawPacketBytes(diskPackets[i], payloadOnly: true),
              ),
            );
          }
        },
      );

      test(
        '[F18][T1] File modification/deletion detection proves disk-backed RandomAccessFile read (not full-file buffer)',
        () {
          final harness = E2eTestHarness.create();
          final builder = ClassicPcapBuilder();
          builder.addBuiltFrame(
            PcapFrameFactory.ethernetUdp(
              srcIp: '192.168.1.10',
              dstIp: '192.168.1.20',
              srcPort: 5000,
              dstPort: 6000,
              payload: Uint8List.fromList([0x41, 0x42, 0x43, 0x44]),
            ),
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs,
          );
          final fixture = builder.buildWithExpectations();
          final file = harness.writeTempCaptureFile('live_raf.pcap', fixture.bytes);
          harness.repository.loadFromFile(file);

          final pkt = harness.repository.queryPackets(limit: 10).single;
          expect(
            harness.repository.readRawPacketBytes(pkt, payloadOnly: true),
            equals(Uint8List.fromList([0x41, 0x42, 0x43, 0x44])),
          );

          // Patch payload byte 0 on disk; disk-backed read sees update immediately
          final bytesCopy = file.readAsBytesSync();
          bytesCopy[pkt.payloadFileOffset] = 0x5A; // 'Z'
          file.writeAsBytesSync(bytesCopy, flush: true);

          expect(
            harness.repository.readRawPacketBytes(pkt, payloadOnly: true),
            equals(Uint8List.fromList([0x5A, 0x42, 0x43, 0x44])),
          );

          // Deleting file makes subsequent slice read return empty cleanly
          file.deleteSync();
          expect(
            harness.repository.readRawPacketBytes(pkt, payloadOnly: true),
            isEmpty,
          );
        },
      );
    });

    group('F21 — Storage Isolation, Default Fallback & Library Bundles', () {
      test(
        '[F21][T1] SharedDeviceDatabase.getDefaultDirectoryPath() & default service paths (read-only)',
        () {
          final defaultDir = SharedDeviceDatabase.getDefaultDirectoryPath();
          final defaultDb = SharedDeviceDatabase.getDefaultDatabasePath();

          expect(p.basename(defaultDir), equals('NetworkSuite'));
          expect(defaultDb, equals(p.join(defaultDir, 'shared_devices.db')));

          // Read-only path checks (never write to host home directory in tests)
          final defaultLib = ProtocolLibraryService();
          expect(
            defaultLib.resolveWritePath('custom_protocols.json'),
            equals(p.join(defaultDir, 'custom_protocols.json')),
          );

          final defaultAi = AiSettingsStorageService();
          expect(
            defaultAi.resolvedFilePath,
            equals(p.join(defaultDir, 'ai_settings.json')),
          );
        },
      );

      test(
        '[F21][T1] Recursive parent directory creation (createSync(recursive: true)) for ProtocolLibraryService & AiSettingsStorageService',
        () {
          final harness = E2eTestHarness.create();
          final nestedDir = Directory(
            p.join(harness.tempDir.path, 'lvl1', 'lvl2', 'lvl3'),
          );
          expect(nestedDir.existsSync(), isFalse);

          final libStorage = ProtocolLibraryService(storageDirectory: nestedDir);
          final aiStorage = AiSettingsStorageService(storageDirectory: nestedDir);

          final rule = buildAcmeRule();
          const profile = BaselineProfile(
            id: 'nested_prof',
            name: 'Nested Profile',
            expectedSubnets: ['10.20.'],
          );
          const sender = EndpointRule(
            id: 's1',
            name: 'PLC-1',
            ipAddress: '10.20.0.5',
            port: 502,
            type: EndpointType.sender,
          );
          const receiver = EndpointRule(
            id: 'r1',
            name: 'SCADA',
            ipAddress: '10.20.0.10',
            type: EndpointType.receiver,
          );
          const settings = AiSettings(
            backendMode: LlmBackendMode.claudeCodeCli,
            claudePath: '/opt/bin/claude',
            claudeModel: 'sonnet',
          );

          libStorage.saveCustomProtocols([rule]);
          libStorage.saveBaselineProfile(profile);
          libStorage.saveSenders([sender]);
          libStorage.saveReceivers([receiver]);
          aiStorage.saveSettings(settings);

          expect(nestedDir.existsSync(), isTrue);
          expect(
            File(p.join(nestedDir.path, 'custom_protocols.json')).existsSync(),
            isTrue,
          );
          expect(
            File(p.join(nestedDir.path, 'baseline_profiles.json')).existsSync(),
            isTrue,
          );
          expect(
            File(p.join(nestedDir.path, 'sender_library.json')).existsSync(),
            isTrue,
          );
          expect(
            File(p.join(nestedDir.path, 'receiver_library.json')).existsSync(),
            isTrue,
          );
          expect(
            File(p.join(nestedDir.path, 'ai_settings.json')).existsSync(),
            isTrue,
          );

          expect(libStorage.loadCustomProtocols().single.id, equals('rule_acme'));
          expect(libStorage.loadBaselineProfile().id, equals('nested_prof'));
          expect(libStorage.loadSenders().single.ipAddress, equals('10.20.0.5'));
          expect(libStorage.loadReceivers().single.ipAddress, equals('10.20.0.10'));
          expect(aiStorage.loadSettings().claudeModel, equals('sonnet'));
        },
      );

      test(
        '[F21][T1] ProtocolLibraryService exportLibraryBundleJson / importLibraryBundleJson full round-trip',
        () {
          final harness = E2eTestHarness.create();
          final repoA = createIsolatedRepo(harness, subDirName: 'export_a');
          final repoB = createIsolatedRepo(harness, subDirName: 'import_b');

          final acme = buildAcmeRule(
            ipAddressFilter: '192.168.1.10',
            defaultTriageStatus: TriageStatus.expected,
          );
          const src = EndpointRule(
            id: 'ep_src',
            name: 'Sensor',
            ipAddress: '192.168.1.10',
            port: 45820,
            colorHex: 0xFF4CAF50,
            type: EndpointType.sender,
          );
          const dst = EndpointRule(
            id: 'ep_dst',
            name: 'Collector',
            ipAddress: '192.168.1.200',
            port: 45820,
            colorHex: 0xFF2196F3,
            type: EndpointType.receiver,
          );

          repoA.addCustomProtocol(acme);
          repoA.addSource(src);
          repoA.addDestination(dst);
          final bundleJson = repoA.exportLibraryBundle();

          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          repoB.loadFromBytes(fixture.bytes, 'bundle_test.pcap');
          final counts = repoB.importLibraryBundle(bundleJson);

          expect(counts['protocols'], equals(1));
          expect(counts['sources'], equals(1));
          expect(counts['destinations'], equals(1));
          expect(repoB.customRules.single.ipAddressFilter, equals('192.168.1.10'));
          expect(repoB.customRules.single.fieldSlices.length, equals(4));
          expect(repoB.senders.single.filterKey, equals('192.168.1.10:45820'));
          expect(repoB.receivers.single.filterKey, equals('192.168.1.200:45820'));

          final relabeled = repoB.queryPackets(protocolPills: {'ACME'}, limit: 10);
          expect(relabeled.length, equals(1));
          expect(relabeled.single.customFields['Tag'], equals('PROD'));
        },
      );

      test(
        '[F21][T1] AiSettingsStorageService encrypted Gemini API key & CLI settings round-trip',
        () {
          final harness = E2eTestHarness.create();
          final aiDir = harness.createSubDir('ai_vault');
          final storage = AiSettingsStorageService(storageDirectory: aiDir);

          const original = AiSettings(
            backendMode: LlmBackendMode.antigravityCli,
            geminiApiKey: 'AIzaSyTestSecretKey987654321',
            geminiModel: 'gemini-3.8-pro',
            ollamaUrl: 'http://127.0.0.1:11434',
            ollamaModel: 'gemma3:4b',
            agyPath: '/usr/local/bin/agy',
            claudePath: '/usr/local/bin/claude',
            codexPath: '/usr/local/bin/codex',
            agyModel: 'gemini-3.8-flash-high',
            claudeModel: 'sonnet',
            codexModel: 'gpt-5',
          );

          storage.saveSettings(original);
          final rawJson = File(storage.resolvedFilePath).readAsStringSync();
          expect(rawJson, isNot(contains('AIzaSyTestSecretKey987654321')));
          final decoded = jsonDecode(rawJson) as Map<String, dynamic>;
          expect(decoded['gemini_api_key_enc'], isA<String>());
          expect((decoded['gemini_api_key_enc'] as String), isNotEmpty);

          final reloaded = storage.loadSettings();
          expect(reloaded.backendMode, equals(LlmBackendMode.antigravityCli));
          expect(reloaded.geminiApiKey, equals('AIzaSyTestSecretKey987654321'));
          expect(reloaded.geminiModel, equals('gemini-3.8-pro'));
          expect(reloaded.ollamaUrl, equals('http://127.0.0.1:11434'));
          expect(reloaded.ollamaModel, equals('gemma3:4b'));
          expect(reloaded.agyPath, equals('/usr/local/bin/agy'));
          expect(reloaded.claudePath, equals('/usr/local/bin/claude'));
          expect(reloaded.codexPath, equals('/usr/local/bin/codex'));
          expect(reloaded.agyModel, equals('gemini-3.8-flash-high'));
          expect(reloaded.claudeModel, equals('sonnet'));
          expect(reloaded.codexModel, equals('gpt-5'));
        },
      );

      test(
        '[F21][T1] SharedDeviceDatabase isolated customPath DB & :memory: theme persistence',
        () async {
          final harness = E2eTestHarness.create();
          final memDb = SharedDeviceDatabase(customPath: ':memory:');
          addTearDown(memDb.dispose);
          expect(await memDb.getThemeMode(), equals('dark'));
          await memDb.setThemeMode('light');
          expect(await memDb.getThemeMode(), equals('light'));

          final dbPath = p.join(harness.tempDir.path, 'nested_db', 'shared.db');
          final fileDb = SharedDeviceDatabase(customPath: dbPath);
          addTearDown(fileDb.dispose);

          int eventCount = 0;
          final sub = fileDb.onDatabaseChanged.listen((_) => eventCount++);
          addTearDown(sub.cancel);

          await fileDb.setThemeMode('light');
          expect(File(dbPath).existsSync(), isTrue);
          expect(await fileDb.getThemeMode(), equals('light'));
          expect(eventCount, greaterThanOrEqualTo(1));
        },
      );
    });

    group('F22 — Parameterized SQLite Queries & 256-Byte payloadPreview Cap', () {
      test(
        '[F22][T1] 256-byte payloadPreview cap on 1400B packet while RandomAccessFile slices full 1400B',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          final file = harness.writeTempCaptureFile('preview_1400.pcap', fixture.bytes);
          harness.repository.loadFromFile(file);

          final largePkt = harness.repository
              .queryPackets(limit: 50)
              .firstWhere((p) => p.payloadLength == 1400);
          final expectedPayload = PcapFrameFactory.repeatedBytesPayload(1400);

          expect(largePkt.payloadPreview.length, equals(PacketDissector.maxPayloadPreviewBytes));
          expect(largePkt.payloadPreview.length, equals(256));
          expect(
            largePkt.payloadPreview,
            equals(expectedPayload.sublist(0, 256)),
          );

          final fullSliced = harness.repository.readRawPacketBytes(
            largePkt,
            payloadOnly: true,
          );
          expect(fullSliced.length, equals(1400));
          expect(fullSliced, equals(expectedPayload));
        },
      );

      test(
        '[F22][T1] Parameterized queryPackets & getPacketCount with triageStatuses, protocolPills, sender/receiverFilters, ipFilters, timeWindow',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          harness.repository.loadFromBytes(fixture.bytes, 'filters.pcap');

          final all = harness.repository.queryPackets(
            limit: 100,
            silenceLanChatter: false,
          );
          final startTs = all[2].timestampUs;
          final endTs = all[6].timestampUs;

          final count = harness.repository.getPacketCount(
            triageStatuses: {TriageStatus.expected},
            silenceLanChatter: false,
            protocolPills: {'DNS', 'HTTP'},
            senderFilters: {'192.168.1.10'},
            ipFilters: {'8.8.8.8', '93.184.216.34'},
            timeStartUs: startTs,
            timeEndUs: endTs,
          );
          final filtered = harness.repository.queryPackets(
            triageStatuses: {TriageStatus.expected},
            silenceLanChatter: false,
            protocolPills: {'DNS', 'HTTP'},
            senderFilters: {'192.168.1.10'},
            ipFilters: {'8.8.8.8', '93.184.216.34'},
            timeStartUs: startTs,
            timeEndUs: endTs,
            limit: 10,
            offset: 0,
            sortColumn: 'timestamp_us',
            sortAscending: false,
          );

          expect(count, equals(2));
          expect(filtered.length, equals(2));
          expect(
            filtered[0].timestampUs,
            greaterThanOrEqualTo(filtered[1].timestampUs),
          );
          final page2 = harness.repository.queryPackets(
            triageStatuses: {TriageStatus.expected},
            silenceLanChatter: false,
            protocolPills: {'DNS', 'HTTP'},
            senderFilters: {'192.168.1.10'},
            ipFilters: {'8.8.8.8', '93.184.216.34'},
            timeStartUs: startTs,
            timeEndUs: endTs,
            limit: 1,
            offset: 1,
          );
          expect(page2.length, equals(1));
        },
      );

      test(
        '[F22][T1] Parameterized queryTopSenders, queryTopReceivers, countPacketsForEndpoint, and countPacketsForEndpoints',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          harness.repository.loadFromBytes(fixture.bytes, 'endpoints.pcap');

          final topSenders = harness.repository.getTopSenders(
            limit: 10,
            silenceLanChatter: false,
          );
          final topReceivers = harness.repository.getTopReceivers(
            limit: 20,
            silenceLanChatter: false,
          );
          expect(topSenders['192.168.1.10'], greaterThanOrEqualTo(5));
          expect(topReceivers['8.8.8.8'], equals(1));

          final keys = ['192.168.1.10', '192.168.1.10:45820', '8.8.8.8'];
          final batchSenders = harness.repository.countPacketsForEndpoints(
            endpointKeys: keys,
            isSender: true,
          );
          for (final key in keys) {
            final parts = key.split(':');
            final ip = parts[0];
            final port = parts.length > 1 ? int.parse(parts[1]) : null;
            final single = harness.repository.countPacketsForEndpoint(
              ip: ip,
              port: port,
              isSender: true,
            );
            expect(batchSenders[key], equals(single));
          }
        },
      );

      test(
        '[F22][T1] Parameterized SQL queries resist SQL injection metacharacters across all filter methods',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          harness.repository.loadFromBytes(fixture.bytes, 'sqli.pcap');
          final baselineTotal = harness.repository.getPacketCount(
            silenceLanChatter: false,
          );

          const payloads = [
            "'; DROP TABLE packets; --",
            "192.168.%' OR '1'='1",
            '" UNION SELECT * FROM sqlite_master --',
          ];

          for (final inj in payloads) {
            expect(
              harness.repository.getPacketCount(
                sourceSearch: inj,
                silenceLanChatter: false,
              ),
              equals(0),
            );
            expect(
              harness.repository.queryPackets(
                destSearch: inj,
                silenceLanChatter: false,
              ),
              isEmpty,
            );
            expect(
              harness.repository.getProtocolCounts(
                sourceSearch: inj,
                silenceLanChatter: false,
              ),
              isEmpty,
            );
            expect(
              harness.repository.queryPackets(
                protocolPills: {inj},
                silenceLanChatter: false,
              ),
              isEmpty,
            );
            expect(
              harness.repository.queryPackets(
                ipFilters: {inj},
                silenceLanChatter: false,
              ),
              isEmpty,
            );
            expect(
              harness.repository.getTopSenders(destSearch: inj),
              isEmpty,
            );
            expect(
              harness.repository.getTopReceivers(sourceSearch: inj),
              isEmpty,
            );
            expect(
              harness.repository.countPacketsForEndpoints(
                endpointKeys: [inj],
                isSender: true,
              ),
              equals({inj: 0}),
            );
          }

          // Table remains completely intact
          expect(
            harness.repository.getPacketCount(silenceLanChatter: false),
            equals(baselineTotal),
          );
        },
      );

      test(
        '[F22][T1] Custom protocol magic bytes & field slices within 256B preview (sACN seq at offset 111 & offset 200)',
        () {
          final harness = E2eTestHarness.create();
          final builder = ClassicPcapBuilder();
          final sacnPayload = PcapFrameFactory.sacnDmxPayload(seq: 77, universe: 3);
          final custom250 = Uint8List(300);
          custom250.setRange(200, 204, 'CTRL'.codeUnits);
          custom250[240] = 0x2A; // decimal 42

          builder.addBuiltFrame(
            PcapFrameFactory.ethernetUdp(
              srcIp: '10.10.1.10',
              dstIp: '239.255.0.3',
              srcPort: 5568,
              dstPort: 5568,
              payload: sacnPayload,
            ),
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs,
          );
          builder.addBuiltFrame(
            PcapFrameFactory.ethernetUdp(
              srcIp: '10.10.1.11',
              dstIp: '10.10.1.12',
              srcPort: 6000,
              dstPort: 6001,
              payload: custom250,
            ),
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs + 1000,
          );

          harness.repository.loadFromBytes(builder.buildBytes(), 'sacn_256.pcap');
          harness.repository.updateCustomProtocols([
            CustomProtocolRule(
              id: 'sacn_rule',
              name: 'sACN',
              colorHex: 0xFF00E676,
              defaultTriageStatus: TriageStatus.expected,
              ipProtocol: 17,
              port: 5568,
              magicBytesOffset: 4,
              magicBytesHex: 'ASC-E1.17'.codeUnits,
              fieldSlices: const [
                ProtocolFieldSlice(
                  name: 'Seq',
                  byteOffset: 111,
                  byteLength: 1,
                  dataType: FieldDataType.uint8,
                ),
                ProtocolFieldSlice(
                  name: 'Universe',
                  byteOffset: 113,
                  byteLength: 2,
                  dataType: FieldDataType.uint16Be,
                ),
              ],
            ),
            CustomProtocolRule(
              id: 'ctrl_200',
              name: 'CTRL300',
              colorHex: 0xFF40C4FF,
              defaultTriageStatus: TriageStatus.expected,
              ipProtocol: 17,
              port: 6001,
              magicBytesOffset: 200,
              magicBytesHex: 'CTRL'.codeUnits,
              fieldSlices: const [
                ProtocolFieldSlice(
                  name: 'Code',
                  byteOffset: 240,
                  byteLength: 1,
                  dataType: FieldDataType.uint8,
                ),
              ],
            ),
          ]);

          final sacnPkt = harness.repository
              .queryPackets(protocolPills: {'sACN'}, limit: 5)
              .single;
          expect(sacnPkt.customFields['Seq'], equals(77));
          expect(sacnPkt.customFields['Universe'], equals(3));

          final ctrlPkt = harness.repository
              .queryPackets(protocolPills: {'CTRL300'}, limit: 5)
              .single;
          expect(ctrlPkt.payloadLength, equals(300));
          expect(ctrlPkt.payloadPreview.length, equals(256));
          expect(ctrlPkt.customFields['Code'], equals(42));
        },
      );
    });

    group('F13–F17 — Post-Cleanup API Contract Verification', () {
      test(
        '[F13][T1] Dependency & import contract: pubspec.yaml excludes cupertino_icons and path_provider',
        () {
          final pubspecText = File('pubspec.yaml').readAsStringSync();
          expect(pubspecText, isNot(contains('cupertino_icons')));
          expect(pubspecText, isNot(contains('path_provider')));
          expect(pubspecText, contains('sqlite3:'));
          expect(pubspecText, contains('path:'));
        },
      );

      test(
        '[F14/F15][T1] Model & Theme post-cleanup contracts',
        () {
          final dark = AppTheme.darkTheme();
          final light = AppTheme.lightTheme();
          expect(dark.brightness, equals(Brightness.dark));
          expect(light.brightness, equals(Brightness.light));
          expect(AppTheme.scaffoldBg, isA<Color>());
          expect(AppTheme.surface, isA<Color>());
          expect(AppTheme.surfaceHigh, isA<Color>());
          expect(AppTheme.border, isA<Color>());
          expect(AppTheme.textPrimary, isA<Color>());
          expect(AppTheme.textSecondary, isA<Color>());
          expect(AppTheme.textMuted, isA<Color>());
          expect(AppTheme.accent, isA<Color>());
          expect(AppTheme.success, isA<Color>());
          expect(AppTheme.error, isA<Color>());
          expect(AppTheme.warning, isA<Color>());

          const slot = CaptureSlot(
            captureIndex: 0,
            label: 'A: Console',
            filePath: 'a.pcap',
            packetCount: 10,
            clockOffsetUs: 2500,
          );
          expect(slot.clockOffsetMs, equals(2.5));
          expect(slot.formattedClockOffset, equals('Baseline (0.0 ms)'));

          const flow = FlowDiffSummary(
            flowHash: 123,
            srcIp: '10.0.0.1',
            dstIp: '10.0.0.2',
            srcPort: 1000,
            dstPort: 2000,
            protocolName: 'UDP',
            totalSent: 5,
            hopDeliveredCounts: {1: 4},
            droppedCount: 1,
            sourceGapCount: 0,
            outOfOrderCount: 0,
            mutatedCount: 0,
            spikeCount: 0,
            avgTransitDeltaUs: 100.0,
            maxTransitDeltaUs: 200,
          );
          expect(flow.totalSent, equals(5));

          const hop = HopMatch(
            captureIndex: 1,
            frameNumber: 2,
            timestampUs: 1000,
            transitDeltaUs: 50,
          );
          expect(hop.frameNumber, equals(2));

          final rec = PacketDiffRecord(
            rowIndex: 1,
            flowHash: 123,
            fingerprintHash: 456,
            occurrenceIndex: 0,
            srcIp: '10.0.0.1',
            dstIp: '10.0.0.2',
            srcPort: 1000,
            dstPort: 2000,
            protocolName: 'UDP',
            baselineCaptureIndex: 0,
            baselineFrameNumber: 1,
            baselineTimestampUs: 950,
            packetLength: 64,
            hopMatches: {1: hop},
            statuses: const {DiffStatus.ok},
            primaryStatus: DiffStatus.ok,
            statusDetail: 'OK',
          );
          expect(rec.flowDisplay, equals('10.0.0.1:1000 -> 10.0.0.2:2000'));
          expect(PacketDiffRecord.dscpLabel(46), equals('EF (46)'));
        },
      );

      test(
        '[F16][T1] Storage & Repo canonical bundle/relabel APIs',
        () {
          final harness = E2eTestHarness.create();
          final storage = ProtocolLibraryService(
            storageDirectory: harness.createSubDir('f16_storage'),
          );
          final json = storage.exportLibraryBundleJson(
            protocols: [buildAcmeRule()],
            sources: const [
              EndpointRule(id: 's1', name: 'Src', ipAddress: '10.0.0.1'),
            ],
            destinations: const [
              EndpointRule(
                id: 'd1',
                name: 'Dst',
                ipAddress: '10.0.0.2',
                type: EndpointType.receiver,
              ),
            ],
          );
          final imported = storage.importLibraryBundleJson(json);
          expect((imported['protocols'] as List).length, equals(1));
          expect((imported['sources'] as List).length, equals(1));
          expect((imported['destinations'] as List).length, equals(1));

          final db = PacketDatabaseService();
          addTearDown(db.close);
          expect(db.relabelAllCustomProtocols([buildAcmeRule()]), equals(0));
        },
      );

      test(
        '[F17][T1] Post-cleanup PacketRepository & PacketDatabaseService query signatures (no isTriageMode)',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          harness.repository.loadFromBytes(fixture.bytes, 'f17.pcap');

          // All 6 PacketRepository query methods called without isTriageMode
          final pkts = harness.repository.queryPackets(
            triageStatuses: {TriageStatus.expected},
            silenceLanChatter: false,
            limit: 50,
          );
          final count = harness.repository.getPacketCount(
            triageStatuses: {TriageStatus.expected},
            silenceLanChatter: false,
          );
          final protos = harness.repository.getProtocolCounts(
            triageStatuses: {TriageStatus.expected},
            silenceLanChatter: false,
          );
          final senders = harness.repository.getTopSenders(
            triageStatuses: {TriageStatus.expected},
            silenceLanChatter: false,
          );
          final receivers = harness.repository.getTopReceivers(
            triageStatuses: {TriageStatus.expected},
            silenceLanChatter: false,
          );
          final epCount = harness.repository.countPacketsForEndpoint(
            ip: '192.168.1.10',
            isSender: true,
            triageStatuses: {TriageStatus.expected},
            silenceLanChatter: false,
          );

          expect(pkts.length, equals(count));
          expect(protos.values.fold<int>(0, (a, b) => a + b), equals(count));
          expect(senders, isNotEmpty);
          expect(receivers, isNotEmpty);
          expect(epCount, greaterThan(0));
        },
      );

      test(
        '[F15/F16][T1] EndpointRule post-cleanup contract and SQL endpoint filtering',
        () {
          final harness = E2eTestHarness.create();
          const sender = EndpointRule(
            id: 'ep_1',
            name: 'Controller',
            ipAddress: '192.168.1.10',
            port: 45820,
            type: EndpointType.sender,
          );
          expect(sender.filterKey, equals('192.168.1.10:45820'));
          expect(sender.displayName, equals('Controller (192.168.1.10:45820)'));

          final roundTrip = EndpointRule.fromMap(sender.toMap());
          expect(roundTrip.filterKey, equals(sender.filterKey));
          expect(roundTrip.type, equals(EndpointType.sender));

          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          harness.repository.loadFromBytes(fixture.bytes, 'ep_filter.pcap');
          final matched = harness.repository.queryPackets(
            senderFilters: {sender.filterKey},
            silenceLanChatter: false,
          );
          expect(matched.length, equals(1));
          expect(matched.single.srcPort, equals(45820));
        },
      );
    });
  });

  group('Tier 2 — Boundary & Corner Cases', () {
    group('F1 — Byte Offset & Parser Boundaries', () {
      test(
        '[F1][T2] Empty capture (header only, 0 packets) yields 0 records cleanly',
        () {
          final harness = E2eTestHarness.create();
          final classicEmpty = ClassicPcapBuilder().buildBytes();
          harness.repository.loadFromBytes(classicEmpty, 'empty.pcap');
          expect(harness.repository.getPacketCount(), equals(0));
          expect(harness.repository.queryPackets(), isEmpty);

          final ng = PcapNgBuilder();
          ng.addInterface(linkType: 1);
          harness.repository.loadFromBytes(ng.buildBytes(), 'empty.pcapng');
          expect(harness.repository.getPacketCount(), equals(0));
          expect(harness.repository.queryPackets(), isEmpty);
        },
      );

      test(
        '[F1][T2] Truncated trailing classic PCAP packet stops cleanly without throwing',
        () {
          final harness = E2eTestHarness.create();
          final builder = ClassicPcapBuilder();
          builder.addBuiltFrame(
            PcapFrameFactory.ethernetUdp(
              srcIp: '10.0.0.1',
              dstIp: '10.0.0.2',
              srcPort: 1000,
              dstPort: 2000,
              payload: Uint8List.fromList([1, 2, 3, 4]),
            ),
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs,
          );
          builder.appendTruncatedTrailingPacket(
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs + 5000,
            claimedLength: 100,
            actualTrailingBytes: 10,
          );

          final file = harness.writeTempCaptureFile('trunc.pcap', builder.buildBytes());
          harness.repository.loadFromFile(file);
          expect(harness.repository.getPacketCount(), equals(1));
          expect(
            harness.repository.readRawPacketBytes(
              harness.repository.queryPackets().single,
              payloadOnly: true,
            ),
            equals(Uint8List.fromList([1, 2, 3, 4])),
          );
        },
      );

      test(
        '[F1][T2] Invalid magic header and <24B file throw FormatException',
        () {
          expect(
            PcapBinaryReader.detectFormat(Uint8List(2)),
            equals(PcapFormat.unknown),
          );
          expect(
            () => PcapBinaryReader.parseBytes(Uint8List(0)),
            throwsFormatException,
          );
          expect(
            () => PcapBinaryReader.parseBytes(
              Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0]),
            ),
            throwsFormatException,
          );
          // Valid classic PCAP magic but < 24 bytes global header
          final shortClassic = Uint8List(20);
          ByteData.sublistView(shortClassic).setUint32(0, 0xA1B2C3D4, Endian.little);
          expect(
            () => PcapBinaryReader.parseBytes(shortClassic),
            throwsFormatException,
          );
        },
      );

      test(
        '[F1][T2] IPv4 options (IHL=24) and TCP options (dataOffset=32) custom raw frame offsets',
        () {
          final harness = E2eTestHarness.create();
          final payload = Uint8List.fromList('OPT_PAYLOAD'.codeUnits);
          // 14B Ethernet + 24B IPv4 (IHL=6) + 32B TCP (dataOffset=8) + 11B payload = 81B
          final frame = Uint8List(14 + 24 + 32 + payload.length);
          frame.setRange(0, 6, PcapFrameFactory.defaultDstMac);
          frame.setRange(6, 12, PcapFrameFactory.defaultSrcMac);
          frame[12] = 0x08;
          frame[13] = 0x00;

          // IPv4 with IHL=6 (24 bytes)
          frame[14] = 0x46;
          ByteData.sublistView(frame, 14, 38)
            ..setUint16(2, 24 + 32 + payload.length, Endian.big)
            ..setUint8(8, 64)
            ..setUint8(9, 6); // TCP
          frame.setRange(14 + 12, 14 + 16, [192, 168, 5, 1]);
          frame.setRange(14 + 16, 14 + 20, [192, 168, 5, 2]);
          // 4B IP options at 34..37
          frame.setRange(34, 38, [0x01, 0x01, 0x01, 0x00]);

          // TCP at offset 38 with dataOffset=8 (32 bytes)
          final tcpBd = ByteData.sublistView(frame, 38, 70);
          tcpBd.setUint16(0, 44444, Endian.big);
          tcpBd.setUint16(2, 8080, Endian.big);
          tcpBd.setUint32(4, 1, Endian.big);
          tcpBd.setUint32(8, 1, Endian.big);
          tcpBd.setUint8(12, 8 << 4);
          tcpBd.setUint8(13, 0x18); // PSH+ACK
          // 12B TCP options at 58..69
          frame.setRange(70, 70 + payload.length, payload);

          final builder = ClassicPcapBuilder();
          builder.addFrame(
            frame,
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs,
            payloadOffsetInFrame: 70,
            l4PayloadBytes: payload,
          );
          final file = harness.writeTempCaptureFile('ip_tcp_opts.pcap', builder.buildBytes());
          harness.repository.loadFromFile(file);

          final pkt = harness.repository.queryPackets().single;
          expect(pkt.payloadFileOffset - pkt.fileByteOffset, equals(14 + 24 + 32));
          expect(
            harness.repository.readRawPacketBytes(pkt, payloadOnly: true),
            equals(payload),
          );
        },
      );

      test(
        '[F1][T2] Zero-length L4 payload (TCP SYN) & non-IP EtherType (0x88CC LLDP)',
        () {
          final harness = E2eTestHarness.create();
          final builder = ClassicPcapBuilder();

          final synFrame = PcapFrameFactory.ethernetTcp(
            srcIp: '10.0.0.1',
            dstIp: '10.0.0.2',
            srcPort: 50000,
            dstPort: 443,
            seqNum: 100,
            ackNum: 0,
            flags: 0x02,
            payload: Uint8List(0),
          );
          builder.addBuiltFrame(
            synFrame,
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs,
          );

          // LLDP frame (EtherType 0x88CC)
          final lldpPayload = Uint8List.fromList([0x02, 0x07, 0x04, 0xAA, 0xBB, 0xCC]);
          final lldpFrame = Uint8List(14 + lldpPayload.length);
          lldpFrame.setRange(0, 6, [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E]);
          lldpFrame.setRange(6, 12, PcapFrameFactory.defaultSrcMac);
          lldpFrame[12] = 0x88;
          lldpFrame[13] = 0xCC;
          lldpFrame.setRange(14, lldpFrame.length, lldpPayload);
          builder.addFrame(
            lldpFrame,
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs + 1000,
            payloadOffsetInFrame: 14,
            l4PayloadBytes: lldpPayload,
          );

          final file = harness.writeTempCaptureFile('syn_lldp.pcap', builder.buildBytes());
          harness.repository.loadFromFile(file);

          final packets = harness.repository.queryPackets(
            limit: 10,
            silenceLanChatter: false,
          );
          expect(packets.length, equals(2));

          // TCP SYN has 0-byte payload but full 54-byte frame
          expect(packets[0].payloadLength, equals(0));
          expect(
            harness.repository.readRawPacketBytes(packets[0], payloadOnly: true),
            isEmpty,
          );
          expect(
            harness.repository.readRawPacketBytes(packets[0], payloadOnly: false),
            equals(synFrame.frameBytes),
          );

          // LLDP dissects cleanly with intact payload slice
          expect(packets[1].detectedProtocol, equals('ETH:0x88cc'));
          expect(
            harness.repository.readRawPacketBytes(packets[1], payloadOnly: true),
            equals(lldpPayload),
          );
        },
      );

      test(
        '[F1][T2] Truncated/malformed L2/L3/L4 frames and loadFromBytes vs loadFromFile parity',
        () {
          final harness = E2eTestHarness.create();
          final builder = ClassicPcapBuilder();

          // 1. Short Ethernet (<14B)
          builder.addFrame(
            Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]),
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs,
          );
          // 2. Short IPv4 (<20B after 14B Ethernet)
          final shortIp = Uint8List(24);
          shortIp[12] = 0x08;
          shortIp[13] = 0x00;
          builder.addFrame(
            shortIp,
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs + 100,
          );
          // 3. Malformed ARP (<28B after 14B Ethernet)
          final shortArp = Uint8List(24);
          shortArp[12] = 0x08;
          shortArp[13] = 0x06;
          builder.addFrame(
            shortArp,
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs + 200,
          );

          final bytes = builder.buildBytes();
          final repoMem = createIsolatedRepo(harness, subDirName: 'mal_mem');
          final repoFile = createIsolatedRepo(harness, subDirName: 'mal_file');
          final file = harness.writeTempCaptureFile('malformed.pcap', bytes);

          repoMem.loadFromBytes(bytes, 'malformed.pcap');
          repoFile.loadFromFile(file);

          final memPkts = repoMem.queryPackets(silenceLanChatter: false);
          final filePkts = repoFile.queryPackets(silenceLanChatter: false);
          expect(memPkts.length, equals(3));
          expect(filePkts.length, equals(3));
          expect(memPkts[0].detectedProtocol, equals('UNKNOWN'));
          expect(memPkts[1].detectedProtocol, equals('UNKNOWN'));
          expect(memPkts[2].summary, equals('Malformed ARP packet'));

          for (int i = 0; i < 3; i++) {
            expect(memPkts[i].fileByteOffset, equals(filePkts[i].fileByteOffset));
            expect(
              repoMem.readRawPacketBytes(memPkts[i]),
              equals(repoFile.readRawPacketBytes(filePkts[i])),
            );
          }
        },
      );
    });

    group('F4 — Custom Protocol & Relabeling Boundaries', () {
      test(
        '[F4][T2] Editing rule IP filter so previously matched packets no longer match resets them accurately',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          harness.repository.loadFromBytes(fixture.bytes, 'edit_ip.pcap');

          final rule = buildAcmeRule(ipAddressFilter: '192.168.1.10');
          expect(harness.repository.addCustomProtocol(rule), equals(1));
          expect(
            harness.repository.queryPackets(protocolPills: {'ACME'}),
            hasLength(1),
          );

          // Change ipAddressFilter to an IP not in capture
          final edited = rule.copyWith(ipAddressFilter: '10.10.10.10');
          final modified = harness.repository.updateCustomProtocols([edited]);
          expect(modified, equals(1));

          expect(
            harness.repository.queryPackets(protocolPills: {'ACME'}),
            isEmpty,
          );
          final resetPkt = harness.repository
              .queryPackets(limit: 50)
              .firstWhere((p) => p.srcPort == 45820);
          expect(resetPkt.detectedProtocol, equals('UDP'));
          expect(resetPkt.summary, equals('45820 → 45820 Len=16'));
          expect(resetPkt.customProtocolId, isNull);
          expect(resetPkt.customFields, isEmpty);
        },
      );

      test(
        '[F4][T2] relabelAllCustomProtocols with rules.isEmpty when no packets had custom_protocol_id returns 0 and leaves L7 intact',
        () {
          final db = PacketDatabaseService();
          addTearDown(db.close);

          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          final raw = PcapBinaryReader.parseBytes(fixture.bytes);
          final records = raw.map((r) {
            final info = PacketDissector.dissect(rawPacket: r);
            return PacketRecord(
              packetNo: r.packetNo,
              timestampUs: r.timestampUs,
              globalDeltaUs: 0,
              streamDeltaUs: 0,
              flowHash: info.flowHash,
              ethType: info.ethType,
              srcIp: info.srcIp,
              dstIp: info.dstIp,
              ipProto: info.ipProto,
              srcPort: info.srcPort,
              dstPort: info.dstPort,
              detectedProtocol: info.detectedProtocol,
              capturedLength: r.capturedLength,
              originalLength: r.originalLength,
              fileByteOffset: r.fileByteOffset,
              payloadFileOffset: r.fileByteOffset + info.payloadOffsetInPacket,
              payloadLength: info.payloadLength,
              payloadPreview: info.payloadPreview,
              summary: info.summary,
              triageStatus: TriageStatus.expected,
              isLanNoise: info.isLanNoise,
              baseProtocol: info.baseProtocol,
              baseSummary: info.baseSummary,
            );
          }).toList();
          db.insertPacketsBatch(records);

          final changed = db.relabelAllCustomProtocols(const []);
          expect(changed, equals(0));
          final after = db.queryPackets(limit: 50, silenceLanChatter: false);
          expect(after.any((p) => p.detectedProtocol == 'DNS'), isTrue);
          expect(after.any((p) => p.detectedProtocol == 'HTTP'), isTrue);
          expect(after.any((p) => p.detectedProtocol == 'TLS'), isTrue);
          expect(after.any((p) => p.detectedProtocol == 'NTP'), isTrue);
        },
      );

      test(
        '[F4][T2] PacketRecord.fromMap handles null, empty, and malformed custom_fields_json gracefully',
        () {
          final baseMap = <String, dynamic>{
            'packet_no': 1,
            'timestamp_us': 1000,
            'detected_protocol': 'ACME',
            'summary': 'ACME',
            'triage_status': 'expected',
            'base_protocol': 'UDP',
            'base_summary': '45820 → 45820 Len=16',
          };

          final nullRec = PacketRecord.fromMap({...baseMap, 'custom_fields_json': null});
          final emptyRec = PacketRecord.fromMap({...baseMap, 'custom_fields_json': ''});
          final badRec = PacketRecord.fromMap({...baseMap, 'custom_fields_json': '{bad json'});

          expect(nullRec.customFields, isEmpty);
          expect(emptyRec.customFields, isEmpty);
          expect(badRec.customFields, isEmpty);

          final withFields = nullRec.copyWith(
            customFields: {'CommandID': 42, 'Tag': 'OK'},
          );
          final roundTrip = PacketRecord.fromMap(withFields.toMap());
          expect(roundTrip.baseProtocol, equals('UDP'));
          expect(roundTrip.baseSummary, equals('45820 → 45820 Len=16'));
          expect(roundTrip.customFields, equals({'CommandID': 42, 'Tag': 'OK'}));
        },
      );

      test(
        '[F4][T2] Field slice out-of-bounds or truncated for UInt16/UInt32 returns partial/omitted cleanly',
        () {
          final rule = CustomProtocolRule(
            id: 'oob_fields',
            name: 'OOB',
            colorHex: 0xFF888888,
            defaultTriageStatus: TriageStatus.unclassified,
            fieldSlices: const [
              ProtocolFieldSlice(
                name: 'ShortByte',
                byteOffset: 0,
                byteLength: 1,
                dataType: FieldDataType.uint8,
              ),
              ProtocolFieldSlice(
                name: 'TruncU32',
                byteOffset: 0,
                byteLength: 4,
                dataType: FieldDataType.uint32Be,
              ),
              ProtocolFieldSlice(
                name: 'PastEnd',
                byteOffset: 50,
                byteLength: 2,
                dataType: FieldDataType.uint16Be,
              ),
              ProtocolFieldSlice(
                name: 'CleanAscii',
                byteOffset: 1,
                byteLength: 4,
                dataType: FieldDataType.asciiString,
              ),
            ],
          );

          // 3 bytes total: ShortByte succeeds, TruncU32 omitted (<4B), PastEnd omitted, CleanAscii filters control byte 0x01
          final extracted = rule.extractFieldValues([0x7F, 0x41, 0x01]);
          expect(extracted['ShortByte'], equals(0x7F));
          expect(extracted.containsKey('TruncU32'), isFalse);
          expect(extracted.containsKey('PastEnd'), isFalse);
          expect(extracted['CleanAscii'], equals('A'));
        },
      );

      test(
        '[F4][T2] Magic byte offset normalization (IP +28/+42 for UDP, +40/+54 for TCP) works on relabel',
        () {
          final harness = E2eTestHarness.create();
          final builder = ClassicPcapBuilder();
          builder.addBuiltFrame(
            PcapFrameFactory.ethernetUdp(
              srcIp: '10.0.0.1',
              dstIp: '10.0.0.2',
              srcPort: 41000,
              dstPort: 41001,
              payload: Uint8List.fromList('U_MAGIC'.codeUnits),
            ),
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs,
          );
          builder.addBuiltFrame(
            PcapFrameFactory.ethernetTcp(
              srcIp: '10.0.0.1',
              dstIp: '10.0.0.2',
              srcPort: 42000,
              dstPort: 42001,
              seqNum: 1,
              ackNum: 1,
              payload: Uint8List.fromList('T_MAGIC'.codeUnits),
            ),
            timestampUs: PcapFixtureBuilder.defaultStartEpochUs + 1000,
          );

          harness.repository.loadFromBytes(builder.buildBytes(), 'norm.pcap');

          final udpRule = CustomProtocolRule(
            id: 'udp_eth_offset',
            name: 'UDP_ETH42',
            colorHex: 0xFF009688,
            defaultTriageStatus: TriageStatus.expected,
            ipProtocol: 17,
            magicBytesOffset: 42, // 14 Eth + 20 IP + 8 UDP
            magicBytesHex: 'U_MAGIC'.codeUnits,
          );
          final tcpRule = CustomProtocolRule(
            id: 'tcp_eth_offset',
            name: 'TCP_ETH54',
            colorHex: 0xFF3F51B5,
            defaultTriageStatus: TriageStatus.expected,
            ipProtocol: 6,
            magicBytesOffset: 54, // 14 Eth + 20 IP + 20 TCP
            magicBytesHex: 'T_MAGIC'.codeUnits,
          );

          final updated = harness.repository.updateCustomProtocols([udpRule, tcpRule]);
          expect(updated, equals(2));

          final packets = harness.repository.queryPackets(limit: 10);
          expect(packets[0].detectedProtocol, equals('UDP_ETH42'));
          expect(packets[1].detectedProtocol, equals('TCP_ETH54'));
        },
      );

      test(
        '[F4][T2] Custom rule matching LAN-noise packet preserves BaselineProfile silenceLanChatter suppression',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          final mdnsOverride = CustomProtocolRule(
            id: 'mdns_unexp',
            name: 'CUSTOM_MDNS',
            colorHex: 0xFFE91E63,
            defaultTriageStatus: TriageStatus.unexpected,
            ipProtocol: 17,
            port: 5353,
          );

          // With silenceLanChatter: true, mDNS remains expected on both ingest & relabel
          harness.repository.updateBaselineProfile(
            const BaselineProfile(
              id: 'lan_silent',
              name: 'LAN Silent',
              expectedProtocols: {},
              silenceLanChatter: true,
            ),
          );
          harness.repository.loadFromBytes(fixture.bytes, 'lan_rule.pcap');
          harness.repository.addCustomProtocol(mdnsOverride);

          var mdns = harness.repository
              .queryPackets(protocolPills: {'CUSTOM_MDNS'}, silenceLanChatter: false)
              .single;
          expect(mdns.isLanNoise, isTrue);
          expect(mdns.triageStatus, equals(TriageStatus.expected));

          // Flipping silenceLanChatter: false re-evaluates to unexpected
          harness.repository.updateBaselineProfile(
            const BaselineProfile(
              id: 'lan_loud',
              name: 'LAN Loud',
              expectedProtocols: {},
              silenceLanChatter: false,
            ),
          );
          mdns = harness.repository
              .queryPackets(protocolPills: {'CUSTOM_MDNS'}, silenceLanChatter: false)
              .single;
          expect(mdns.triageStatus, equals(TriageStatus.unexpected));
        },
      );
    });

    group('F6 — BaselineProfile Triage Boundaries', () {
      test(
        '[F6][T2] Unexpected IP / unexpectedSubnet overrides expectedSubnets & expectedProtocols',
        () {
          const profile = BaselineProfile(
            id: 'unexp_wins',
            name: 'Unexpected Wins',
            expectedSubnets: ['192.168.1.'],
            unexpectedSubnets: ['10.99.88.'],
            expectedProtocols: {'HTTP'},
            silenceLanChatter: false,
          );

          expect(
            profile.evaluateTriage(
              srcIp: '192.168.1.10',
              dstIp: '10.99.88.77',
              detectedProtocol: 'HTTP',
              isLanNoise: false,
            ),
            equals(TriageStatus.unexpected),
          );
        },
      );

      test(
        '[F6][T2] silenceLanChatter=true overrides even unexpectedIps for isLanNoise=true',
        () {
          const silent = BaselineProfile(
            id: 'silent_lan',
            name: 'Silent LAN',
            unexpectedIps: {'192.168.1.10'},
            silenceLanChatter: true,
          );
          const loud = BaselineProfile(
            id: 'loud_lan',
            name: 'Loud LAN',
            unexpectedIps: {'192.168.1.10'},
            silenceLanChatter: false,
          );

          expect(
            silent.evaluateTriage(
              srcIp: '192.168.1.10',
              dstIp: '224.0.0.251',
              detectedProtocol: 'mDNS',
              isLanNoise: true,
            ),
            equals(TriageStatus.expected),
          );
          expect(
            loud.evaluateTriage(
              srcIp: '192.168.1.10',
              dstIp: '224.0.0.251',
              detectedProtocol: 'mDNS',
              isLanNoise: true,
            ),
            equals(TriageStatus.unexpected),
          );
        },
      );

      test(
        '[F6][T2] Empty BaselineProfile falls back strictly to defaultRuleStatus',
        () {
          const empty = BaselineProfile(
            id: 'empty',
            name: 'Empty',
            expectedIps: {},
            unexpectedIps: {},
            expectedSubnets: [],
            unexpectedSubnets: [],
            expectedProtocols: {},
            silenceLanChatter: false,
          );

          expect(
            empty.evaluateTriage(
              srcIp: '192.168.1.1',
              dstIp: '8.8.8.8',
              detectedProtocol: 'HTTP',
              isLanNoise: true,
            ),
            equals(TriageStatus.unclassified),
          );
          expect(
            empty.evaluateTriage(
              srcIp: '192.168.1.1',
              dstIp: '8.8.8.8',
              detectedProtocol: 'ACME',
              isLanNoise: false,
              defaultRuleStatus: TriageStatus.expected,
            ),
            equals(TriageStatus.expected),
          );
        },
      );

      test(
        '[F6][T2] Prefix boundary false-positive prevention (192.168.1. vs 192.168.10.5)',
        () {
          const profile = BaselineProfile(
            id: 'prefix_guard',
            name: 'Prefix Guard',
            expectedSubnets: ['192.168.1.', '10.0.'],
            expectedProtocols: {},
            silenceLanChatter: false,
          );

          expect(
            profile.evaluateTriage(
              srcIp: '192.168.10.5',
              dstIp: '10.1.0.5',
              detectedProtocol: 'CUSTOM',
              isLanNoise: false,
            ),
            equals(TriageStatus.unclassified),
          );
        },
      );

      test(
        '[F6][T2] BaselineProfile JSON serialize/deserialize round-trip preserves all sets, lists, and flags',
        () {
          const original = BaselineProfile(
            id: 'prod_v1',
            name: 'Production',
            expectedIps: {'10.0.0.1', '10.0.0.2'},
            unexpectedIps: {'198.51.100.9'},
            expectedSubnets: ['192.168.1.', '10.0.'],
            unexpectedSubnets: ['10.99.'],
            expectedProtocols: {'DNS', 'TLS'},
            silenceLanChatter: false,
          );

          final restored = BaselineProfile.deserialize(
            BaselineProfile.serialize(original),
          );
          expect(restored.id, equals(original.id));
          expect(restored.name, equals(original.name));
          expect(restored.expectedIps, equals(original.expectedIps));
          expect(restored.unexpectedIps, equals(original.unexpectedIps));
          expect(restored.expectedSubnets, equals(original.expectedSubnets));
          expect(restored.unexpectedSubnets, equals(original.unexpectedSubnets));
          expect(restored.expectedProtocols, equals(original.expectedProtocols));
          expect(restored.silenceLanChatter, equals(original.silenceLanChatter));
        },
      );
    });

    group('F7 — PCAPNG Multi-IDB & Timestamp Boundaries', () {
      test(
        '[F7][T2] EPB with out-of-range interfaceId (>= interfaces.length) falls back safely',
        () {
          final ng = PcapNgBuilder();
          ng.addInterface(linkType: 113, tsResolCode: 6);
          final ethFrame = PcapFrameFactory.ethernetUdp(
            srcIp: '10.0.0.1',
            dstIp: '10.0.0.2',
            srcPort: 1000,
            dstPort: 2000,
            payload: Uint8List.fromList([1, 2, 3, 4]),
          );
          ng.addEnhancedPacket(
            interfaceId: 99,
            frameBytes: ethFrame.frameBytes,
            rawTimestamp: BigInt.from(1700000000000000),
          );

          final parsed = PcapBinaryReader.parseBytes(ng.buildBytes());
          expect(parsed.length, equals(1));
          expect(parsed.single.linkType, equals(1)); // safe fallback Ethernet
          expect(parsed.single.timestampUs, equals(1700000000000000));
        },
      );

      test(
        '[F7][T2] SPB before any IDB falls back safely to linkType = 1',
        () {
          final ng = PcapNgBuilder();
          final ethFrame = PcapFrameFactory.ethernetUdp(
            srcIp: '10.0.0.1',
            dstIp: '10.0.0.2',
            srcPort: 3000,
            dstPort: 4000,
            payload: Uint8List.fromList([5, 6, 7, 8]),
          );
          ng.addSimpleBuiltFrame(ethFrame);

          final parsed = PcapBinaryReader.parseBytes(ng.buildBytes());
          expect(parsed.length, equals(1));
          expect(parsed.single.linkType, equals(1));
          expect(
            PacketDissector.dissect(rawPacket: parsed.single).srcIp,
            equals('10.0.0.1'),
          );
        },
      );

      test(
        '[F7][T2] Invalid/extreme if_tsresol option values (binary exp >= 63, decimal exp > 18) fall back safely to 1000000',
        () {
          for (final badCode in [0x80 | 63, 19]) {
            final ng = PcapNgBuilder();
            // Build with valid code 6 (writes tsResolCode byte at SHB(28) + 20 = offset 48), then patch
            final ifId = ng.addInterface(linkType: 1, tsResolCode: 6);
            final frame = PcapFrameFactory.ethernetUdp(
              srcIp: '10.0.0.1',
              dstIp: '10.0.0.2',
              srcPort: 1000,
              dstPort: 2000,
              payload: Uint8List.fromList([1, 2]),
            );
            ng.addEnhancedPacket(
              interfaceId: ifId,
              frameBytes: frame.frameBytes,
              rawTimestamp: BigInt.from(1700000000123456),
            );

            final bytes = ng.buildBytes();
            expect(bytes[48], equals(6));
            bytes[48] = badCode;

            final parsed = PcapBinaryReader.parseBytes(bytes);
            expect(parsed.length, equals(1));
            expect(parsed.single.timestampUs, equals(1700000000123456));
          }
        },
      );

      test(
        '[F7][T2] Truncated PCAPNG block (blockTotalLength < 12 or extends past EOF) stops cleanly',
        () {
          final ng = PcapNgBuilder();
          final ifId = ng.addInterface(linkType: 1);
          ng.addEnhancedBuiltFrame(
            interfaceId: ifId,
            built: PcapFrameFactory.ethernetUdp(
              srcIp: '10.0.0.1',
              dstIp: '10.0.0.2',
              srcPort: 1000,
              dstPort: 2000,
              payload: Uint8List.fromList([1, 2, 3, 4]),
            ),
            timestampUs: 1700000000000000,
          );
          ng.appendTruncatedBlock(claimedTotalLength: 256, actualBytes: 16);

          final parsedTrunc = PcapBinaryReader.parseBytes(ng.buildBytes());
          expect(parsedTrunc.length, equals(1));

          // Also verify blockTotalLength < 12 stops without infinite loop
          final ngBadLen = PcapNgBuilder();
          final badBlock = Uint8List(12);
          ByteData.sublistView(badBlock)
            ..setUint32(0, 0x00000006, Endian.little)
            ..setUint32(4, 4, Endian.little);
          final combined = Uint8List.fromList([...ngBadLen.buildBytes(), ...badBlock]);
          expect(PcapBinaryReader.parseBytes(combined), isEmpty);
        },
      );

      test(
        '[F7][T2] Unaligned Ethernet/SLL frame lengths in EPB & SPB honor 4-byte block padding',
        () {
          final ng = PcapNgBuilder();
          final ifEth = ng.addInterface(linkType: 1);

          // 47-byte frame (14 + 20 + 8 + 5) -> requires 1 byte padding to 48
          final unalignedEpb = PcapFrameFactory.ethernetUdp(
            srcIp: '10.0.0.1',
            dstIp: '10.0.0.2',
            srcPort: 1000,
            dstPort: 2000,
            payload: Uint8List.fromList([1, 2, 3, 4, 5]),
          );
          // 53-byte frame (14 + 20 + 8 + 11) -> requires 3 bytes padding to 56
          final unalignedSpb = PcapFrameFactory.ethernetUdp(
            srcIp: '10.0.0.3',
            dstIp: '10.0.0.4',
            srcPort: 1001,
            dstPort: 2001,
            payload: Uint8List.fromList([6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
          );
          final trailingEpb = PcapFrameFactory.ethernetUdp(
            srcIp: '10.0.0.5',
            dstIp: '10.0.0.6',
            srcPort: 1002,
            dstPort: 2002,
            payload: Uint8List.fromList([0xAA, 0xBB]),
          );

          ng.addEnhancedBuiltFrame(
            interfaceId: ifEth,
            built: unalignedEpb,
            timestampUs: 1700000000000000,
          );
          ng.addSimpleBuiltFrame(unalignedSpb);
          ng.addEnhancedBuiltFrame(
            interfaceId: ifEth,
            built: trailingEpb,
            timestampUs: 1700000000001000,
          );

          final parsed = PcapBinaryReader.parseBytes(ng.buildBytes());
          expect(parsed.length, equals(3));
          expect(parsed[0].data, equals(unalignedEpb.frameBytes));
          expect(
            parsed[1].data.sublist(0, unalignedSpb.frameBytes.length),
            equals(unalignedSpb.frameBytes),
          );
          expect(parsed[2].data, equals(trailingEpb.frameBytes));
        },
      );

      test(
        '[F7][T2] Extreme 64-bit timestamp (tsHigh = 0x0FFFFFFF, tsLow = 0xFFFFFFFF) with 10^-9 and 2^-32',
        () {
          final ng = PcapNgBuilder();
          final ifNs = ng.addInterface(linkType: 1, tsResolCode: 9);
          final ifBin = ng.addInterface(linkType: 1, tsResolCode: 0x80 | 32);

          final frame = PcapFrameFactory.ethernetUdp(
            srcIp: '10.0.0.1',
            dstIp: '10.0.0.2',
            srcPort: 1000,
            dstPort: 2000,
            payload: Uint8List.fromList([1, 2]),
          );
          final extremeRaw =
              (BigInt.from(0x0FFFFFFF) << 32) | BigInt.from(0xFFFFFFFF);

          ng.addEnhancedPacket(
            interfaceId: ifNs,
            frameBytes: frame.frameBytes,
            rawTimestamp: extremeRaw,
          );
          ng.addEnhancedPacket(
            interfaceId: ifBin,
            frameBytes: frame.frameBytes,
            rawTimestamp: extremeRaw,
          );

          final parsed = PcapBinaryReader.parseBytes(ng.buildBytes());
          expect(parsed.length, equals(2));
          expect(
            parsed[0].timestampUs,
            equals((extremeRaw ~/ BigInt.from(1000)).toInt()),
          );
          expect(
            parsed[1].timestampUs,
            equals(
              ((extremeRaw * BigInt.from(1000000)) ~/ (BigInt.one << 32)).toInt(),
            ),
          );
          expect(parsed[0].timestampUs, greaterThan(0));
          expect(parsed[1].timestampUs, greaterThan(0));
        },
      );
    });

    group('F18 — RandomAccessFile Slice Boundaries', () {
      test(
        '[F18][T2] Negative fileByteOffset / payloadFileOffset returns Uint8List(0)',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          final file = harness.writeTempCaptureFile('neg_offset.pcap', fixture.bytes);
          harness.repository.loadFromFile(file);

          final base = harness.repository.queryPackets(limit: 5).first;
          expect(
            harness.repository.readRawPacketBytes(
              base.copyWith(fileByteOffset: -1),
              payloadOnly: false,
            ),
            isEmpty,
          );
          expect(
            harness.repository.readRawPacketBytes(
              base.copyWith(payloadFileOffset: -10),
              payloadOnly: true,
            ),
            isEmpty,
          );
        },
      );

      test(
        '[F18][T2] Offset >= file length (beyond EOF) returns Uint8List(0)',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          final file = harness.writeTempCaptureFile('eof_offset.pcap', fixture.bytes);
          harness.repository.loadFromFile(file);

          final base = harness.repository.queryPackets(limit: 5).first;
          final len = fixture.bytes.length;
          expect(
            harness.repository.readRawPacketBytes(
              base.copyWith(fileByteOffset: len),
              payloadOnly: false,
            ),
            isEmpty,
          );
          expect(
            harness.repository.readRawPacketBytes(
              base.copyWith(payloadFileOffset: len + 500),
              payloadOnly: true,
            ),
            isEmpty,
          );
        },
      );

      test(
        '[F18][T2] Zero or negative length (capturedLength <= 0, payloadLength <= 0) returns Uint8List(0)',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          final file = harness.writeTempCaptureFile('zero_len.pcap', fixture.bytes);
          harness.repository.loadFromFile(file);

          final base = harness.repository.queryPackets(limit: 5).first;
          expect(
            harness.repository.readRawPacketBytes(
              base.copyWith(capturedLength: 0),
              payloadOnly: false,
            ),
            isEmpty,
          );
          expect(
            harness.repository.readRawPacketBytes(
              base.copyWith(payloadLength: -5),
              payloadOnly: true,
            ),
            isEmpty,
          );

          // Memory mode parity
          harness.repository.loadFromBytes(fixture.bytes, 'mem.pcap');
          expect(
            harness.repository.readRawPacketBytes(
              base.copyWith(capturedLength: -1),
              payloadOnly: false,
            ),
            isEmpty,
          );
        },
      );

      test(
        '[F18][T2] Partial EOF-crossing slice clamps cleanly to remaining bytes',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          final file = harness.writeTempCaptureFile('clamp.pcap', fixture.bytes);
          harness.repository.loadFromFile(file);

          final base = harness.repository.queryPackets(limit: 5).first;
          final fileLen = fixture.bytes.length;
          final clampedRecord = base.copyWith(
            fileByteOffset: fileLen - 10,
            capturedLength: 64,
          );

          final diskSlice = harness.repository.readRawPacketBytes(
            clampedRecord,
            payloadOnly: false,
          );
          expect(diskSlice.length, equals(10));
          expect(diskSlice, equals(fixture.bytes.sublist(fileLen - 10)));

          harness.repository.loadFromBytes(fixture.bytes, 'clamp_mem.pcap');
          final memSlice = harness.repository.readRawPacketBytes(
            clampedRecord,
            payloadOnly: false,
          );
          expect(memSlice, equals(diskSlice));
        },
      );

      test(
        '[F18][T2] Missing file / cleared capture / uninitialized repository returns Uint8List(0)',
        () {
          final harness = E2eTestHarness.create();
          const dummy = PacketRecord(
            packetNo: 1,
            timestampUs: 0,
            globalDeltaUs: 0,
            streamDeltaUs: 0,
            flowHash: 0,
            ethType: 0x0800,
            srcIp: '10.0.0.1',
            dstIp: '10.0.0.2',
            ipProto: 17,
            srcPort: 1000,
            dstPort: 2000,
            detectedProtocol: 'UDP',
            capturedLength: 50,
            originalLength: 50,
            fileByteOffset: 40,
            payloadFileOffset: 82,
            payloadLength: 8,
            payloadPreview: [],
            summary: 'test',
            triageStatus: TriageStatus.expected,
            isLanNoise: false,
          );

          // Uninitialized
          expect(harness.repository.readRawPacketBytes(dummy), isEmpty);

          // Loaded then cleared
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          final file = harness.writeTempCaptureFile('cleared.pcap', fixture.bytes);
          harness.repository.loadFromFile(file);
          harness.repository.clearCapture();
          expect(harness.repository.readRawPacketBytes(dummy), isEmpty);

          // Loaded then backing file deleted
          harness.repository.loadFromFile(file);
          file.deleteSync();
          expect(harness.repository.readRawPacketBytes(dummy), isEmpty);
        },
      );
    });

    group('F21 — Storage & Bundle Boundaries', () {
      test(
        '[F21][T2] Missing storage files return safe defaults without throwing',
        () {
          final harness = E2eTestHarness.create();
          final emptyDir = harness.createSubDir('empty_store');
          final lib = ProtocolLibraryService(storageDirectory: emptyDir);
          final ai = AiSettingsStorageService(storageDirectory: emptyDir);

          expect(lib.loadCustomProtocols(), isEmpty);
          expect(lib.loadSenders(), isEmpty);
          expect(lib.loadReceivers(), isEmpty);
          final baseline = lib.loadBaselineProfile();
          expect(baseline.id, equals('default'));
          expect(baseline.silenceLanChatter, isTrue);

          final settings = ai.loadSettings();
          expect(settings.backendMode, equals(LlmBackendMode.deterministicLocal));
          expect(settings.geminiApiKey, isEmpty);
        },
      );

      test(
        '[F21][T2] Corrupted JSON files on disk return safe defaults without throwing',
        () {
          final harness = E2eTestHarness.create();
          final corruptDir = harness.createSubDir('corrupt_store');
          for (final name in [
            'custom_protocols.json',
            'baseline_profiles.json',
            'sender_library.json',
            'receiver_library.json',
            'ai_settings.json',
          ]) {
            File(p.join(corruptDir.path, name)).writeAsStringSync('{corrupt');
          }

          final lib = ProtocolLibraryService(storageDirectory: corruptDir);
          final ai = AiSettingsStorageService(storageDirectory: corruptDir);

          expect(lib.loadCustomProtocols(), isEmpty);
          expect(lib.loadBaselineProfile().id, equals('default'));
          expect(lib.loadSenders(), isEmpty);
          expect(lib.loadReceivers(), isEmpty);
          expect(
            ai.loadSettings().backendMode,
            equals(LlmBackendMode.deterministicLocal),
          );
        },
      );

      test(
        '[F21][T2] Tampered encrypted Gemini API key in ai_settings.json fails MAC verification safely',
        () {
          final harness = E2eTestHarness.create();
          final dir = harness.createSubDir('tamper_vault');
          final ai = AiSettingsStorageService(storageDirectory: dir);

          ai.saveSettings(
            const AiSettings(
              backendMode: LlmBackendMode.geminiCloud,
              geminiApiKey: 'secret-key-123',
            ),
          );

          final file = File(ai.resolvedFilePath);
          final map = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
          final rawBytes = base64.decode(map['gemini_api_key_enc'] as String);
          rawBytes[rawBytes.length - 1] ^= 0xFF; // flip last byte
          map['gemini_api_key_enc'] = base64.encode(rawBytes);
          file.writeAsStringSync(jsonEncode(map));

          expect(ai.loadSettings().geminiApiKey, isEmpty);
          expect(AiSettingsStorageService.decryptSecret('short'), isEmpty);
        },
      );

      test(
        '[F21][T2] importLibraryBundleJson handles legacy list format, senders/receivers aliases, and empty/invalid JSON',
        () {
          final harness = E2eTestHarness.create();
          final lib = ProtocolLibraryService(
            storageDirectory: harness.createSubDir('bundle_edge'),
          );

          // Legacy list format
          final legacyList = jsonEncode([
            buildAcmeRule().toMap(),
            const EndpointRule(
              id: 's1',
              name: 'Sender1',
              ipAddress: '10.0.0.1',
              type: EndpointType.sender,
            ).toMap(),
            const EndpointRule(
              id: 'r1',
              name: 'Recv1',
              ipAddress: '10.0.0.2',
              type: EndpointType.receiver,
            ).toMap(),
          ]);
          final fromList = lib.importLibraryBundleJson(legacyList);
          expect((fromList['protocols'] as List), hasLength(1));
          expect((fromList['sources'] as List), hasLength(1));
          expect((fromList['destinations'] as List), hasLength(1));

          // Alias keys senders/receivers
          final aliasMap = jsonEncode({
            'senders': [
              const EndpointRule(
                id: 's2',
                name: 'S2',
                ipAddress: '10.0.0.3',
              ).toMap(),
            ],
            'receivers': [
              const EndpointRule(
                id: 'r2',
                name: 'R2',
                ipAddress: '10.0.0.4',
                type: EndpointType.receiver,
              ).toMap(),
            ],
          });
          final fromAlias = lib.importLibraryBundleJson(aliasMap);
          expect((fromAlias['sources'] as List), hasLength(1));
          expect((fromAlias['destinations'] as List), hasLength(1));

          // Empty JSON object & malformed JSON
          final emptyObj = lib.importLibraryBundleJson('{}');
          expect((emptyObj['protocols'] as List), isEmpty);
          expect((emptyObj['sources'] as List), isEmpty);
          expect((emptyObj['destinations'] as List), isEmpty);
          expect(() => lib.importLibraryBundleJson('{bad'), throwsFormatException);
        },
      );

      test(
        '[F21][T2] Unwritable storage path (regular file used as storageDirectory) catches FileSystemException safely',
        () {
          final harness = E2eTestHarness.create();
          final blockingFile = File(p.join(harness.tempDir.path, 'not_a_dir'));
          blockingFile.writeAsStringSync('blocker');
          final badDir = Directory(blockingFile.path);

          final lib = ProtocolLibraryService(storageDirectory: badDir);
          final ai = AiSettingsStorageService(storageDirectory: badDir);

          expect(() => lib.saveCustomProtocols([buildAcmeRule()]), returnsNormally);
          expect(
            () => lib.saveBaselineProfile(
              const BaselineProfile(id: 'x', name: 'X'),
            ),
            returnsNormally,
          );
          expect(
            () => lib.saveSenders(const [
              EndpointRule(id: 's', name: 'S', ipAddress: '1.1.1.1'),
            ]),
            returnsNormally,
          );
          expect(
            () => lib.saveReceivers(const [
              EndpointRule(
                id: 'r',
                name: 'R',
                ipAddress: '2.2.2.2',
                type: EndpointType.receiver,
              ),
            ]),
            returnsNormally,
          );
          expect(
            () => ai.saveSettings(const AiSettings(geminiApiKey: 'abc')),
            returnsNormally,
          );
        },
      );
    });

    group('F22 — SQLite Parameterization & Preview Boundaries', () {
      test(
        '[F22][T2] SQL injection payloads inside packet strings (custom rule name, summary) & sortColumn whitelist',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          harness.repository.loadFromBytes(fixture.bytes, 'inj_names.pcap');

          const evilName = "Test'; DROP TABLE packets;--";
          final evilRule = buildAcmeRule(name: evilName);
          expect(harness.repository.addCustomProtocol(evilRule), equals(1));

          final queried = harness.repository.queryPackets(
            protocolPills: {evilName},
            sortColumn: 'packet_no; DROP TABLE packets;--',
            sortAscending: true,
          );
          expect(queried.length, equals(1));
          expect(queried.single.detectedProtocol, equals(evilName));
          expect(harness.repository.getPacketCount(), greaterThan(10));
        },
      );

      test(
        '[F22][T2] LIKE wildcard metacharacters (%, _, \\) in sourceSearch / destSearch',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          harness.repository.loadFromBytes(fixture.bytes, 'like_meta.pcap');

          final total = harness.repository.getPacketCount(silenceLanChatter: false);
          expect(total, greaterThan(0));

          // '_' and '%' match via parameterized LIKE without throwing
          expect(
            () => harness.repository.queryPackets(
              sourceSearch: r"192.168.1._\'",
              destSearch: '%',
              silenceLanChatter: false,
            ),
            returnsNormally,
          );
          expect(
            harness.repository.getPacketCount(
              sourceSearch: r"nonexistent_%_\'drop",
              silenceLanChatter: false,
            ),
            equals(0),
          );
        },
      );

      test(
        '[F22][T2] Boundary payload sizes: 0B, 255B, 256B, 257B, 1400B',
        () {
          final harness = E2eTestHarness.create();
          final sizes = [0, 255, 256, 257, 1400];
          final builder = ClassicPcapBuilder();
          for (int i = 0; i < sizes.length; i++) {
            builder.addBuiltFrame(
              PcapFrameFactory.ethernetUdp(
                srcIp: '10.0.0.1',
                dstIp: '10.0.0.2',
                srcPort: 5000 + i,
                dstPort: 6000 + i,
                payload: PcapFrameFactory.repeatedBytesPayload(sizes[i]),
              ),
              timestampUs: PcapFixtureBuilder.defaultStartEpochUs + i * 1000,
            );
          }

          harness.repository.loadFromBytes(builder.buildBytes(), 'sizes.pcap');
          final packets = harness.repository.queryPackets(limit: 10);
          expect(packets.length, equals(5));

          final expectedPreviewLens = [0, 255, 256, 256, 256];
          for (int i = 0; i < sizes.length; i++) {
            expect(packets[i].payloadLength, equals(sizes[i]));
            expect(packets[i].payloadPreview.length, equals(expectedPreviewLens[i]));
          }
        },
      );

      test(
        '[F22][T2] Inverted filters (isTriageNot, isSourceSearchNot, isDestSearchNot, isProtocolNot, isSenderNot, isReceiverNot) with metacharacters',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          harness.repository.loadFromBytes(fixture.bytes, 'inverted.pcap');

          final total = harness.repository.getPacketCount(silenceLanChatter: false);
          final notDns = harness.repository.queryPackets(
            protocolPills: {'DNS', "'; DROP TABLE packets;--"},
            isProtocolNot: true,
            silenceLanChatter: false,
            limit: 100,
          );
          expect(notDns.any((p) => p.detectedProtocol == 'DNS'), isFalse);
          expect(notDns.length, equals(total - 2));

          final invertedAll = harness.repository.queryPackets(
            triageStatuses: {TriageStatus.unexpected},
            isTriageNot: true,
            sourceSearch: "x' OR '1'='1",
            isSourceSearchNot: true,
            destSearch: 'y" OR 1=1',
            isDestSearchNot: true,
            senderFilters: {"bad';--"},
            isSenderNot: true,
            receiverFilters: {'bad2";--'},
            isReceiverNot: true,
            silenceLanChatter: false,
            limit: 100,
          );
          expect(invertedAll, isNotEmpty);
          expect(
            invertedAll.any((p) => p.triageStatus == TriageStatus.unexpected),
            isFalse,
          );
        },
      );

      test(
        '[F22][T2] Empty filter sets, limit=0, and countPacketsForEndpoints(endpointKeys: {})',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          harness.repository.loadFromBytes(fixture.bytes, 'empty_filters.pcap');

          expect(
            harness.repository.queryPackets(
              triageStatuses: const {},
              limit: 0,
            ),
            isEmpty,
          );
          expect(
            harness.repository.countPacketsForEndpoints(
              endpointKeys: const [],
              isSender: true,
            ),
            isEmpty,
          );
          expect(
            harness.repository.getPacketCount(
              protocolPills: const {},
              senderFilters: const {},
              receiverFilters: const {},
              ipFilters: const {},
            ),
            greaterThan(0),
          );
        },
      );
    });

    group('F13–F17 — Contract Boundary & Negative Cases', () {
      test(
        '[F17][T2] Triage filtering behavior without isTriageMode when triageStatuses is subset vs all-3 vs empty',
        () {
          final harness = E2eTestHarness.create();
          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          harness.repository.loadFromBytes(fixture.bytes, 'triage_modes.pcap');

          final total = harness.repository.getPacketCount(silenceLanChatter: false);
          final expectedOnly = harness.repository.getPacketCount(
            triageStatuses: {TriageStatus.expected},
            silenceLanChatter: false,
          );
          final allThree = harness.repository.getPacketCount(
            triageStatuses: {
              TriageStatus.expected,
              TriageStatus.unclassified,
              TriageStatus.unexpected,
            },
            silenceLanChatter: false,
          );
          final notExpected = harness.repository.getPacketCount(
            triageStatuses: {TriageStatus.expected},
            isTriageNot: true,
            silenceLanChatter: false,
          );

          expect(allThree, equals(total));
          expect(expectedOnly + notExpected, equals(total));
        },
      );

      test(
        '[F16][T2] relabelAllCustomProtocols replaces single-rule relabel for add, edit, reorder, and full removal',
        () {
          final db = PacketDatabaseService();
          addTearDown(db.close);

          final fixture = PcapFixtureBuilder.buildRichInspectorCapture();
          final raw = PcapBinaryReader.parseBytes(fixture.bytes);
          final records = raw.map((r) {
            final info = PacketDissector.dissect(rawPacket: r);
            return PacketRecord(
              packetNo: r.packetNo,
              timestampUs: r.timestampUs,
              globalDeltaUs: 0,
              streamDeltaUs: 0,
              flowHash: info.flowHash,
              ethType: info.ethType,
              srcIp: info.srcIp,
              dstIp: info.dstIp,
              ipProto: info.ipProto,
              srcPort: info.srcPort,
              dstPort: info.dstPort,
              detectedProtocol: info.detectedProtocol,
              capturedLength: r.capturedLength,
              originalLength: r.originalLength,
              fileByteOffset: r.fileByteOffset,
              payloadFileOffset: r.fileByteOffset + info.payloadOffsetInPacket,
              payloadLength: info.payloadLength,
              payloadPreview: info.payloadPreview,
              summary: info.summary,
              triageStatus: TriageStatus.expected,
              isLanNoise: info.isLanNoise,
              baseProtocol: info.baseProtocol,
              baseSummary: info.baseSummary,
            );
          }).toList();
          db.insertPacketsBatch(records);

          final r1 = buildAcmeRule(name: 'ACME_V1');
          expect(db.relabelAllCustomProtocols([r1]), equals(1));
          expect(
            db.queryPackets(protocolPills: {'ACME_V1'}).single.detectedProtocol,
            equals('ACME_V1'),
          );

          final r2 = buildAcmeRule(name: 'ACME_V2');
          expect(db.relabelAllCustomProtocols([r2]), equals(1));
          expect(
            db.queryPackets(protocolPills: {'ACME_V2'}).single.detectedProtocol,
            equals('ACME_V2'),
          );

          // Full removal restores baseProtocol
          expect(db.relabelAllCustomProtocols(const []), equals(1));
          expect(db.queryPackets(protocolPills: {'ACME_V2'}), isEmpty);
        },
      );

      test(
        '[F15][T2] PacketRepository encapsulates DB lifecycle cleanly across loadFromBytes -> loadFromFile -> clearCapture',
        () {
          final harness = E2eTestHarness.create();
          final repo = createIsolatedRepo(harness, subDirName: 'encap');

          final f1 = PcapFixtureBuilder.buildRichInspectorCapture();
          final f2 = PcapFixtureBuilder.buildMultiIdbPcapNg();
          final diskFile = harness.writeTempCaptureFile('ng_f2.pcapng', f2.bytes);

          repo.loadFromBytes(f1.bytes, 'f1.pcap');
          expect(
            repo.getPacketCount(silenceLanChatter: false),
            equals(f1.expectations.length),
          );

          repo.loadFromFile(diskFile);
          expect(repo.getPacketCount(), equals(4));
          expect(repo.loadedFilePath, equals(diskFile.path));

          repo.clearCapture();
          expect(repo.getPacketCount(), equals(0));
          expect(repo.loadedFilePath, isNull);
        },
      );

      test(
        '[F13/F21][T2] Cross-platform storage resolution works without path_provider',
        () {
          final dir = SharedDeviceDatabase.getDefaultDirectoryPath();
          expect(dir, isNotEmpty);
          expect(p.isAbsolute(dir) || dir.startsWith('NetworkSuite'), isTrue);

          final lib = ProtocolLibraryService();
          final ai = AiSettingsStorageService();
          expect(lib.resolveWritePath('sender_library.json'), contains('NetworkSuite'));
          expect(ai.resolvedFilePath, contains('NetworkSuite'));
        },
      );

      test(
        '[F14][T2] Direct PacketDatabaseService & PacketRepository ingestion operates without IngestProgress',
        () {
          final harness = E2eTestHarness.create();
          final single = ClassicPcapBuilder()
            ..addBuiltFrame(
              PcapFrameFactory.ethernetUdp(
                srcIp: '10.0.0.1',
                dstIp: '10.0.0.2',
                srcPort: 1000,
                dstPort: 2000,
                payload: Uint8List.fromList([1]),
              ),
              timestampUs: PcapFixtureBuilder.defaultStartEpochUs,
            );
          harness.repository.loadFromBytes(single.buildBytes(), 'one.pcap');
          expect(harness.repository.getPacketCount(), equals(1));

          final bulk = PcapFixtureBuilder.buildBulkPcap(packetCount: 1500);
          final bulkFile = harness.writeTempCaptureFile('bulk_no_prog.pcap', bulk.bytes);
          harness.repository.loadFromFile(bulkFile);
          expect(harness.repository.getPacketCount(), equals(1500));
        },
      );
    });
  });
}
