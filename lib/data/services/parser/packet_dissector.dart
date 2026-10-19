import 'dart:typed_data';
import '../../../domain/models/custom_protocol_rule.dart';
import 'pcap_binary_reader.dart';

class DissectedPacketInfo {
  DissectedPacketInfo({
    required this.ethType,
    required this.srcIp,
    required this.dstIp,
    required this.ipProto,
    required this.srcPort,
    required this.dstPort,
    required this.detectedProtocol,
    required this.summary,
    required this.payloadOffsetInPacket,
    required this.payloadLength,
    required this.payloadPreview,
    required this.isLanNoise,
    required this.flowHash,
    this.customProtocolId,
    this.customFields = const {},
  });

  final int ethType;
  final String srcIp;
  final String dstIp;
  final int ipProto;
  final int? srcPort;
  final int? dstPort;
  String detectedProtocol;
  String summary;
  final int payloadOffsetInPacket;
  final int payloadLength;
  final List<int> payloadPreview;
  bool isLanNoise;
  final int flowHash;
  String? customProtocolId;
  Map<String, dynamic> customFields;
}

class PacketDissector {
  static DissectedPacketInfo dissect({
    required RawCapturedPacket rawPacket,
    List<CustomProtocolRule> customRules = const [],
  }) {
    final bytes = rawPacket.data;
    if (bytes.isEmpty) {
      return _emptyDissection();
    }

    int linkOffset = 0;
    int ethType = 0x0800; // Default IPv4

    switch (rawPacket.linkType) {
      case 1: // Ethernet II
        if (bytes.length < 14) return _emptyDissection();
        ethType = (bytes[12] << 8) | bytes[13];
        linkOffset = 14;
        if (ethType == 0x8100 && bytes.length >= 18) {
          // 802.1Q VLAN Tagged
          ethType = (bytes[16] << 8) | bytes[17];
          linkOffset = 18;
        }
        break;
      case 113: // Linux Cooked SLL
        if (bytes.length < 16) return _emptyDissection();
        ethType = (bytes[14] << 8) | bytes[15];
        linkOffset = 16;
        break;
      case 0: // Loopback / Null
        if (bytes.length < 4) return _emptyDissection();
        final family = bytes[0] | (bytes[1] << 8);
        ethType = (family == 2) ? 0x0800 : 0x86DD;
        linkOffset = 4;
        break;
      case 101: // Raw IP
        linkOffset = 0;
        final version = (bytes[0] >> 4) & 0x0F;
        ethType = (version == 6) ? 0x86DD : 0x0800;
        break;
      default:
        linkOffset = 0;
    }

    if (ethType == 0x0806) {
      // ARP
      return _dissectArp(bytes, linkOffset);
    } else if (ethType == 0x0800) {
      // IPv4
      return _dissectIPv4(bytes, linkOffset, customRules);
    } else if (ethType == 0x86DD) {
      // IPv6
      return _dissectIPv6(bytes, linkOffset, customRules);
    }

    return DissectedPacketInfo(
      ethType: ethType,
      srcIp: '',
      dstIp: '',
      ipProto: 0,
      srcPort: null,
      dstPort: null,
      detectedProtocol: 'ETH:0x${ethType.toRadixString(16).padLeft(4, '0')}',
      summary: 'Link-layer frame (type 0x${ethType.toRadixString(16)})',
      payloadOffsetInPacket: linkOffset,
      payloadLength: bytes.length > linkOffset ? bytes.length - linkOffset : 0,
      payloadPreview: _extractPreview(bytes, linkOffset, bytes.length - linkOffset),
      isLanNoise: false,
      flowHash: 0,
    );
  }

  static DissectedPacketInfo _dissectArp(Uint8List bytes, int offset) {
    if (bytes.length < offset + 28) {
      return DissectedPacketInfo(
        ethType: 0x0806,
        srcIp: '',
        dstIp: '',
        ipProto: 0,
        srcPort: null,
        dstPort: null,
        detectedProtocol: 'ARP',
        summary: 'Malformed ARP packet',
        payloadOffsetInPacket: offset,
        payloadLength: bytes.length - offset,
        payloadPreview: _extractPreview(bytes, offset, bytes.length - offset),
        isLanNoise: true,
        flowHash: 0,
      );
    }

    final opcode = (bytes[offset + 6] << 8) | bytes[offset + 7];
    final senderIp = '${bytes[offset + 14]}.${bytes[offset + 15]}.${bytes[offset + 16]}.${bytes[offset + 17]}';
    final targetIp = '${bytes[offset + 24]}.${bytes[offset + 25]}.${bytes[offset + 26]}.${bytes[offset + 27]}';

    final String summary;
    if (opcode == 1) {
      summary = 'Who has $targetIp? Tell $senderIp';
    } else if (opcode == 2) {
      summary = '$senderIp is at ${_formatMac(bytes, offset + 8)}';
    } else {
      summary = 'ARP Opcode $opcode';
    }

    final flowHash = computeFlowHash(senderIp, targetIp, 0, 0, 0x0806);

    return DissectedPacketInfo(
      ethType: 0x0806,
      srcIp: senderIp,
      dstIp: targetIp,
      ipProto: 0,
      srcPort: null,
      dstPort: null,
      detectedProtocol: 'ARP',
      summary: summary,
      payloadOffsetInPacket: offset,
      payloadLength: 28,
      payloadPreview: _extractPreview(bytes, offset, 28),
      isLanNoise: true,
      flowHash: flowHash,
    );
  }

  static DissectedPacketInfo _dissectIPv4(
    Uint8List bytes,
    int offset,
    List<CustomProtocolRule> customRules,
  ) {
    if (bytes.length < offset + 20) {
      return _emptyDissection();
    }

    final ihl = (bytes[offset] & 0x0F) * 4;
    if (ihl < 20 || offset + ihl > bytes.length) {
      return _emptyDissection();
    }

    final ipProto = bytes[offset + 9];
    final srcIp = '${bytes[offset + 12]}.${bytes[offset + 13]}.${bytes[offset + 14]}.${bytes[offset + 15]}';
    final dstIp = '${bytes[offset + 16]}.${bytes[offset + 17]}.${bytes[offset + 18]}.${bytes[offset + 19]}';

    final l4Offset = offset + ihl;
    return _dissectTransport(
      bytes: bytes,
      ethType: 0x0800,
      srcIp: srcIp,
      dstIp: dstIp,
      ipProto: ipProto,
      l4Offset: l4Offset,
      customRules: customRules,
    );
  }

  static DissectedPacketInfo _dissectIPv6(
    Uint8List bytes,
    int offset,
    List<CustomProtocolRule> customRules,
  ) {
    if (bytes.length < offset + 40) {
      return _emptyDissection();
    }

    final nextHeader = bytes[offset + 6];
    final srcIp = _formatIPv6(bytes, offset + 8);
    final dstIp = _formatIPv6(bytes, offset + 24);

    final l4Offset = offset + 40;
    return _dissectTransport(
      bytes: bytes,
      ethType: 0x86DD,
      srcIp: srcIp,
      dstIp: dstIp,
      ipProto: nextHeader,
      l4Offset: l4Offset,
      customRules: customRules,
    );
  }

  static DissectedPacketInfo _dissectTransport({
    required Uint8List bytes,
    required int ethType,
    required String srcIp,
    required String dstIp,
    required int ipProto,
    required int l4Offset,
    required List<CustomProtocolRule> customRules,
  }) {
    int? srcPort;
    int? dstPort;
    String protoName = 'IP';
    String summary = '';
    int payloadOffset = l4Offset;
    int payloadLength = 0;
    bool isLanNoise = false;

    if (ipProto == 6 && bytes.length >= l4Offset + 20) {
      // TCP
      srcPort = (bytes[l4Offset] << 8) | bytes[l4Offset + 1];
      dstPort = (bytes[l4Offset + 2] << 8) | bytes[l4Offset + 3];
      final seqNum = (bytes[l4Offset + 4] << 24) |
          (bytes[l4Offset + 5] << 16) |
          (bytes[l4Offset + 6] << 8) |
          bytes[l4Offset + 7];
      final ackNum = (bytes[l4Offset + 8] << 24) |
          (bytes[l4Offset + 9] << 16) |
          (bytes[l4Offset + 10] << 8) |
          bytes[l4Offset + 11];
      final dataOffset = ((bytes[l4Offset + 12] >> 4) & 0x0F) * 4;
      final flagsByte = bytes[l4Offset + 13];

      final flagList = <String>[];
      if ((flagsByte & 0x02) != 0) flagList.add('SYN');
      if ((flagsByte & 0x10) != 0) flagList.add('ACK');
      if ((flagsByte & 0x01) != 0) flagList.add('FIN');
      if ((flagsByte & 0x04) != 0) flagList.add('RST');
      if ((flagsByte & 0x08) != 0) flagList.add('PSH');

      payloadOffset = l4Offset + dataOffset;
      payloadLength = (bytes.length >= payloadOffset) ? bytes.length - payloadOffset : 0;
      protoName = 'TCP';
      summary = '$srcPort → $dstPort [${flagList.join(',')}] Seq=$seqNum Ack=$ackNum Len=$payloadLength';
    } else if (ipProto == 17 && bytes.length >= l4Offset + 8) {
      // UDP
      srcPort = (bytes[l4Offset] << 8) | bytes[l4Offset + 1];
      dstPort = (bytes[l4Offset + 2] << 8) | bytes[l4Offset + 3];
      final udpLen = (bytes[l4Offset + 4] << 8) | bytes[l4Offset + 5];
      payloadOffset = l4Offset + 8;
      payloadLength = (udpLen >= 8) ? udpLen - 8 : 0;
      if (payloadOffset + payloadLength > bytes.length) {
        payloadLength = bytes.length - payloadOffset;
      }
      protoName = 'UDP';
      summary = '$srcPort → $dstPort Len=$payloadLength';
    } else if (ipProto == 1 && bytes.length >= l4Offset + 4) {
      // ICMP
      final type = bytes[l4Offset];
      final code = bytes[l4Offset + 1];
      protoName = 'ICMP';
      payloadOffset = l4Offset + 8;
      payloadLength = (bytes.length >= payloadOffset) ? bytes.length - payloadOffset : 0;
      if (type == 8) {
        summary = 'Echo (ping) request';
      } else if (type == 0) {
        summary = 'Echo (ping) reply';
      } else if (type == 3) {
        summary = 'Destination unreachable (code $code)';
      } else {
        summary = 'ICMP type $type code $code';
      }
    } else if (ipProto == 2) {
      // IGMP
      protoName = 'IGMP';
      isLanNoise = true;
      payloadOffset = l4Offset;
      payloadLength = bytes.length - l4Offset;
      summary = 'IGMP membership message';
    } else if (ipProto == 58 && bytes.length >= l4Offset + 4) {
      // ICMPv6
      final type = bytes[l4Offset];
      protoName = 'ICMPv6';
      payloadOffset = l4Offset + 8;
      payloadLength = (bytes.length >= payloadOffset) ? bytes.length - payloadOffset : 0;
      if (type >= 133 && type <= 137) {
        isLanNoise = true;
        summary = 'ICMPv6 Router/Neighbor Discovery (type $type)';
      } else if (type == 128) {
        summary = 'Echo request';
      } else if (type == 129) {
        summary = 'Echo reply';
      } else {
        summary = 'ICMPv6 type $type';
      }
    } else {
      payloadOffset = l4Offset;
      payloadLength = (bytes.length >= l4Offset) ? bytes.length - l4Offset : 0;
      protoName = 'IP(proto $ipProto)';
      summary = 'Protocol $ipProto';
    }

    // Inspect L7 Application Layer
    final payloadSlice = (payloadOffset < bytes.length && payloadLength > 0)
        ? Uint8List.sublistView(bytes, payloadOffset, payloadOffset + payloadLength)
        : Uint8List(0);

    final l7Result = _inspectL7(
      ipProto: ipProto,
      srcPort: srcPort,
      dstPort: dstPort,
      payload: payloadSlice,
    );

    if (l7Result != null) {
      protoName = l7Result.protocol;
      if (l7Result.summary != null) {
        summary = l7Result.summary!;
      }
      if (l7Result.isLanNoise) {
        isLanNoise = true;
      }
    }

    final preview = _extractPreview(bytes, payloadOffset, payloadLength);
    final flowHash = computeFlowHash(srcIp, dstIp, srcPort ?? 0, dstPort ?? 0, ipProto);

    // Evaluate Custom Protocol Rules
    String? matchedRuleId;
    Map<String, dynamic> customFields = const {};
    for (final rule in customRules) {
      if (rule.matches(
        ipProto: ipProto,
        srcPort: srcPort,
        dstPort: dstPort,
        srcIp: srcIp,
        dstIp: dstIp,
        payload: payloadSlice,
      )) {
        protoName = rule.name;
        matchedRuleId = rule.id;
        customFields = rule.extractFieldValues(payloadSlice);
        if (customFields.isNotEmpty) {
          final fieldsStr = customFields.entries.map((e) => '${e.key}=${e.value}').join(', ');
          summary = '${rule.name} [$fieldsStr]';
        }
        break;
      }
    }

    return DissectedPacketInfo(
      ethType: ethType,
      srcIp: srcIp,
      dstIp: dstIp,
      ipProto: ipProto,
      srcPort: srcPort,
      dstPort: dstPort,
      detectedProtocol: protoName,
      summary: summary,
      payloadOffsetInPacket: payloadOffset,
      payloadLength: payloadLength,
      payloadPreview: preview,
      isLanNoise: isLanNoise,
      flowHash: flowHash,
      customProtocolId: matchedRuleId,
      customFields: customFields,
    );
  }

  static _L7Result? _inspectL7({
    required int ipProto,
    required int? srcPort,
    required int? dstPort,
    required Uint8List payload,
  }) {
    if (srcPort == null || dstPort == null) return null;

    // DNS (Port 53)
    if (srcPort == 53 || dstPort == 53) {
      return _L7Result('DNS', isLanNoise: false, summary: _dissectDnsSummary(payload, srcPort == 53));
    }

    // mDNS (UDP 5353)
    if (srcPort == 5353 || dstPort == 5353) {
      return _L7Result('mDNS', isLanNoise: true, summary: 'Multicast DNS query/response');
    }

    // SSDP (UDP 1900)
    if (srcPort == 1900 || dstPort == 1900) {
      return _L7Result('SSDP', isLanNoise: true, summary: 'Simple Service Discovery Protocol');
    }

    // NBNS (UDP 137)
    if (srcPort == 137 || dstPort == 137) {
      return _L7Result('NBNS', isLanNoise: true, summary: 'NetBIOS Name Service');
    }

    // DHCP (UDP 67 / 68)
    if ((srcPort == 67 && dstPort == 68) || (srcPort == 68 && dstPort == 67)) {
      return _L7Result('DHCP', isLanNoise: true, summary: 'Dynamic Host Configuration Protocol');
    }

    // NTP (UDP 123)
    if (srcPort == 123 || dstPort == 123) {
      return _L7Result('NTP', isLanNoise: false, summary: 'Network Time Protocol');
    }

    // TLS Handshake (TCP 443 or Record Type 0x16 0x03)
    if (payload.length >= 5 && payload[0] == 0x16 && payload[1] == 0x03) {
      return _L7Result('TLS', isLanNoise: false, summary: 'TLS Handshake (Encrypted)');
    } else if (srcPort == 443 || dstPort == 443) {
      return _L7Result('TLS', isLanNoise: false, summary: 'TLS encrypted payload');
    }

    // HTTP
    if (payload.isNotEmpty) {
      final asciiStr = String.fromCharCodes(
        payload.take(10).where((c) => c >= 32 && c <= 126),
      );
      if (asciiStr.startsWith('GET ') ||
          asciiStr.startsWith('POST ') ||
          asciiStr.startsWith('PUT ') ||
          asciiStr.startsWith('HEAD ') ||
          asciiStr.startsWith('HTTP/1.')) {
        final firstLineEnd = payload.indexOf(0x0A); // newline '\n'
        String line = '';
        if (firstLineEnd > 0) {
          line = String.fromCharCodes(
            payload.take(firstLineEnd).where((c) => c >= 32 && c <= 126),
          );
        } else {
          line = asciiStr;
        }
        return _L7Result('HTTP', isLanNoise: false, summary: line);
      }
    }

    return null;
  }

  static String _dissectDnsSummary(Uint8List payload, bool isResponse) {
    if (payload.length < 12) return isResponse ? 'DNS Response' : 'DNS Query';
    final qCount = (payload[4] << 8) | payload[5];
    final anCount = (payload[6] << 8) | payload[7];
    return isResponse
        ? 'DNS Standard response, $anCount answers'
        : 'DNS Standard query, $qCount questions';
  }

  static int computeFlowHash(
    String ipA,
    String ipB,
    int portA,
    int portB,
    int ipProto,
  ) {
    // Canonical symmetric flow hashing:
    // (min(EndpointA, EndpointB), max(EndpointA, EndpointB), ipProto)
    final epA = '$ipA:$portA';
    final epB = '$ipB:$portB';
    final String key;
    if (epA.compareTo(epB) <= 0) {
      key = '$epA|$epB|$ipProto';
    } else {
      key = '$epB|$epA|$ipProto';
    }
    return key.hashCode;
  }

  static List<int> _extractPreview(Uint8List bytes, int offset, int length) {
    if (offset >= bytes.length || length <= 0) return const [];
    final actualLen = (offset + length <= bytes.length) ? length : (bytes.length - offset);
    final count = actualLen > 64 ? 64 : actualLen;
    return bytes.sublist(offset, offset + count).toList();
  }

  static String _formatMac(Uint8List bytes, int offset) {
    return [
      for (int i = 0; i < 6; i++)
        bytes[offset + i].toRadixString(16).padLeft(2, '0')
    ].join(':');
  }

  static String _formatIPv6(Uint8List bytes, int offset) {
    final segments = <String>[];
    for (int i = 0; i < 16; i += 2) {
      final val = (bytes[offset + i] << 8) | bytes[offset + i + 1];
      segments.add(val.toRadixString(16));
    }
    return segments.join(':');
  }

  static DissectedPacketInfo _emptyDissection() {
    return DissectedPacketInfo(
      ethType: 0,
      srcIp: '',
      dstIp: '',
      ipProto: 0,
      srcPort: null,
      dstPort: null,
      detectedProtocol: 'UNKNOWN',
      summary: 'Empty or corrupted packet',
      payloadOffsetInPacket: 0,
      payloadLength: 0,
      payloadPreview: const [],
      isLanNoise: false,
      flowHash: 0,
    );
  }
}

class _L7Result {
  const _L7Result(this.protocol, {required this.isLanNoise, this.summary});
  final String protocol;
  final bool isLanNoise;
  final String? summary;
}
