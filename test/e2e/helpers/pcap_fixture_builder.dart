import 'dart:io';
import 'dart:typed_data';

import 'package:packet_inspector/data/services/diff/multi_capture_diff_engine.dart';

/// Ground-truth expectation for a single generated packet inside a binary capture.
class BuiltPacketExpectation {
  const BuiltPacketExpectation({
    required this.packetNo,
    required this.timestampUs,
    required this.linkType,
    required this.frameBytes,
    required this.l4PayloadBytes,
    required this.payloadOffsetInFrame,
    required this.expectedFrameFileOffset,
    required this.expectedPayloadFileOffset,
  });

  final int packetNo;
  final int timestampUs;
  final int linkType;
  final Uint8List frameBytes;
  final Uint8List l4PayloadBytes;
  final int payloadOffsetInFrame;
  final int expectedFrameFileOffset;
  final int expectedPayloadFileOffset;
}

/// Complete generated capture buffer paired with per-packet ground-truth offsets.
class BuiltCaptureFixture {
  const BuiltCaptureFixture({
    required this.bytes,
    required this.expectations,
  });

  final Uint8List bytes;
  final List<BuiltPacketExpectation> expectations;
}

/// A link-layer frame coupled with its L4 payload slice and relative offset.
class BuiltFrame {
  const BuiltFrame({
    required this.linkType,
    required this.frameBytes,
    required this.payloadOffsetInFrame,
    required this.l4PayloadBytes,
  });

  final int linkType;
  final Uint8List frameBytes;
  final int payloadOffsetInFrame;
  final Uint8List l4PayloadBytes;
}

/// Multi-hop diff fixture containing raw buffers, files, and [CaptureSourceInput]s.
class BuiltDiffFixture {
  const BuiltDiffFixture({
    required this.inputs,
    required this.hopBytes,
    required this.files,
  });

  final List<CaptureSourceInput> inputs;
  final List<Uint8List> hopBytes;
  final List<File> files;
}

/// Pure-Dart builders for valid L2/L3/L4/L7 frames and payloads.
class PcapFrameFactory {
  static const List<int> defaultDstMac = [0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA];
  static const List<int> defaultSrcMac = [0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB];

  static Uint8List udpSegment({
    required int srcPort,
    required int dstPort,
    required Uint8List payload,
  }) {
    final seg = Uint8List(8 + payload.length);
    final bd = ByteData.sublistView(seg);
    bd.setUint16(0, srcPort, Endian.big);
    bd.setUint16(2, dstPort, Endian.big);
    bd.setUint16(4, seg.length, Endian.big);
    bd.setUint16(6, 0, Endian.big);
    if (payload.isNotEmpty) {
      seg.setRange(8, seg.length, payload);
    }
    return seg;
  }

  static Uint8List tcpSegment({
    required int srcPort,
    required int dstPort,
    required int seqNum,
    required int ackNum,
    int flags = 0x18,
    int windowSize = 64240,
    Uint8List? payload,
  }) {
    final body = payload ?? Uint8List(0);
    final seg = Uint8List(20 + body.length);
    final bd = ByteData.sublistView(seg);
    bd.setUint16(0, srcPort, Endian.big);
    bd.setUint16(2, dstPort, Endian.big);
    bd.setUint32(4, seqNum, Endian.big);
    bd.setUint32(8, ackNum, Endian.big);
    bd.setUint8(12, 5 << 4);
    bd.setUint8(13, flags);
    bd.setUint16(14, windowSize, Endian.big);
    bd.setUint16(16, 0, Endian.big);
    bd.setUint16(18, 0, Endian.big);
    if (body.isNotEmpty) {
      seg.setRange(20, seg.length, body);
    }
    return seg;
  }

  static Uint8List icmpEcho({
    int type = 8,
    int code = 0,
    int identifier = 1,
    int seqNum = 1,
    Uint8List? payload,
  }) {
    final body = payload ?? Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF]);
    final seg = Uint8List(8 + body.length);
    final bd = ByteData.sublistView(seg);
    bd.setUint8(0, type);
    bd.setUint8(1, code);
    bd.setUint16(2, 0, Endian.big);
    bd.setUint16(4, identifier, Endian.big);
    bd.setUint16(6, seqNum, Endian.big);
    if (body.isNotEmpty) {
      seg.setRange(8, seg.length, body);
    }
    final checksum = _onesComplementChecksum(seg);
    bd.setUint16(2, checksum, Endian.big);
    return seg;
  }

  static Uint8List dnsQueryPayload({
    int txId = 0x1234,
    String domain = 'example.com',
  }) {
    final builder = BytesBuilder();
    final header = ByteData(12)
      ..setUint16(0, txId, Endian.big)
      ..setUint16(2, 0x0100, Endian.big)
      ..setUint16(4, 1, Endian.big);
    builder.add(header.buffer.asUint8List());
    for (final label in domain.split('.')) {
      final bytes = label.codeUnits;
      builder.addByte(bytes.length);
      builder.add(bytes);
    }
    builder.add([0x00, 0x00, 0x01, 0x00, 0x01]);
    return builder.toBytes();
  }

  static Uint8List dnsResponsePayload({
    int txId = 0x1234,
    String domain = 'example.com',
    String answerIp = '93.184.216.34',
  }) {
    final builder = BytesBuilder();
    final header = ByteData(12)
      ..setUint16(0, txId, Endian.big)
      ..setUint16(2, 0x8180, Endian.big)
      ..setUint16(4, 1, Endian.big)
      ..setUint16(6, 1, Endian.big);
    builder.add(header.buffer.asUint8List());
    for (final label in domain.split('.')) {
      final bytes = label.codeUnits;
      builder.addByte(bytes.length);
      builder.add(bytes);
    }
    builder.add([0x00, 0x00, 0x01, 0x00, 0x01]);
    builder.add([
      0xC0, 0x0C,
      0x00, 0x01,
      0x00, 0x01,
      0x00, 0x00, 0x01, 0x2C,
      0x00, 0x04,
      ..._parseIpv4(answerIp),
    ]);
    return builder.toBytes();
  }

  static Uint8List httpRequestPayload({
    String method = 'GET',
    String path = '/index.html',
    String host = 'example.com',
  }) {
    return Uint8List.fromList(
      '$method $path HTTP/1.1\r\nHost: $host\r\n\r\n'.codeUnits,
    );
  }

  static Uint8List httpResponsePayload({
    int statusCode = 200,
    String reason = 'OK',
    String body = 'Hello World!',
  }) {
    return Uint8List.fromList(
      'HTTP/1.1 $statusCode $reason\r\nContent-Length: ${body.length}\r\n\r\n$body'
          .codeUnits,
    );
  }

  static Uint8List tlsClientHelloPayload({String sni = 'api.example.com'}) {
    final sniBytes = sni.codeUnits;
    final payload = BytesBuilder();
    payload.add([0x16, 0x03, 0x01, 0x00, 0x20 + sniBytes.length]);
    payload.add([0x01, 0x00, 0x00, 0x1C + sniBytes.length, 0x03, 0x03]);
    payload.add(List<int>.filled(24, 0xAB));
    payload.add(sniBytes);
    return payload.toBytes();
  }

  static Uint8List mdnsQueryPayload() {
    return dnsQueryPayload(txId: 0x0000, domain: 'printer.local');
  }

  static Uint8List ssdpDiscoverPayload() {
    return Uint8List.fromList(
      'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n\r\n'
          .codeUnits,
    );
  }

  static Uint8List nbnsQueryPayload() {
    return Uint8List.fromList([
      0xAB, 0xCD, 0x01, 0x10, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4B, 0x41,
    ]);
  }

  static Uint8List dhcpDiscoverPayload() {
    final buf = Uint8List(240);
    buf[0] = 0x01; // BOOTREQUEST
    buf[1] = 0x01; // Ethernet
    buf[2] = 0x06; // MAC length
    buf[236] = 0x63;
    buf[237] = 0x82;
    buf[238] = 0x53;
    buf[239] = 0x63;
    return buf;
  }

  static Uint8List ntpRequestPayload() {
    final buf = Uint8List(48);
    buf[0] = 0x1B; // LI=0, VN=3, Mode=3 (Client)
    return buf;
  }

  /// Builds an sACN (ANSI E1.31) DMX payload with sequence byte at offset 111.
  static Uint8List sacnDmxPayload({
    required int seq,
    int universe = 1,
    int slotCount = 24,
  }) {
    final len = 126 + slotCount;
    final payload = Uint8List(len);
    // Preamble (0x0010) + Post-amble (0x0000)
    payload[1] = 0x10;
    // ACN Packet Identifier: "ASC-E1.17\0\0\0"
    final acnId = 'ASC-E1.17'.codeUnits;
    payload.setRange(4, 4 + acnId.length, acnId);
    // Universe (big-endian at offset 113..114)
    payload[113] = (universe >> 8) & 0xFF;
    payload[114] = universe & 0xFF;
    // Sequence Number at offset 111
    payload[111] = seq & 0xFF;
    for (int i = 0; i < slotCount; i++) {
      payload[126 + i] = (i + seq) & 0xFF;
    }
    return payload;
  }

  /// Builds proprietary ACME telemetry payload matching UDP port 45820:
  /// `[0..3] = 'ACME'`, `[4..5] = CommandID (BE)`, `[6..9] = Serial (BE)`,
  /// `[10] = Status`, `[11..14] = Tag (ASCII)`, `[15..] = padding`.
  static Uint8List acmeTelemetryPayload({
    int commandId = 101,
    int serial = 883719,
    int status = 1,
    String tag = 'PROD',
    int totalLength = 16,
  }) {
    final len = totalLength < 16 ? 16 : totalLength;
    final payload = Uint8List(len);
    final bd = ByteData.sublistView(payload);
    payload[0] = 0x41; // A
    payload[1] = 0x43; // C
    payload[2] = 0x4D; // M
    payload[3] = 0x45; // E
    bd.setUint16(4, commandId, Endian.big);
    bd.setUint32(6, serial, Endian.big);
    bd.setUint8(10, status);
    final tagUnits = tag.codeUnits;
    for (int i = 0; i < 4 && i < tagUnits.length; i++) {
      payload[11 + i] = tagUnits[i];
    }
    for (int i = 15; i < len; i++) {
      payload[i] = i & 0xFF;
    }
    return payload;
  }

  /// Builds a deterministic payload of arbitrary [length] (e.g., 1400 bytes for F22).
  static Uint8List repeatedBytesPayload(int length, {int seed = 0x41}) {
    return Uint8List.fromList(
      List<int>.generate(length, (i) => (seed + (i % 26)) & 0xFF),
    );
  }

  /// Builds an Ethernet II + IPv4 frame (with optional 802.1Q VLAN tag).
  static BuiltFrame ethernetIpv4({
    List<int> dstMac = defaultDstMac,
    List<int> srcMac = defaultSrcMac,
    int? vlanId,
    int dscp = 0,
    int ecn = 0,
    int ttl = 64,
    int id = 0x1234,
    required int ipProto,
    required String srcIp,
    required String dstIp,
    required Uint8List l4Segment,
    required int l4HeaderLength,
  }) {
    final ethHeaderLen = vlanId != null ? 18 : 14;
    const ipHeaderLen = 20;
    final ipTotalLen = ipHeaderLen + l4Segment.length;
    final frame = Uint8List(ethHeaderLen + ipTotalLen);

    frame.setRange(0, 6, dstMac);
    frame.setRange(6, 12, srcMac);
    if (vlanId != null) {
      frame[12] = 0x81;
      frame[13] = 0x00;
      frame[14] = (vlanId >> 8) & 0x0F;
      frame[15] = vlanId & 0xFF;
      frame[16] = 0x08;
      frame[17] = 0x00;
    } else {
      frame[12] = 0x08;
      frame[13] = 0x00;
    }

    _writeIpv4Header(
      frame,
      offset: ethHeaderLen,
      totalLength: ipTotalLen,
      dscp: dscp,
      ecn: ecn,
      ttl: ttl,
      id: id,
      protocol: ipProto,
      srcIp: srcIp,
      dstIp: dstIp,
    );

    final l4Offset = ethHeaderLen + ipHeaderLen;
    frame.setRange(l4Offset, frame.length, l4Segment);

    final payloadOffsetInFrame = l4Offset + l4HeaderLength;
    final l4PayloadBytes = payloadOffsetInFrame <= frame.length
        ? Uint8List.fromList(frame.sublist(payloadOffsetInFrame))
        : Uint8List(0);

    return BuiltFrame(
      linkType: 1,
      frameBytes: frame,
      payloadOffsetInFrame: payloadOffsetInFrame,
      l4PayloadBytes: l4PayloadBytes,
    );
  }

  /// Convenience builder for Ethernet II + IPv4 + UDP.
  static BuiltFrame ethernetUdp({
    required String srcIp,
    required String dstIp,
    required int srcPort,
    required int dstPort,
    required Uint8List payload,
    List<int> dstMac = defaultDstMac,
    List<int> srcMac = defaultSrcMac,
    int? vlanId,
    int dscp = 0,
    int ttl = 64,
  }) {
    return ethernetIpv4(
      dstMac: dstMac,
      srcMac: srcMac,
      vlanId: vlanId,
      dscp: dscp,
      ttl: ttl,
      ipProto: 17,
      srcIp: srcIp,
      dstIp: dstIp,
      l4Segment: udpSegment(srcPort: srcPort, dstPort: dstPort, payload: payload),
      l4HeaderLength: 8,
    );
  }

  /// Convenience builder for Ethernet II + IPv4 + TCP.
  static BuiltFrame ethernetTcp({
    required String srcIp,
    required String dstIp,
    required int srcPort,
    required int dstPort,
    required int seqNum,
    required int ackNum,
    int flags = 0x18,
    Uint8List? payload,
    List<int> dstMac = defaultDstMac,
    List<int> srcMac = defaultSrcMac,
    int? vlanId,
    int dscp = 0,
    int ttl = 64,
  }) {
    return ethernetIpv4(
      dstMac: dstMac,
      srcMac: srcMac,
      vlanId: vlanId,
      dscp: dscp,
      ttl: ttl,
      ipProto: 6,
      srcIp: srcIp,
      dstIp: dstIp,
      l4Segment: tcpSegment(
        srcPort: srcPort,
        dstPort: dstPort,
        seqNum: seqNum,
        ackNum: ackNum,
        flags: flags,
        payload: payload,
      ),
      l4HeaderLength: 20,
    );
  }

  /// Convenience builder for Ethernet II + IPv4 + ICMP.
  static BuiltFrame ethernetIcmp({
    required String srcIp,
    required String dstIp,
    int type = 8,
    int code = 0,
    int seqNum = 1,
    Uint8List? payload,
  }) {
    return ethernetIpv4(
      ipProto: 1,
      srcIp: srcIp,
      dstIp: dstIp,
      l4Segment: icmpEcho(type: type, code: code, seqNum: seqNum, payload: payload),
      l4HeaderLength: 8,
    );
  }

  /// Builds an Ethernet II + ARP packet (`linkType = 1`).
  static BuiltFrame ethernetArp({
    required String senderIp,
    required String targetIp,
    int opcode = 1,
    int? vlanId,
  }) {
    final ethHeaderLen = vlanId != null ? 18 : 14;
    final frame = Uint8List(ethHeaderLen + 28);
    for (int i = 0; i < 6; i++) {
      frame[i] = 0xFF;
    }
    frame.setRange(6, 12, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    if (vlanId != null) {
      frame[12] = 0x81;
      frame[13] = 0x00;
      frame[14] = (vlanId >> 8) & 0x0F;
      frame[15] = vlanId & 0xFF;
      frame[16] = 0x08;
      frame[17] = 0x06;
    } else {
      frame[12] = 0x08;
      frame[13] = 0x06;
    }

    final bd = ByteData.sublistView(frame, ethHeaderLen, ethHeaderLen + 28);
    bd.setUint16(0, 1, Endian.big);
    bd.setUint16(2, 0x0800, Endian.big);
    bd.setUint8(4, 6);
    bd.setUint8(5, 4);
    bd.setUint16(6, opcode, Endian.big);
    frame.setRange(ethHeaderLen + 8, ethHeaderLen + 14, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.setRange(ethHeaderLen + 14, ethHeaderLen + 18, _parseIpv4(senderIp));
    frame.setRange(
      ethHeaderLen + 18,
      ethHeaderLen + 24,
      List<int>.filled(6, opcode == 1 ? 0x00 : 0xFF),
    );
    frame.setRange(ethHeaderLen + 24, ethHeaderLen + 28, _parseIpv4(targetIp));

    return BuiltFrame(
      linkType: 1,
      frameBytes: frame,
      payloadOffsetInFrame: ethHeaderLen,
      l4PayloadBytes: Uint8List.fromList(frame.sublist(ethHeaderLen)),
    );
  }

  /// Builds a Linux Cooked SLL (`linkType = 113`) IPv4/UDP packet.
  static BuiltFrame linuxSllUdp({
    required String srcIp,
    required String dstIp,
    required int srcPort,
    required int dstPort,
    required Uint8List payload,
  }) {
    final l4Seg = udpSegment(srcPort: srcPort, dstPort: dstPort, payload: payload);
    const sllLen = 16;
    const ipLen = 20;
    final frame = Uint8List(sllLen + ipLen + l4Seg.length);
    final bd = ByteData.sublistView(frame);
    bd.setUint16(0, 0, Endian.big); // packet type: host
    bd.setUint16(2, 1, Endian.big); // ARPHRD_ETHER
    bd.setUint16(4, 6, Endian.big);
    bd.setUint16(14, 0x0800, Endian.big); // IPv4

    _writeIpv4Header(
      frame,
      offset: sllLen,
      totalLength: ipLen + l4Seg.length,
      protocol: 17,
      srcIp: srcIp,
      dstIp: dstIp,
    );
    frame.setRange(sllLen + ipLen, frame.length, l4Seg);
    final payloadOffsetInFrame = sllLen + ipLen + 8;

    return BuiltFrame(
      linkType: 113,
      frameBytes: frame,
      payloadOffsetInFrame: payloadOffsetInFrame,
      l4PayloadBytes: Uint8List.fromList(payload),
    );
  }

  /// Builds a Loopback/Null (`linkType = 0`) IPv4/UDP packet.
  static BuiltFrame loopbackUdp({
    required String srcIp,
    required String dstIp,
    required int srcPort,
    required int dstPort,
    required Uint8List payload,
  }) {
    final l4Seg = udpSegment(srcPort: srcPort, dstPort: dstPort, payload: payload);
    const nullLen = 4;
    const ipLen = 20;
    final frame = Uint8List(nullLen + ipLen + l4Seg.length);
    // AF_INET = 2 in little-endian 32-bit header
    ByteData.sublistView(frame).setUint32(0, 2, Endian.little);
    _writeIpv4Header(
      frame,
      offset: nullLen,
      totalLength: ipLen + l4Seg.length,
      protocol: 17,
      srcIp: srcIp,
      dstIp: dstIp,
    );
    frame.setRange(nullLen + ipLen, frame.length, l4Seg);
    final payloadOffsetInFrame = nullLen + ipLen + 8;

    return BuiltFrame(
      linkType: 0,
      frameBytes: frame,
      payloadOffsetInFrame: payloadOffsetInFrame,
      l4PayloadBytes: Uint8List.fromList(payload),
    );
  }

  /// Builds a Raw IP (`linkType = 101`) IPv4/UDP packet.
  static BuiltFrame rawIpUdp({
    required String srcIp,
    required String dstIp,
    required int srcPort,
    required int dstPort,
    required Uint8List payload,
  }) {
    final l4Seg = udpSegment(srcPort: srcPort, dstPort: dstPort, payload: payload);
    const ipLen = 20;
    final frame = Uint8List(ipLen + l4Seg.length);
    _writeIpv4Header(
      frame,
      offset: 0,
      totalLength: ipLen + l4Seg.length,
      protocol: 17,
      srcIp: srcIp,
      dstIp: dstIp,
    );
    frame.setRange(ipLen, frame.length, l4Seg);
    const payloadOffsetInFrame = ipLen + 8;

    return BuiltFrame(
      linkType: 101,
      frameBytes: frame,
      payloadOffsetInFrame: payloadOffsetInFrame,
      l4PayloadBytes: Uint8List.fromList(payload),
    );
  }

  /// Builds an Ethernet II + IPv6 + UDP packet.
  static BuiltFrame ethernetIpv6Udp({
    required Uint8List srcIpBytes,
    required Uint8List dstIpBytes,
    required int srcPort,
    required int dstPort,
    required Uint8List payload,
    int dscp = 0,
  }) {
    final l4Seg = udpSegment(srcPort: srcPort, dstPort: dstPort, payload: payload);
    const ethLen = 14;
    const ip6Len = 40;
    final frame = Uint8List(ethLen + ip6Len + l4Seg.length);
    frame.setRange(0, 6, defaultDstMac);
    frame.setRange(6, 12, defaultSrcMac);
    frame[12] = 0x86;
    frame[13] = 0xDD;

    final bd = ByteData.sublistView(frame, ethLen, ethLen + ip6Len);
    final trafficClass = (dscp & 0x3F) << 2;
    bd.setUint32(0, (6 << 28) | (trafficClass << 20), Endian.big);
    bd.setUint16(4, l4Seg.length, Endian.big);
    bd.setUint8(6, 17); // Next Header: UDP
    bd.setUint8(7, 64); // Hop Limit
    frame.setRange(ethLen + 8, ethLen + 24, srcIpBytes);
    frame.setRange(ethLen + 24, ethLen + 40, dstIpBytes);
    frame.setRange(ethLen + ip6Len, frame.length, l4Seg);

    const payloadOffsetInFrame = ethLen + ip6Len + 8;
    return BuiltFrame(
      linkType: 1,
      frameBytes: frame,
      payloadOffsetInFrame: payloadOffsetInFrame,
      l4PayloadBytes: Uint8List.fromList(payload),
    );
  }

  static void _writeIpv4Header(
    Uint8List frame, {
    required int offset,
    required int totalLength,
    required int protocol,
    required String srcIp,
    required String dstIp,
    int dscp = 0,
    int ecn = 0,
    int ttl = 64,
    int id = 0x1234,
  }) {
    final bd = ByteData.sublistView(frame, offset, offset + 20);
    bd.setUint8(0, 0x45);
    bd.setUint8(1, ((dscp & 0x3F) << 2) | (ecn & 0x03));
    bd.setUint16(2, totalLength, Endian.big);
    bd.setUint16(4, id, Endian.big);
    bd.setUint16(6, 0x4000, Endian.big);
    bd.setUint8(8, ttl);
    bd.setUint8(9, protocol);
    bd.setUint16(10, 0, Endian.big);
    frame.setRange(offset + 12, offset + 16, _parseIpv4(srcIp));
    frame.setRange(offset + 16, offset + 20, _parseIpv4(dstIp));
    final checksum = _onesComplementChecksum(
      Uint8List.sublistView(frame, offset, offset + 20),
    );
    bd.setUint16(10, checksum, Endian.big);
  }

  static List<int> _parseIpv4(String ip) {
    final parts = ip.split('.');
    if (parts.length != 4) {
      throw ArgumentError('Invalid IPv4 address: $ip');
    }
    return parts.map((p) => int.parse(p) & 0xFF).toList();
  }

  static int _onesComplementChecksum(Uint8List data) {
    int sum = 0;
    for (int i = 0; i + 1 < data.length; i += 2) {
      sum += (data[i] << 8) | data[i + 1];
    }
    if (data.length.isOdd) {
      sum += data.last << 8;
    }
    while ((sum >> 16) != 0) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (~sum) & 0xFFFF;
  }
}

/// Fluent builder for classic `.pcap` (microsecond/nanosecond, LE/BE) buffers.
class ClassicPcapBuilder {
  ClassicPcapBuilder({
    this.endian = Endian.little,
    this.nanosecond = false,
    this.linkType = 1,
    this.snapLen = 65535,
  }) {
    final gh = ByteData(24);
    final magic = nanosecond ? 0xA1B23C4D : 0xA1B2C3D4;
    gh.setUint32(0, magic, endian);
    gh.setUint16(4, 2, endian);
    gh.setUint16(6, 4, endian);
    gh.setInt32(8, 0, endian);
    gh.setUint32(12, 0, endian);
    gh.setUint32(16, snapLen, endian);
    gh.setUint32(20, linkType, endian);
    _buffer.add(gh.buffer.asUint8List());
  }

  final Endian endian;
  final bool nanosecond;
  final int linkType;
  final int snapLen;

  final BytesBuilder _buffer = BytesBuilder();
  final List<BuiltPacketExpectation> _expectations = [];
  int _packetNo = 1;

  void addFrame(
    Uint8List frameBytes, {
    required int timestampUs,
    int? originalLength,
    int payloadOffsetInFrame = 0,
    Uint8List? l4PayloadBytes,
  }) {
    final tsSec = timestampUs ~/ 1000000;
    final remUs = timestampUs % 1000000;
    final tsFrac = nanosecond ? remUs * 1000 : remUs;
    final origLen = originalLength ?? frameBytes.length;

    final hdr = ByteData(16)
      ..setUint32(0, tsSec, endian)
      ..setUint32(4, tsFrac, endian)
      ..setUint32(8, frameBytes.length, endian)
      ..setUint32(12, origLen, endian);
    _buffer.add(hdr.buffer.asUint8List());

    final frameOffset = _buffer.length;
    _buffer.add(frameBytes);

    final effectivePayload = l4PayloadBytes ??
        (payloadOffsetInFrame <= frameBytes.length
            ? Uint8List.fromList(frameBytes.sublist(payloadOffsetInFrame))
            : Uint8List(0));

    _expectations.add(BuiltPacketExpectation(
      packetNo: _packetNo++,
      timestampUs: timestampUs,
      linkType: linkType,
      frameBytes: Uint8List.fromList(frameBytes),
      l4PayloadBytes: effectivePayload,
      payloadOffsetInFrame: payloadOffsetInFrame,
      expectedFrameFileOffset: frameOffset,
      expectedPayloadFileOffset: frameOffset + payloadOffsetInFrame,
    ));
  }

  void addBuiltFrame(
    BuiltFrame built, {
    required int timestampUs,
    int? originalLength,
  }) {
    addFrame(
      built.frameBytes,
      timestampUs: timestampUs,
      originalLength: originalLength,
      payloadOffsetInFrame: built.payloadOffsetInFrame,
      l4PayloadBytes: built.l4PayloadBytes,
    );
  }

  /// Appends an incomplete trailing packet record claiming [claimedLength] bytes
  /// while only writing [actualTrailingBytes] bytes for truncation boundary tests.
  void appendTruncatedTrailingPacket({
    required int timestampUs,
    int claimedLength = 64,
    int actualTrailingBytes = 12,
  }) {
    final tsSec = timestampUs ~/ 1000000;
    final remUs = timestampUs % 1000000;
    final hdr = ByteData(16)
      ..setUint32(0, tsSec, endian)
      ..setUint32(4, nanosecond ? remUs * 1000 : remUs, endian)
      ..setUint32(8, claimedLength, endian)
      ..setUint32(12, claimedLength, endian);
    _buffer.add(hdr.buffer.asUint8List());
    _buffer.add(Uint8List(actualTrailingBytes));
  }

  Uint8List buildBytes() => _buffer.toBytes();

  BuiltCaptureFixture buildWithExpectations() => BuiltCaptureFixture(
        bytes: _buffer.toBytes(),
        expectations: List.unmodifiable(_expectations),
      );
}

class _NgInterfaceMeta {
  const _NgInterfaceMeta({
    required this.linkType,
    required this.tsResolution,
  });

  final int linkType;
  final int tsResolution;
}

/// Fluent builder for `.pcapng` captures (multi-SHB, multi-IDB, EPB, SPB).
class PcapNgBuilder {
  PcapNgBuilder({Endian initialEndian = Endian.little}) {
    addSection(endian: initialEndian);
  }

  final BytesBuilder _buffer = BytesBuilder();
  final List<BuiltPacketExpectation> _expectations = [];
  final List<_NgInterfaceMeta> _sectionInterfaces = [];
  Endian _currentEndian = Endian.little;
  int _packetNo = 1;

  /// Starts a new Section Header Block (`0x0A0D0D0A`) and resets section interfaces.
  void addSection({Endian endian = Endian.little}) {
    _currentEndian = endian;
    _sectionInterfaces.clear();

    final shb = ByteData(28)
      ..setUint32(0, 0x0A0D0D0A, endian)
      ..setUint32(4, 28, endian)
      ..setUint32(8, 0x1A2B3C4D, endian)
      ..setUint16(12, 1, endian)
      ..setUint16(14, 0, endian)
      ..setInt64(16, -1, endian)
      ..setUint32(24, 28, endian);
    _buffer.add(shb.buffer.asUint8List());
  }

  /// Adds an Interface Description Block (`0x00000001`) and returns its 0-based ID.
  ///
  /// [tsResolCode] corresponds to PCAPNG `if_tsresol` (option code 9):
  /// - `null` -> default `10^-6` (1,000,000)
  /// - `6` -> `10^-6`, `9` -> `10^-9`
  /// - `0x80 | 32` -> binary `2^-32` (4,294,967,296 ticks/sec)
  int addInterface({
    int linkType = 1,
    int snapLen = 65535,
    int? tsResolCode,
  }) {
    final int tsResolution;
    if (tsResolCode == null) {
      tsResolution = 1000000;
    } else if ((tsResolCode & 0x80) != 0) {
      final exp = tsResolCode & 0x7F;
      tsResolution = 1 << exp;
    } else {
      int r = 1;
      for (int i = 0; i < tsResolCode; i++) {
        r *= 10;
      }
      tsResolution = r;
    }

    if (tsResolCode == null) {
      final idb = ByteData(20)
        ..setUint32(0, 0x00000001, _currentEndian)
        ..setUint32(4, 20, _currentEndian)
        ..setUint16(8, linkType, _currentEndian)
        ..setUint16(10, 0, _currentEndian)
        ..setUint32(12, snapLen, _currentEndian)
        ..setUint32(16, 20, _currentEndian);
      _buffer.add(idb.buffer.asUint8List());
    } else {
      // 16B header + 8B option(if_tsresol: code=9, len=1, 1B val + 3B pad) + 4B endofopt + 4B trailing len = 32B
      final idb = ByteData(32)
        ..setUint32(0, 0x00000001, _currentEndian)
        ..setUint32(4, 32, _currentEndian)
        ..setUint16(8, linkType, _currentEndian)
        ..setUint16(10, 0, _currentEndian)
        ..setUint32(12, snapLen, _currentEndian)
        ..setUint16(16, 9, _currentEndian)
        ..setUint16(18, 1, _currentEndian)
        ..setUint8(20, tsResolCode)
        ..setUint16(24, 0, _currentEndian)
        ..setUint16(26, 0, _currentEndian)
        ..setUint32(28, 32, _currentEndian);
      _buffer.add(idb.buffer.asUint8List());
    }

    _sectionInterfaces.add(
      _NgInterfaceMeta(linkType: linkType, tsResolution: tsResolution),
    );
    return _sectionInterfaces.length - 1;
  }

  /// Adds an Enhanced Packet Block (`0x00000006`) using an explicit 64-bit [rawTimestamp].
  void addEnhancedPacket({
    required int interfaceId,
    required Uint8List frameBytes,
    required BigInt rawTimestamp,
    int? originalLength,
    int payloadOffsetInFrame = 0,
    Uint8List? l4PayloadBytes,
  }) {
    final meta = (interfaceId >= 0 && interfaceId < _sectionInterfaces.length)
        ? _sectionInterfaces[interfaceId]
        : const _NgInterfaceMeta(linkType: 1, tsResolution: 1000000);

    final paddedCapLen = (frameBytes.length + 3) & ~3;
    final totalLen = 32 + paddedCapLen;
    final blockStart = _buffer.length;
    final frameOffset = blockStart + 28;

    final mask32 = BigInt.from(0xFFFFFFFF);
    final tsHigh = ((rawTimestamp >> 32) & mask32).toInt();
    final tsLow = (rawTimestamp & mask32).toInt();
    final origLen = originalLength ?? frameBytes.length;

    final epb = Uint8List(totalLen);
    final bd = ByteData.sublistView(epb)
      ..setUint32(0, 0x00000006, _currentEndian)
      ..setUint32(4, totalLen, _currentEndian)
      ..setUint32(8, interfaceId, _currentEndian)
      ..setUint32(12, tsHigh, _currentEndian)
      ..setUint32(16, tsLow, _currentEndian)
      ..setUint32(20, frameBytes.length, _currentEndian)
      ..setUint32(24, origLen, _currentEndian);
    epb.setRange(28, 28 + frameBytes.length, frameBytes);
    bd.setUint32(totalLen - 4, totalLen, _currentEndian);
    _buffer.add(epb);

    final expectedTimestampUs = meta.tsResolution > 0
        ? ((rawTimestamp * BigInt.from(1000000)) ~/ BigInt.from(meta.tsResolution)).toInt()
        : rawTimestamp.toInt();

    final effectivePayload = l4PayloadBytes ??
        (payloadOffsetInFrame <= frameBytes.length
            ? Uint8List.fromList(frameBytes.sublist(payloadOffsetInFrame))
            : Uint8List(0));

    _expectations.add(BuiltPacketExpectation(
      packetNo: _packetNo++,
      timestampUs: expectedTimestampUs,
      linkType: meta.linkType,
      frameBytes: Uint8List.fromList(frameBytes),
      l4PayloadBytes: effectivePayload,
      payloadOffsetInFrame: payloadOffsetInFrame,
      expectedFrameFileOffset: frameOffset,
      expectedPayloadFileOffset: frameOffset + payloadOffsetInFrame,
    ));
  }

  /// Convenience helper converting [timestampUs] to raw ticks for [interfaceId].
  void addEnhancedBuiltFrame({
    required int interfaceId,
    required BuiltFrame built,
    required int timestampUs,
    int? originalLength,
  }) {
    final meta = (interfaceId >= 0 && interfaceId < _sectionInterfaces.length)
        ? _sectionInterfaces[interfaceId]
        : const _NgInterfaceMeta(linkType: 1, tsResolution: 1000000);
    final rawTs = (BigInt.from(timestampUs) * BigInt.from(meta.tsResolution)) ~/
        BigInt.from(1000000);
    addEnhancedPacket(
      interfaceId: interfaceId,
      frameBytes: built.frameBytes,
      rawTimestamp: rawTs,
      originalLength: originalLength,
      payloadOffsetInFrame: built.payloadOffsetInFrame,
      l4PayloadBytes: built.l4PayloadBytes,
    );
  }

  /// Adds a Simple Packet Block (`0x00000003`) using interface 0.
  void addSimplePacket({
    required Uint8List frameBytes,
    int? originalLength,
    int payloadOffsetInFrame = 0,
    Uint8List? l4PayloadBytes,
  }) {
    final meta = _sectionInterfaces.isNotEmpty
        ? _sectionInterfaces.first
        : const _NgInterfaceMeta(linkType: 1, tsResolution: 1000000);
    final paddedCapLen = (frameBytes.length + 3) & ~3;
    final totalLen = 16 + paddedCapLen;
    final blockStart = _buffer.length;
    final frameOffset = blockStart + 12;
    final origLen = originalLength ?? frameBytes.length;

    final spb = Uint8List(totalLen);
    final bd = ByteData.sublistView(spb)
      ..setUint32(0, 0x00000003, _currentEndian)
      ..setUint32(4, totalLen, _currentEndian)
      ..setUint32(8, origLen, _currentEndian);
    spb.setRange(12, 12 + frameBytes.length, frameBytes);
    bd.setUint32(totalLen - 4, totalLen, _currentEndian);
    _buffer.add(spb);

    final effectivePayload = l4PayloadBytes ??
        (payloadOffsetInFrame <= frameBytes.length
            ? Uint8List.fromList(frameBytes.sublist(payloadOffsetInFrame))
            : Uint8List(0));

    _expectations.add(BuiltPacketExpectation(
      packetNo: _packetNo++,
      timestampUs: 0,
      linkType: meta.linkType,
      frameBytes: Uint8List.fromList(frameBytes),
      l4PayloadBytes: effectivePayload,
      payloadOffsetInFrame: payloadOffsetInFrame,
      expectedFrameFileOffset: frameOffset,
      expectedPayloadFileOffset: frameOffset + payloadOffsetInFrame,
    ));
  }

  void addSimpleBuiltFrame(BuiltFrame built, {int? originalLength}) {
    addSimplePacket(
      frameBytes: built.frameBytes,
      originalLength: originalLength,
      payloadOffsetInFrame: built.payloadOffsetInFrame,
      l4PayloadBytes: built.l4PayloadBytes,
    );
  }

  /// Appends a truncated block claiming [claimedTotalLength] for boundary tests.
  void appendTruncatedBlock({int claimedTotalLength = 128, int actualBytes = 16}) {
    final partial = Uint8List(actualBytes);
    if (actualBytes >= 8) {
      ByteData.sublistView(partial)
        ..setUint32(0, 0x00000006, _currentEndian)
        ..setUint32(4, claimedTotalLength, _currentEndian);
    }
    _buffer.add(partial);
  }

  Uint8List buildBytes() => _buffer.toBytes();

  BuiltCaptureFixture buildWithExpectations() => BuiltCaptureFixture(
        bytes: _buffer.toBytes(),
        expectations: List.unmodifiable(_expectations),
      );
}

/// High-level preset capture & multi-hop diff fixture factory for E2E tests.
class PcapFixtureBuilder {
  static const int defaultStartEpochUs = 1700000000000000;

  /// Writes [bytes] into `<dir>/<filename>` and returns the created [File].
  static File writeTempCaptureFile(
    Directory dir,
    String filename,
    Uint8List bytes,
  ) {
    final file = File('${dir.path}${Platform.pathSeparator}$filename');
    file.parent.createSync(recursive: true);
    file.writeAsBytesSync(bytes, flush: true);
    return file;
  }

  /// Builds a rich multi-protocol classic PCAP containing LAN noise, DNS, HTTP,
  /// TLS, ICMP, NTP, a `<50us` micro-burst, a `>100ms` stall, ACME UDP/45820,
  /// and a large >256B (`1400B`) payload packet.
  static BuiltCaptureFixture buildRichInspectorCapture({
    Endian endian = Endian.little,
    bool nanosecond = false,
    int startTimestampUs = defaultStartEpochUs,
  }) {
    final b = ClassicPcapBuilder(endian: endian, nanosecond: nanosecond);
    int ts = startTimestampUs;

    void append(BuiltFrame frame, int deltaUs) {
      ts += deltaUs;
      b.addBuiltFrame(frame, timestampUs: ts);
    }

    // 1-2. ARP Request + Reply (LAN noise)
    append(
      PcapFrameFactory.ethernetArp(
        senderIp: '192.168.1.50',
        targetIp: '192.168.1.1',
        opcode: 1,
      ),
      0,
    );
    append(
      PcapFrameFactory.ethernetArp(
        senderIp: '192.168.1.1',
        targetIp: '192.168.1.50',
        opcode: 2,
      ),
      1500,
    );

    // 3-4. DNS Query & Response
    append(
      PcapFrameFactory.ethernetUdp(
        srcIp: '192.168.1.10',
        dstIp: '8.8.8.8',
        srcPort: 54321,
        dstPort: 53,
        payload: PcapFrameFactory.dnsQueryPayload(),
      ),
      10000,
    );
    append(
      PcapFrameFactory.ethernetUdp(
        srcIp: '8.8.8.8',
        dstIp: '192.168.1.10',
        srcPort: 53,
        dstPort: 54321,
        payload: PcapFrameFactory.dnsResponsePayload(),
      ),
      12000,
    );

    // 5-6. HTTP GET & 200 OK
    append(
      PcapFrameFactory.ethernetTcp(
        srcIp: '192.168.1.10',
        dstIp: '93.184.216.34',
        srcPort: 49152,
        dstPort: 80,
        seqNum: 1001,
        ackNum: 1,
        payload: PcapFrameFactory.httpRequestPayload(),
      ),
      20000,
    );
    append(
      PcapFrameFactory.ethernetTcp(
        srcIp: '93.184.216.34',
        dstIp: '192.168.1.10',
        srcPort: 80,
        dstPort: 49152,
        seqNum: 1,
        ackNum: 1045,
        payload: PcapFrameFactory.httpResponsePayload(),
      ),
      25000,
    );

    // 7. TLS ClientHello
    append(
      PcapFrameFactory.ethernetTcp(
        srcIp: '192.168.1.10',
        dstIp: '104.16.132.229',
        srcPort: 49153,
        dstPort: 443,
        seqNum: 10,
        ackNum: 1,
        payload: PcapFrameFactory.tlsClientHelloPayload(),
      ),
      15000,
    );

    // 8-11. mDNS, SSDP, NBNS, DHCP (LAN noise) & NTP
    append(
      PcapFrameFactory.ethernetUdp(
        srcIp: '192.168.1.10',
        dstIp: '224.0.0.251',
        srcPort: 5353,
        dstPort: 5353,
        payload: PcapFrameFactory.mdnsQueryPayload(),
      ),
      30000,
    );
    append(
      PcapFrameFactory.ethernetUdp(
        srcIp: '192.168.1.10',
        dstIp: '239.255.255.250',
        srcPort: 50123,
        dstPort: 1900,
        payload: PcapFrameFactory.ssdpDiscoverPayload(),
      ),
      30000,
    );
    append(
      PcapFrameFactory.ethernetUdp(
        srcIp: '192.168.1.10',
        dstIp: '192.168.1.255',
        srcPort: 137,
        dstPort: 137,
        payload: PcapFrameFactory.nbnsQueryPayload(),
      ),
      20000,
    );
    append(
      PcapFrameFactory.ethernetUdp(
        srcIp: '0.0.0.0',
        dstIp: '255.255.255.255',
        srcPort: 68,
        dstPort: 67,
        payload: PcapFrameFactory.dhcpDiscoverPayload(),
      ),
      20000,
    );
    append(
      PcapFrameFactory.ethernetUdp(
        srcIp: '192.168.1.10',
        dstIp: '129.6.15.28',
        srcPort: 52000,
        dstPort: 123,
        payload: PcapFrameFactory.ntpRequestPayload(),
      ),
      20000,
    );

    // 13-17. Micro-burst (<50us delta) from unexpected IP 10.99.88.77
    for (int i = 0; i < 5; i++) {
      append(
        PcapFrameFactory.ethernetTcp(
          srcIp: '10.99.88.77',
          dstIp: '192.168.1.10',
          srcPort: 40000 + i,
          dstPort: 445,
          seqNum: 100 + i * 20,
          ackNum: 0,
          flags: 0x02,
          payload: Uint8List(0),
        ),
        35,
      );
    }

    // 18. Latency stall (>100ms = 450,000us)
    append(
      PcapFrameFactory.ethernetTcp(
        srcIp: '192.168.1.10',
        dstIp: '93.184.216.34',
        srcPort: 49152,
        dstPort: 80,
        seqNum: 1045,
        ackNum: 60,
        flags: 0x10,
        payload: Uint8List(0),
      ),
      450000,
    );

    // 19. ACME custom protocol on UDP 45820
    append(
      PcapFrameFactory.ethernetUdp(
        srcIp: '192.168.1.10',
        dstIp: '192.168.1.200',
        srcPort: 45820,
        dstPort: 45820,
        payload: PcapFrameFactory.acmeTelemetryPayload(),
      ),
      20000,
    );

    // 20. Large 1400-byte UDP payload (exceeds 256-byte preview cap for F22/F18)
    append(
      PcapFrameFactory.ethernetUdp(
        srcIp: '192.168.1.10',
        dstIp: '10.0.5.50',
        srcPort: 55000,
        dstPort: 9000,
        payload: PcapFrameFactory.repeatedBytesPayload(1400),
      ),
      20000,
    );

    // 21. ICMP Echo Request
    append(
      PcapFrameFactory.ethernetIcmp(
        srcIp: '192.168.1.10',
        dstIp: '10.0.5.50',
      ),
      15000,
    );

    return b.buildWithExpectations();
  }

  /// Builds a large PCAP capture with [packetCount] packets (default 1,500)
  /// for pagination, search debounce, and full CSV export beyond page 1.
  static BuiltCaptureFixture buildBulkPcap({
    int packetCount = 1500,
    int stepDeltaUs = 1000,
    int startTimestampUs = defaultStartEpochUs,
  }) {
    final b = ClassicPcapBuilder();
    int ts = startTimestampUs;
    for (int i = 0; i < packetCount; i++) {
      ts += stepDeltaUs;
      final isDns = (i % 5 == 0);
      final isUnexpected = (i % 10 == 9);
      final srcIp = isUnexpected ? '10.99.88.${(i % 20) + 1}' : '192.168.1.${(i % 40) + 10}';
      final dstIp = isDns ? '8.8.8.8' : '10.0.0.${(i % 10) + 20}';
      final payload = isDns
          ? PcapFrameFactory.dnsQueryPayload(txId: i & 0xFFFF)
          : Uint8List.fromList([0x42, 0x55, 0x4C, 0x4B, (i >> 8) & 0xFF, i & 0xFF, 0x00, 0x01]);
      b.addBuiltFrame(
        PcapFrameFactory.ethernetUdp(
          srcIp: srcIp,
          dstIp: dstIp,
          srcPort: 50000 + (i % 100),
          dstPort: isDns ? 53 : 9100,
          payload: payload,
        ),
        timestampUs: ts,
      );
    }
    return b.buildWithExpectations();
  }

  /// Builds a multi-SHB, multi-IDB PCAPNG capture exercising `10^-6`, `10^-9`,
  /// binary `2^-32` (`if_tsresol = 0x80 | 32`), EPB, and SPB packets.
  static BuiltCaptureFixture buildMultiIdbPcapNg() {
    final ng = PcapNgBuilder(initialEndian: Endian.little);
    // Section 1: IDB 0 = Ethernet (10^-6), IDB 1 = Ethernet (2^-32)
    final if0 = ng.addInterface(linkType: 1, tsResolCode: 6);
    final if1 = ng.addInterface(linkType: 1, tsResolCode: 0x80 | 32);

    final dnsFrame = PcapFrameFactory.ethernetUdp(
      srcIp: '192.168.10.5',
      dstIp: '8.8.8.8',
      srcPort: 51111,
      dstPort: 53,
      payload: PcapFrameFactory.dnsQueryPayload(),
    );
    ng.addEnhancedBuiltFrame(
      interfaceId: if0,
      built: dnsFrame,
      timestampUs: 1700000000000000,
    );

    // 2^-32 ticks/sec: 1700000001 seconds * 2^32 ticks/sec (overflows 64-bit signed if multiplied by 10^6 as int64!)
    final acmeFrame = PcapFrameFactory.ethernetUdp(
      srcIp: '192.168.10.20',
      dstIp: '192.168.10.99',
      srcPort: 45820,
      dstPort: 45820,
      payload: PcapFrameFactory.acmeTelemetryPayload(commandId: 202, serial: 991122),
    );
    final raw2Pow32 = BigInt.from(1700000001) * (BigInt.one << 32);
    ng.addEnhancedPacket(
      interfaceId: if1,
      frameBytes: acmeFrame.frameBytes,
      rawTimestamp: raw2Pow32,
      payloadOffsetInFrame: acmeFrame.payloadOffsetInFrame,
      l4PayloadBytes: acmeFrame.l4PayloadBytes,
    );

    // Section 2 (big endian, resets interfaces): IDB 0 = Linux SLL (10^-9)
    ng.addSection(endian: Endian.big);
    final s2If0 = ng.addInterface(linkType: 113, tsResolCode: 9);
    final sllFrame = PcapFrameFactory.linuxSllUdp(
      srcIp: '172.16.0.10',
      dstIp: '172.16.0.20',
      srcPort: 6000,
      dstPort: 7000,
      payload: Uint8List.fromList([0x53, 0x4C, 0x4C, 0x31]), // "SLL1"
    );
    ng.addEnhancedBuiltFrame(
      interfaceId: s2If0,
      built: sllFrame,
      timestampUs: 1700000002500000,
    );

    // Simple Packet Block in Section 2
    ng.addSimpleBuiltFrame(
      PcapFrameFactory.linuxSllUdp(
        srcIp: '172.16.0.11',
        dstIp: '172.16.0.21',
        srcPort: 6001,
        dstPort: 7001,
        payload: Uint8List.fromList([0x53, 0x50, 0x42, 0x32]), // "SPB2"
      ),
    );

    return ng.buildWithExpectations();
  }

  /// Builds 3 correlated hop PCAPs (`A: Console`, `B: Switch`, `C: Rack`) with
  /// configurable clock skew, drops, source gaps, out-of-order, DSCP/VLAN
  /// mutations, latency spikes, and ARP noise.
  static BuiltDiffFixture buildMultiHopDiffCaptures({
    Directory? tempDir,
    int clockSkewHop1Us = 40000,
    int clockSkewHop2Us = -15000,
    bool includeArpNoise = true,
    bool includeDrop = true,
    bool includeSourceGap = true,
    bool includeOutOfOrder = true,
    bool includeDscpMutation = true,
    bool includeVlanMutation = true,
    bool includeLatencySpike = true,
  }) {
    final hop0 = ClassicPcapBuilder();
    final hop1 = ClassicPcapBuilder();
    final hop2 = ClassicPcapBuilder();

    const baseTs = defaultStartEpochUs;

    if (includeArpNoise) {
      hop0.addBuiltFrame(
        PcapFrameFactory.ethernetArp(senderIp: '10.10.1.5', targetIp: '10.10.1.1'),
        timestampUs: baseTs,
      );
      hop1.addBuiltFrame(
        PcapFrameFactory.ethernetArp(senderIp: '10.10.1.99', targetIp: '10.10.1.1'),
        timestampUs: baseTs + clockSkewHop1Us + 50,
      );
    }

    // Anchor sACN frames (seq 1, 2, 3, [gap -> 5], 6, 7)
    // Note: seq 6 is dropped at Hop 2 if includeDrop, seq 4/5 swapped at Hop 2 if includeOutOfOrder
    final sacnSeqs = includeSourceGap ? [1, 2, 3, 5, 6, 7] : [1, 2, 3, 4, 5, 6];
    final hop2Deferred = <({BuiltFrame frame, int ts})>[];

    for (int i = 0; i < sacnSeqs.length; i++) {
      final seq = sacnSeqs[i];
      final ts0 = baseTs + (i + 1) * 10000;
      final frame0 = PcapFrameFactory.ethernetUdp(
        srcIp: '10.10.1.10',
        dstIp: '239.255.0.1',
        srcPort: 5568,
        dstPort: 5568,
        dscp: 34,
        payload: PcapFrameFactory.sacnDmxPayload(seq: seq),
      );
      hop0.addBuiltFrame(frame0, timestampUs: ts0);

      final extraLatency1 = (includeLatencySpike && i == 1) ? 25000 : 120;
      hop1.addBuiltFrame(
        frame0,
        timestampUs: ts0 + clockSkewHop1Us + extraLatency1,
      );

      // Drop packet index 4 (seq 6) at Hop 2
      if (includeDrop && i == 4) {
        continue;
      }

      final frame2 = PcapFrameFactory.ethernetUdp(
        srcIp: '10.10.1.10',
        dstIp: '239.255.0.1',
        srcPort: 5568,
        dstPort: 5568,
        dscp: 34,
        payload: PcapFrameFactory.sacnDmxPayload(seq: seq),
      );
      final ts2 = ts0 + clockSkewHop2Us + 240;

      if (includeOutOfOrder && i == 2) {
        hop2Deferred.add((frame: frame2, ts: ts2 + 6000));
      } else {
        hop2.addBuiltFrame(frame2, timestampUs: ts2);
        if (includeOutOfOrder && i == 3 && hop2Deferred.isNotEmpty) {
          final delayed = hop2Deferred.removeLast();
          hop2.addBuiltFrame(delayed.frame, timestampUs: delayed.ts);
        }
      }
    }

    // Dante/UDP frame with DSCP mutation (46 -> 0 at Hop 1 & 2)
    final danteTs = baseTs + 80000;
    final dantePayload = Uint8List.fromList([0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x01, 0x02, 0x03]);
    hop0.addBuiltFrame(
      PcapFrameFactory.ethernetUdp(
        srcIp: '10.10.1.20',
        dstIp: '10.10.1.30',
        srcPort: 14336,
        dstPort: 14336,
        dscp: 46,
        payload: dantePayload,
      ),
      timestampUs: danteTs,
    );
    hop1.addBuiltFrame(
      PcapFrameFactory.ethernetUdp(
        srcIp: '10.10.1.20',
        dstIp: '10.10.1.30',
        srcPort: 14336,
        dstPort: 14336,
        dscp: includeDscpMutation ? 0 : 46,
        payload: dantePayload,
      ),
      timestampUs: danteTs + clockSkewHop1Us + 150,
    );
    hop2.addBuiltFrame(
      PcapFrameFactory.ethernetUdp(
        srcIp: '10.10.1.20',
        dstIp: '10.10.1.30',
        srcPort: 14336,
        dstPort: 14336,
        dscp: includeDscpMutation ? 0 : 46,
        payload: dantePayload,
      ),
      timestampUs: danteTs + clockSkewHop2Us + 300,
    );

    // VLAN-tagged control packet (VLAN 100 -> 200 at Hop 2)
    final vlanTs = baseTs + 95000;
    final vlanPayload = Uint8List.fromList([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    hop0.addBuiltFrame(
      PcapFrameFactory.ethernetUdp(
        srcIp: '10.10.1.40',
        dstIp: '10.10.1.41',
        srcPort: 5001,
        dstPort: 5002,
        vlanId: 100,
        payload: vlanPayload,
      ),
      timestampUs: vlanTs,
    );
    hop1.addBuiltFrame(
      PcapFrameFactory.ethernetUdp(
        srcIp: '10.10.1.40',
        dstIp: '10.10.1.41',
        srcPort: 5001,
        dstPort: 5002,
        vlanId: 100,
        payload: vlanPayload,
      ),
      timestampUs: vlanTs + clockSkewHop1Us + 150,
    );
    hop2.addBuiltFrame(
      PcapFrameFactory.ethernetUdp(
        srcIp: '10.10.1.40',
        dstIp: '10.10.1.41',
        srcPort: 5001,
        dstPort: 5002,
        vlanId: includeVlanMutation ? 200 : 100,
        payload: vlanPayload,
      ),
      timestampUs: vlanTs + clockSkewHop2Us + 300,
    );

    final bytesList = [hop0.buildBytes(), hop1.buildBytes(), hop2.buildBytes()];
    final labels = ['A: Console Port', 'B: FOH Switch', 'C: Dimmer Rack'];
    final filenames = ['hop0_console.pcap', 'hop1_switch.pcap', 'hop2_rack.pcap'];
    final files = <File>[];
    final inputs = <CaptureSourceInput>[];

    for (int i = 0; i < 3; i++) {
      String path = filenames[i];
      if (tempDir != null) {
        final f = writeTempCaptureFile(tempDir, filenames[i], bytesList[i]);
        files.add(f);
        path = f.path;
      }
      inputs.add(
        CaptureSourceInput(
          label: labels[i],
          filePath: path,
          bytes: tempDir == null ? bytesList[i] : null,
        ),
      );
    }

    return BuiltDiffFixture(
      inputs: inputs,
      hopBytes: bytesList,
      files: files,
    );
  }
}
