import 'dart:typed_data';

class DemoPcapGenerator {
  /// Generates a valid classic microsecond PCAP byte buffer with diverse realistic traffic.
  static Uint8List generateClassicPcap() {
    final builder = BytesBuilder();

    // 24-byte PCAP Global Header (Little Endian)
    // Magic bytes for Little Endian microsecond PCAP: [0xD4, 0xC3, 0xB2, 0xA1]
    final globalHeader = ByteData(24);
    globalHeader.setUint8(0, 0xD4);
    globalHeader.setUint8(1, 0xC3);
    globalHeader.setUint8(2, 0xB2);
    globalHeader.setUint8(3, 0xA1);
    globalHeader.setUint16(4, 2, Endian.little); // Version Major = 2
    globalHeader.setUint16(6, 4, Endian.little); // Version Minor = 4
    globalHeader.setInt32(8, 0, Endian.little); // ThisZone = 0
    globalHeader.setUint32(12, 0, Endian.little); // SigFigs = 0
    globalHeader.setUint32(16, 65535, Endian.little); // SnapLen = 65535
    globalHeader.setUint32(20, 1, Endian.little); // LinkType = 1 (Ethernet)
    builder.add(globalHeader.buffer.asUint8List());

    int currentTimestampUs = 1700000000 * 1000000; // Fixed epoch time ~Nov 2023

    void addPacket(Uint8List frameBytes, int advanceDeltaUs) {
      currentTimestampUs += advanceDeltaUs;
      final tsSec = currentTimestampUs ~/ 1000000;
      final tsUsec = currentTimestampUs % 1000000;

      final packetHeader = ByteData(16);
      packetHeader.setUint32(0, tsSec, Endian.little);
      packetHeader.setUint32(4, tsUsec, Endian.little);
      packetHeader.setUint32(8, frameBytes.length, Endian.little);
      packetHeader.setUint32(12, frameBytes.length, Endian.little);

      builder.add(packetHeader.buffer.asUint8List());
      builder.add(frameBytes);
    }

    // 1. ARP Request (LAN noise)
    addPacket(_buildArpPacket('192.168.1.50', '192.168.1.1', opcode: 1), 0);

    // 2. ARP Reply (LAN noise)
    addPacket(_buildArpPacket('192.168.1.1', '192.168.1.50', opcode: 2), 1500);

    // 3. DNS Query: 192.168.1.10 -> 8.8.8.8
    addPacket(
      _buildUdpPacket(
        srcIp: '192.168.1.10',
        dstIp: '8.8.8.8',
        srcPort: 54321,
        dstPort: 53,
        payload: Uint8List.fromList([
          0x12, 0x34, // Transaction ID
          0x01, 0x00, // Standard query
          0x00, 0x01, // Questions: 1
          0x00, 0x00, // Answer RRs: 0
          0x00, 0x00, 0x00, 0x00,
          0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // example
          0x03, 0x63, 0x6f, 0x6d, 0x00, // com
          0x00, 0x01, 0x00, 0x01, // Type A, Class IN
        ]),
      ),
      12000,
    );

    // 4. DNS Response: 8.8.8.8 -> 192.168.1.10
    addPacket(
      _buildUdpPacket(
        srcIp: '8.8.8.8',
        dstIp: '192.168.1.10',
        srcPort: 53,
        dstPort: 54321,
        payload: Uint8List.fromList([
          0x12, 0x34,
          0x81, 0x80, // Response
          0x00, 0x01, // Questions: 1
          0x00, 0x01, // Answers: 1
          0x00, 0x00, 0x00, 0x00,
          0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
          0x03, 0x63, 0x6f, 0x6d, 0x00,
          0x00, 0x01, 0x00, 0x01,
          0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04,
          93, 184, 216, 34, // 93.184.216.34
        ]),
      ),
      15000,
    );

    // 5. HTTP GET: 192.168.1.10:49152 -> 93.184.216.34:80
    addPacket(
      _buildTcpPacket(
        srcIp: '192.168.1.10',
        dstIp: '93.184.216.34',
        srcPort: 49152,
        dstPort: 80,
        seqNum: 1001,
        ackNum: 1,
        flags: 0x18, // PSH, ACK
        payload: Uint8List.fromList('GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'.codeUnits),
      ),
      35000,
    );

    // 6. HTTP 200 OK Response: 93.184.216.34:80 -> 192.168.1.10:49152
    addPacket(
      _buildTcpPacket(
        srcIp: '93.184.216.34',
        dstIp: '192.168.1.10',
        srcPort: 80,
        dstPort: 49152,
        seqNum: 1,
        ackNum: 1045,
        flags: 0x18, // PSH, ACK
        payload: Uint8List.fromList('HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!'.codeUnits),
      ),
      40000,
    );

    // 7. mDNS Broadcast (LAN noise)
    addPacket(
      _buildUdpPacket(
        srcIp: '192.168.1.10',
        dstIp: '224.0.0.251',
        srcPort: 5353,
        dstPort: 5353,
        payload: Uint8List.fromList([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]),
      ),
      80000,
    );

    // 8. SSDP Discover (LAN noise)
    addPacket(
      _buildUdpPacket(
        srcIp: '192.168.1.10',
        dstIp: '239.255.255.250',
        srcPort: 50123,
        dstPort: 1900,
        payload: Uint8List.fromList('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n\r\n'.codeUnits),
      ),
      120000,
    );

    // 9. Traffic Burst Spike from Unexpected IP 10.99.88.77 (10 packets with 40us delta)
    for (int i = 0; i < 10; i++) {
      addPacket(
        _buildTcpPacket(
          srcIp: '10.99.88.77',
          dstIp: '192.168.1.10',
          srcPort: 40000 + i,
          dstPort: 445,
          seqNum: 100 + i * 50,
          ackNum: 0,
          flags: 0x02, // SYN
          payload: Uint8List(0),
        ),
        40, // 40 microseconds -> Micro-burst spike!
      );
    }

    // 10. Stream Latency Stall: Normal TCP conversation experiences a 450ms (450,000us) delay
    addPacket(
      _buildTcpPacket(
        srcIp: '192.168.1.10',
        dstIp: '93.184.216.34',
        srcPort: 49152,
        dstPort: 80,
        seqNum: 1045,
        ackNum: 60,
        flags: 0x10, // ACK
        payload: Uint8List(0),
      ),
      450000, // 450 ms stall!
    );

    // 11. Unknown Custom Protocol: ACME Sensor Telemetry on UDP 45820
    // Starts with Magic Bytes 'A','C','M','E' (0x41, 0x43, 0x4D, 0x45)
    // Offset 4: Command ID = 101 (UInt16 BE: 0x00, 0x65)
    // Offset 6: Device Serial = 883719 (UInt32 BE: 0x00, 0x0D, 0x7C, 0x07)
    // Offset 10: Status Code = 1 (UInt8: 0x01)
    // Offset 11: Tag = "PROD" (ASCII: 0x50, 0x52, 0x4F, 0x44)
    final acmePayload = ByteData(16);
    acmePayload.setUint8(0, 0x41); // A
    acmePayload.setUint8(1, 0x43); // C
    acmePayload.setUint8(2, 0x4D); // M
    acmePayload.setUint8(3, 0x45); // E
    acmePayload.setUint16(4, 101, Endian.big); // Command ID = 101
    acmePayload.setUint32(6, 883719, Endian.big); // Serial = 883719
    acmePayload.setUint8(10, 1); // Status = 1
    acmePayload.setUint8(11, 0x50); // P
    acmePayload.setUint8(12, 0x52); // R
    acmePayload.setUint8(13, 0x4F); // O
    acmePayload.setUint8(14, 0x44); // D
    acmePayload.setUint8(15, 0x00);

    addPacket(
      _buildUdpPacket(
        srcIp: '192.168.1.10',
        dstIp: '192.168.1.200',
        srcPort: 45820,
        dstPort: 45820,
        payload: acmePayload.buffer.asUint8List(),
      ),
      60000,
    );

    return builder.toBytes();
  }

  /// Generates a valid PCAPNG byte buffer with an SHB, IDB, and EPBs.
  static Uint8List generatePcapNg() {
    final builder = BytesBuilder();

    // 1. Section Header Block (SHB)
    final shb = ByteData(28);
    shb.setUint32(0, 0x0A0D0D0A, Endian.little); // Type: SHB
    shb.setUint32(4, 28, Endian.little); // Block Total Length
    shb.setUint32(8, 0x1A2B3C4D, Endian.little); // Byte-Order Magic
    shb.setUint16(12, 1, Endian.little); // Major 1
    shb.setUint16(14, 0, Endian.little); // Minor 0
    shb.setInt64(16, -1, Endian.little); // Section Length = -1 (unspecified)
    shb.setUint32(24, 28, Endian.little); // Block Total Length
    builder.add(shb.buffer.asUint8List());

    // 2. Interface Description Block (IDB)
    final idb = ByteData(20);
    idb.setUint32(0, 0x00000001, Endian.little); // Type: IDB
    idb.setUint32(4, 20, Endian.little); // Block Total Length
    idb.setUint16(8, 1, Endian.little); // LinkType: Ethernet (1)
    idb.setUint16(10, 0, Endian.little); // Reserved
    idb.setUint32(12, 65535, Endian.little); // SnapLen
    idb.setUint32(16, 20, Endian.little); // Block Total Length
    builder.add(idb.buffer.asUint8List());

    // 3. Enhanced Packet Block (EPB)
    final dnsPacket = _buildUdpPacket(
      srcIp: '192.168.1.10',
      dstIp: '8.8.8.8',
      srcPort: 54321,
      dstPort: 53,
      payload: Uint8List.fromList([0x12, 0x34, 0x01, 0x00, 0x00, 0x01]),
    );

    final paddedCapLen = (dnsPacket.length + 3) & ~3;
    final epbTotalLen = 32 + paddedCapLen;
    final epb = ByteData(epbTotalLen);

    epb.setUint32(0, 0x00000006, Endian.little); // Type: EPB
    epb.setUint32(4, epbTotalLen, Endian.little); // Total length
    epb.setUint32(8, 0, Endian.little); // Interface ID
    epb.setUint32(12, 0, Endian.little); // Timestamp High
    epb.setUint32(16, 1700000000, Endian.little); // Timestamp Low (us)
    epb.setUint32(20, dnsPacket.length, Endian.little); // Captured Length
    epb.setUint32(24, dnsPacket.length, Endian.little); // Original Length

    for (int i = 0; i < dnsPacket.length; i++) {
      epb.setUint8(28 + i, dnsPacket[i]);
    }
    epb.setUint32(epbTotalLen - 4, epbTotalLen, Endian.little); // Trailing Total length
    builder.add(epb.buffer.asUint8List());

    return builder.toBytes();
  }

  // --- Helpers to build Ethernet + IP frames ---

  static Uint8List _buildArpPacket(String senderIp, String targetIp, {required int opcode}) {
    final frame = Uint8List(14 + 28);
    // Ethernet Header (14 bytes)
    // Dst MAC: FF:FF:FF:FF:FF:FF
    for (int i = 0; i < 6; i++) {
      frame[i] = 0xFF;
    }
    // Src MAC: 00:11:22:33:44:55
    frame[6] = 0x00; frame[7] = 0x11; frame[8] = 0x22;
    frame[9] = 0x33; frame[10] = 0x44; frame[11] = 0x55;
    // EthType: 0x0806 (ARP)
    frame[12] = 0x08; frame[13] = 0x06;

    // ARP Payload (28 bytes)
    final bd = ByteData.sublistView(frame, 14, 14 + 28);
    bd.setUint16(0, 1, Endian.big); // HW type: Ethernet
    bd.setUint16(2, 0x0800, Endian.big); // Proto type: IPv4
    bd.setUint8(4, 6); // HW size: 6
    bd.setUint8(5, 4); // Proto size: 4
    bd.setUint16(6, opcode, Endian.big);

    // Sender MAC
    frame[22] = 0x00; frame[23] = 0x11; frame[24] = 0x22;
    frame[25] = 0x33; frame[26] = 0x44; frame[27] = 0x55;
    // Sender IP
    final sParts = senderIp.split('.').map(int.parse).toList();
    for (int i = 0; i < 4; i++) {
      frame[28 + i] = sParts[i];
    }

    // Target MAC
    for (int i = 0; i < 6; i++) {
      frame[32 + i] = (opcode == 1) ? 0x00 : 0xFF;
    }
    // Target IP
    final tParts = targetIp.split('.').map(int.parse).toList();
    for (int i = 0; i < 4; i++) {
      frame[38 + i] = tParts[i];
    }

    return frame;
  }

  static Uint8List _buildUdpPacket({
    required String srcIp,
    required String dstIp,
    required int srcPort,
    required int dstPort,
    required Uint8List payload,
  }) {
    final udpLen = 8 + payload.length;
    final ipTotalLen = 20 + udpLen;
    final frame = Uint8List(14 + ipTotalLen);

    // Ethernet (14 bytes)
    _writeEthernetHeader(frame, 0x0800);

    // IPv4 Header (20 bytes)
    _writeIpv4Header(frame, 14, ipTotalLen, 17, srcIp, dstIp);

    // UDP Header (8 bytes)
    final udpOffset = 14 + 20;
    final bd = ByteData.sublistView(frame, udpOffset, udpOffset + 8);
    bd.setUint16(0, srcPort, Endian.big);
    bd.setUint16(2, dstPort, Endian.big);
    bd.setUint16(4, udpLen, Endian.big);
    bd.setUint16(6, 0, Endian.big); // Checksum 0 for mock

    // Payload
    frame.setRange(udpOffset + 8, udpOffset + 8 + payload.length, payload);
    return frame;
  }

  static Uint8List _buildTcpPacket({
    required String srcIp,
    required String dstIp,
    required int srcPort,
    required int dstPort,
    required int seqNum,
    required int ackNum,
    required int flags,
    required Uint8List payload,
  }) {
    const tcpHeaderLen = 20;
    final ipTotalLen = 20 + tcpHeaderLen + payload.length;
    final frame = Uint8List(14 + ipTotalLen);

    // Ethernet
    _writeEthernetHeader(frame, 0x0800);

    // IPv4 Header
    _writeIpv4Header(frame, 14, ipTotalLen, 6, srcIp, dstIp);

    // TCP Header (20 bytes)
    final tcpOffset = 14 + 20;
    final bd = ByteData.sublistView(frame, tcpOffset, tcpOffset + 20);
    bd.setUint16(0, srcPort, Endian.big);
    bd.setUint16(2, dstPort, Endian.big);
    bd.setUint32(4, seqNum, Endian.big);
    bd.setUint32(8, ackNum, Endian.big);
    bd.setUint8(12, (5 << 4)); // Data offset = 5 words (20 bytes)
    bd.setUint8(13, flags);
    bd.setUint16(14, 64240, Endian.big); // Window size
    bd.setUint16(16, 0, Endian.big); // Checksum
    bd.setUint16(18, 0, Endian.big); // Urgent pointer

    // Payload
    if (payload.isNotEmpty) {
      frame.setRange(tcpOffset + 20, tcpOffset + 20 + payload.length, payload);
    }
    return frame;
  }

  static void _writeEthernetHeader(Uint8List frame, int ethType) {
    for (int i = 0; i < 6; i++) {
      frame[i] = 0xAA;
    }
    for (int i = 6; i < 12; i++) {
      frame[i] = 0xBB;
    }
    frame[12] = (ethType >> 8) & 0xFF;
    frame[13] = ethType & 0xFF;
  }

  static void _writeIpv4Header(
    Uint8List frame,
    int offset,
    int totalLength,
    int protocol,
    String srcIp,
    String dstIp,
  ) {
    final bd = ByteData.sublistView(frame, offset, offset + 20);
    bd.setUint8(0, 0x45); // IPv4, IHL=5 (20 bytes)
    bd.setUint8(1, 0x00); // DSCP/ECN
    bd.setUint16(2, totalLength, Endian.big);
    bd.setUint16(4, 0x1234, Endian.big); // ID
    bd.setUint16(6, 0x4000, Endian.big); // Don't fragment
    bd.setUint8(8, 64); // TTL
    bd.setUint8(9, protocol);
    bd.setUint16(10, 0, Endian.big); // Checksum (0 for mock)

    final sParts = srcIp.split('.').map(int.parse).toList();
    for (int i = 0; i < 4; i++) {
      frame[offset + 12 + i] = sParts[i];
    }

    final dParts = dstIp.split('.').map(int.parse).toList();
    for (int i = 0; i < 4; i++) {
      frame[offset + 16 + i] = dParts[i];
    }
  }
}
