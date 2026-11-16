import 'dart:typed_data';
import '../parser/pcap_binary_reader.dart';
import 'multi_capture_diff_engine.dart';

/// Generates synthetic multi-hop PCAP captures (Console -> FOH Switch -> Dimmer Rack)
/// demonstrating drops, out-of-order arrival, QoS DSCP stripping, and latency spikes.
class DemoDiffGenerator {
  static List<CaptureSourceInput> buildDemoCaptures() {
    const baseTimeUs = 1794000000000000;
    const fohClockOffsetUs = 42350; // +42.35 ms unsynced laptop clock
    const dimmerClockOffsetUs = -18700; // -18.70 ms unsynced laptop clock

    final consolePackets = <RawCapturedPacket>[];
    final fohPackets = <RawCapturedPacket>[];
    final dimmerPackets = <RawCapturedPacket>[];

    RawCapturedPacket makePacket(int packetNo, int timestampUs, Uint8List data) {
      return RawCapturedPacket(
        packetNo: packetNo,
        timestampUs: timestampUs,
        capturedLength: data.length,
        originalLength: data.length,
        linkType: 1,
        fileByteOffset: 0,
        data: data,
      );
    }

    // Add unrelated background ARP/mDNS noise in FOH Switch (Capture 1)
    for (int i = 0; i < 6; i++) {
      fohPackets.add(makePacket(
        fohPackets.length + 1,
        baseTimeUs + fohClockOffsetUs + i * 12000,
        _buildArpPacket('10.101.99.${10 + i}', '10.101.99.1'),
      ));
    }

    // Generate 40 sACN packets (Universe 1) + 20 Dante Audio packets (EF DSCP 46)
    RawCapturedPacket? bufferedOutOfOrderPacket;

    for (int seq = 1; seq <= 40; seq++) {
      final ts = baseTimeUs + seq * 22700; // ~44 Hz sACN
      final sacnFrame = _buildSacnUdpPacket(
        srcIp: '10.101.1.10',
        dstIp: '239.255.0.1',
        seq: seq,
        dscp: 34, // AF41
        universe: 1,
        identicalBlackout: seq <= 15, // Identical payload frames to exercise occurrence_index
      );

      consolePackets.add(makePacket(
        consolePackets.length + 1,
        ts,
        sacnFrame,
      ));

      // Simulate packet #18 dropped between Console and FOH Switch
      if (seq != 18) {
        final fohLatency = (seq == 28) ? 8400 : 350; // 8.4 ms spike on seq 28
        fohPackets.add(makePacket(
          fohPackets.length + 1,
          ts + fohClockOffsetUs + fohLatency,
          Uint8List.fromList(sacnFrame),
        ));
      }

      // Simulate packet #18 and #25 dropped at Dimmer Rack
      // and seq #32/#33 arriving out-of-order at Dimmer Rack
      if (seq != 18 && seq != 25) {
        final dimmerLatency = (seq == 28) ? 14200 : 620;
        final dimmerData = Uint8List.fromList(sacnFrame);

        if (seq == 32) {
          bufferedOutOfOrderPacket = makePacket(
            0, // packetNo assigned when appended
            ts + dimmerClockOffsetUs + dimmerLatency,
            dimmerData,
          );
        } else if (seq == 33) {
          dimmerPackets.add(makePacket(
            dimmerPackets.length + 1,
            ts + dimmerClockOffsetUs + dimmerLatency,
            dimmerData,
          ));
          if (bufferedOutOfOrderPacket != null) {
            dimmerPackets.add(makePacket(
              dimmerPackets.length + 1,
              bufferedOutOfOrderPacket.timestampUs,
              bufferedOutOfOrderPacket.data,
            ));
            bufferedOutOfOrderPacket = null;
          }
        } else {
          dimmerPackets.add(makePacket(
            dimmerPackets.length + 1,
            ts + dimmerClockOffsetUs + dimmerLatency,
            dimmerData,
          ));
        }
      }

      // Interleave Dante packets every 2nd frame with DSCP EF (46) stripped to CS0 (0) at FOH
      if (seq % 2 == 0) {
        final danteSeq = seq ~/ 2;
        final danteFrameSrc = _buildUdpPacket(
          srcIp: '10.101.2.5',
          dstIp: '239.69.1.1',
          srcPort: 5004,
          dstPort: 5004,
          dscp: 46, // EF
          payload: _buildDanteRtpPayload(danteSeq),
        );
        final danteFrameStripped = _buildUdpPacket(
          srcIp: '10.101.2.5',
          dstIp: '239.69.1.1',
          srcPort: 5004,
          dstPort: 5004,
          dscp: 0, // CS0 stripped by switch
          payload: _buildDanteRtpPayload(danteSeq),
        );

        consolePackets.add(makePacket(
          consolePackets.length + 1,
          ts + 500,
          danteFrameSrc,
        ));

        // Strip DSCP on seq 12 and 24
        final fohDanteData = (seq == 12 || seq == 24) ? danteFrameStripped : danteFrameSrc;
        fohPackets.add(makePacket(
          fohPackets.length + 1,
          ts + 500 + fohClockOffsetUs + 280,
          fohDanteData,
        ));

        dimmerPackets.add(makePacket(
          dimmerPackets.length + 1,
          ts + 500 + dimmerClockOffsetUs + 490,
          Uint8List.fromList(fohDanteData),
        ));
      }
    }

    return [
      CaptureSourceInput(
        label: 'Console Port',
        filePath: 'demo://console_port.pcapng',
        rawPackets: consolePackets,
      ),
      CaptureSourceInput(
        label: 'FOH Switch Trunk',
        filePath: 'demo://foh_trunk.pcapng',
        rawPackets: fohPackets,
      ),
      CaptureSourceInput(
        label: 'Dimmer Rack Node',
        filePath: 'demo://dimmer_rack.pcapng',
        rawPackets: dimmerPackets,
      ),
    ];
  }

  static Uint8List _buildSacnUdpPacket({
    required String srcIp,
    required String dstIp,
    required int seq,
    required int dscp,
    required int universe,
    bool identicalBlackout = false,
  }) {
    final payload = Uint8List(126);
    // ACN Packet Identifier "ASC-E1.17\0\0\0" at offset 4..15
    const acnPid = [0x41, 0x53, 0x43, 0x2d, 0x45, 0x31, 0x2e, 0x31, 0x37, 0x00, 0x00, 0x00];
    for (int i = 0; i < acnPid.length; i++) {
      payload[4 + i] = acnPid[i];
    }
    payload[111] = seq & 0xFF;
    payload[113] = (universe >> 8) & 0xFF;
    payload[114] = universe & 0xFF;
    if (!identicalBlackout) {
      payload[125] = seq & 0xFF;
    }
    return _buildUdpPacket(
      srcIp: srcIp,
      dstIp: dstIp,
      srcPort: 5568,
      dstPort: 5568,
      dscp: dscp,
      payload: payload,
    );
  }

  static Uint8List _buildDanteRtpPayload(int seq) {
    final payload = Uint8List(32);
    payload[0] = 0x80; // RTP v2
    payload[1] = 0x60;
    payload[2] = (seq >> 8) & 0xFF;
    payload[3] = seq & 0xFF;
    return payload;
  }

  static Uint8List _buildUdpPacket({
    required String srcIp,
    required String dstIp,
    required int srcPort,
    required int dstPort,
    required int dscp,
    required Uint8List payload,
  }) {
    final udpLen = 8 + payload.length;
    final totalIpLen = 20 + udpLen;
    final frame = Uint8List(14 + totalIpLen);

    // Ethernet II header
    frame[12] = 0x08;
    frame[13] = 0x00;

    // IPv4 header
    const ip = 14;
    frame[ip] = 0x45;
    frame[ip + 1] = (dscp & 0x3F) << 2;
    frame[ip + 2] = (totalIpLen >> 8) & 0xFF;
    frame[ip + 3] = totalIpLen & 0xFF;
    frame[ip + 8] = 64; // TTL
    frame[ip + 9] = 17; // UDP

    final srcParts = srcIp.split('.').map(int.parse).toList();
    final dstParts = dstIp.split('.').map(int.parse).toList();
    for (int i = 0; i < 4; i++) {
      frame[ip + 12 + i] = srcParts[i];
      frame[ip + 16 + i] = dstParts[i];
    }

    // UDP header
    const udp = 34;
    frame[udp] = (srcPort >> 8) & 0xFF;
    frame[udp + 1] = srcPort & 0xFF;
    frame[udp + 2] = (dstPort >> 8) & 0xFF;
    frame[udp + 3] = dstPort & 0xFF;
    frame[udp + 4] = (udpLen >> 8) & 0xFF;
    frame[udp + 5] = udpLen & 0xFF;

    frame.setRange(42, 42 + payload.length, payload);
    return frame;
  }

  static Uint8List _buildArpPacket(String senderIp, String targetIp) {
    final frame = Uint8List(42);
    frame[12] = 0x08;
    frame[13] = 0x06;
    frame[20] = 0x00;
    frame[21] = 0x01; // Who has
    final s = senderIp.split('.').map(int.parse).toList();
    final t = targetIp.split('.').map(int.parse).toList();
    for (int i = 0; i < 4; i++) {
      frame[28 + i] = s[i];
      frame[38 + i] = t[i];
    }
    return frame;
  }
}
