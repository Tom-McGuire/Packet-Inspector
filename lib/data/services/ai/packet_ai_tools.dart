import '../../../domain/models/packet_record.dart';
import '../../repositories/packet_repository.dart';

class AiToolResult {
  const AiToolResult({
    required this.toolName,
    required this.summaryText,
    required this.data,
    this.widgetType,
  });

  final String toolName;
  final String summaryText;
  final Map<String, dynamic> data;
  final String? widgetType; // 'summary_card', 'top_talkers_chart', 'timing_spikes_table', 'custom_protocol_suggestion'
}

class PacketAiTools {
  PacketAiTools({required this.repository});

  final PacketRepository repository;

  AiToolResult getCaptureSummary({bool onlyUnexpected = false}) {
    final protocolCounts = repository.getProtocolCounts();
    final triageCounts = repository.getTriageCounts(silenceLanChatter: false);
    final totalPackets = repository.getPacketCount(silenceLanChatter: false);

    final unexpectedCount = triageCounts[TriageStatus.unexpected] ?? 0;
    final expectedCount = triageCounts[TriageStatus.expected] ?? 0;
    final unclassifiedCount = triageCounts[TriageStatus.unclassified] ?? 0;

    final summaryText = 'Capture Overview:\n'
        '• Total Packets: $totalPackets\n'
        '• Expected: $expectedCount | Unclassified: $unclassifiedCount | Unexpected: $unexpectedCount\n'
        '• Top Protocols: ${protocolCounts.entries.take(4).map((e) => '${e.key} (${e.value})').join(', ')}';

    return AiToolResult(
      toolName: 'get_capture_summary',
      summaryText: summaryText,
      widgetType: 'summary_card',
      data: {
        'totalPackets': totalPackets,
        'expectedCount': expectedCount,
        'unclassifiedCount': unclassifiedCount,
        'unexpectedCount': unexpectedCount,
        'protocols': protocolCounts,
      },
    );
  }

  AiToolResult getTopTalkers({
    String metric = 'bytes',
    int limit = 5,
    bool onlyUnexpected = false,
  }) {
    final talkers = repository.getTopTalkers(
      metric: metric,
      limit: limit,
      onlyUnexpected: onlyUnexpected,
    );

    final summaryText = 'Top $limit Talkers by ${metric.toUpperCase()}${onlyUnexpected ? ' (Unexpected only)' : ''}:\n${talkers.map((t) => '• ${t['src_ip']} → ${t['dst_ip']} (${t['protocol']}): '
            '${t['packet_count']} pkts, ${t['total_bytes']} bytes').join('\n')}';

    return AiToolResult(
      toolName: 'get_top_talkers',
      summaryText: summaryText,
      widgetType: 'top_talkers_chart',
      data: {
        'metric': metric,
        'talkers': talkers,
      },
    );
  }

  AiToolResult findTimingAnomalies({
    bool isBurst = true,
    int? thresholdUs,
    int limit = 10,
  }) {
    final actualThreshold = thresholdUs ?? (isBurst ? 100 : 50000); // 100us for bursts, 50ms for stalls
    final anomalies = repository.getTimingAnomalies(
      isBurst: isBurst,
      thresholdUs: actualThreshold,
      limit: limit,
    );

    final typeLabel = isBurst ? 'Micro-Bursts (Traffic Spikes)' : 'Stream Latency Stalls';
    final summaryText = anomalies.isEmpty
        ? 'No $typeLabel found beyond threshold ($actualThreshold µs).'
        : 'Found ${anomalies.length} $typeLabel:\n${anomalies.take(5).map((p) => '• Packet #${p.packetNo}: ${p.srcIp} → ${p.dstIp} (${p.detectedProtocol}), '
                '${isBurst ? 'Global Δt=${p.globalDeltaMs}ms' : 'Stream Δt=${p.streamDeltaMs}ms'} at ${p.timestampSeconds.toStringAsFixed(3)}s').join('\n')}';

    return AiToolResult(
      toolName: 'find_timing_anomalies',
      summaryText: summaryText,
      widgetType: 'timing_spikes_table',
      data: {
        'isBurst': isBurst,
        'thresholdUs': actualThreshold,
        'spikes': anomalies.map((p) => {
          'packetNo': p.packetNo,
          'timestampUs': p.timestampUs,
          'timestampSeconds': p.timestampSeconds,
          'srcIp': p.srcIp,
          'dstIp': p.dstIp,
          'protocol': p.detectedProtocol,
          'deltaMs': isBurst ? p.globalDeltaMs : p.streamDeltaMs,
          'summary': p.summary,
        }).toList(),
      },
    );
  }

  AiToolResult suggestCustomProtocolSignature({
    required int port,
    int ipProto = 17, // default UDP
  }) {
    final packets = repository.queryPackets(
      limit: 20,
      isTriageMode: false,
    ).where((p) => (p.srcPort == port || p.dstPort == port) && p.ipProto == ipProto).toList();

    if (packets.isEmpty) {
      return AiToolResult(
        toolName: 'suggest_custom_protocol_signature',
        summaryText: 'No packets found for Port $port (IP Proto $ipProto).',
        data: {'port': port, 'found': false},
      );
    }

    // Compare preview payloads across sample packets to find common magic prefix
    final firstPreview = packets.first.payloadPreview;
    int commonPrefixLen = 0;
    if (firstPreview.isNotEmpty) {
      for (int i = 0; i < firstPreview.length; i++) {
        final b = firstPreview[i];
        bool allMatch = true;
        for (final p in packets) {
          if (p.payloadPreview.length <= i || p.payloadPreview[i] != b) {
            allMatch = false;
            break;
          }
        }
        if (allMatch) {
          commonPrefixLen = i + 1;
        } else {
          break;
        }
      }
    }

    final capLen = (packets.length == 1 && commonPrefixLen > 4) ? 4 : commonPrefixLen;
    final magicSlice = (capLen > 0) ? firstPreview.sublist(0, capLen) : <int>[];
    final magicHex = magicSlice.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ');
    final asciiCandidate = String.fromCharCodes(magicSlice.where((b) => b >= 32 && b <= 126));

    final suggestedName = asciiCandidate.length >= 2 ? asciiCandidate : 'Custom_Port_$port';

    final summaryText = 'Analyzed ${packets.length} packets on Port $port:\n'
        '• Suggested Protocol: "$suggestedName"\n'
        '• Invariant Magic Bytes (${magicSlice.length} bytes at Offset 0): $magicHex'
        '${asciiCandidate.isNotEmpty ? ' ("$asciiCandidate")' : ''}';

    return AiToolResult(
      toolName: 'suggest_custom_protocol_signature',
      summaryText: summaryText,
      widgetType: 'custom_protocol_suggestion',
      data: {
        'port': port,
        'ipProto': ipProto,
        'suggestedName': suggestedName,
        'magicBytesHex': magicHex,
        'magicBytesList': magicSlice,
        'sampleCount': packets.length,
      },
    );
  }
}
