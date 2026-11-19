import '../../../domain/models/packet_diff_record.dart';
import '../../../domain/models/packet_record.dart';
import '../../repositories/packet_repository.dart';
import '../diff/multi_capture_diff_engine.dart';
import 'ai_filter_references.dart';

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

  AiToolResult getCaptureSummary() {
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

  AiToolResult generateFilteredReport({
    required AiFilterReferences refs,
  }) {
    final protocolPills = refs.allProtocolNames;
    final senderFilters = refs.allSenderKeys;
    final receiverFilters = refs.allReceiverKeys;

    final matchingPacketCount = repository.getPacketCount(
      protocolPills: protocolPills,
      senderFilters: senderFilters,
      receiverFilters: receiverFilters,
      silenceLanChatter: false,
    );

    final totalCaptureCount = repository.getPacketCount(silenceLanChatter: false);
    final percentage = totalCaptureCount > 0
        ? (matchingPacketCount / totalCaptureCount * 100).toStringAsFixed(1)
        : '0.0';

    // Sample matching packets (up to 100)
    final samplePackets = repository.queryPackets(
      limit: 100,
      protocolPills: protocolPills,
      senderFilters: senderFilters,
      receiverFilters: receiverFilters,
      silenceLanChatter: false,
    );

    int totalBytes = 0;
    for (final p in samplePackets) {
      totalBytes += p.originalLength;
    }

    final double startSec = samplePackets.isNotEmpty ? samplePackets.first.timestampSeconds : 0.0;
    final double endSec = samplePackets.isNotEmpty ? samplePackets.last.timestampSeconds : 0.0;
    final double timeSpan = (endSec - startSec).abs();

    final sb = StringBuffer();
    sb.writeln('### 📊 Filtered Traffic Analysis');
    sb.writeln(refs.buildLibraryContextSummary());
    sb.writeln();
    sb.writeln('**Capture Traffic Findings:**');
    sb.writeln('• Matching Packets: $matchingPacketCount ($percentage% of capture)');
    if (samplePackets.isNotEmpty) {
      final avgLen = (totalBytes / samplePackets.length).round();
      sb.writeln('• Sample Volume (${samplePackets.length} pkts): ${(totalBytes / 1024).toStringAsFixed(2)} KB (avg $avgLen bytes/pkt)');
      sb.writeln('• Active Time Span: ${startSec.toStringAsFixed(3)}s → ${endSec.toStringAsFixed(3)}s (${timeSpan.toStringAsFixed(3)}s)');
    } else {
      sb.writeln('• No packets currently match this exact combination in the active capture.');
    }

    return AiToolResult(
      toolName: 'generate_filtered_report',
      summaryText: sb.toString().trim(),
      widgetType: 'filtered_library_report',
      data: {
        'matchingPacketCount': matchingPacketCount,
        'totalCaptureCount': totalCaptureCount,
        'percentage': percentage,
        'totalBytes': totalBytes,
        'timeSpan': timeSpan,
        'protocols': protocolPills.toList(),
        'senders': senderFilters.toList(),
        'receivers': receiverFilters.toList(),
        'matchedProtocolSpecs': refs.matchedProtocolRules.map((r) => r.toJson()).toList(),
        'matchedSenderSpecs': refs.matchedSenders.map((s) => s.toMap()).toList(),
        'matchedReceiverSpecs': refs.matchedReceivers.map((r) => r.toMap()).toList(),
        'samplePackets': samplePackets.take(5).map((p) => {
          'packetNo': p.packetNo,
          'timestampSeconds': p.timestampSeconds,
          'srcIp': p.srcIp,
          'dstIp': p.dstIp,
          'srcPort': p.srcPort,
          'dstPort': p.dstPort,
          'protocol': p.detectedProtocol,
          'summary': p.summary,
        }).toList(),
      },
    );
  }

  /// Deterministic GenUI tool summarizing multi-capture hop-by-hop loss,
  /// clock skew, QoS/VLAN mutations, and providing a "Jump to First Drop" target.
  AiToolResult compareCapturesSummary(MultiCaptureDiffEngine diffEngine) {
    final slots = diffEngine.slots;
    if (slots.length < 2) {
      return const AiToolResult(
        toolName: 'compare_captures_summary',
        summaryText: 'No active multi-capture comparison loaded. Use "Compare PCAPs" to load 2–4 captures.',
        widgetType: 'compare_summary_card',
        data: {'hasComparison': false},
      );
    }

    var records = diffEngine.queryDiffRecords(filterMode: DiffFilterMode.sharedFlowsOnly);
    if (records.isEmpty && slots.first.packetCount > 0) {
      records = diffEngine
          .queryDiffRecords(filterMode: DiffFilterMode.fullDiff)
          .where((r) => r.primaryStatus != DiffStatus.injected)
          .toList();
    }
    final totalShared = records.length;
    final droppedRecords = records.where((r) => r.statuses.contains(DiffStatus.dropped)).toList();
    final sourceGapCount = records.where((r) => r.statuses.contains(DiffStatus.sourceGap)).length;
    final outOfOrderCount = records.where((r) => r.statuses.contains(DiffStatus.outOfOrder)).length;
    final mutatedCount = records.where((r) => r.statuses.contains(DiffStatus.qosVlanMutated)).length;
    final spikeCount = records.where((r) => r.statuses.contains(DiffStatus.latencySpike)).length;

    final sb = StringBuffer();
    sb.writeln('Multi-Capture Path Comparison Summary:');
    sb.writeln('• Correlated Shared-Flow Packets: $totalShared');
    for (int i = 1; i < slots.length; i++) {
      final slot = slots[i];
      final delivered = records.where((r) => r.hopMatches.containsKey(i)).length;
      final pct = totalShared > 0 ? ((delivered / totalShared) * 100).toStringAsFixed(1) : '0.0';
      sb.writeln('• Hop $i (${slot.label}): $delivered/$totalShared ($pct%) • Skew: ${slot.formattedClockOffset}');
    }
    sb.writeln(
      '• Faults: ${droppedRecords.length} Dropped | $sourceGapCount Source Gaps | '
      '$outOfOrderCount Out-of-Order | $mutatedCount QoS/VLAN Mutated | $spikeCount Latency Spikes',
    );

    final firstDropRow = droppedRecords.isNotEmpty ? droppedRecords.first : null;
    if (firstDropRow != null) {
      sb.writeln(
        '• First Drop: Baseline Frame #${firstDropRow.baselineFrameNumber} '
        '(${firstDropRow.protocolName} ${firstDropRow.flowDisplay}) — ${firstDropRow.statusDetail}',
      );
    }

    return AiToolResult(
      toolName: 'compare_captures_summary',
      summaryText: sb.toString().trim(),
      widgetType: 'compare_summary_card',
      data: {
        'hasComparison': true,
        'totalShared': totalShared,
        'droppedCount': droppedRecords.length,
        'sourceGapCount': sourceGapCount,
        'outOfOrderCount': outOfOrderCount,
        'mutatedCount': mutatedCount,
        'spikeCount': spikeCount,
        'firstDropRowIndex': firstDropRow?.rowIndex,
        'firstDropFrameNumber': firstDropRow?.baselineFrameNumber,
      },
    );
  }
}
