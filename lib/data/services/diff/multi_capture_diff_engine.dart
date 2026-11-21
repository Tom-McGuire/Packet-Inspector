import 'dart:io';
import 'dart:typed_data';
import 'package:sqlite3/sqlite3.dart';
import '../../../domain/models/capture_slot.dart';
import '../../../domain/models/custom_protocol_rule.dart';
import '../../../domain/models/flow_diff_summary.dart';
import '../../../domain/models/packet_diff_record.dart';
import '../../database/diff_database_schema.dart';
import '../parser/packet_dissector.dart';
import 'package:network_suite_shared/network_suite_shared.dart';
import 'clock_skew_estimator.dart';

/// Input descriptor for loading a capture into the multi-capture diff engine.
class CaptureSourceInput {
  const CaptureSourceInput({
    required this.label,
    required this.filePath,
    this.bytes,
    this.rawPackets,
  });

  final String label;
  final String filePath;
  final Uint8List? bytes;
  final List<RawCapturedPacket>? rawPackets;
}

/// Correlates 2..N PCAP/PCAPNG captures in an isolated SQLite database,
/// performing fingerprint matching, clock skew calibration, noise filtering,
/// and hop-by-hop fault classification.
class MultiCaptureDiffEngine {
  MultiCaptureDiffEngine({Database? database})
      : _db = database ?? sqlite3.openInMemory() {
    DiffDatabaseSchema.initializeSchema(_db);
  }

  final Database _db;
  List<CaptureSlot> _slots = const [];
  List<PacketDiffRecord> _correlatedRecords = const [];
  List<PacketDiffRecord> _injectedRecords = const [];
  List<FlowDiffSummary> _flowSummaries = const [];
  Set<int> _sharedFlowHashes = const {};

  List<CaptureSlot> get slots => _slots;
  List<FlowDiffSummary> get flowSummaries => _flowSummaries;

  void dispose() {
    _db.close();
  }

  /// Ingests 2 or more captures, calibrates clock skew, and computes diff state.
  Future<void> ingestCaptures(
    List<CaptureSourceInput> inputs, {
    List<CustomProtocolRule> customRules = const [],
    int latencySpikeThresholdUs = 5000,
  }) async {
    if (inputs.length < 2) {
      throw ArgumentError('At least 2 captures are required for comparison.');
    }

    DiffDatabaseSchema.clearTables(_db);
    final newSlots = <CaptureSlot>[];

    final insertPacketStmt = _db.prepare('''
      INSERT INTO diff_packets (
        capture_index, frame_number, timestamp_us, flow_hash, fingerprint_hash,
        occurrence_index, src_ip, dst_ip, src_port, dst_port, protocol_name,
        extracted_seq, dscp_value, vlan_id, packet_length, raw_bytes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''');

    final insertSessionStmt = _db.prepare('''
      INSERT INTO capture_sessions (
        capture_index, label, file_path, packet_count, clock_offset_us
      ) VALUES (?, ?, ?, ?, ?)
    ''');

    try {
      for (int captureIdx = 0; captureIdx < inputs.length; captureIdx++) {
        final input = inputs[captureIdx];
        final List<RawCapturedPacket> rawPackets;
        if (input.rawPackets != null) {
          rawPackets = input.rawPackets!;
        } else if (input.bytes != null) {
          rawPackets = PcapBinaryReader.parseBytes(input.bytes!);
        } else {
          rawPackets = PcapBinaryReader.parseFile(File(input.filePath)).toList();
        }

        final occurrenceCounters = <String, int>{};

        _db.execute('BEGIN TRANSACTION;');
        try {
          for (int i = 0; i < rawPackets.length; i++) {
            final raw = rawPackets[i];
            final frameNo = i + 1;
            final info = PacketDissector.dissect(
              rawPacket: raw,
              customRules: customRules,
            );

            final occKey = '${info.flowHash}:${info.fingerprintHash}';
            final occIdx = (occurrenceCounters[occKey] ?? 0) + 1;
            occurrenceCounters[occKey] = occIdx;

            insertPacketStmt.execute([
              captureIdx,
              frameNo,
              raw.timestampUs,
              info.flowHash,
              info.fingerprintHash,
              occIdx,
              info.srcIp,
              info.dstIp,
              info.srcPort,
              info.dstPort,
              info.detectedProtocol,
              info.extractedSeq,
              info.dscpValue,
              info.vlanId,
              raw.originalLength,
              raw.data,
            ]);
          }
          _db.execute('COMMIT;');
        } catch (e) {
          _db.execute('ROLLBACK;');
          rethrow;
        }

        final clockOffsetUs = captureIdx == 0
            ? 0
            : ClockSkewEstimator.estimateClockOffsetUs(_db, targetCaptureIndex: captureIdx);

        insertSessionStmt.execute([
          captureIdx,
          input.label,
          input.filePath,
          rawPackets.length,
          clockOffsetUs,
        ]);

        newSlots.add(CaptureSlot(
          captureIndex: captureIdx,
          label: input.label,
          filePath: input.filePath,
          packetCount: rawPackets.length,
          clockOffsetUs: clockOffsetUs,
        ));
      }
    } finally {
      insertPacketStmt.close();
      insertSessionStmt.close();
    }

    _slots = newSlots;
    _buildCorrelationAndSummaries(latencySpikeThresholdUs: latencySpikeThresholdUs);
  }

  /// Re-evaluates latency spike thresholds without re-parsing files.
  void recomputeWithThreshold(int latencySpikeThresholdUs) {
    if (_slots.isEmpty) return;
    _buildCorrelationAndSummaries(latencySpikeThresholdUs: latencySpikeThresholdUs);
  }

  void _buildCorrelationAndSummaries({required int latencySpikeThresholdUs}) {
    if (_slots.isEmpty) return;

    // Determine shared flow hashes (present in Capture 0 AND at least one downstream capture)
    final sharedRows = _db.select('''
      SELECT DISTINCT a.flow_hash
      FROM diff_packets a
      INNER JOIN diff_packets b
        ON a.flow_hash = b.flow_hash
      WHERE a.capture_index = 0
        AND b.capture_index > 0
    ''');
    _sharedFlowHashes = sharedRows.map((r) => r['flow_hash'] as int).toSet();

    // Index all downstream packets by composite match key (flow_hash, fingerprint_hash, occurrence_index)
    // and track out-of-order sequences per (capture_index, flow_hash).
    final downstreamByKey = <String, Map<int, _RawDiffRow>>{};
    final outOfOrderFrames = <String>{}; // '$captureIndex:$frameNumber'
    final unmatchedDownstream = <_RawDiffRow>[];

    final baselineKeys = <String>{};
    final baselineRows = _db.select('''
      SELECT frame_number, timestamp_us, flow_hash, fingerprint_hash, occurrence_index,
             src_ip, dst_ip, src_port, dst_port, protocol_name, extracted_seq,
             dscp_value, vlan_id, packet_length
      FROM diff_packets
      WHERE capture_index = 0
      ORDER BY frame_number ASC
    ''');

    for (final r in baselineRows) {
      final key = '${r['flow_hash']}:${r['fingerprint_hash']}:${r['occurrence_index']}';
      baselineKeys.add(key);
    }

    for (int capIdx = 1; capIdx < _slots.length; capIdx++) {
      final rows = _db.select(
        '''
        SELECT frame_number, timestamp_us, flow_hash, fingerprint_hash, occurrence_index,
               src_ip, dst_ip, src_port, dst_port, protocol_name, extracted_seq,
               dscp_value, vlan_id, packet_length
        FROM diff_packets
        WHERE capture_index = ?
        ORDER BY frame_number ASC
        ''',
        [capIdx],
      );

      final maxSeqByFlow = <int, int>{};

      for (final r in rows) {
        final row = _RawDiffRow.fromMap(capIdx, r);
        final key = '${row.flowHash}:${row.fingerprintHash}:${row.occurrenceIndex}';
        downstreamByKey.putIfAbsent(key, () => {})[capIdx] = row;

        if (!baselineKeys.contains(key)) {
          unmatchedDownstream.add(row);
        }

        // Check Out-of-Order arrival in this capture
        if (row.extractedSeq != null) {
          final maxSeen = maxSeqByFlow[row.flowHash];
          if (maxSeen != null) {
            final isTcp = row.protocolName == 'TCP';
            if (isTcp) {
              if (row.extractedSeq! < maxSeen) {
                outOfOrderFrames.add('$capIdx:${row.frameNumber}');
              } else {
                maxSeqByFlow[row.flowHash] = row.extractedSeq!;
              }
            } else {
              // Handle 8-bit wrap (e.g. 255 -> 0) gracefully
              final diff = maxSeen - row.extractedSeq!;
              if (diff > 0 && diff < 128) {
                outOfOrderFrames.add('$capIdx:${row.frameNumber}');
              } else if (row.extractedSeq! > maxSeen || diff >= 128) {
                maxSeqByFlow[row.flowHash] = row.extractedSeq!;
              }
            }
          } else {
            maxSeqByFlow[row.flowHash] = row.extractedSeq!;
          }
        }
      }
    }

    // Walk Baseline Capture 0 in frame order, detect Source Gaps, and assemble PacketDiffRecords
    final lastSeqByFlowInBaseline = <int, int>{};
    final correlated = <PacketDiffRecord>[];
    final flowAccumulators = <int, _FlowAccumulator>{};

    int rowCounter = 1;
    for (final r in baselineRows) {
      final base = _RawDiffRow.fromMap(0, r);
      final key = '${base.flowHash}:${base.fingerprintHash}:${base.occurrenceIndex}';
      final matchedHopsRaw = downstreamByKey[key] ?? const <int, _RawDiffRow>{};

      final statuses = <DiffStatus>{};
      final detailParts = <String>[];

      // 1. Source Gap detection on Baseline Capture 0 (non-TCP datagram seqs)
      if (base.extractedSeq != null && base.protocolName != 'TCP') {
        final prevSeq = lastSeqByFlowInBaseline[base.flowHash];
        if (prevSeq != null) {
          final expectedNext = (prevSeq + 1) & 0xFF;
          if (base.extractedSeq != prevSeq + 1 && base.extractedSeq != expectedNext) {
            statuses.add(DiffStatus.sourceGap);
            detailParts.add('Source seq gap ($prevSeq -> ${base.extractedSeq})');
          }
        }
        lastSeqByFlowInBaseline[base.flowHash] = base.extractedSeq!;
      }

      // 2. Evaluate each downstream hop 1..N
      final hopMatches = <int, HopMatch>{};
      int? maxTransitDeltaUs;
      final missingHops = <String>[];

      for (int capIdx = 1; capIdx < _slots.length; capIdx++) {
        final hopRow = matchedHopsRaw[capIdx];
        if (hopRow == null) {
          statuses.add(DiffStatus.dropped);
          missingHops.add(_slots[capIdx].label);
          continue;
        }

        final clockOffset = _slots[capIdx].clockOffsetUs;
        final transitDelta = (hopRow.timestampUs - base.timestampUs) - clockOffset;
        if (maxTransitDeltaUs == null || transitDelta.abs() > maxTransitDeltaUs.abs()) {
          maxTransitDeltaUs = transitDelta;
        }

        hopMatches[capIdx] = HopMatch(
          captureIndex: capIdx,
          frameNumber: hopRow.frameNumber,
          timestampUs: hopRow.timestampUs,
          transitDeltaUs: transitDelta,
          dscpValue: hopRow.dscpValue,
          vlanId: hopRow.vlanId,
        );

        // Out-of-order check
        if (outOfOrderFrames.contains('$capIdx:${hopRow.frameNumber}')) {
          statuses.add(DiffStatus.outOfOrder);
          detailParts.add('Out of order at ${_slots[capIdx].label}');
        }

        // QoS / VLAN mutation check
        if (hopRow.dscpValue != base.dscpValue) {
          statuses.add(DiffStatus.qosVlanMutated);
          detailParts.add(
            'DSCP ${PacketDiffRecord.dscpLabel(base.dscpValue)} -> '
            '${PacketDiffRecord.dscpLabel(hopRow.dscpValue)} at ${_slots[capIdx].label}',
          );
        }
        if (hopRow.vlanId != base.vlanId) {
          statuses.add(DiffStatus.qosVlanMutated);
          detailParts.add(
            'VLAN ${base.vlanId ?? "none"} -> ${hopRow.vlanId ?? "none"} at ${_slots[capIdx].label}',
          );
        }

        // Latency spike check
        if (transitDelta > latencySpikeThresholdUs) {
          statuses.add(DiffStatus.latencySpike);
          detailParts.add(
            'Latency spike +${(transitDelta / 1000.0).toStringAsFixed(2)} ms at ${_slots[capIdx].label}',
          );
        }
      }

      if (missingHops.isNotEmpty) {
        detailParts.insert(0, 'Dropped at ${missingHops.join(", ")}');
      }

      if (statuses.isEmpty) {
        statuses.add(DiffStatus.ok);
        detailParts.add('OK');
      }

      final primaryStatus = _pickPrimaryStatus(statuses);

      final record = PacketDiffRecord(
        rowIndex: rowCounter++,
        flowHash: base.flowHash,
        fingerprintHash: base.fingerprintHash,
        occurrenceIndex: base.occurrenceIndex,
        srcIp: base.srcIp,
        dstIp: base.dstIp,
        srcPort: base.srcPort,
        dstPort: base.dstPort,
        protocolName: base.protocolName,
        extractedSeq: base.extractedSeq,
        baselineCaptureIndex: 0,
        baselineFrameNumber: base.frameNumber,
        baselineTimestampUs: base.timestampUs,
        baselineDscp: base.dscpValue,
        baselineVlanId: base.vlanId,
        packetLength: base.packetLength,
        hopMatches: hopMatches,
        statuses: statuses,
        primaryStatus: primaryStatus,
        maxTransitDeltaUs: maxTransitDeltaUs,
        statusDetail: detailParts.join(' • '),
      );
      correlated.add(record);

      // Accumulate flow statistics (for shared flows or all baseline flows)
      final acc = flowAccumulators.putIfAbsent(
        base.flowHash,
        () => _FlowAccumulator(
          flowHash: base.flowHash,
          srcIp: base.srcIp,
          dstIp: base.dstIp,
          srcPort: base.srcPort,
          dstPort: base.dstPort,
          protocolName: base.protocolName,
        ),
      );
      acc.addRecord(record, _slots.length);
    }

    // Build injected records for Full Diff mode
    final injected = <PacketDiffRecord>[];
    for (final extra in unmatchedDownstream) {
      injected.add(PacketDiffRecord(
        rowIndex: rowCounter++,
        flowHash: extra.flowHash,
        fingerprintHash: extra.fingerprintHash,
        occurrenceIndex: extra.occurrenceIndex,
        srcIp: extra.srcIp,
        dstIp: extra.dstIp,
        srcPort: extra.srcPort,
        dstPort: extra.dstPort,
        protocolName: extra.protocolName,
        extractedSeq: extra.extractedSeq,
        baselineCaptureIndex: extra.captureIndex,
        baselineFrameNumber: extra.frameNumber,
        baselineTimestampUs: extra.timestampUs,
        baselineDscp: extra.dscpValue,
        baselineVlanId: extra.vlanId,
        packetLength: extra.packetLength,
        hopMatches: {
          extra.captureIndex: HopMatch(
            captureIndex: extra.captureIndex,
            frameNumber: extra.frameNumber,
            timestampUs: extra.timestampUs,
            transitDeltaUs: 0,
            dscpValue: extra.dscpValue,
            vlanId: extra.vlanId,
          ),
        },
        statuses: const {DiffStatus.injected},
        primaryStatus: DiffStatus.injected,
        maxTransitDeltaUs: null,
        statusDetail: 'Extra / Injected at ${_slots[extra.captureIndex].label}',
      ));
    }

    _correlatedRecords = correlated;
    _injectedRecords = injected;
    _flowSummaries = flowAccumulators.values
        .map((a) => a.toSummary())
        .toList()
      ..sort((a, b) => b.totalSent.compareTo(a.totalSent));
  }

  static DiffStatus _pickPrimaryStatus(Set<DiffStatus> statuses) {
    if (statuses.contains(DiffStatus.dropped)) return DiffStatus.dropped;
    if (statuses.contains(DiffStatus.sourceGap)) return DiffStatus.sourceGap;
    if (statuses.contains(DiffStatus.outOfOrder)) return DiffStatus.outOfOrder;
    if (statuses.contains(DiffStatus.qosVlanMutated)) return DiffStatus.qosVlanMutated;
    if (statuses.contains(DiffStatus.latencySpike)) return DiffStatus.latencySpike;
    if (statuses.contains(DiffStatus.injected)) return DiffStatus.injected;
    return DiffStatus.ok;
  }

  /// Queries correlated diff records according to noise filter mode and status filter.
  List<PacketDiffRecord> queryDiffRecords({
    DiffFilterMode filterMode = DiffFilterMode.sharedFlowsOnly,
    int? selectedFlowHash,
    DiffStatusFilter statusFilter = DiffStatusFilter.all,
  }) {
    Iterable<PacketDiffRecord> source;

    switch (filterMode) {
      case DiffFilterMode.sharedFlowsOnly:
        source = _correlatedRecords.where((r) => _sharedFlowHashes.contains(r.flowHash));
        break;
      case DiffFilterMode.selectedFlow:
        source = selectedFlowHash == null
            ? _correlatedRecords
            : _correlatedRecords.where((r) => r.flowHash == selectedFlowHash);
        break;
      case DiffFilterMode.fullDiff:
        source = [..._correlatedRecords, ..._injectedRecords];
        break;
    }

    switch (statusFilter) {
      case DiffStatusFilter.all:
        return source.toList();
      case DiffStatusFilter.droppedOnly:
        return source.where((r) => r.statuses.contains(DiffStatus.dropped)).toList();
      case DiffStatusFilter.sourceGaps:
        return source.where((r) => r.statuses.contains(DiffStatus.sourceGap)).toList();
      case DiffStatusFilter.outOfOrder:
        return source.where((r) => r.statuses.contains(DiffStatus.outOfOrder)).toList();
      case DiffStatusFilter.mutated:
        return source.where((r) => r.statuses.contains(DiffStatus.qosVlanMutated)).toList();
      case DiffStatusFilter.latencySpikes:
        return source.where((r) => r.statuses.contains(DiffStatus.latencySpike)).toList();
    }
  }

  /// Fetches raw packet bytes for a specific capture slot and frame number
  /// (used for side-by-side Hex Diff inspection).
  Uint8List? getPacketRawBytes(int captureIndex, int frameNumber) {
    final rows = _db.select(
      '''
      SELECT raw_bytes FROM diff_packets
      WHERE capture_index = ? AND frame_number = ?
      LIMIT 1
      ''',
      [captureIndex, frameNumber],
    );
    if (rows.isEmpty) return null;
    final data = rows.first['raw_bytes'];
    if (data is Uint8List) return data;
    if (data is List<int>) return Uint8List.fromList(data);
    return null;
  }
}

class _RawDiffRow {
  _RawDiffRow({
    required this.captureIndex,
    required this.frameNumber,
    required this.timestampUs,
    required this.flowHash,
    required this.fingerprintHash,
    required this.occurrenceIndex,
    required this.srcIp,
    required this.dstIp,
    this.srcPort,
    this.dstPort,
    required this.protocolName,
    this.extractedSeq,
    this.dscpValue,
    this.vlanId,
    required this.packetLength,
  });

  factory _RawDiffRow.fromMap(int captureIndex, Row row) {
    return _RawDiffRow(
      captureIndex: captureIndex,
      frameNumber: row['frame_number'] as int,
      timestampUs: row['timestamp_us'] as int,
      flowHash: row['flow_hash'] as int,
      fingerprintHash: row['fingerprint_hash'] as int,
      occurrenceIndex: row['occurrence_index'] as int,
      srcIp: (row['src_ip'] as String?) ?? '',
      dstIp: (row['dst_ip'] as String?) ?? '',
      srcPort: row['src_port'] as int?,
      dstPort: row['dst_port'] as int?,
      protocolName: (row['protocol_name'] as String?) ?? 'UNKNOWN',
      extractedSeq: row['extracted_seq'] as int?,
      dscpValue: row['dscp_value'] as int?,
      vlanId: row['vlan_id'] as int?,
      packetLength: (row['packet_length'] as int?) ?? 0,
    );
  }

  final int captureIndex;
  final int frameNumber;
  final int timestampUs;
  final int flowHash;
  final int fingerprintHash;
  final int occurrenceIndex;
  final String srcIp;
  final String dstIp;
  final int? srcPort;
  final int? dstPort;
  final String protocolName;
  final int? extractedSeq;
  final int? dscpValue;
  final int? vlanId;
  final int packetLength;
}

class _FlowAccumulator {
  _FlowAccumulator({
    required this.flowHash,
    required this.srcIp,
    required this.dstIp,
    this.srcPort,
    this.dstPort,
    required this.protocolName,
  });

  final int flowHash;
  final String srcIp;
  final String dstIp;
  final int? srcPort;
  final int? dstPort;
  final String protocolName;

  int totalSent = 0;
  final Map<int, int> hopDeliveredCounts = {};
  int droppedCount = 0;
  int sourceGapCount = 0;
  int outOfOrderCount = 0;
  int mutatedCount = 0;
  int spikeCount = 0;
  int _deltaSumUs = 0;
  int _deltaCount = 0;
  int maxTransitDeltaUs = 0;

  void addRecord(PacketDiffRecord record, int slotCount) {
    totalSent++;
    for (int i = 1; i < slotCount; i++) {
      if (record.hopMatches.containsKey(i)) {
        hopDeliveredCounts[i] = (hopDeliveredCounts[i] ?? 0) + 1;
      }
    }
    if (record.statuses.contains(DiffStatus.dropped)) droppedCount++;
    if (record.statuses.contains(DiffStatus.sourceGap)) sourceGapCount++;
    if (record.statuses.contains(DiffStatus.outOfOrder)) outOfOrderCount++;
    if (record.statuses.contains(DiffStatus.qosVlanMutated)) mutatedCount++;
    if (record.statuses.contains(DiffStatus.latencySpike)) spikeCount++;
    if (record.maxTransitDeltaUs != null) {
      _deltaSumUs += record.maxTransitDeltaUs!;
      _deltaCount++;
      if (record.maxTransitDeltaUs!.abs() > maxTransitDeltaUs.abs()) {
        maxTransitDeltaUs = record.maxTransitDeltaUs!;
      }
    }
  }

  FlowDiffSummary toSummary() {
    return FlowDiffSummary(
      flowHash: flowHash,
      srcIp: srcIp,
      dstIp: dstIp,
      srcPort: srcPort,
      dstPort: dstPort,
      protocolName: protocolName,
      totalSent: totalSent,
      hopDeliveredCounts: hopDeliveredCounts,
      droppedCount: droppedCount,
      sourceGapCount: sourceGapCount,
      outOfOrderCount: outOfOrderCount,
      mutatedCount: mutatedCount,
      spikeCount: spikeCount,
      avgTransitDeltaUs: _deltaCount > 0 ? _deltaSumUs / _deltaCount : 0.0,
      maxTransitDeltaUs: maxTransitDeltaUs,
    );
  }
}
