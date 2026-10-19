import 'dart:typed_data';
import 'package:sqlite3/sqlite3.dart';
import '../../../domain/models/packet_record.dart';
import '../../../domain/models/custom_protocol_rule.dart';
import '../../../domain/models/timeline_bucket.dart';

class FlowSummary {
  const FlowSummary({
    required this.flowHash,
    required this.srcIp,
    required this.dstIp,
    required this.srcPort,
    required this.dstPort,
    required this.ipProto,
    required this.protocol,
    required this.packetCount,
    required this.totalBytes,
    required this.minDeltaUs,
    required this.maxDeltaUs,
    required this.avgDeltaUs,
    required this.firstSeenUs,
    required this.lastSeenUs,
  });

  final int flowHash;
  final String srcIp;
  final String dstIp;
  final int? srcPort;
  final int? dstPort;
  final int ipProto;
  final String protocol;
  final int packetCount;
  final int totalBytes;
  final int minDeltaUs;
  final int maxDeltaUs;
  final double avgDeltaUs;
  final int firstSeenUs;
  final int lastSeenUs;

  Map<String, dynamic> toMap() => {
        'flow_hash': flowHash,
        'src_ip': srcIp,
        'dst_ip': dstIp,
        'src_port': srcPort,
        'dst_port': dstPort,
        'ip_proto': ipProto,
        'protocol': protocol,
        'packet_count': packetCount,
        'total_bytes': totalBytes,
        'min_delta_us': minDeltaUs,
        'max_delta_us': maxDeltaUs,
        'avg_delta_us': avgDeltaUs,
        'first_seen_us': firstSeenUs,
        'last_seen_us': lastSeenUs,
      };

  factory FlowSummary.fromRow(Row row) => FlowSummary(
        flowHash: row['flow_hash'] as int,
        srcIp: row['src_ip'] as String,
        dstIp: row['dst_ip'] as String,
        srcPort: row['src_port'] as int?,
        dstPort: row['dst_port'] as int?,
        ipProto: row['ip_proto'] as int,
        protocol: row['protocol'] as String,
        packetCount: row['packet_count'] as int,
        totalBytes: row['total_bytes'] as int,
        minDeltaUs: row['min_delta_us'] as int,
        maxDeltaUs: row['max_delta_us'] as int,
        avgDeltaUs: (row['avg_delta_us'] as num).toDouble(),
        firstSeenUs: row['first_seen_us'] as int,
        lastSeenUs: row['last_seen_us'] as int,
      );
}

class PacketDatabaseService {
  PacketDatabaseService({Database? db}) : _db = db ?? sqlite3.openInMemory() {
    _initSchema();
  }

  final Database _db;
  Database get db => _db;

  void _initSchema() {
    _db.execute('''
      CREATE TABLE IF NOT EXISTS packets (
        packet_no INTEGER PRIMARY KEY,
        timestamp_us INTEGER NOT NULL,
        global_delta_us INTEGER NOT NULL,
        stream_delta_us INTEGER NOT NULL,
        flow_hash INTEGER NOT NULL,
        eth_type INTEGER NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        ip_proto INTEGER NOT NULL,
        src_port INTEGER,
        dst_port INTEGER,
        detected_protocol TEXT NOT NULL,
        captured_length INTEGER NOT NULL,
        original_length INTEGER NOT NULL,
        file_byte_offset INTEGER NOT NULL,
        payload_file_offset INTEGER NOT NULL,
        payload_length INTEGER NOT NULL,
        payload_preview BLOB NOT NULL,
        summary TEXT NOT NULL,
        triage_status TEXT NOT NULL,
        is_lan_noise INTEGER NOT NULL,
        custom_protocol_id TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(timestamp_us);
      CREATE INDEX IF NOT EXISTS idx_packets_proto ON packets(detected_protocol);
      CREATE INDEX IF NOT EXISTS idx_packets_triage ON packets(triage_status, is_lan_noise);
      CREATE INDEX IF NOT EXISTS idx_packets_endpoints ON packets(src_ip, dst_ip);
      CREATE INDEX IF NOT EXISTS idx_packets_global_delta ON packets(global_delta_us);
      CREATE INDEX IF NOT EXISTS idx_packets_stream_delta ON packets(stream_delta_us);
      CREATE INDEX IF NOT EXISTS idx_packets_flow ON packets(flow_hash);

      CREATE TABLE IF NOT EXISTS flows (
        flow_hash INTEGER PRIMARY KEY,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        src_port INTEGER,
        dst_port INTEGER,
        ip_proto INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        packet_count INTEGER NOT NULL,
        total_bytes INTEGER NOT NULL,
        min_delta_us INTEGER NOT NULL,
        max_delta_us INTEGER NOT NULL,
        avg_delta_us REAL NOT NULL,
        first_seen_us INTEGER NOT NULL,
        last_seen_us INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS timeline_buckets (
        bucket_index INTEGER PRIMARY KEY,
        bucket_start_us INTEGER NOT NULL,
        bucket_end_us INTEGER NOT NULL,
        packet_count INTEGER NOT NULL,
        total_bytes INTEGER NOT NULL,
        min_global_delta_us INTEGER NOT NULL,
        max_stream_delta_us INTEGER NOT NULL,
        avg_stream_delta_us REAL NOT NULL,
        unexpected_count INTEGER NOT NULL
      );
    ''');
  }

  void insertPacketsBatch(List<PacketRecord> packets) {
    if (packets.isEmpty) return;

    _db.execute('BEGIN TRANSACTION');
    try {
      final stmt = _db.prepare('''
        INSERT INTO packets (
          packet_no, timestamp_us, global_delta_us, stream_delta_us,
          flow_hash, eth_type, src_ip, dst_ip, ip_proto,
          src_port, dst_port, detected_protocol, captured_length, original_length,
          file_byte_offset, payload_file_offset, payload_length,
          payload_preview, summary, triage_status, is_lan_noise, custom_protocol_id
        ) VALUES (
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
      ''');

      for (final p in packets) {
        stmt.execute([
          p.packetNo,
          p.timestampUs,
          p.globalDeltaUs,
          p.streamDeltaUs,
          p.flowHash,
          p.ethType,
          p.srcIp,
          p.dstIp,
          p.ipProto,
          p.srcPort,
          p.dstPort,
          p.detectedProtocol,
          p.capturedLength,
          p.originalLength,
          p.fileByteOffset,
          p.payloadFileOffset,
          p.payloadLength,
          p.payloadPreview,
          p.summary,
          p.triageStatus.name,
          p.isLanNoise ? 1 : 0,
          p.customProtocolId,
        ]);
      }
      stmt.close();
      _db.execute('COMMIT');
    } catch (e) {
      _db.execute('ROLLBACK');
      rethrow;
    }
  }

  void buildFlowsAndBuckets({int bucketCount = 200}) {
    // 1. Build flows table
    _db.execute('DELETE FROM flows');
    _db.execute('''
      INSERT INTO flows (
        flow_hash, src_ip, dst_ip, src_port, dst_port, ip_proto, protocol,
        packet_count, total_bytes, min_delta_us, max_delta_us, avg_delta_us,
        first_seen_us, last_seen_us
      )
      SELECT
        flow_hash,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        ip_proto,
        detected_protocol,
        COUNT(*),
        SUM(captured_length),
        MIN(stream_delta_us),
        MAX(stream_delta_us),
        AVG(stream_delta_us),
        MIN(timestamp_us),
        MAX(timestamp_us)
      FROM packets
      GROUP BY flow_hash
    ''');

    // 2. Build timeline buckets
    _db.execute('DELETE FROM timeline_buckets');
    final rangeResult = _db.select('SELECT MIN(timestamp_us) as min_ts, MAX(timestamp_us) as max_ts, COUNT(*) as cnt FROM packets');
    if (rangeResult.isEmpty || rangeResult.first['cnt'] == 0) return;

    final minTs = rangeResult.first['min_ts'] as int;
    final maxTs = rangeResult.first['max_ts'] as int;
    final totalSpan = maxTs - minTs;
    if (totalSpan <= 0) {
      // Single timestamp bucket
      _db.execute('''
        INSERT INTO timeline_buckets (
          bucket_index, bucket_start_us, bucket_end_us, packet_count,
          total_bytes, min_global_delta_us, max_stream_delta_us, avg_stream_delta_us, unexpected_count
        )
        SELECT
          0,
          MIN(timestamp_us),
          MAX(timestamp_us),
          COUNT(*),
          COALESCE(SUM(captured_length), 0),
          COALESCE(MIN(global_delta_us), 0),
          COALESCE(MAX(stream_delta_us), 0),
          COALESCE(AVG(stream_delta_us), 0),
          COALESCE(SUM(CASE WHEN triage_status = 'unexpected' THEN 1 ELSE 0 END), 0)
        FROM packets
      ''');
      return;
    }

    final bucketWidthUs = (totalSpan / bucketCount).ceil();

    _db.execute('''
      INSERT INTO timeline_buckets (
        bucket_index, bucket_start_us, bucket_end_us, packet_count,
        total_bytes, min_global_delta_us, max_stream_delta_us, avg_stream_delta_us, unexpected_count
      )
      SELECT
        CAST((timestamp_us - $minTs) / $bucketWidthUs AS INTEGER) AS b_idx,
        $minTs + (CAST((timestamp_us - $minTs) / $bucketWidthUs AS INTEGER) * $bucketWidthUs),
        $minTs + ((CAST((timestamp_us - $minTs) / $bucketWidthUs AS INTEGER) + 1) * $bucketWidthUs),
        COUNT(*),
        SUM(captured_length),
        MIN(global_delta_us),
        MAX(stream_delta_us),
        AVG(stream_delta_us),
        SUM(CASE WHEN triage_status = 'unexpected' THEN 1 ELSE 0 END)
      FROM packets
      GROUP BY b_idx
      ORDER BY b_idx ASC
    ''');
  }

  List<PacketRecord> queryPackets({
    int offset = 0,
    int limit = 100,
    bool isTriageMode = true,
    Set<TriageStatus> triageStatuses = const {
      TriageStatus.expected,
      TriageStatus.unclassified,
      TriageStatus.unexpected,
    },
    bool silenceLanChatter = true,
    Set<String> protocolPills = const {},
    Set<String> ipFilters = const {},
    int? timeStartUs,
    int? timeEndUs,
  }) {
    final whereClauses = <String>[];
    final params = <dynamic>[];

    if (isTriageMode) {
      if (triageStatuses.length < 3) {
        final statusNames = triageStatuses.map((s) => "'${s.name}'").join(',');
        whereClauses.add('triage_status IN ($statusNames)');
      }
      if (silenceLanChatter) {
        whereClauses.add('is_lan_noise = 0');
      }
    } else {
      // Quick-filter pill mode
      if (protocolPills.isNotEmpty) {
        final placeholders = List.filled(protocolPills.length, '?').join(',');
        whereClauses.add('detected_protocol IN ($placeholders)');
        params.addAll(protocolPills);
      }
      if (ipFilters.isNotEmpty) {
        final ipPlaceholders = List.filled(ipFilters.length, '?').join(',');
        whereClauses.add('(src_ip IN ($ipPlaceholders) OR dst_ip IN ($ipPlaceholders))');
        params.addAll(ipFilters);
        params.addAll(ipFilters);
      }
    }

    if (timeStartUs != null) {
      whereClauses.add('timestamp_us >= ?');
      params.add(timeStartUs);
    }
    if (timeEndUs != null) {
      whereClauses.add('timestamp_us <= ?');
      params.add(timeEndUs);
    }

    final whereSql = whereClauses.isNotEmpty ? 'WHERE ${whereClauses.join(' AND ')}' : '';
    final sql = '''
      SELECT * FROM packets
      $whereSql
      ORDER BY packet_no ASC
      LIMIT ? OFFSET ?
    ''';
    params.add(limit);
    params.add(offset);

    final results = _db.select(sql, params);
    return results.map((row) {
      final map = <String, dynamic>{};
      for (final col in row.keys) {
        map[col] = row[col];
      }
      return PacketRecord.fromMap(map);
    }).toList();
  }

  int getPacketCount({
    bool isTriageMode = true,
    Set<TriageStatus> triageStatuses = const {
      TriageStatus.expected,
      TriageStatus.unclassified,
      TriageStatus.unexpected,
    },
    bool silenceLanChatter = true,
    Set<String> protocolPills = const {},
    Set<String> ipFilters = const {},
    int? timeStartUs,
    int? timeEndUs,
  }) {
    final whereClauses = <String>[];
    final params = <dynamic>[];

    if (isTriageMode) {
      if (triageStatuses.length < 3) {
        final statusNames = triageStatuses.map((s) => "'${s.name}'").join(',');
        whereClauses.add('triage_status IN ($statusNames)');
      }
      if (silenceLanChatter) {
        whereClauses.add('is_lan_noise = 0');
      }
    } else {
      if (protocolPills.isNotEmpty) {
        final placeholders = List.filled(protocolPills.length, '?').join(',');
        whereClauses.add('detected_protocol IN ($placeholders)');
        params.addAll(protocolPills);
      }
      if (ipFilters.isNotEmpty) {
        final ipPlaceholders = List.filled(ipFilters.length, '?').join(',');
        whereClauses.add('(src_ip IN ($ipPlaceholders) OR dst_ip IN ($ipPlaceholders))');
        params.addAll(ipFilters);
        params.addAll(ipFilters);
      }
    }

    if (timeStartUs != null) {
      whereClauses.add('timestamp_us >= ?');
      params.add(timeStartUs);
    }
    if (timeEndUs != null) {
      whereClauses.add('timestamp_us <= ?');
      params.add(timeEndUs);
    }

    final whereSql = whereClauses.isNotEmpty ? 'WHERE ${whereClauses.join(' AND ')}' : '';
    final sql = 'SELECT COUNT(*) as cnt FROM packets $whereSql';
    final result = _db.select(sql, params);
    return result.first['cnt'] as int;
  }

  List<TimelineBucket> queryTimelineBuckets() {
    final rows = _db.select('SELECT * FROM timeline_buckets ORDER BY bucket_index ASC');
    return rows.map((r) {
      final map = <String, dynamic>{};
      for (final col in r.keys) {
        map[col] = r[col];
      }
      return TimelineBucket.fromMap(map);
    }).toList();
  }

  Map<String, int> queryProtocolCounts() {
    final rows = _db.select('''
      SELECT detected_protocol, COUNT(*) as cnt
      FROM packets
      GROUP BY detected_protocol
      ORDER BY cnt DESC
    ''');
    final counts = <String, int>{};
    for (final r in rows) {
      counts[r['detected_protocol'] as String] = r['cnt'] as int;
    }
    return counts;
  }

  Map<TriageStatus, int> queryTriageCounts({bool silenceLanChatter = false}) {
    final sql = silenceLanChatter
        ? '''
          SELECT triage_status, COUNT(*) as cnt
          FROM packets
          WHERE is_lan_noise = 0
          GROUP BY triage_status
        '''
        : '''
          SELECT triage_status, COUNT(*) as cnt
          FROM packets
          GROUP BY triage_status
        ''';
    final rows = _db.select(sql);
    final counts = <TriageStatus, int>{
      TriageStatus.expected: 0,
      TriageStatus.unclassified: 0,
      TriageStatus.unexpected: 0,
    };
    for (final r in rows) {
      final status = TriageStatus.fromString(r['triage_status'] as String?);
      counts[status] = (counts[status] ?? 0) + (r['cnt'] as int);
    }
    return counts;
  }

  List<FlowSummary> queryFlows({int limit = 100}) {
    final rows = _db.select('''
      SELECT * FROM flows
      ORDER BY packet_count DESC
      LIMIT ?
    ''', [limit]);
    return rows.map((r) => FlowSummary.fromRow(r)).toList();
  }

  List<Map<String, dynamic>> queryTopTalkers({
    required String metric, // 'packets' or 'bytes'
    required int limit,
    bool onlyUnexpected = false,
  }) {
    final orderCol = (metric == 'bytes') ? 'total_bytes' : 'packet_count';
    final where = onlyUnexpected ? "WHERE triage_status = 'unexpected'" : '';
    final rows = _db.select('''
      SELECT
        src_ip,
        dst_ip,
        detected_protocol as protocol,
        COUNT(*) as packet_count,
        SUM(captured_length) as total_bytes
      FROM packets
      $where
      GROUP BY src_ip, dst_ip, detected_protocol
      ORDER BY $orderCol DESC
      LIMIT ?
    ''', [limit]);

    return rows.map((r) => {
      'src_ip': r['src_ip'],
      'dst_ip': r['dst_ip'],
      'protocol': r['protocol'],
      'packet_count': r['packet_count'],
      'total_bytes': r['total_bytes'],
    }).toList();
  }

  List<PacketRecord> queryTimingAnomalies({
    required bool isBurst, // true = micro-bursts (global_delta), false = stream stalls
    required int thresholdUs,
    int limit = 20,
  }) {
    final sql = isBurst
        ? '''
          SELECT * FROM packets
          WHERE global_delta_us <= ? AND global_delta_us > 0
          ORDER BY global_delta_us ASC
          LIMIT ?
        '''
        : '''
          SELECT * FROM packets
          WHERE stream_delta_us >= ?
          ORDER BY stream_delta_us DESC
          LIMIT ?
        ''';

    final rows = _db.select(sql, [thresholdUs, limit]);
    return rows.map((r) {
      final map = <String, dynamic>{};
      for (final col in r.keys) {
        map[col] = r[col];
      }
      return PacketRecord.fromMap(map);
    }).toList();
  }

  /// Retroactively updates all matching packets when a new CustomProtocolRule is added.
  /// Executes in SQLite directly without re-reading the PCAP file!
  int relabelCustomProtocol(CustomProtocolRule rule) {
    final conditions = <String>[];
    final params = <dynamic>[];

    if (rule.ipProtocol != null) {
      conditions.add('ip_proto = ?');
      params.add(rule.ipProtocol);
    }

    if (rule.port != null) {
      switch (rule.portDirection) {
        case PortMatchDirection.src:
          conditions.add('src_port = ?');
          params.add(rule.port);
          break;
        case PortMatchDirection.dst:
          conditions.add('dst_port = ?');
          params.add(rule.port);
          break;
        case PortMatchDirection.either:
          conditions.add('(src_port = ? OR dst_port = ?)');
          params.add(rule.port);
          params.add(rule.port);
          break;
      }
    }

    if (rule.ipAddressFilter != null && rule.ipAddressFilter!.isNotEmpty) {
      conditions.add('(src_ip = ? OR dst_ip = ?)');
      params.add(rule.ipAddressFilter);
      params.add(rule.ipAddressFilter);
    }

    final whereSql = conditions.isNotEmpty ? 'WHERE ${conditions.join(' AND ')}' : '';
    final candidateRows = _db.select('''
      SELECT packet_no, payload_preview FROM packets $whereSql
    ''', params);

    final matchedPacketNos = <int>[];
    final magicBytes = rule.magicBytesHex;
    final offset = rule.magicBytesOffset ?? 0;

    for (final row in candidateRows) {
      final packetNo = row['packet_no'] as int;
      if (magicBytes == null || magicBytes.isEmpty) {
        matchedPacketNos.add(packetNo);
        continue;
      }

      final blob = row['payload_preview'];
      final List<int> preview;
      if (blob is List<int>) {
        preview = blob;
      } else if (blob is Uint8List) {
        preview = blob.toList();
      } else {
        preview = const [];
      }

      if (preview.length >= offset + magicBytes.length) {
        bool matches = true;
        for (int i = 0; i < magicBytes.length; i++) {
          if (preview[offset + i] != magicBytes[i]) {
            matches = false;
            break;
          }
        }
        if (matches) {
          matchedPacketNos.add(packetNo);
        }
      }
    }

    if (matchedPacketNos.isEmpty) return 0;

    _db.execute('BEGIN TRANSACTION');
    try {
      final updateStmt = _db.prepare('''
        UPDATE packets
        SET detected_protocol = ?, custom_protocol_id = ?, triage_status = ?
        WHERE packet_no = ?
      ''');

      for (final no in matchedPacketNos) {
        updateStmt.execute([
          rule.name,
          rule.id,
          rule.defaultTriageStatus.name,
          no,
        ]);
      }
      updateStmt.close();
      _db.execute('COMMIT');
    } catch (e) {
      _db.execute('ROLLBACK');
      rethrow;
    }

    // Refresh flows and buckets to keep statistics synchronized
    buildFlowsAndBuckets();
    return matchedPacketNos.length;
  }

  void close() {
    _db.close();
  }
}
