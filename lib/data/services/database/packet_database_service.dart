import 'dart:typed_data';
import 'package:sqlite3/sqlite3.dart';
import '../../../domain/models/packet_record.dart';
import '../../../domain/models/custom_protocol_rule.dart';
import '../../../domain/models/timeline_bucket.dart';
import '../../../domain/models/baseline_profile.dart';

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
      CREATE INDEX IF NOT EXISTS idx_packets_src_port ON packets(src_ip, src_port);
      CREATE INDEX IF NOT EXISTS idx_packets_dst_port ON packets(dst_ip, dst_port);
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

  void _appendEndpointFilter(
    List<String> whereClauses,
    List<dynamic> params,
    Set<String> filters,
    String ipCol,
    String portCol, {
    bool isNot = false,
  }) {
    if (filters.isEmpty) return;
    final subClauses = <String>[];
    for (final f in filters) {
      if (f.contains(':')) {
        final parts = f.split(':');
        final ip = parts[0];
        final port = int.tryParse(parts[1]);
        if (port != null) {
          subClauses.add('($ipCol = ? AND $portCol = ?)');
          params.add(ip);
          params.add(port);
          continue;
        }
      }
      subClauses.add('$ipCol = ?');
      params.add(f);
    }
    if (subClauses.isNotEmpty) {
      final joined = subClauses.join(' OR ');
      if (isNot) {
        whereClauses.add('NOT ($joined)');
      } else {
        whereClauses.add('($joined)');
      }
    }
  }

  (String, List<dynamic>) _buildWhereClauseAndParams({
    bool isTriageMode = true,
    Set<TriageStatus> triageStatuses = const {
      TriageStatus.expected,
      TriageStatus.unclassified,
      TriageStatus.unexpected,
    },
    bool isTriageNot = false,
    bool silenceLanChatter = true,
    String sourceSearch = '',
    bool isSourceSearchNot = false,
    String destSearch = '',
    bool isDestSearchNot = false,
    Set<String> protocolPills = const {},
    bool isProtocolNot = false,
    Set<String> senderFilters = const {},
    bool isSenderNot = false,
    Set<String> receiverFilters = const {},
    bool isReceiverNot = false,
    Set<String> ipFilters = const {},
    int? timeStartUs,
    int? timeEndUs,
  }) {
    final whereClauses = <String>[];
    final params = <dynamic>[];

    // 1. Triage Statuses
    if (triageStatuses.isNotEmpty) {
      if (!isTriageNot && triageStatuses.length >= 3) {
        // all 3 statuses selected positive -> match all, no restriction
      } else {
        final statusNames = triageStatuses.map((s) => "'${s.name}'").join(',');
        if (isTriageNot) {
          whereClauses.add('triage_status NOT IN ($statusNames)');
        } else {
          whereClauses.add('triage_status IN ($statusNames)');
        }
      }
    }

    // 2. Silence LAN Chatter
    if (silenceLanChatter) {
      whereClauses.add('is_lan_noise = 0');
    }

    // 3. Source IP Search Box
    final trimmedSrc = sourceSearch.trim();
    if (trimmedSrc.isNotEmpty) {
      if (trimmedSrc.contains(':')) {
        final parts = trimmedSrc.split(':');
        final ipPart = parts[0];
        final portPart = int.tryParse(parts[1]);
        if (portPart != null) {
          if (isSourceSearchNot) {
            whereClauses.add('NOT (src_ip LIKE ? AND src_port = ?)');
          } else {
            whereClauses.add('(src_ip LIKE ? AND src_port = ?)');
          }
          params.add('%$ipPart%');
          params.add(portPart);
        } else {
          if (isSourceSearchNot) {
            whereClauses.add('src_ip NOT LIKE ?');
          } else {
            whereClauses.add('src_ip LIKE ?');
          }
          params.add('%$trimmedSrc%');
        }
      } else {
        if (isSourceSearchNot) {
          whereClauses.add('src_ip NOT LIKE ?');
        } else {
          whereClauses.add('src_ip LIKE ?');
        }
        params.add('%$trimmedSrc%');
      }
    }

    // 4. Destination IP Search Box
    final trimmedDst = destSearch.trim();
    if (trimmedDst.isNotEmpty) {
      if (trimmedDst.contains(':')) {
        final parts = trimmedDst.split(':');
        final ipPart = parts[0];
        final portPart = int.tryParse(parts[1]);
        if (portPart != null) {
          if (isDestSearchNot) {
            whereClauses.add('NOT (dst_ip LIKE ? AND dst_port = ?)');
          } else {
            whereClauses.add('(dst_ip LIKE ? AND dst_port = ?)');
          }
          params.add('%$ipPart%');
          params.add(portPart);
        } else {
          if (isDestSearchNot) {
            whereClauses.add('dst_ip NOT LIKE ?');
          } else {
            whereClauses.add('dst_ip LIKE ?');
          }
          params.add('%$trimmedDst%');
        }
      } else {
        if (isDestSearchNot) {
          whereClauses.add('dst_ip NOT LIKE ?');
        } else {
          whereClauses.add('dst_ip LIKE ?');
        }
        params.add('%$trimmedDst%');
      }
    }

    // 5. Protocol Pills
    if (protocolPills.isNotEmpty) {
      final placeholders = List.filled(protocolPills.length, '?').join(',');
      if (isProtocolNot) {
        whereClauses.add('detected_protocol NOT IN ($placeholders)');
      } else {
        whereClauses.add('detected_protocol IN ($placeholders)');
      }
      params.addAll(protocolPills);
    }

    // 6. Sender Filters (Sources)
    _appendEndpointFilter(whereClauses, params, senderFilters, 'src_ip', 'src_port', isNot: isSenderNot);

    // 7. Receiver Filters (Destinations)
    _appendEndpointFilter(whereClauses, params, receiverFilters, 'dst_ip', 'dst_port', isNot: isReceiverNot);

    // 8. IP Filters (generic)
    if (ipFilters.isNotEmpty) {
      final ipPlaceholders = List.filled(ipFilters.length, '?').join(',');
      whereClauses.add('(src_ip IN ($ipPlaceholders) OR dst_ip IN ($ipPlaceholders))');
      params.addAll(ipFilters);
      params.addAll(ipFilters);
    }

    // 9. Time Window
    if (timeStartUs != null) {
      whereClauses.add('timestamp_us >= ?');
      params.add(timeStartUs);
    }
    if (timeEndUs != null) {
      whereClauses.add('timestamp_us <= ?');
      params.add(timeEndUs);
    }

    final whereSql = whereClauses.isNotEmpty ? 'WHERE ${whereClauses.join(' AND ')}' : '';
    return (whereSql, params);
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
    bool isTriageNot = false,
    bool silenceLanChatter = true,
    String sourceSearch = '',
    bool isSourceSearchNot = false,
    String destSearch = '',
    bool isDestSearchNot = false,
    Set<String> protocolPills = const {},
    bool isProtocolNot = false,
    Set<String> senderFilters = const {},
    bool isSenderNot = false,
    Set<String> receiverFilters = const {},
    bool isReceiverNot = false,
    Set<String> ipFilters = const {},
    int? timeStartUs,
    int? timeEndUs,
    String sortColumn = 'packet_no',
    bool sortAscending = true,
  }) {
    final (whereSql, params) = _buildWhereClauseAndParams(
      isTriageMode: isTriageMode,
      triageStatuses: triageStatuses,
      isTriageNot: isTriageNot,
      silenceLanChatter: silenceLanChatter,
      sourceSearch: sourceSearch,
      isSourceSearchNot: isSourceSearchNot,
      destSearch: destSearch,
      isDestSearchNot: isDestSearchNot,
      protocolPills: protocolPills,
      isProtocolNot: isProtocolNot,
      senderFilters: senderFilters,
      isSenderNot: isSenderNot,
      receiverFilters: receiverFilters,
      isReceiverNot: isReceiverNot,
      ipFilters: ipFilters,
      timeStartUs: timeStartUs,
      timeEndUs: timeEndUs,
    );

    final validColumns = {
      'packet_no': 'packet_no',
      'timestamp_us': 'timestamp_us',
      'global_delta_us': 'global_delta_us',
      'stream_delta_us': 'stream_delta_us',
      'src_ip': 'src_ip',
      'dst_ip': 'dst_ip',
      'detected_protocol': 'detected_protocol',
      'captured_length': 'captured_length',
      'triage_status': 'triage_status',
      'summary': 'summary',
    };
    final orderCol = validColumns[sortColumn] ?? 'packet_no';
    final orderDir = sortAscending ? 'ASC' : 'DESC';
    final orderClause = (orderCol == 'packet_no')
        ? 'ORDER BY packet_no $orderDir'
        : 'ORDER BY $orderCol $orderDir, packet_no ASC';

    final sql = '''
      SELECT * FROM packets
      $whereSql
      $orderClause
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
    bool isTriageNot = false,
    bool silenceLanChatter = true,
    String sourceSearch = '',
    bool isSourceSearchNot = false,
    String destSearch = '',
    bool isDestSearchNot = false,
    Set<String> protocolPills = const {},
    bool isProtocolNot = false,
    Set<String> senderFilters = const {},
    bool isSenderNot = false,
    Set<String> receiverFilters = const {},
    bool isReceiverNot = false,
    Set<String> ipFilters = const {},
    int? timeStartUs,
    int? timeEndUs,
  }) {
    final (whereSql, params) = _buildWhereClauseAndParams(
      isTriageMode: isTriageMode,
      triageStatuses: triageStatuses,
      isTriageNot: isTriageNot,
      silenceLanChatter: silenceLanChatter,
      sourceSearch: sourceSearch,
      isSourceSearchNot: isSourceSearchNot,
      destSearch: destSearch,
      isDestSearchNot: isDestSearchNot,
      protocolPills: protocolPills,
      isProtocolNot: isProtocolNot,
      senderFilters: senderFilters,
      isSenderNot: isSenderNot,
      receiverFilters: receiverFilters,
      isReceiverNot: isReceiverNot,
      ipFilters: ipFilters,
      timeStartUs: timeStartUs,
      timeEndUs: timeEndUs,
    );

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

  Map<String, int> queryProtocolCounts({
    bool isTriageMode = true,
    Set<TriageStatus> triageStatuses = const {
      TriageStatus.expected,
      TriageStatus.unclassified,
      TriageStatus.unexpected,
    },
    bool isTriageNot = false,
    bool silenceLanChatter = false,
    String sourceSearch = '',
    bool isSourceSearchNot = false,
    String destSearch = '',
    bool isDestSearchNot = false,
    Set<String> senderFilters = const {},
    bool isSenderNot = false,
    Set<String> receiverFilters = const {},
    bool isReceiverNot = false,
    Set<String> ipFilters = const {},
    int? timeStartUs,
    int? timeEndUs,
  }) {
    final (whereSql, params) = _buildWhereClauseAndParams(
      isTriageMode: isTriageMode,
      triageStatuses: triageStatuses,
      isTriageNot: isTriageNot,
      silenceLanChatter: silenceLanChatter,
      sourceSearch: sourceSearch,
      isSourceSearchNot: isSourceSearchNot,
      destSearch: destSearch,
      isDestSearchNot: isDestSearchNot,
      protocolPills: const {},
      isProtocolNot: false,
      senderFilters: senderFilters,
      isSenderNot: isSenderNot,
      receiverFilters: receiverFilters,
      isReceiverNot: isReceiverNot,
      ipFilters: ipFilters,
      timeStartUs: timeStartUs,
      timeEndUs: timeEndUs,
    );

    final sql = '''
      SELECT detected_protocol, COUNT(*) as cnt
      FROM packets
      $whereSql
      GROUP BY detected_protocol
      ORDER BY cnt DESC
    ''';
    final rows = _db.select(sql, params);
    final counts = <String, int>{};
    for (final r in rows) {
      counts[r['detected_protocol'] as String] = r['cnt'] as int;
    }
    return counts;
  }

  Map<String, int> queryTopSenders({
    int limit = 15,
    bool isTriageMode = true,
    Set<TriageStatus> triageStatuses = const {
      TriageStatus.expected,
      TriageStatus.unclassified,
      TriageStatus.unexpected,
    },
    bool isTriageNot = false,
    bool silenceLanChatter = false,
    String destSearch = '',
    bool isDestSearchNot = false,
    Set<String> protocolPills = const {},
    bool isProtocolNot = false,
    Set<String> receiverFilters = const {},
    bool isReceiverNot = false,
    Set<String> ipFilters = const {},
    int? timeStartUs,
    int? timeEndUs,
  }) {
    final (whereSql, params) = _buildWhereClauseAndParams(
      isTriageMode: isTriageMode,
      triageStatuses: triageStatuses,
      isTriageNot: isTriageNot,
      silenceLanChatter: silenceLanChatter,
      sourceSearch: '',
      isSourceSearchNot: false,
      destSearch: destSearch,
      isDestSearchNot: isDestSearchNot,
      protocolPills: protocolPills,
      isProtocolNot: isProtocolNot,
      senderFilters: const {},
      isSenderNot: false,
      receiverFilters: receiverFilters,
      isReceiverNot: isReceiverNot,
      ipFilters: ipFilters,
      timeStartUs: timeStartUs,
      timeEndUs: timeEndUs,
    );

    final sql = '''
      SELECT src_ip, COUNT(*) as cnt
      FROM packets
      $whereSql
      GROUP BY src_ip
      ORDER BY cnt DESC
      LIMIT $limit
    ''';
    final rows = _db.select(sql, params);
    final counts = <String, int>{};
    for (final r in rows) {
      counts[r['src_ip'] as String] = r['cnt'] as int;
    }
    return counts;
  }

  Map<String, int> queryTopReceivers({
    int limit = 15,
    bool isTriageMode = true,
    Set<TriageStatus> triageStatuses = const {
      TriageStatus.expected,
      TriageStatus.unclassified,
      TriageStatus.unexpected,
    },
    bool isTriageNot = false,
    bool silenceLanChatter = false,
    String sourceSearch = '',
    bool isSourceSearchNot = false,
    Set<String> protocolPills = const {},
    bool isProtocolNot = false,
    Set<String> senderFilters = const {},
    bool isSenderNot = false,
    Set<String> ipFilters = const {},
    int? timeStartUs,
    int? timeEndUs,
  }) {
    final (whereSql, params) = _buildWhereClauseAndParams(
      isTriageMode: isTriageMode,
      triageStatuses: triageStatuses,
      isTriageNot: isTriageNot,
      silenceLanChatter: silenceLanChatter,
      sourceSearch: sourceSearch,
      isSourceSearchNot: isSourceSearchNot,
      destSearch: '',
      isDestSearchNot: false,
      protocolPills: protocolPills,
      isProtocolNot: isProtocolNot,
      senderFilters: senderFilters,
      isSenderNot: isSenderNot,
      receiverFilters: const {},
      isReceiverNot: false,
      ipFilters: ipFilters,
      timeStartUs: timeStartUs,
      timeEndUs: timeEndUs,
    );

    final sql = '''
      SELECT dst_ip, COUNT(*) as cnt
      FROM packets
      $whereSql
      GROUP BY dst_ip
      ORDER BY cnt DESC
      LIMIT $limit
    ''';
    final rows = _db.select(sql, params);
    final counts = <String, int>{};
    for (final r in rows) {
      counts[r['dst_ip'] as String] = r['cnt'] as int;
    }
    return counts;
  }

  int countPacketsForEndpoint({
    required String ip,
    int? port,
    required bool isSender,
    bool isTriageMode = true,
    Set<TriageStatus> triageStatuses = const {
      TriageStatus.expected,
      TriageStatus.unclassified,
      TriageStatus.unexpected,
    },
    bool isTriageNot = false,
    bool silenceLanChatter = false,
    String sourceSearch = '',
    bool isSourceSearchNot = false,
    String destSearch = '',
    bool isDestSearchNot = false,
    Set<String> protocolPills = const {},
    bool isProtocolNot = false,
    Set<String> senderFilters = const {},
    bool isSenderNot = false,
    Set<String> receiverFilters = const {},
    bool isReceiverNot = false,
    Set<String> ipFilters = const {},
    int? timeStartUs,
    int? timeEndUs,
  }) {
    final (whereSql, params) = _buildWhereClauseAndParams(
      isTriageMode: isTriageMode,
      triageStatuses: triageStatuses,
      isTriageNot: isTriageNot,
      silenceLanChatter: silenceLanChatter,
      sourceSearch: isSender ? '' : sourceSearch,
      isSourceSearchNot: isSender ? false : isSourceSearchNot,
      destSearch: isSender ? destSearch : '',
      isDestSearchNot: isSender ? isDestSearchNot : false,
      protocolPills: protocolPills,
      isProtocolNot: isProtocolNot,
      senderFilters: isSender ? const {} : senderFilters,
      isSenderNot: isSender ? false : isSenderNot,
      receiverFilters: isSender ? receiverFilters : const {},
      isReceiverNot: isSender ? isReceiverNot : false,
      ipFilters: ipFilters,
      timeStartUs: timeStartUs,
      timeEndUs: timeEndUs,
    );

    final ipCol = isSender ? 'src_ip' : 'dst_ip';
    final portCol = isSender ? 'src_port' : 'dst_port';
    final endpointClause = port != null ? '$ipCol = ? AND $portCol = ?' : '$ipCol = ?';
    final fullWhere = whereSql.isNotEmpty ? '$whereSql AND ($endpointClause)' : 'WHERE $endpointClause';
    params.add(ip);
    if (port != null) params.add(port);

    final rows = _db.select('SELECT COUNT(*) as cnt FROM packets $fullWhere', params);
    return (rows.firstOrNull?['cnt'] as int?) ?? 0;
  }

  Map<int, double> queryPortBandwidth({int limit = 10}) {
    final range = _db.select('SELECT MIN(timestamp_us) as min_ts, MAX(timestamp_us) as max_ts FROM packets');
    if (range.isEmpty || range.first['min_ts'] == null || range.first['max_ts'] == null) {
      return {};
    }
    final minTs = range.first['min_ts'] as int;
    final maxTs = range.first['max_ts'] as int;
    final durationSec = (maxTs - minTs) > 0 ? (maxTs - minTs) / 1000000.0 : 1.0;

    final rows = _db.select('''
      SELECT
        COALESCE(dst_port, src_port) as port,
        SUM(captured_length) as total_bytes
      FROM packets
      WHERE COALESCE(dst_port, src_port) IS NOT NULL
      GROUP BY port
      ORDER BY total_bytes DESC
      LIMIT $limit
    ''');

    final result = <int, double>{};
    for (final r in rows) {
      final port = r['port'] as int;
      final bytes = (r['total_bytes'] as int?) ?? 0;
      final bps = (bytes * 8.0) / durationSec;
      result[port] = bps;
    }
    return result;
  }

  double queryCaptureBandwidthBps() {
    final res = _db.select('SELECT MIN(timestamp_us) as min_ts, MAX(timestamp_us) as max_ts, SUM(captured_length) as total_bytes FROM packets');
    if (res.isEmpty || res.first['min_ts'] == null || res.first['max_ts'] == null) {
      return 0.0;
    }
    final minTs = res.first['min_ts'] as int;
    final maxTs = res.first['max_ts'] as int;
    final totalBytes = (res.first['total_bytes'] as int?) ?? 0;
    final durationSec = (maxTs - minTs) > 0 ? (maxTs - minTs) / 1000000.0 : 1.0;
    return (totalBytes * 8.0) / durationSec;
  }

  Map<TriageStatus, int> queryTriageCounts({
    bool silenceLanChatter = false,
    String sourceSearch = '',
    bool isSourceSearchNot = false,
    String destSearch = '',
    bool isDestSearchNot = false,
    Set<String> protocolPills = const {},
    bool isProtocolNot = false,
    Set<String> senderFilters = const {},
    bool isSenderNot = false,
    Set<String> receiverFilters = const {},
    bool isReceiverNot = false,
    Set<String> ipFilters = const {},
    int? timeStartUs,
    int? timeEndUs,
  }) {
    final (whereSql, params) = _buildWhereClauseAndParams(
      isTriageMode: true,
      triageStatuses: const {
        TriageStatus.expected,
        TriageStatus.unclassified,
        TriageStatus.unexpected,
      },
      isTriageNot: false,
      silenceLanChatter: silenceLanChatter,
      sourceSearch: sourceSearch,
      isSourceSearchNot: isSourceSearchNot,
      destSearch: destSearch,
      isDestSearchNot: isDestSearchNot,
      protocolPills: protocolPills,
      isProtocolNot: isProtocolNot,
      senderFilters: senderFilters,
      isSenderNot: isSenderNot,
      receiverFilters: receiverFilters,
      isReceiverNot: isReceiverNot,
      ipFilters: ipFilters,
      timeStartUs: timeStartUs,
      timeEndUs: timeEndUs,
    );

    final sql = '''
      SELECT triage_status, COUNT(*) as cnt
      FROM packets
      $whereSql
      GROUP BY triage_status
    ''';
    final rows = _db.select(sql, params);
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

  /// Retroactively updates all packets according to custom protocol rules,
  /// honoring rule specificity (Tier 2 magic bytes before Tier 1 generic port catch-alls).
  int relabelAllCustomProtocols(List<CustomProtocolRule> rules) {
    if (rules.isEmpty) {
      _db.execute('''
        UPDATE packets
        SET detected_protocol = CASE
          WHEN ip_proto = 6 THEN 'TCP'
          WHEN ip_proto = 17 THEN 'UDP'
          WHEN ip_proto = 1 THEN 'ICMP'
          ELSE 'IP'
        END,
        custom_protocol_id = NULL
        WHERE custom_protocol_id IS NOT NULL
      ''');
      buildFlowsAndBuckets();
      return 0;
    }

    // Sort rules by specificity (Tier 2 magic bytes rules first)
    final sortedRules = List<CustomProtocolRule>.from(rules)
      ..sort((a, b) => b.specificityScore.compareTo(a.specificityScore));

    final rows = _db.select('''
      SELECT packet_no, ip_proto, src_port, dst_port, src_ip, dst_ip, payload_preview, summary, detected_protocol, custom_protocol_id
      FROM packets
    ''');

    int updatedCount = 0;
    _db.execute('BEGIN TRANSACTION');
    try {
      final updateStmt = _db.prepare('''
        UPDATE packets
        SET detected_protocol = ?, custom_protocol_id = ?, triage_status = ?, summary = ?
        WHERE packet_no = ?
      ''');

      for (final row in rows) {
        final packetNo = row['packet_no'] as int;
        final ipProto = row['ip_proto'] as int;
        final srcPort = row['src_port'] as int?;
        final dstPort = row['dst_port'] as int?;
        final srcIp = row['src_ip'] as String;
        final dstIp = row['dst_ip'] as String;
        final originalSummary = row['summary'] as String;
        final currentProto = row['detected_protocol'] as String;
        final currentCustomId = row['custom_protocol_id'] as String?;

        final blob = row['payload_preview'];
        final List<int> preview;
        if (blob is List<int>) {
          preview = blob;
        } else if (blob is Uint8List) {
          preview = blob.toList();
        } else {
          preview = const [];
        }

        CustomProtocolRule? matchedRule;
        for (final rule in sortedRules) {
          if (rule.matches(
            ipProto: ipProto,
            srcPort: srcPort,
            dstPort: dstPort,
            srcIp: srcIp,
            dstIp: dstIp,
            payload: preview,
          )) {
            matchedRule = rule;
            break;
          }
        }

        if (matchedRule != null) {
          String newSummary = originalSummary;
          final fields = matchedRule.extractFieldValues(preview);
          if (fields.isNotEmpty) {
            final fieldsStr = fields.entries.map((e) => '${e.key}=${e.value}').join(', ');
            newSummary = '${matchedRule.name} [$fieldsStr]';
          } else if (!newSummary.startsWith(matchedRule.name)) {
            newSummary = '$srcPort → $dstPort [${matchedRule.name}] Len=${preview.length}';
          }

          updateStmt.execute([
            matchedRule.name,
            matchedRule.id,
            matchedRule.defaultTriageStatus.name,
            newSummary,
            packetNo,
          ]);
          if (currentProto != matchedRule.name || currentCustomId != matchedRule.id) {
            updatedCount++;
          }
        }
      }
      updateStmt.close();
      _db.execute('COMMIT');
    } catch (e) {
      _db.execute('ROLLBACK');
      rethrow;
    }

    buildFlowsAndBuckets();
    return updatedCount;
  }

  /// Retroactively updates matching packets when a rule is added or modified.
  int relabelCustomProtocol(CustomProtocolRule rule, [List<CustomProtocolRule>? allRules]) {
    final rules = allRules ?? [rule];
    return relabelAllCustomProtocols(rules);
  }

  /// Re-evaluates triage status for all packets based on the updated baseline profile and custom rules.
  int reclassifyWithBaseline(BaselineProfile profile, List<CustomProtocolRule> customRules) {
    final rows = _db.select(
      'SELECT packet_no, src_ip, dst_ip, detected_protocol, is_lan_noise, custom_protocol_id FROM packets',
    );
    if (rows.isEmpty) return 0;

    final ruleMap = {for (final r in customRules) r.id: r};

    _db.execute('BEGIN TRANSACTION');
    try {
      final stmt = _db.prepare('UPDATE packets SET triage_status = ? WHERE packet_no = ?');
      for (final row in rows) {
        final packetNo = row['packet_no'] as int;
        final srcIp = row['src_ip'] as String;
        final dstIp = row['dst_ip'] as String;
        final detectedProtocol = row['detected_protocol'] as String;
        final isLanNoise = (row['is_lan_noise'] as int) == 1;
        final customId = row['custom_protocol_id'] as String?;
        final defaultStatus = (customId != null && ruleMap.containsKey(customId))
            ? ruleMap[customId]!.defaultTriageStatus
            : TriageStatus.unclassified;

        final newStatus = profile.evaluateTriage(
          srcIp: srcIp,
          dstIp: dstIp,
          detectedProtocol: detectedProtocol,
          isLanNoise: isLanNoise,
          defaultRuleStatus: defaultStatus,
        );

        stmt.execute([newStatus.name, packetNo]);
      }
      stmt.close();
      _db.execute('COMMIT');
    } catch (e) {
      _db.execute('ROLLBACK');
      rethrow;
    }

    buildFlowsAndBuckets();
    return rows.length;
  }

  /// Directly updates the triage status of an individual packet.
  void updatePacketTriage(int packetNo, TriageStatus status) {
    _db.execute('UPDATE packets SET triage_status = ? WHERE packet_no = ?', [status.name, packetNo]);
    buildFlowsAndBuckets();
  }

  void close() {
    _db.close();
  }
}
