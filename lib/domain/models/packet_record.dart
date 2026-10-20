import 'dart:typed_data';

enum TriageStatus {
  expected,
  unclassified,
  unexpected;

  String get displayName {
    switch (this) {
      case TriageStatus.expected:
        return 'Expected';
      case TriageStatus.unclassified:
        return 'Unclassified';
      case TriageStatus.unexpected:
        return 'Unexpected';
    }
  }

  static TriageStatus fromString(String? value) {
    switch (value?.toLowerCase()) {
      case 'expected':
        return TriageStatus.expected;
      case 'unexpected':
        return TriageStatus.unexpected;
      case 'unclassified':
      default:
        return TriageStatus.unclassified;
    }
  }
}

class PacketRecord {
  const PacketRecord({
    required this.packetNo,
    required this.timestampUs,
    required this.globalDeltaUs,
    required this.streamDeltaUs,
    required this.flowHash,
    required this.ethType,
    required this.srcIp,
    required this.dstIp,
    required this.ipProto,
    required this.srcPort,
    required this.dstPort,
    required this.detectedProtocol,
    required this.capturedLength,
    required this.originalLength,
    required this.fileByteOffset,
    required this.payloadFileOffset,
    required this.payloadLength,
    required this.payloadPreview,
    required this.summary,
    required this.triageStatus,
    required this.isLanNoise,
    this.customProtocolId,
    this.customFields = const {},
  });

  final int packetNo;
  final int timestampUs;
  final int globalDeltaUs;
  final int streamDeltaUs;
  final int flowHash;
  final int ethType;
  final String srcIp;
  final String dstIp;
  final int ipProto; // 1=ICMP, 6=TCP, 17=UDP, etc.
  final int? srcPort;
  final int? dstPort;
  final String detectedProtocol;
  final int capturedLength;
  final int originalLength;
  final int fileByteOffset;
  final int payloadFileOffset;
  final int payloadLength;
  final List<int> payloadPreview; // First up to 64 bytes for instant magic-byte matching
  final String summary;
  final TriageStatus triageStatus;
  final bool isLanNoise;
  final String? customProtocolId;
  final Map<String, dynamic> customFields;

  double get timestampSeconds => timestampUs / 1000000.0;
  double get globalDeltaMs => globalDeltaUs / 1000.0;
  double get streamDeltaMs => streamDeltaUs / 1000.0;

  DateTime get dateTime => DateTime.fromMicrosecondsSinceEpoch(timestampUs);

  String get formattedDateTime {
    final dt = DateTime.fromMicrosecondsSinceEpoch(timestampUs);
    final y = dt.year.toString().padLeft(4, '0');
    final m = dt.month.toString().padLeft(2, '0');
    final d = dt.day.toString().padLeft(2, '0');
    final h = dt.hour.toString().padLeft(2, '0');
    final min = dt.minute.toString().padLeft(2, '0');
    final s = dt.second.toString().padLeft(2, '0');
    final ms = dt.millisecond.toString().padLeft(3, '0');
    return '$y-$m-$d $h:$min:$s.$ms';
  }

  Map<String, dynamic> toMap() {
    return {
      'packet_no': packetNo,
      'timestamp_us': timestampUs,
      'global_delta_us': globalDeltaUs,
      'stream_delta_us': streamDeltaUs,
      'flow_hash': flowHash,
      'eth_type': ethType,
      'src_ip': srcIp,
      'dst_ip': dstIp,
      'ip_proto': ipProto,
      'src_port': srcPort,
      'dst_port': dstPort,
      'detected_protocol': detectedProtocol,
      'captured_length': capturedLength,
      'original_length': originalLength,
      'file_byte_offset': fileByteOffset,
      'payload_file_offset': payloadFileOffset,
      'payload_length': payloadLength,
      'payload_preview': Uint8List.fromList(payloadPreview),
      'summary': summary,
      'triage_status': triageStatus.name,
      'is_lan_noise': isLanNoise ? 1 : 0,
      'custom_protocol_id': customProtocolId,
    };
  }

  factory PacketRecord.fromMap(Map<String, dynamic> map) {
    final previewRaw = map['payload_preview'];
    final List<int> preview;
    if (previewRaw is List<int>) {
      preview = previewRaw;
    } else if (previewRaw is Uint8List) {
      preview = previewRaw.toList();
    } else {
      preview = const [];
    }

    return PacketRecord(
      packetNo: map['packet_no'] as int,
      timestampUs: map['timestamp_us'] as int,
      globalDeltaUs: map['global_delta_us'] as int? ?? 0,
      streamDeltaUs: map['stream_delta_us'] as int? ?? 0,
      flowHash: map['flow_hash'] as int? ?? 0,
      ethType: map['eth_type'] as int? ?? 0x0800,
      srcIp: map['src_ip'] as String? ?? '',
      dstIp: map['dst_ip'] as String? ?? '',
      ipProto: map['ip_proto'] as int? ?? 0,
      srcPort: map['src_port'] as int?,
      dstPort: map['dst_port'] as int?,
      detectedProtocol: map['detected_protocol'] as String? ?? 'UNKNOWN',
      capturedLength: map['captured_length'] as int? ?? 0,
      originalLength: map['original_length'] as int? ?? 0,
      fileByteOffset: map['file_byte_offset'] as int? ?? 0,
      payloadFileOffset: map['payload_file_offset'] as int? ?? 0,
      payloadLength: map['payload_length'] as int? ?? 0,
      payloadPreview: preview,
      summary: map['summary'] as String? ?? '',
      triageStatus: TriageStatus.fromString(map['triage_status'] as String?),
      isLanNoise: (map['is_lan_noise'] as int? ?? 0) == 1,
      customProtocolId: map['custom_protocol_id'] as String?,
    );
  }

  PacketRecord copyWith({
    int? packetNo,
    int? timestampUs,
    int? globalDeltaUs,
    int? streamDeltaUs,
    int? flowHash,
    int? ethType,
    String? srcIp,
    String? dstIp,
    int? ipProto,
    int? srcPort,
    int? dstPort,
    String? detectedProtocol,
    int? capturedLength,
    int? originalLength,
    int? fileByteOffset,
    int? payloadFileOffset,
    int? payloadLength,
    List<int>? payloadPreview,
    String? summary,
    TriageStatus? triageStatus,
    bool? isLanNoise,
    String? customProtocolId,
    Map<String, dynamic>? customFields,
  }) {
    return PacketRecord(
      packetNo: packetNo ?? this.packetNo,
      timestampUs: timestampUs ?? this.timestampUs,
      globalDeltaUs: globalDeltaUs ?? this.globalDeltaUs,
      streamDeltaUs: streamDeltaUs ?? this.streamDeltaUs,
      flowHash: flowHash ?? this.flowHash,
      ethType: ethType ?? this.ethType,
      srcIp: srcIp ?? this.srcIp,
      dstIp: dstIp ?? this.dstIp,
      ipProto: ipProto ?? this.ipProto,
      srcPort: srcPort ?? this.srcPort,
      dstPort: dstPort ?? this.dstPort,
      detectedProtocol: detectedProtocol ?? this.detectedProtocol,
      capturedLength: capturedLength ?? this.capturedLength,
      originalLength: originalLength ?? this.originalLength,
      fileByteOffset: fileByteOffset ?? this.fileByteOffset,
      payloadFileOffset: payloadFileOffset ?? this.payloadFileOffset,
      payloadLength: payloadLength ?? this.payloadLength,
      payloadPreview: payloadPreview ?? this.payloadPreview,
      summary: summary ?? this.summary,
      triageStatus: triageStatus ?? this.triageStatus,
      isLanNoise: isLanNoise ?? this.isLanNoise,
      customProtocolId: customProtocolId ?? this.customProtocolId,
      customFields: customFields ?? this.customFields,
    );
  }
}
