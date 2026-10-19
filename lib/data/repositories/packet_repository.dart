import 'dart:io';
import 'dart:typed_data';
import '../../../domain/models/packet_record.dart';
import '../../../domain/models/custom_protocol_rule.dart';
import '../../../domain/models/baseline_profile.dart';
import '../../../domain/models/timeline_bucket.dart';
import '../services/database/packet_database_service.dart';
import '../services/parser/pcap_binary_reader.dart';
import '../services/parser/packet_dissector.dart';
import '../services/parser/demo_pcap_generator.dart';
import '../services/storage/protocol_library_service.dart';

class IngestProgress {
  const IngestProgress({
    required this.packetsProcessed,
    required this.totalBytes,
    required this.isDone,
  });
  final int packetsProcessed;
  final int totalBytes;
  final bool isDone;
}

class PacketRepository {
  PacketRepository({
    PacketDatabaseService? dbService,
    ProtocolLibraryService? storageService,
  })  : _dbService = dbService ?? PacketDatabaseService(),
        _storageService = storageService ?? ProtocolLibraryService() {
    _customRules = _storageService.loadCustomProtocols();
    _baselineProfile = _storageService.loadBaselineProfile();
  }

  PacketDatabaseService _dbService;
  final ProtocolLibraryService _storageService;

  List<CustomProtocolRule> _customRules = [];
  BaselineProfile _baselineProfile = const BaselineProfile(
    id: 'default',
    name: 'Default Baseline Profile',
    silenceLanChatter: true,
  );

  String? _loadedFilePath;
  Uint8List? _inMemoryBuffer;

  List<CustomProtocolRule> get customRules => List.unmodifiable(_customRules);
  BaselineProfile get baselineProfile => _baselineProfile;
  PacketDatabaseService get dbService => _dbService;
  String? get loadedFilePath => _loadedFilePath;

  /// Loads a demo PCAP entirely in memory for instant inspection and tests.
  void loadDemoCapture() {
    final bytes = DemoPcapGenerator.generateClassicPcap();
    loadFromBytes(bytes, 'demo_capture.pcap');
  }

  /// Ingests a PCAP or PCAPNG buffer directly from memory.
  void loadFromBytes(Uint8List bytes, [String filename = 'capture.pcap']) {
    _inMemoryBuffer = bytes;
    _loadedFilePath = filename;

    _resetDatabase();

    final rawPackets = PcapBinaryReader.parseBytes(bytes);
    _processRawPackets(rawPackets);
  }

  /// Ingests a PCAP or PCAPNG file from disk.
  void loadFromFile(File file) {
    _loadedFilePath = file.path;
    _inMemoryBuffer = null;

    _resetDatabase();

    final rawPackets = PcapBinaryReader.parseFile(file);
    _processRawPackets(rawPackets);
  }

  void _resetDatabase() {
    _dbService.close();
    _dbService = PacketDatabaseService();
  }

  void _processRawPackets(List<RawCapturedPacket> rawPackets) {
    if (rawPackets.isEmpty) return;

    final records = <PacketRecord>[];
    int lastTimestampUs = rawPackets.first.timestampUs;
    final lastFlowTsMap = <int, int>{};

    for (final raw in rawPackets) {
      // 1. Calculate Global Delta (time since previous packet in capture)
      final globalDeltaUs = raw.timestampUs - lastTimestampUs;
      lastTimestampUs = raw.timestampUs;

      // 2. Dissect L2-L7 headers and match custom rules
      final info = PacketDissector.dissect(
        rawPacket: raw,
        customRules: _customRules,
      );

      // 3. Calculate 5-Tuple Stream Delta (time since previous packet in this conversation)
      final prevFlowTs = lastFlowTsMap[info.flowHash];
      final int streamDeltaUs = (prevFlowTs != null) ? (raw.timestampUs - prevFlowTs) : 0;
      lastFlowTsMap[info.flowHash] = raw.timestampUs;

      // 4. Initial Triage classification based on baseline profile
      final triageStatus = _baselineProfile.evaluateTriage(
        srcIp: info.srcIp,
        dstIp: info.dstIp,
        detectedProtocol: info.detectedProtocol,
        isLanNoise: info.isLanNoise,
      );

      records.add(PacketRecord(
        packetNo: raw.packetNo,
        timestampUs: raw.timestampUs,
        globalDeltaUs: globalDeltaUs >= 0 ? globalDeltaUs : 0,
        streamDeltaUs: streamDeltaUs >= 0 ? streamDeltaUs : 0,
        flowHash: info.flowHash,
        ethType: info.ethType,
        srcIp: info.srcIp,
        dstIp: info.dstIp,
        ipProto: info.ipProto,
        srcPort: info.srcPort,
        dstPort: info.dstPort,
        detectedProtocol: info.detectedProtocol,
        capturedLength: raw.capturedLength,
        originalLength: raw.originalLength,
        fileByteOffset: raw.fileByteOffset,
        payloadFileOffset: raw.fileByteOffset + info.payloadOffsetInPacket,
        payloadLength: info.payloadLength,
        payloadPreview: info.payloadPreview,
        summary: info.summary,
        triageStatus: triageStatus,
        isLanNoise: info.isLanNoise,
        customProtocolId: info.customProtocolId,
        customFields: info.customFields,
      ));
    }

    _dbService.insertPacketsBatch(records);
    _dbService.buildFlowsAndBuckets();
  }

  /// Reads the raw frame bytes or L4 payload bytes for a specific packet on demand.
  Uint8List readRawPacketBytes(PacketRecord packet, {bool payloadOnly = false}) {
    final Uint8List sourceBytes;
    if (_inMemoryBuffer != null) {
      sourceBytes = _inMemoryBuffer!;
    } else if (_loadedFilePath != null && File(_loadedFilePath!).existsSync()) {
      sourceBytes = File(_loadedFilePath!).readAsBytesSync();
    } else {
      return Uint8List(0);
    }

    if (payloadOnly) {
      final offset = packet.payloadFileOffset;
      final length = packet.payloadLength;
      if (offset >= sourceBytes.length || length <= 0) return Uint8List(0);
      final readLen = (offset + length <= sourceBytes.length) ? length : (sourceBytes.length - offset);
      return sourceBytes.sublist(offset, offset + readLen);
    } else {
      final offset = packet.fileByteOffset;
      final length = packet.capturedLength;
      if (offset >= sourceBytes.length) return Uint8List(0);
      final readLen = (offset + length <= sourceBytes.length) ? length : (sourceBytes.length - offset);
      return sourceBytes.sublist(offset, offset + readLen);
    }
  }

  /// Adds a new custom protocol rule, immediately re-labeling matching packets in SQLite!
  int addCustomProtocol(CustomProtocolRule rule) {
    _customRules = [
      ..._customRules.where((r) => r.id != rule.id),
      rule,
    ];
    _storageService.saveCustomProtocols(_customRules);
    return _dbService.relabelCustomProtocol(rule);
  }

  void updateBaselineProfile(BaselineProfile profile) {
    _baselineProfile = profile;
    _storageService.saveBaselineProfile(profile);
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
    return _dbService.queryPackets(
      offset: offset,
      limit: limit,
      isTriageMode: isTriageMode,
      triageStatuses: triageStatuses,
      silenceLanChatter: silenceLanChatter,
      protocolPills: protocolPills,
      ipFilters: ipFilters,
      timeStartUs: timeStartUs,
      timeEndUs: timeEndUs,
    );
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
    return _dbService.getPacketCount(
      isTriageMode: isTriageMode,
      triageStatuses: triageStatuses,
      silenceLanChatter: silenceLanChatter,
      protocolPills: protocolPills,
      ipFilters: ipFilters,
      timeStartUs: timeStartUs,
      timeEndUs: timeEndUs,
    );
  }

  List<TimelineBucket> getTimelineBuckets() => _dbService.queryTimelineBuckets();

  Map<String, int> getProtocolCounts() => _dbService.queryProtocolCounts();

  Map<TriageStatus, int> getTriageCounts({bool silenceLanChatter = false}) =>
      _dbService.queryTriageCounts(silenceLanChatter: silenceLanChatter);

  List<FlowSummary> getFlows({int limit = 100}) => _dbService.queryFlows(limit: limit);

  List<Map<String, dynamic>> getTopTalkers({
    required String metric,
    required int limit,
    bool onlyUnexpected = false,
  }) {
    return _dbService.queryTopTalkers(
      metric: metric,
      limit: limit,
      onlyUnexpected: onlyUnexpected,
    );
  }

  List<PacketRecord> getTimingAnomalies({
    required bool isBurst,
    required int thresholdUs,
    int limit = 20,
  }) {
    return _dbService.queryTimingAnomalies(
      isBurst: isBurst,
      thresholdUs: thresholdUs,
      limit: limit,
    );
  }

  void dispose() {
    _dbService.close();
  }
}
