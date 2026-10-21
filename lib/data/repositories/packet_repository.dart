import 'dart:io';
import 'dart:typed_data';
import '../../../domain/models/packet_record.dart';
import '../../../domain/models/custom_protocol_rule.dart';
import '../../../domain/models/baseline_profile.dart';
import '../../../domain/models/timeline_bucket.dart';
import '../../../domain/models/endpoint_rule.dart';
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
    _senders = _storageService.loadSenders();
    _receivers = _storageService.loadReceivers();
  }

  PacketDatabaseService _dbService;
  final ProtocolLibraryService _storageService;

  List<CustomProtocolRule> _customRules = [];
  List<EndpointRule> _senders = [];
  List<EndpointRule> _receivers = [];
  BaselineProfile _baselineProfile = const BaselineProfile(
    id: 'default',
    name: 'Default Baseline Profile',
    silenceLanChatter: true,
  );

  String? _loadedFilePath;
  Uint8List? _inMemoryBuffer;

  List<CustomProtocolRule> get customRules => List.unmodifiable(_customRules);
  List<EndpointRule> get senders => List.unmodifiable(_senders);
  List<EndpointRule> get receivers => List.unmodifiable(_receivers);
  List<EndpointRule> get sources => senders;
  List<EndpointRule> get destinations => receivers;
  BaselineProfile get baselineProfile => _baselineProfile;
  PacketDatabaseService get dbService => _dbService;
  ProtocolLibraryService get storageService => _storageService;
  String? get loadedFilePath => _loadedFilePath;

  void addSender(EndpointRule sender) {
    _senders = [..._senders.where((s) => s.id != sender.id), sender];
    _storageService.saveSenders(_senders);
  }

  void addSource(EndpointRule source) => addSender(source);
  void updateSource(EndpointRule source) => updateSender(source);
  void deleteSource(String id) => deleteSender(id);

  void updateSender(EndpointRule sender) {
    _senders = _senders.map((s) => s.id == sender.id ? sender : s).toList();
    if (!_senders.any((s) => s.id == sender.id)) {
      _senders.add(sender);
    }
    _storageService.saveSenders(_senders);
  }

  void updateSenders(List<EndpointRule> senders) {
    _senders = List.from(senders);
    _storageService.saveSenders(_senders);
  }

  void deleteSender(String id) {
    _senders = _senders.where((s) => s.id != id).toList();
    _storageService.saveSenders(_senders);
  }

  void addReceiver(EndpointRule receiver) {
    _receivers = [..._receivers.where((r) => r.id != receiver.id), receiver];
    _storageService.saveReceivers(_receivers);
  }

  void addDestination(EndpointRule destination) => addReceiver(destination);
  void updateDestination(EndpointRule destination) => updateReceiver(destination);
  void deleteDestination(String id) => deleteReceiver(id);

  String exportLibraryBundle() {
    return _storageService.exportLibraryBundleJson(
      protocols: _customRules,
      sources: _senders,
      destinations: _receivers,
    );
  }

  Map<String, int> importLibraryBundle(String jsonStr) {
    final parsed = _storageService.importLibraryBundleJson(jsonStr);
    final newProtos = parsed['protocols'] as List<CustomProtocolRule>;
    final newSources = parsed['sources'] as List<EndpointRule>;
    final newDests = parsed['destinations'] as List<EndpointRule>;

    int importedProtos = 0;
    if (newProtos.isNotEmpty) {
      final existingIds = _customRules.map((r) => r.id).toSet();
      final updatedList = List<CustomProtocolRule>.from(_customRules);
      for (final p in newProtos) {
        if (!existingIds.contains(p.id)) {
          updatedList.add(p);
        } else {
          final idx = updatedList.indexWhere((r) => r.id == p.id);
          if (idx != -1) updatedList[idx] = p;
        }
        importedProtos++;
      }
      _customRules = updatedList;
      _storageService.saveCustomProtocols(_customRules);
      _dbService.relabelAllCustomProtocols(_customRules);
    }

    int importedSources = 0;
    if (newSources.isNotEmpty) {
      final existingIds = _senders.map((s) => s.id).toSet();
      final updatedList = List<EndpointRule>.from(_senders);
      for (final s in newSources) {
        if (!existingIds.contains(s.id)) {
          updatedList.add(s);
        } else {
          final idx = updatedList.indexWhere((r) => r.id == s.id);
          if (idx != -1) updatedList[idx] = s;
        }
        importedSources++;
      }
      _senders = updatedList;
      _storageService.saveSenders(_senders);
    }

    int importedDests = 0;
    if (newDests.isNotEmpty) {
      final existingIds = _receivers.map((r) => r.id).toSet();
      final updatedList = List<EndpointRule>.from(_receivers);
      for (final d in newDests) {
        if (!existingIds.contains(d.id)) {
          updatedList.add(d);
        } else {
          final idx = updatedList.indexWhere((r) => r.id == d.id);
          if (idx != -1) updatedList[idx] = d;
        }
        importedDests++;
      }
      _receivers = updatedList;
      _storageService.saveReceivers(_receivers);
    }

    return {
      'protocols': importedProtos,
      'sources': importedSources,
      'destinations': importedDests,
    };
  }

  void updateReceiver(EndpointRule receiver) {
    _receivers = _receivers.map((r) => r.id == receiver.id ? receiver : r).toList();
    if (!_receivers.any((r) => r.id == receiver.id)) {
      _receivers.add(receiver);
    }
    _storageService.saveReceivers(_receivers);
  }

  void updateReceivers(List<EndpointRule> receivers) {
    _receivers = List.from(receivers);
    _storageService.saveReceivers(_receivers);
  }

  void deleteReceiver(String id) {
    _receivers = _receivers.where((r) => r.id != id).toList();
    _storageService.saveReceivers(_receivers);
  }

  Map<String, int> getTopSenders({int limit = 15}) =>
      _dbService.queryTopSenders(limit: limit);

  Map<String, int> getTopReceivers({int limit = 15}) =>
      _dbService.queryTopReceivers(limit: limit);

  int countPacketsForEndpoint({
    required String ip,
    int? port,
    required bool isSender,
  }) =>
      _dbService.countPacketsForEndpoint(ip: ip, port: port, isSender: isSender);

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
    return _dbService.relabelAllCustomProtocols(_customRules);
  }

  /// Deletes a custom protocol rule and retroactively re-evaluates remaining rules.
  int deleteCustomProtocol(String ruleId) {
    _customRules = _customRules.where((r) => r.id != ruleId).toList();
    _storageService.saveCustomProtocols(_customRules);
    return _dbService.relabelAllCustomProtocols(_customRules);
  }

  /// Bulk updates all custom protocol rules.
  int updateCustomProtocols(List<CustomProtocolRule> rules) {
    _customRules = List.from(rules);
    _storageService.saveCustomProtocols(_customRules);
    return _dbService.relabelAllCustomProtocols(_customRules);
  }

  void updateBaselineProfile(BaselineProfile profile) {
    _baselineProfile = profile;
    _storageService.saveBaselineProfile(profile);
    _dbService.reclassifyWithBaseline(profile, _customRules);
  }

  void setPacketTriage(int packetNo, TriageStatus status) {
    _dbService.updatePacketTriage(packetNo, status);
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
    Set<String> senderFilters = const {},
    Set<String> receiverFilters = const {},
    Set<String> ipFilters = const {},
    int? timeStartUs,
    int? timeEndUs,
    String sortColumn = 'packet_no',
    bool sortAscending = true,
  }) {
    return _dbService.queryPackets(
      offset: offset,
      limit: limit,
      isTriageMode: isTriageMode,
      triageStatuses: triageStatuses,
      silenceLanChatter: silenceLanChatter,
      protocolPills: protocolPills,
      senderFilters: senderFilters,
      receiverFilters: receiverFilters,
      ipFilters: ipFilters,
      timeStartUs: timeStartUs,
      timeEndUs: timeEndUs,
      sortColumn: sortColumn,
      sortAscending: sortAscending,
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
    Set<String> senderFilters = const {},
    Set<String> receiverFilters = const {},
    Set<String> ipFilters = const {},
    int? timeStartUs,
    int? timeEndUs,
  }) {
    return _dbService.getPacketCount(
      isTriageMode: isTriageMode,
      triageStatuses: triageStatuses,
      silenceLanChatter: silenceLanChatter,
      protocolPills: protocolPills,
      senderFilters: senderFilters,
      receiverFilters: receiverFilters,
      ipFilters: ipFilters,
      timeStartUs: timeStartUs,
      timeEndUs: timeEndUs,
    );
  }

  List<TimelineBucket> getTimelineBuckets() => _dbService.queryTimelineBuckets();

  Map<int, double> getPortBandwidth({int limit = 10}) => _dbService.queryPortBandwidth(limit: limit);

  double getCaptureBandwidthBps() => _dbService.queryCaptureBandwidthBps();

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
