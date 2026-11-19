import 'dart:io';
import 'dart:typed_data';
import 'package:material_ui/material_ui.dart';
import '../../../../domain/models/packet_record.dart';
import '../../../../domain/models/custom_protocol_rule.dart';
import '../../../../domain/models/endpoint_rule.dart';
import '../../../../domain/models/baseline_profile.dart';
import '../../../../domain/models/timeline_bucket.dart';
import '../../../../data/repositories/packet_repository.dart';
import '../../../../data/services/export/csv_export_service.dart';
import '../../../../data/services/storage/ai_settings_storage_service.dart';
import '../../../../data/services/ai/llm_provider_service.dart';
import '../../../../data/services/ai/packet_ai_tools.dart';

class InspectorViewModel extends ChangeNotifier {
  InspectorViewModel({
    PacketRepository? repository,
    AiSettingsStorageService? aiSettingsStorage,
    LlmProviderService? llmService,
  })  : _repository = repository ?? PacketRepository(),
        _aiSettingsStorage = aiSettingsStorage ??
            AiSettingsStorageService(
              storageDirectory: repository?.storageService.storageDirectory,
            ) {
    _llmService = llmService ??
        LlmProviderService(
          tools: PacketAiTools(repository: _repository),
          storageService: _aiSettingsStorage,
        );
    _refreshState();
  }

  final PacketRepository _repository;
  final AiSettingsStorageService _aiSettingsStorage;
  late final LlmProviderService _llmService;

  PacketRepository get repository => _repository;
  AiSettingsStorageService get aiSettingsStorage => _aiSettingsStorage;
  LlmProviderService get llmService => _llmService;

  bool _isTriageMode = false;
  bool _silenceLanChatter = true;
  Set<TriageStatus> _selectedTriageStatuses = {};
  bool _isTriageNot = false;

  String _sourceSearch = '';
  bool _isSourceSearchNot = false;

  String _destSearch = '';
  bool _isDestSearchNot = false;

  final Set<String> _selectedProtocolPills = {};
  bool _isProtocolNot = false;

  final Set<String> _selectedSenderKeys = {};
  bool _isSenderNot = false;

  final Set<String> _selectedReceiverKeys = {};
  bool _isReceiverNot = false;

  final Set<String> _selectedIps = {};
  int? _timeWindowStartUs;
  int? _timeWindowEndUs;

  List<PacketRecord> _packets = [];
  PacketRecord? _selectedPacket;
  Uint8List? _selectedPacketRawBytes;
  Uint8List? _selectedPacketPayloadBytes;

  List<TimelineBucket> _timelineBuckets = [];
  Map<String, int> _protocolCounts = {};
  Map<String, int> _senderCounts = {};
  Map<String, int> _receiverCounts = {};
  Map<TriageStatus, int> _triageCounts = {};
  int _totalPacketCount = 0;
  int _rawCapturePacketCount = 0;
  bool _isAiPanelOpen = false;
  bool _isLoading = false;
  bool _isDemoMode = false;

  String _sortColumn = 'packet_no';
  bool _sortAscending = true;

  static const int defaultPageSize = 1000;
  int _pageSize = defaultPageSize;
  bool _isLoadingMore = false;
  bool _hasMorePackets = false;
  bool _showAutoDetected = true;

  double _avgCaptureBandwidthBps = 0.0;
  Map<int, double> _portBandwidths = {};

  final Map<int, PacketRecord> _flaggedPackets = {};
  int? _requestScrollToPacketNo;

  // Getters
  List<PacketRecord> get flaggedPackets =>
      _flaggedPackets.values.toList()..sort((a, b) => a.timestampUs.compareTo(b.timestampUs));
  int get flaggedPacketCount => _flaggedPackets.length;
  bool isPacketFlagged(int packetNo) => _flaggedPackets.containsKey(packetNo);
  int? get requestScrollToPacketNo => _requestScrollToPacketNo;

  bool get isTriageMode => _isTriageMode;
  bool get silenceLanChatter => _silenceLanChatter;
  bool get showAutoDetected => _showAutoDetected;
  Set<TriageStatus> get selectedTriageStatuses => _selectedTriageStatuses;
  bool get isTriageNot => _isTriageNot;

  String get sourceSearch => _sourceSearch;
  bool get isSourceSearchNot => _isSourceSearchNot;

  String get destSearch => _destSearch;
  bool get isDestSearchNot => _isDestSearchNot;

  Set<String> get selectedProtocolPills => _selectedProtocolPills;
  bool get isProtocolNot => _isProtocolNot;

  Set<String> get selectedSenderKeys => _selectedSenderKeys;
  bool get isSenderNot => _isSenderNot;

  Set<String> get selectedReceiverKeys => _selectedReceiverKeys;
  bool get isReceiverNot => _isReceiverNot;

  bool get hasActiveFilters =>
      _selectedTriageStatuses.isNotEmpty ||
      _isTriageNot ||
      _sourceSearch.trim().isNotEmpty ||
      _isSourceSearchNot ||
      _destSearch.trim().isNotEmpty ||
      _isDestSearchNot ||
      _selectedProtocolPills.isNotEmpty ||
      _isProtocolNot ||
      _selectedSenderKeys.isNotEmpty ||
      _isSenderNot ||
      _selectedReceiverKeys.isNotEmpty ||
      _isReceiverNot ||
      _selectedIps.isNotEmpty ||
      _timeWindowStartUs != null ||
      _timeWindowEndUs != null;

  Set<String> get selectedIps => _selectedIps;
  int? get timeWindowStartUs => _timeWindowStartUs;
  int? get timeWindowEndUs => _timeWindowEndUs;
  List<PacketRecord> get packets => _packets;
  PacketRecord? get selectedPacket => _selectedPacket;
  Uint8List? get selectedPacketRawBytes => _selectedPacketRawBytes;
  Uint8List? get selectedPacketPayloadBytes => _selectedPacketPayloadBytes;
  List<TimelineBucket> get timelineBuckets => _timelineBuckets;
  Map<String, int> get protocolCounts => _protocolCounts;
  Map<String, int> get senderCounts => _senderCounts;
  Map<String, int> get receiverCounts => _receiverCounts;
  Map<TriageStatus, int> get triageCounts => _triageCounts;
  int get totalPacketCount => _totalPacketCount;
  int get rawCapturePacketCount => _rawCapturePacketCount;
  bool get isAiPanelOpen => _isAiPanelOpen;
  bool get isLoading => _isLoading;
  bool get isDemoMode => _isDemoMode;
  String? get loadedFileName => _repository.loadedFilePath;
  List<CustomProtocolRule> get customRules => _repository.customRules;
  List<EndpointRule> get senders => _repository.senders;
  List<EndpointRule> get receivers => _repository.receivers;
  BaselineProfile get baselineProfile => _repository.baselineProfile;
  String get sortColumn => _sortColumn;
  bool get sortAscending => _sortAscending;
  int get pageSize => _pageSize;
  bool get isLoadingMore => _isLoadingMore;
  bool get hasMorePackets => _hasMorePackets;

  double get avgCaptureBandwidthBps => _avgCaptureBandwidthBps;
  Map<int, double> get portBandwidths => _portBandwidths;
  double get peakBucketBandwidthBps {
    if (_timelineBuckets.isEmpty) return 0.0;
    return _timelineBuckets.map((b) => b.bitsPerSecond).reduce((a, b) => a > b ? a : b);
  }
  String get formattedAvgBandwidth => formatBandwidth(_avgCaptureBandwidthBps);
  String get formattedPeakBandwidth => formatBandwidth(peakBucketBandwidthBps);

  static String formatBandwidth(double bps) {
    if (bps >= 1000000.0) {
      return '${(bps / 1000000.0).toStringAsFixed(2)} Mbps';
    } else if (bps >= 1000.0) {
      return '${(bps / 1000.0).toStringAsFixed(1)} Kbps';
    } else {
      return '${bps.toStringAsFixed(0)} bps';
    }
  }

  String exportLibraryBundle() => _repository.exportLibraryBundle();

  Map<String, int> importLibraryBundle(String jsonStr) {
    final result = _repository.importLibraryBundle(jsonStr);
    _refreshState();
    notifyListeners();
    return result;
  }

  void setPageSize(int size) {
    if (size > 0 && _pageSize != size) {
      _pageSize = size;
      _refreshPackets();
      notifyListeners();
    }
  }

  void loadMorePackets() {
    if (_isLoadingMore || !_hasMorePackets) return;

    _isLoadingMore = true;
    notifyListeners();

    final nextBatch = _repository.queryPackets(
      offset: _packets.length,
      limit: _pageSize,
      triageStatuses: _selectedTriageStatuses,
      isTriageNot: _isTriageNot,
      silenceLanChatter: _silenceLanChatter,
      sourceSearch: _sourceSearch,
      isSourceSearchNot: _isSourceSearchNot,
      destSearch: _destSearch,
      isDestSearchNot: _isDestSearchNot,
      protocolPills: _selectedProtocolPills,
      isProtocolNot: _isProtocolNot,
      senderFilters: _selectedSenderKeys,
      isSenderNot: _isSenderNot,
      receiverFilters: _selectedReceiverKeys,
      isReceiverNot: _isReceiverNot,
      ipFilters: _selectedIps,
      timeStartUs: _timeWindowStartUs,
      timeEndUs: _timeWindowEndUs,
      sortColumn: _sortColumn,
      sortAscending: _sortAscending,
    );

    if (nextBatch.isNotEmpty) {
      _packets.addAll(nextBatch);
    }
    _hasMorePackets = _packets.length < _totalPacketCount;
    _isLoadingMore = false;
    notifyListeners();
  }

  void sortBy(String column) {
    if (_sortColumn == column) {
      _sortAscending = !_sortAscending;
    } else {
      _sortColumn = column;
      _sortAscending = true;
    }
    _refreshPackets();
    notifyListeners();
  }

  void loadDemoCapture() {
    _isLoading = true;
    notifyListeners();

    _repository.loadDemoCapture();
    _resetFilters();
    _refreshState();

    _isLoading = false;
    notifyListeners();
  }

  void startDemoWalkthrough() {
    _isDemoMode = true;
    loadDemoCapture();
  }

  void clearCapture() {
    _isDemoMode = false;
    _repository.clearCapture();
    _flaggedPackets.clear();
    _requestScrollToPacketNo = null;
    _resetFilters();
    _refreshState();
    notifyListeners();
  }

  void endDemoWalkthrough() => clearCapture();

  void loadFile(File file) {
    _isDemoMode = false;
    _isLoading = true;
    notifyListeners();

    _repository.loadFromFile(file);
    _resetFilters();
    _refreshState();

    _isLoading = false;
    notifyListeners();
  }

  void loadBytes(Uint8List bytes, String name) {
    _isDemoMode = false;
    _isLoading = true;
    notifyListeners();

    _repository.loadFromBytes(bytes, name);
    _resetFilters();
    _refreshState();

    _isLoading = false;
    notifyListeners();
  }

  void setTriageMode(bool enabled) {
    if (_isTriageMode != enabled) {
      _isTriageMode = enabled;
      _refreshPackets();
      notifyListeners();
    }
  }

  void setSilenceLanChatter(bool silence) {
    if (_silenceLanChatter != silence) {
      _silenceLanChatter = silence;
      _refreshPackets();
      notifyListeners();
    }
  }

  void toggleTriageStatus(TriageStatus status) {
    if (_selectedTriageStatuses.contains(status)) {
      _selectedTriageStatuses = {..._selectedTriageStatuses}..remove(status);
    } else {
      _selectedTriageStatuses = {..._selectedTriageStatuses, status};
    }
    _refreshPackets();
    notifyListeners();
  }

  void setTriageNot(bool val) {
    if (_isTriageNot != val) {
      _isTriageNot = val;
      _refreshPackets();
      notifyListeners();
    }
  }

  void setSourceSearch(String query) {
    if (_sourceSearch != query) {
      _sourceSearch = query;
      _refreshPackets();
      notifyListeners();
    }
  }

  void setSourceSearchNot(bool val) {
    if (_isSourceSearchNot != val) {
      _isSourceSearchNot = val;
      _refreshPackets();
      notifyListeners();
    }
  }

  void setDestSearch(String query) {
    if (_destSearch != query) {
      _destSearch = query;
      _refreshPackets();
      notifyListeners();
    }
  }

  void setDestSearchNot(bool val) {
    if (_isDestSearchNot != val) {
      _isDestSearchNot = val;
      _refreshPackets();
      notifyListeners();
    }
  }

  void setProtocolNot(bool val) {
    if (_isProtocolNot != val) {
      _isProtocolNot = val;
      _refreshPackets();
      notifyListeners();
    }
  }

  void setSenderNot(bool val) {
    if (_isSenderNot != val) {
      _isSenderNot = val;
      _refreshPackets();
      notifyListeners();
    }
  }

  void setReceiverNot(bool val) {
    if (_isReceiverNot != val) {
      _isReceiverNot = val;
      _refreshPackets();
      notifyListeners();
    }
  }

  void toggleProtocolPill(String proto) {
    if (_selectedProtocolPills.contains(proto)) {
      _selectedProtocolPills.remove(proto);
    } else {
      _selectedProtocolPills.add(proto);
    }
    _refreshPackets();
    notifyListeners();
  }

  void setProtocolFilter(Set<String> protocols) {
    _selectedProtocolPills.clear();
    _selectedProtocolPills.addAll(protocols);
    _refreshPackets();
    notifyListeners();
  }

  void toggleSenderPill(String key) {
    if (_selectedSenderKeys.contains(key)) {
      _selectedSenderKeys.remove(key);
    } else {
      _selectedSenderKeys.add(key);
    }
    _refreshPackets();
    notifyListeners();
  }

  void toggleReceiverPill(String key) {
    if (_selectedReceiverKeys.contains(key)) {
      _selectedReceiverKeys.remove(key);
    } else {
      _selectedReceiverKeys.add(key);
    }
    _refreshPackets();
    notifyListeners();
  }

  void clearAllFilters() {
    _selectedTriageStatuses.clear();
    _isTriageNot = false;
    _sourceSearch = '';
    _isSourceSearchNot = false;
    _destSearch = '';
    _isDestSearchNot = false;
    _selectedProtocolPills.clear();
    _isProtocolNot = false;
    _selectedSenderKeys.clear();
    _isSenderNot = false;
    _selectedReceiverKeys.clear();
    _isReceiverNot = false;
    _selectedIps.clear();
    _timeWindowStartUs = null;
    _timeWindowEndUs = null;
    _refreshPackets();
    notifyListeners();
  }

  void applyQuickFilters({
    Set<String>? protocols,
    Set<String>? senders,
    Set<String>? receivers,
  }) {
    _isTriageMode = false;
    _selectedProtocolPills.clear();
    _selectedSenderKeys.clear();
    _selectedReceiverKeys.clear();
    if (protocols != null) _selectedProtocolPills.addAll(protocols);
    if (senders != null) _selectedSenderKeys.addAll(senders);
    if (receivers != null) _selectedReceiverKeys.addAll(receivers);
    _refreshPackets();
    notifyListeners();
  }

  void setShowAutoDetected(bool show) {
    if (_showAutoDetected != show) {
      _showAutoDetected = show;
      notifyListeners();
    }
  }

  void addSender(EndpointRule rule) {
    _repository.addSender(rule);
    _selectedSenderKeys.add(rule.filterKey);
    _refreshState();
    notifyListeners();
  }

  void updateSender(EndpointRule sender) {
    _repository.updateSender(sender);
    _refreshState();
    notifyListeners();
  }

  void toggleSenderVisibility(String id) {
    final updated = _repository.senders.map((s) {
      if (s.id == id) {
        return s.copyWith(isVisible: !s.isVisible);
      }
      return s;
    }).toList();
    _repository.updateSenders(updated);
    _refreshState();
    notifyListeners();
  }

  void deleteSender(String id) {
    _repository.deleteSender(id);
    _refreshState();
    notifyListeners();
  }

  void addReceiver(EndpointRule rule) {
    _repository.addReceiver(rule);
    _selectedReceiverKeys.add(rule.filterKey);
    _refreshState();
    notifyListeners();
  }

  void updateReceiver(EndpointRule receiver) {
    _repository.updateReceiver(receiver);
    _refreshState();
    notifyListeners();
  }

  void toggleReceiverVisibility(String id) {
    final updated = _repository.receivers.map((r) {
      if (r.id == id) {
        return r.copyWith(isVisible: !r.isVisible);
      }
      return r;
    }).toList();
    _repository.updateReceivers(updated);
    _refreshState();
    notifyListeners();
  }

  void deleteReceiver(String id) {
    _repository.deleteReceiver(id);
    _refreshState();
    notifyListeners();
  }

  void setIpFilter(Set<String> ips) {
    _selectedIps.clear();
    _selectedIps.addAll(ips);
    _refreshPackets();
    notifyListeners();
  }

  void setTimeRange(int? startUs, int? endUs) {
    _timeWindowStartUs = startUs;
    _timeWindowEndUs = endUs;
    _refreshPackets();
    notifyListeners();
  }

  void resetTimeRange() {
    _timeWindowStartUs = null;
    _timeWindowEndUs = null;
    _refreshPackets();
    notifyListeners();
  }

  void selectPacket(PacketRecord? packet) {
    _selectedPacket = packet;
    if (packet != null) {
      _selectedPacketRawBytes = _repository.readRawPacketBytes(packet, payloadOnly: false);
      _selectedPacketPayloadBytes = _repository.readRawPacketBytes(packet, payloadOnly: true);
    } else {
      _selectedPacketRawBytes = null;
      _selectedPacketPayloadBytes = null;
    }
    notifyListeners();
  }

  void consumeScrollToPacketRequest() {
    _requestScrollToPacketNo = null;
  }

  void togglePacketFlag(PacketRecord packet) {
    if (_flaggedPackets.containsKey(packet.packetNo)) {
      _flaggedPackets.remove(packet.packetNo);
    } else {
      _flaggedPackets[packet.packetNo] = packet;
    }
    notifyListeners();
  }

  void clearAllFlaggedPackets() {
    _flaggedPackets.clear();
    notifyListeners();
  }

  void jumpToPacket(PacketRecord packet) {
    if (_timeWindowStartUs != null && packet.timestampUs < _timeWindowStartUs! ||
        _timeWindowEndUs != null && packet.timestampUs > _timeWindowEndUs!) {
      _timeWindowStartUs = null;
      _timeWindowEndUs = null;
      _refreshPackets();
    }
    selectPacket(packet);
    _requestScrollToPacketNo = packet.packetNo;
    notifyListeners();
  }

  void selectNextPacket() {
    if (_packets.isEmpty) return;
    if (_selectedPacket == null) {
      selectPacket(_packets.first);
      _requestScrollToPacketNo = _packets.first.packetNo;
      notifyListeners();
      return;
    }
    final currentIndex = _packets.indexWhere((p) => p.packetNo == _selectedPacket!.packetNo);
    if (currentIndex != -1 && currentIndex < _packets.length - 1) {
      final nextPacket = _packets[currentIndex + 1];
      selectPacket(nextPacket);
      _requestScrollToPacketNo = nextPacket.packetNo;
      notifyListeners();
    }
  }

  void selectPreviousPacket() {
    if (_packets.isEmpty) return;
    if (_selectedPacket == null) {
      selectPacket(_packets.last);
      _requestScrollToPacketNo = _packets.last.packetNo;
      notifyListeners();
      return;
    }
    final currentIndex = _packets.indexWhere((p) => p.packetNo == _selectedPacket!.packetNo);
    if (currentIndex > 0) {
      final prevPacket = _packets[currentIndex - 1];
      selectPacket(prevPacket);
      _requestScrollToPacketNo = prevPacket.packetNo;
      notifyListeners();
    }
  }

  void addCustomProtocol(CustomProtocolRule rule) {
    _repository.addCustomProtocol(rule);
    _selectedProtocolPills.add(rule.name);
    _refreshState();
    notifyListeners();
  }

  void deleteCustomProtocol(String ruleId) {
    _repository.deleteCustomProtocol(ruleId);
    _refreshState();
    notifyListeners();
  }

  void updateCustomProtocols(List<CustomProtocolRule> rules) {
    _repository.updateCustomProtocols(rules);
    _refreshState();
    notifyListeners();
  }

  void updateCustomProtocol(CustomProtocolRule updatedRule) {
    final rules = _repository.customRules.map((r) => r.id == updatedRule.id ? updatedRule : r).toList();
    if (!rules.any((r) => r.id == updatedRule.id)) {
      rules.add(updatedRule);
    }
    _repository.updateCustomProtocols(rules);
    _refreshState();
    notifyListeners();
  }

  void toggleProtocolVisibility(String ruleId) {
    final rules = _repository.customRules.map((r) {
      if (r.id == ruleId) {
        return r.copyWith(isVisible: !r.isVisible);
      }
      return r;
    }).toList();
    _repository.updateCustomProtocols(rules);
    _refreshState();
    notifyListeners();
  }

  void markIpExpected(String ip) {
    final updated = _repository.baselineProfile.copyWith(
      expectedIps: {..._repository.baselineProfile.expectedIps, ip},
      unexpectedIps: {..._repository.baselineProfile.unexpectedIps}..remove(ip),
    );
    _repository.updateBaselineProfile(updated);
    _refreshState();
    notifyListeners();
  }

  void markIpUnexpected(String ip) {
    final updated = _repository.baselineProfile.copyWith(
      unexpectedIps: {..._repository.baselineProfile.unexpectedIps, ip},
      expectedIps: {..._repository.baselineProfile.expectedIps}..remove(ip),
    );
    _repository.updateBaselineProfile(updated);
    _refreshState();
    notifyListeners();
  }

  void resetIpTriage(String ip) {
    final updated = _repository.baselineProfile.copyWith(
      expectedIps: {..._repository.baselineProfile.expectedIps}..remove(ip),
      unexpectedIps: {..._repository.baselineProfile.unexpectedIps}..remove(ip),
    );
    _repository.updateBaselineProfile(updated);
    _refreshState();
    notifyListeners();
  }

  void setPacketTriage(int packetNo, TriageStatus status) {
    _repository.setPacketTriage(packetNo, status);
    _refreshState();
    notifyListeners();
  }

  void toggleAiPanel() {
    _isAiPanelOpen = !_isAiPanelOpen;
    notifyListeners();
  }

  void setAiPanelOpen(bool open) {
    if (_isAiPanelOpen != open) {
      _isAiPanelOpen = open;
      notifyListeners();
    }
  }

  String exportFilteredPacketsCsv() {
    final allMatching = _repository.queryPackets(
      offset: 0,
      limit: _totalPacketCount > 0 ? _totalPacketCount : 1000000,
      triageStatuses: _selectedTriageStatuses,
      isTriageNot: _isTriageNot,
      silenceLanChatter: _silenceLanChatter,
      sourceSearch: _sourceSearch,
      isSourceSearchNot: _isSourceSearchNot,
      destSearch: _destSearch,
      isDestSearchNot: _isDestSearchNot,
      protocolPills: _selectedProtocolPills,
      isProtocolNot: _isProtocolNot,
      senderFilters: _selectedSenderKeys,
      isSenderNot: _isSenderNot,
      receiverFilters: _selectedReceiverKeys,
      isReceiverNot: _isReceiverNot,
      ipFilters: _selectedIps,
      timeStartUs: _timeWindowStartUs,
      timeEndUs: _timeWindowEndUs,
      sortColumn: _sortColumn,
      sortAscending: _sortAscending,
    );
    return CsvExportService.exportPacketsToCsv(allMatching);
  }

  String exportFlowsCsv() {
    final flows = _repository.getFlows(limit: 500);
    return CsvExportService.exportFlowsToCsv(flows);
  }

  void resetFilters() {
    _resetFilters();
    _refreshPackets();
    notifyListeners();
  }

  void _resetFilters() {
    _selectedTriageStatuses.clear();
    _isTriageNot = false;
    _sourceSearch = '';
    _isSourceSearchNot = false;
    _destSearch = '';
    _isDestSearchNot = false;
    _selectedProtocolPills.clear();
    _isProtocolNot = false;
    _selectedSenderKeys.clear();
    _isSenderNot = false;
    _selectedReceiverKeys.clear();
    _isReceiverNot = false;
    _selectedIps.clear();
    _timeWindowStartUs = null;
    _timeWindowEndUs = null;
    _selectedPacket = null;
    _selectedPacketRawBytes = null;
    _selectedPacketPayloadBytes = null;
  }

  void _refreshState() {
    _rawCapturePacketCount = _repository.getPacketCount(silenceLanChatter: false);
    _timelineBuckets = _repository.getTimelineBuckets();
    _avgCaptureBandwidthBps = _repository.getCaptureBandwidthBps();
    _portBandwidths = _repository.getPortBandwidth(limit: 10);
    _refreshPackets();
  }

  void _updateFilterCounts() {
    // 1. Triage counts
    _triageCounts = _repository.getTriageCounts(
      silenceLanChatter: _silenceLanChatter,
      sourceSearch: _sourceSearch,
      isSourceSearchNot: _isSourceSearchNot,
      destSearch: _destSearch,
      isDestSearchNot: _isDestSearchNot,
      protocolPills: _selectedProtocolPills,
      isProtocolNot: _isProtocolNot,
      senderFilters: _selectedSenderKeys,
      isSenderNot: _isSenderNot,
      receiverFilters: _selectedReceiverKeys,
      isReceiverNot: _isReceiverNot,
      ipFilters: _selectedIps,
      timeStartUs: _timeWindowStartUs,
      timeEndUs: _timeWindowEndUs,
    );

    // 2. Protocol counts (all protocols under active non-protocol filters)
    final dbProtoCounts = _repository.getProtocolCounts(
      triageStatuses: _selectedTriageStatuses,
      isTriageNot: _isTriageNot,
      silenceLanChatter: _silenceLanChatter,
      sourceSearch: _sourceSearch,
      isSourceSearchNot: _isSourceSearchNot,
      destSearch: _destSearch,
      isDestSearchNot: _isDestSearchNot,
      senderFilters: _selectedSenderKeys,
      isSenderNot: _isSenderNot,
      receiverFilters: _selectedReceiverKeys,
      isReceiverNot: _isReceiverNot,
      ipFilters: _selectedIps,
      timeStartUs: _timeWindowStartUs,
      timeEndUs: _timeWindowEndUs,
    );
    final pCounts = Map<String, int>.from(dbProtoCounts);
    for (final rule in customRules) {
      pCounts.putIfAbsent(rule.name, () => 0);
    }
    for (final selectedProto in _selectedProtocolPills) {
      pCounts.putIfAbsent(selectedProto, () => 0);
    }
    _protocolCounts = pCounts;

    // 3. Sender counts (Sources)
    final topSenders = _repository.getTopSenders(
      triageStatuses: _selectedTriageStatuses,
      isTriageNot: _isTriageNot,
      silenceLanChatter: _silenceLanChatter,
      destSearch: _destSearch,
      isDestSearchNot: _isDestSearchNot,
      protocolPills: _selectedProtocolPills,
      isProtocolNot: _isProtocolNot,
      receiverFilters: _selectedReceiverKeys,
      isReceiverNot: _isReceiverNot,
      ipFilters: _selectedIps,
      timeStartUs: _timeWindowStartUs,
      timeEndUs: _timeWindowEndUs,
    );
    final sCounts = Map<String, int>.from(topSenders);
    final senderKeysToCount = <String>{
      for (final s in senders)
        if (!sCounts.containsKey(s.filterKey)) s.filterKey,
      for (final selectedKey in _selectedSenderKeys)
        if (!sCounts.containsKey(selectedKey)) selectedKey,
    };
    if (senderKeysToCount.isNotEmpty) {
      sCounts.addAll(_repository.countPacketsForEndpoints(
        endpointKeys: senderKeysToCount,
        isSender: true,
        triageStatuses: _selectedTriageStatuses,
        isTriageNot: _isTriageNot,
        silenceLanChatter: _silenceLanChatter,
        destSearch: _destSearch,
        isDestSearchNot: _isDestSearchNot,
        protocolPills: _selectedProtocolPills,
        isProtocolNot: _isProtocolNot,
        receiverFilters: _selectedReceiverKeys,
        isReceiverNot: _isReceiverNot,
        ipFilters: _selectedIps,
        timeStartUs: _timeWindowStartUs,
        timeEndUs: _timeWindowEndUs,
      ));
    }
    _senderCounts = sCounts;

    // 4. Receiver counts (Destinations)
    final topReceivers = _repository.getTopReceivers(
      triageStatuses: _selectedTriageStatuses,
      isTriageNot: _isTriageNot,
      silenceLanChatter: _silenceLanChatter,
      sourceSearch: _sourceSearch,
      isSourceSearchNot: _isSourceSearchNot,
      protocolPills: _selectedProtocolPills,
      isProtocolNot: _isProtocolNot,
      senderFilters: _selectedSenderKeys,
      isSenderNot: _isSenderNot,
      ipFilters: _selectedIps,
      timeStartUs: _timeWindowStartUs,
      timeEndUs: _timeWindowEndUs,
    );
    final rCounts = Map<String, int>.from(topReceivers);
    final receiverKeysToCount = <String>{
      for (final r in receivers)
        if (!rCounts.containsKey(r.filterKey)) r.filterKey,
      for (final selectedKey in _selectedReceiverKeys)
        if (!rCounts.containsKey(selectedKey)) selectedKey,
    };
    if (receiverKeysToCount.isNotEmpty) {
      rCounts.addAll(_repository.countPacketsForEndpoints(
        endpointKeys: receiverKeysToCount,
        isSender: false,
        triageStatuses: _selectedTriageStatuses,
        isTriageNot: _isTriageNot,
        silenceLanChatter: _silenceLanChatter,
        sourceSearch: _sourceSearch,
        isSourceSearchNot: _isSourceSearchNot,
        protocolPills: _selectedProtocolPills,
        isProtocolNot: _isProtocolNot,
        senderFilters: _selectedSenderKeys,
        isSenderNot: _isSenderNot,
        ipFilters: _selectedIps,
        timeStartUs: _timeWindowStartUs,
        timeEndUs: _timeWindowEndUs,
      ));
    }
    _receiverCounts = rCounts;
  }

  void _refreshPackets() {
    _totalPacketCount = _repository.getPacketCount(
      triageStatuses: _selectedTriageStatuses,
      isTriageNot: _isTriageNot,
      silenceLanChatter: _silenceLanChatter,
      sourceSearch: _sourceSearch,
      isSourceSearchNot: _isSourceSearchNot,
      destSearch: _destSearch,
      isDestSearchNot: _isDestSearchNot,
      protocolPills: _selectedProtocolPills,
      isProtocolNot: _isProtocolNot,
      senderFilters: _selectedSenderKeys,
      isSenderNot: _isSenderNot,
      receiverFilters: _selectedReceiverKeys,
      isReceiverNot: _isReceiverNot,
      ipFilters: _selectedIps,
      timeStartUs: _timeWindowStartUs,
      timeEndUs: _timeWindowEndUs,
    );

    _packets = _repository.queryPackets(
      offset: 0,
      limit: _pageSize,
      triageStatuses: _selectedTriageStatuses,
      isTriageNot: _isTriageNot,
      silenceLanChatter: _silenceLanChatter,
      sourceSearch: _sourceSearch,
      isSourceSearchNot: _isSourceSearchNot,
      destSearch: _destSearch,
      isDestSearchNot: _isDestSearchNot,
      protocolPills: _selectedProtocolPills,
      isProtocolNot: _isProtocolNot,
      senderFilters: _selectedSenderKeys,
      isSenderNot: _isSenderNot,
      receiverFilters: _selectedReceiverKeys,
      isReceiverNot: _isReceiverNot,
      ipFilters: _selectedIps,
      timeStartUs: _timeWindowStartUs,
      timeEndUs: _timeWindowEndUs,
      sortColumn: _sortColumn,
      sortAscending: _sortAscending,
    );

    _hasMorePackets = _packets.length < _totalPacketCount;

    if (_selectedPacket != null) {
      final selectedNo = _selectedPacket!.packetNo;
      final matchIdx = _packets.indexWhere((p) => p.packetNo == selectedNo);
      if (matchIdx != -1) {
        _selectedPacket = _packets[matchIdx];
        _selectedPacketRawBytes = _repository.readRawPacketBytes(_selectedPacket!, payloadOnly: false);
        _selectedPacketPayloadBytes = _repository.readRawPacketBytes(_selectedPacket!, payloadOnly: true);
      } else {
        _selectedPacket = null;
        _selectedPacketRawBytes = null;
        _selectedPacketPayloadBytes = null;
      }
    }

    _updateFilterCounts();
  }

  @override
  void dispose() {
    _repository.dispose();
    super.dispose();
  }
}
