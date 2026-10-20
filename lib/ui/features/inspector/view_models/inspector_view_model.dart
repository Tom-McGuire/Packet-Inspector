import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../../../../domain/models/packet_record.dart';
import '../../../../domain/models/custom_protocol_rule.dart';
import '../../../../domain/models/endpoint_rule.dart';
import '../../../../domain/models/baseline_profile.dart';
import '../../../../domain/models/timeline_bucket.dart';
import '../../../../data/repositories/packet_repository.dart';
import '../../../../data/services/export/csv_export_service.dart';

class InspectorViewModel extends ChangeNotifier {
  InspectorViewModel({PacketRepository? repository})
      : _repository = repository ?? PacketRepository() {
    _refreshState();
  }

  final PacketRepository _repository;
  PacketRepository get repository => _repository;

  bool _isTriageMode = true;
  bool _silenceLanChatter = true;
  Set<TriageStatus> _selectedTriageStatuses = {
    TriageStatus.expected,
    TriageStatus.unclassified,
    TriageStatus.unexpected,
  };
  final Set<String> _selectedProtocolPills = {};
  final Set<String> _selectedSenderKeys = {};
  final Set<String> _selectedReceiverKeys = {};
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
  bool _isAiPanelOpen = false;
  bool _isLoading = false;

  String _sortColumn = 'packet_no';
  bool _sortAscending = true;

  static const int defaultPageSize = 1000;
  int _pageSize = defaultPageSize;
  bool _isLoadingMore = false;
  bool _hasMorePackets = false;
  bool _showAutoDetected = true;

  // Getters
  bool get isTriageMode => _isTriageMode;
  bool get silenceLanChatter => _silenceLanChatter;
  bool get showAutoDetected => _showAutoDetected;
  Set<TriageStatus> get selectedTriageStatuses => _selectedTriageStatuses;
  Set<String> get selectedProtocolPills => _selectedProtocolPills;
  Set<String> get selectedSenderKeys => _selectedSenderKeys;
  Set<String> get selectedReceiverKeys => _selectedReceiverKeys;
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
  bool get isAiPanelOpen => _isAiPanelOpen;
  bool get isLoading => _isLoading;
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
      isTriageMode: _isTriageMode,
      triageStatuses: _selectedTriageStatuses,
      silenceLanChatter: _silenceLanChatter,
      protocolPills: _selectedProtocolPills,
      senderFilters: _selectedSenderKeys,
      receiverFilters: _selectedReceiverKeys,
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

  void loadFile(File file) {
    _isLoading = true;
    notifyListeners();

    _repository.loadFromFile(file);
    _resetFilters();
    _refreshState();

    _isLoading = false;
    notifyListeners();
  }

  void loadBytes(Uint8List bytes, String name) {
    _isLoading = true;
    notifyListeners();

    _repository.loadFromBytes(bytes, name);
    _resetFilters();
    _refreshState();

    _isLoading = false;
    notifyListeners();
  }

  void toggleTriageMode() {
    _isTriageMode = !_isTriageMode;
    _refreshPackets();
    notifyListeners();
  }

  void setTriageMode(bool enabled) {
    if (_isTriageMode != enabled) {
      _isTriageMode = enabled;
      _refreshPackets();
      notifyListeners();
    }
  }

  void toggleSilenceLanChatter() {
    _silenceLanChatter = !_silenceLanChatter;
    _refreshPackets();
    notifyListeners();
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
      if (_selectedTriageStatuses.length > 1) {
        _selectedTriageStatuses = {..._selectedTriageStatuses}..remove(status);
      }
    } else {
      _selectedTriageStatuses = {..._selectedTriageStatuses, status};
    }
    _refreshPackets();
    notifyListeners();
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

  void clearProtocolPills() {
    _selectedProtocolPills.clear();
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

  void clearSenderPills() {
    _selectedSenderKeys.clear();
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

  void clearReceiverPills() {
    _selectedReceiverKeys.clear();
    _refreshPackets();
    notifyListeners();
  }

  void clearAllQuickFilters() {
    _selectedProtocolPills.clear();
    _selectedSenderKeys.clear();
    _selectedReceiverKeys.clear();
    _selectedIps.clear();
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

  void toggleIpFilter(String ip) {
    if (_selectedIps.contains(ip)) {
      _selectedIps.remove(ip);
    } else {
      _selectedIps.add(ip);
    }
    _refreshPackets();
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
    return CsvExportService.exportPacketsToCsv(_packets);
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
    _selectedProtocolPills.clear();
    _selectedSenderKeys.clear();
    _selectedReceiverKeys.clear();
    _selectedIps.clear();
    _timeWindowStartUs = null;
    _timeWindowEndUs = null;
    _selectedPacket = null;
    _selectedPacketRawBytes = null;
    _selectedPacketPayloadBytes = null;
  }

  void _refreshState() {
    final dbCounts = _repository.getProtocolCounts();
    final counts = Map<String, int>.from(dbCounts);
    for (final rule in customRules) {
      counts.putIfAbsent(rule.name, () => 0);
    }
    _protocolCounts = counts;

    // Sender counts
    final topSenders = _repository.getTopSenders();
    final sCounts = Map<String, int>.from(topSenders);
    for (final s in senders) {
      final cnt = _repository.countPacketsForEndpoint(ip: s.ipAddress, port: s.port, isSender: true);
      sCounts[s.filterKey] = cnt;
    }
    _senderCounts = sCounts;

    // Receiver counts
    final topReceivers = _repository.getTopReceivers();
    final rCounts = Map<String, int>.from(topReceivers);
    for (final r in receivers) {
      final cnt = _repository.countPacketsForEndpoint(ip: r.ipAddress, port: r.port, isSender: false);
      rCounts[r.filterKey] = cnt;
    }
    _receiverCounts = rCounts;

    _triageCounts = _repository.getTriageCounts(silenceLanChatter: _silenceLanChatter);
    _timelineBuckets = _repository.getTimelineBuckets();
    _refreshPackets();
  }

  void _refreshPackets() {
    _totalPacketCount = _repository.getPacketCount(
      isTriageMode: _isTriageMode,
      triageStatuses: _selectedTriageStatuses,
      silenceLanChatter: _silenceLanChatter,
      protocolPills: _selectedProtocolPills,
      senderFilters: _selectedSenderKeys,
      receiverFilters: _selectedReceiverKeys,
      ipFilters: _selectedIps,
      timeStartUs: _timeWindowStartUs,
      timeEndUs: _timeWindowEndUs,
    );

    _packets = _repository.queryPackets(
      offset: 0,
      limit: _pageSize,
      isTriageMode: _isTriageMode,
      triageStatuses: _selectedTriageStatuses,
      silenceLanChatter: _silenceLanChatter,
      protocolPills: _selectedProtocolPills,
      senderFilters: _selectedSenderKeys,
      receiverFilters: _selectedReceiverKeys,
      ipFilters: _selectedIps,
      timeStartUs: _timeWindowStartUs,
      timeEndUs: _timeWindowEndUs,
      sortColumn: _sortColumn,
      sortAscending: _sortAscending,
    );

    _hasMorePackets = _packets.length < _totalPacketCount;

    if (_selectedPacket != null && !_packets.any((p) => p.packetNo == _selectedPacket!.packetNo)) {
      _selectedPacket = null;
      _selectedPacketRawBytes = null;
      _selectedPacketPayloadBytes = null;
    }
  }

  @override
  void dispose() {
    _repository.dispose();
    super.dispose();
  }
}
