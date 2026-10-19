import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../../../../domain/models/packet_record.dart';
import '../../../../domain/models/custom_protocol_rule.dart';
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
  final Set<String> _selectedIps = {};
  int? _timeWindowStartUs;
  int? _timeWindowEndUs;

  List<PacketRecord> _packets = [];
  PacketRecord? _selectedPacket;
  Uint8List? _selectedPacketRawBytes;
  Uint8List? _selectedPacketPayloadBytes;

  List<TimelineBucket> _timelineBuckets = [];
  Map<String, int> _protocolCounts = {};
  Map<TriageStatus, int> _triageCounts = {};
  int _totalPacketCount = 0;
  bool _isAiPanelOpen = false;
  bool _isLoading = false;

  // Getters
  bool get isTriageMode => _isTriageMode;
  bool get silenceLanChatter => _silenceLanChatter;
  Set<TriageStatus> get selectedTriageStatuses => _selectedTriageStatuses;
  Set<String> get selectedProtocolPills => _selectedProtocolPills;
  Set<String> get selectedIps => _selectedIps;
  int? get timeWindowStartUs => _timeWindowStartUs;
  int? get timeWindowEndUs => _timeWindowEndUs;
  List<PacketRecord> get packets => _packets;
  PacketRecord? get selectedPacket => _selectedPacket;
  Uint8List? get selectedPacketRawBytes => _selectedPacketRawBytes;
  Uint8List? get selectedPacketPayloadBytes => _selectedPacketPayloadBytes;
  List<TimelineBucket> get timelineBuckets => _timelineBuckets;
  Map<String, int> get protocolCounts => _protocolCounts;
  Map<TriageStatus, int> get triageCounts => _triageCounts;
  int get totalPacketCount => _totalPacketCount;
  bool get isAiPanelOpen => _isAiPanelOpen;
  bool get isLoading => _isLoading;
  String? get loadedFileName => _repository.loadedFilePath;
  List<CustomProtocolRule> get customRules => _repository.customRules;
  BaselineProfile get baselineProfile => _repository.baselineProfile;

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

  void _resetFilters() {
    _selectedProtocolPills.clear();
    _selectedIps.clear();
    _timeWindowStartUs = null;
    _timeWindowEndUs = null;
    _selectedPacket = null;
    _selectedPacketRawBytes = null;
    _selectedPacketPayloadBytes = null;
  }

  void _refreshState() {
    _protocolCounts = _repository.getProtocolCounts();
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
      ipFilters: _selectedIps,
      timeStartUs: _timeWindowStartUs,
      timeEndUs: _timeWindowEndUs,
    );

    _packets = _repository.queryPackets(
      offset: 0,
      limit: 250, // virtualized initial window
      isTriageMode: _isTriageMode,
      triageStatuses: _selectedTriageStatuses,
      silenceLanChatter: _silenceLanChatter,
      protocolPills: _selectedProtocolPills,
      ipFilters: _selectedIps,
      timeStartUs: _timeWindowStartUs,
      timeEndUs: _timeWindowEndUs,
    );

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
