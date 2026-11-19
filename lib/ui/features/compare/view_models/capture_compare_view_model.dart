import 'dart:typed_data';
import 'package:material_ui/material_ui.dart';
import '../../../../data/services/diff/demo_diff_generator.dart';
import '../../../../data/services/diff/multi_capture_diff_engine.dart';
import '../../../../domain/models/capture_slot.dart';
import '../../../../domain/models/custom_protocol_rule.dart';
import '../../../../domain/models/flow_diff_summary.dart';
import '../../../../domain/models/packet_diff_record.dart';

class CaptureCompareViewModel extends ChangeNotifier {
  CaptureCompareViewModel({MultiCaptureDiffEngine? engine})
      : _engine = engine ?? MultiCaptureDiffEngine();

  final MultiCaptureDiffEngine _engine;

  bool _isCompareMode = false;
  bool _isLoading = false;
  String? _errorMessage;

  DiffFilterMode _filterMode = DiffFilterMode.sharedFlowsOnly;
  DiffStatusFilter _statusFilter = DiffStatusFilter.all;
  int? _selectedFlowHash;
  double _latencyThresholdMs = 5.0;

  List<PacketDiffRecord> _cachedAllFilteredByMode = const [];
  int _cachedDroppedCount = 0;
  int _cachedSourceGapCount = 0;
  int _cachedOutOfOrderCount = 0;
  int _cachedMutatedCount = 0;
  int _cachedSpikeCount = 0;
  Map<int, int> _cachedDeliveredCountsByHop = const {};

  List<PacketDiffRecord> _visibleRecords = const [];
  PacketDiffRecord? _selectedRecord;
  int _selectedHopForHexDiff = 1;
  int? _requestScrollToRowIndex;

  // Getters
  MultiCaptureDiffEngine get engine => _engine;
  bool get isCompareMode => _isCompareMode;
  bool get isLoading => _isLoading;
  String? get errorMessage => _errorMessage;
  List<CaptureSlot> get slots => _engine.slots;
  List<FlowDiffSummary> get flowSummaries => _engine.flowSummaries;
  DiffFilterMode get filterMode => _filterMode;
  DiffStatusFilter get statusFilter => _statusFilter;
  int? get selectedFlowHash => _selectedFlowHash;
  double get latencyThresholdMs => _latencyThresholdMs;
  List<PacketDiffRecord> get visibleRecords => _visibleRecords;
  PacketDiffRecord? get selectedRecord => _selectedRecord;
  int get selectedHopForHexDiff => _selectedHopForHexDiff;
  int? get requestScrollToRowIndex => _requestScrollToRowIndex;

  // Summary counts over the active noise filter (ignoring status chip filter)
  int get totalModePacketCount => _cachedAllFilteredByMode.length;
  int get droppedCount => _cachedDroppedCount;
  int get sourceGapCount => _cachedSourceGapCount;
  int get outOfOrderCount => _cachedOutOfOrderCount;
  int get mutatedCount => _cachedMutatedCount;
  int get spikeCount => _cachedSpikeCount;

  int deliveredCountForHop(int captureIndex) {
    return _cachedDeliveredCountsByHop[captureIndex] ?? 0;
  }

  double deliveryPercentForHop(int captureIndex) {
    final total = totalModePacketCount;
    if (total == 0) return 0.0;
    return (deliveredCountForHop(captureIndex) / total) * 100.0;
  }

  Future<void> loadCaptures(
    List<CaptureSourceInput> inputs, {
    List<CustomProtocolRule> customRules = const [],
  }) async {
    _isLoading = true;
    _errorMessage = null;
    notifyListeners();

    try {
      await _engine.ingestCaptures(
        inputs,
        customRules: customRules,
        latencySpikeThresholdUs: (_latencyThresholdMs * 1000).round(),
      );
      _isCompareMode = true;
      _filterMode = DiffFilterMode.sharedFlowsOnly;
      _statusFilter = DiffStatusFilter.all;
      _selectedFlowHash = null;
      _selectedRecord = null;
      _selectedHopForHexDiff = _engine.slots.length > 1 ? 1 : 0;
      _refreshVisibleRecords();
    } catch (e) {
      _errorMessage = e.toString();
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<void> loadDemoDiff({List<CustomProtocolRule> customRules = const []}) async {
    final demoInputs = DemoDiffGenerator.buildDemoCaptures();
    await loadCaptures(demoInputs, customRules: customRules);
  }

  void exitCompareMode() {
    _isCompareMode = false;
    _selectedRecord = null;
    _visibleRecords = const [];
    _cachedAllFilteredByMode = const [];
    _cachedDroppedCount = 0;
    _cachedSourceGapCount = 0;
    _cachedOutOfOrderCount = 0;
    _cachedMutatedCount = 0;
    _cachedSpikeCount = 0;
    _cachedDeliveredCountsByHop = const {};
    notifyListeners();
  }

  void setFilterMode(DiffFilterMode mode) {
    if (_filterMode == mode) return;
    _filterMode = mode;
    if (mode != DiffFilterMode.selectedFlow) {
      _selectedFlowHash = null;
    } else if (_selectedFlowHash == null && _engine.flowSummaries.isNotEmpty) {
      _selectedFlowHash = _engine.flowSummaries.first.flowHash;
    }
    _refreshVisibleRecords();
    notifyListeners();
  }

  void setSelectedFlowHash(int? flowHash) {
    _selectedFlowHash = flowHash;
    if (flowHash != null) {
      _filterMode = DiffFilterMode.selectedFlow;
    }
    _refreshVisibleRecords();
    notifyListeners();
  }

  void setStatusFilter(DiffStatusFilter filter) {
    if (_statusFilter == filter) return;
    _statusFilter = filter;
    _refreshVisibleRecords();
    notifyListeners();
  }

  void setLatencyThresholdMs(double ms) {
    if (_latencyThresholdMs == ms) return;
    _latencyThresholdMs = ms;
    _engine.recomputeWithThreshold((ms * 1000).round());
    _refreshVisibleRecords();
    notifyListeners();
  }

  void selectRecord(PacketDiffRecord? record) {
    _selectedRecord = record;
    notifyListeners();
  }

  void setSelectedHopForHexDiff(int captureIndex) {
    _selectedHopForHexDiff = captureIndex;
    notifyListeners();
  }

  void jumpToFirstDrop() {
    final firstDrop = _visibleRecords.cast<PacketDiffRecord?>().firstWhere(
          (r) => r!.statuses.contains(DiffStatus.dropped),
          orElse: () => null,
        );
    if (firstDrop != null) {
      _selectedRecord = firstDrop;
      _requestScrollToRowIndex = firstDrop.rowIndex;
      notifyListeners();
    }
  }

  void jumpToRowIndex(int rowIndex) {
    final target = _visibleRecords.cast<PacketDiffRecord?>().firstWhere(
          (r) => r!.rowIndex == rowIndex,
          orElse: () => null,
        );
    if (target != null) {
      _selectedRecord = target;
      _requestScrollToRowIndex = rowIndex;
      notifyListeners();
    }
  }

  void consumeScrollRequest() {
    _requestScrollToRowIndex = null;
  }

  Uint8List? getRawBytes(int captureIndex, int frameNumber) {
    return _engine.getPacketRawBytes(captureIndex, frameNumber);
  }

  void _refreshVisibleRecords() {
    _cachedAllFilteredByMode = _engine.queryDiffRecords(
      filterMode: _filterMode,
      selectedFlowHash: _selectedFlowHash,
      statusFilter: DiffStatusFilter.all,
    );

    var dropped = 0;
    var sourceGap = 0;
    var outOfOrder = 0;
    var mutated = 0;
    var spike = 0;
    final deliveredByHop = <int, int>{};

    for (final r in _cachedAllFilteredByMode) {
      if (r.statuses.contains(DiffStatus.dropped)) dropped++;
      if (r.statuses.contains(DiffStatus.sourceGap)) sourceGap++;
      if (r.statuses.contains(DiffStatus.outOfOrder)) outOfOrder++;
      if (r.statuses.contains(DiffStatus.qosVlanMutated)) mutated++;
      if (r.statuses.contains(DiffStatus.latencySpike)) spike++;
      for (final hopIdx in r.hopMatches.keys) {
        deliveredByHop[hopIdx] = (deliveredByHop[hopIdx] ?? 0) + 1;
      }
    }

    _cachedDroppedCount = dropped;
    _cachedSourceGapCount = sourceGap;
    _cachedOutOfOrderCount = outOfOrder;
    _cachedMutatedCount = mutated;
    _cachedSpikeCount = spike;
    _cachedDeliveredCountsByHop = deliveredByHop;

    _visibleRecords = _statusFilter == DiffStatusFilter.all
        ? _cachedAllFilteredByMode
        : _engine.queryDiffRecords(
            filterMode: _filterMode,
            selectedFlowHash: _selectedFlowHash,
            statusFilter: _statusFilter,
          );

    if (_selectedRecord != null) {
      final match = _visibleRecords.cast<PacketDiffRecord?>().firstWhere(
            (r) => r!.rowIndex == _selectedRecord!.rowIndex,
            orElse: () => null,
          );
      _selectedRecord = match;
    }
  }

  @override
  void dispose() {
    _engine.dispose();
    super.dispose();
  }
}
