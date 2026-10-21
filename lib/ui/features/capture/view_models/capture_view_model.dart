import 'dart:async';
import 'dart:io';
import 'package:flutter/foundation.dart';
import '../../../../domain/models/capture_config.dart';
import '../../../../data/services/capture/tshark_service.dart';
import '../../../../data/services/storage/capture_storage_service.dart';

class CaptureViewModel extends ChangeNotifier {
  CaptureViewModel({
    TSharkService? tsharkService,
    CaptureStorageService? storageService,
  })  : _tsharkService = tsharkService ?? TSharkService(),
        _storageService = storageService ?? CaptureStorageService() {
    init();
  }

  final TSharkService _tsharkService;
  final CaptureStorageService _storageService;

  String? _tsharkPath;
  String? get tsharkPath => _tsharkPath;
  bool get hasTShark => _tsharkPath != null;

  bool _isLoading = false;
  bool get isLoading => _isLoading;

  String? _lastError;
  String? get lastError => _lastError;

  String? _reconnectedNotice;
  String? get reconnectedNotice => _reconnectedNotice;

  List<CaptureInterface> _interfaces = [];
  List<CaptureInterface> get interfaces => _interfaces;

  CaptureInterface? _selectedInterface;
  CaptureInterface? get selectedInterface => _selectedInterface;

  String _outputDirectory = '';
  String get outputDirectory => _outputDirectory;

  bool _createSubfolder = true;
  bool get createSubfolder => _createSubfolder;

  String _filePrefix = 'capture';
  String get filePrefix => _filePrefix;

  bool _isQuickCapture = true;
  bool get isQuickCapture => _isQuickCapture;

  int _hours = 0;
  int get hours => _hours;

  int _minutes = 10;
  int get minutes => _minutes;

  bool _isRingBuffer = false;
  bool get isRingBuffer => _isRingBuffer;

  int _ringFiles = 5;
  int get ringFiles => _ringFiles;

  ActiveCaptureSession? _activeSession;
  ActiveCaptureSession? get activeSession => _activeSession;
  bool get isCapturing => _activeSession != null;

  Duration _elapsed = Duration.zero;
  Duration get elapsed => _elapsed;

  Timer? _elapsedTimer;
  Process? _activeProcess;

  Future<void> init() async {
    _isLoading = true;
    notifyListeners();

    try {
      _tsharkPath = await _tsharkService.findTSharkPath();
      final defaultDir = await _storageService.loadDefaultOutputDirectory();
      if (defaultDir != null) {
        _outputDirectory = defaultDir;
      }

      if (_tsharkPath != null) {
        _interfaces = await _tsharkService.getInterfaces(_tsharkPath!);
        if (_interfaces.isNotEmpty) {
          _selectedInterface = _interfaces.first;
        }
      }

      await checkExistingSession();
    } catch (e) {
      _lastError = 'Initialization failed: $e';
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<void> refreshInterfaces() async {
    if (_tsharkPath == null) return;
    _isLoading = true;
    notifyListeners();

    try {
      _interfaces = await _tsharkService.getInterfaces(_tsharkPath!);
      if (_interfaces.isNotEmpty && _selectedInterface == null) {
        _selectedInterface = _interfaces.first;
      }
    } catch (e) {
      _lastError = 'Failed to fetch interfaces: $e';
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<void> checkExistingSession() async {
    final session = await _storageService.loadActiveSession();
    if (session == null) return;

    final isAlive = await _tsharkService.isProcessAlive(session.pid);
    if (isAlive) {
      _activeSession = session;
      _outputDirectory = session.outputDirectory;
      _reconnectedNotice =
          'Detected active background capture (PID ${session.pid}) started at ${_formatTime(session.startedAt)}.';
      _startElapsedTimer();
    } else {
      // The session ended while the app was closed
      await _storageService.clearActiveSession();
      _activeSession = null;
    }
    notifyListeners();
  }

  void setSelectedInterface(CaptureInterface? iface) {
    _selectedInterface = iface;
    notifyListeners();
  }

  void setOutputDirectory(String dir) {
    _outputDirectory = dir;
    _storageService.saveDefaultOutputDirectory(dir);
    notifyListeners();
  }

  void setCreateSubfolder(bool val) {
    _createSubfolder = val;
    notifyListeners();
  }

  void setFilePrefix(String val) {
    _filePrefix = val.trim();
    notifyListeners();
  }

  void setQuickCapture(bool val) {
    _isQuickCapture = val;
    notifyListeners();
  }

  void setHours(int val) {
    _hours = val.clamp(0, 720);
    notifyListeners();
  }

  void setMinutes(int val) {
    _minutes = val.clamp(0, 59);
    notifyListeners();
  }

  void setRingBuffer(bool val) {
    _isRingBuffer = val;
    notifyListeners();
  }

  void setRingFiles(int val) {
    _ringFiles = val.clamp(2, 500);
    notifyListeners();
  }

  void clearNotice() {
    _reconnectedNotice = null;
    notifyListeners();
  }

  void clearError() {
    _lastError = null;
    notifyListeners();
  }

  CaptureMode get determinedMode {
    if (_isQuickCapture) return CaptureMode.quick;
    if (_isRingBuffer) return CaptureMode.ringBuffer;
    return CaptureMode.timed;
  }

  Future<bool> startCapture({bool detached = false}) async {
    if (_tsharkPath == null) {
      _lastError = 'TShark executable was not found on this system.';
      notifyListeners();
      return false;
    }

    if (_selectedInterface == null) {
      _lastError = 'No capture interface selected.';
      notifyListeners();
      return false;
    }

    if (_outputDirectory.isEmpty) {
      _lastError = 'Please choose a storage destination folder.';
      notifyListeners();
      return false;
    }

    _lastError = null;
    _isLoading = true;
    notifyListeners();

    try {
      final config = CaptureConfig(
        interface: _selectedInterface!,
        outputDirectory: _outputDirectory,
        filePrefix: _filePrefix.isNotEmpty ? _filePrefix : 'capture',
        createSubfolder: _createSubfolder,
        mode: determinedMode,
        hours: _hours,
        minutes: _minutes,
        ringFiles: _ringFiles,
      );

      final result = await _tsharkService.startCapture(
        tsharkPath: _tsharkPath!,
        config: config,
        detached: detached,
      );

      _activeProcess = result.process;

      _activeSession = ActiveCaptureSession(
        pid: result.pid,
        startedAt: DateTime.now(),
        outputDirectory: result.targetDirectory,
        targetFilePath: result.targetFilePath,
        mode: config.mode,
        interfaceName: config.interface.displayName,
        hours: config.hours,
        minutes: config.minutes,
        ringFiles: config.ringFiles,
      );

      await _storageService.saveActiveSession(_activeSession!);
      _startElapsedTimer();

      _isLoading = false;
      notifyListeners();
      return true;
    } catch (e) {
      _lastError = 'Failed to start TShark: $e';
      _isLoading = false;
      notifyListeners();
      return false;
    }
  }

  Future<void> stopCapture() async {
    if (_activeSession == null) return;

    _isLoading = true;
    notifyListeners();

    try {
      await _tsharkService.stopCapture(_activeSession!.pid);
      if (_activeProcess != null) {
        _activeProcess!.kill();
        _activeProcess = null;
      }
      await _storageService.clearActiveSession();
      _activeSession = null;
      _stopElapsedTimer();
    } catch (e) {
      _lastError = 'Error stopping capture: $e';
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<void> openOutputFolder() async {
    final folder = _activeSession?.outputDirectory ?? _outputDirectory;
    if (folder.isNotEmpty) {
      await _tsharkService.openFolder(folder);
    }
  }

  void _startElapsedTimer() {
    _stopElapsedTimer();
    _elapsed = _activeSession?.elapsed ?? Duration.zero;
    _elapsedTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (_activeSession != null) {
        _elapsed = _activeSession!.elapsed;
        notifyListeners();
      }
    });
  }

  void _stopElapsedTimer() {
    _elapsedTimer?.cancel();
    _elapsedTimer = null;
    _elapsed = Duration.zero;
  }

  String _formatTime(DateTime dt) {
    return '${dt.hour.toString().padLeft(2, '0')}:${dt.minute.toString().padLeft(2, '0')}';
  }

  String formatDuration(Duration d) {
    final hours = d.inHours.toString().padLeft(2, '0');
    final minutes = (d.inMinutes % 60).toString().padLeft(2, '0');
    final seconds = (d.inSeconds % 60).toString().padLeft(2, '0');
    return '$hours:$minutes:$seconds';
  }

  @override
  void dispose() {
    _stopElapsedTimer();
    super.dispose();
  }
}
