import 'dart:io';
import 'dart:typed_data';

import 'package:csv/csv.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:packet_inspector/core/theme/app_theme.dart';
import 'package:packet_inspector/data/repositories/packet_repository.dart';
import 'package:packet_inspector/data/services/ai/llm_provider_service.dart';
import 'package:packet_inspector/data/services/ai/packet_ai_tools.dart';
import 'package:packet_inspector/data/services/storage/ai_settings_storage_service.dart';
import 'package:packet_inspector/data/services/storage/protocol_library_service.dart';
import 'package:packet_inspector/data/services/storage/shared_device_database.dart';
import 'package:packet_inspector/main.dart';
import 'package:packet_inspector/ui/features/ai_assistant/views/ai_assistant_panel.dart';
import 'package:packet_inspector/ui/features/compare/view_models/capture_compare_view_model.dart';
import 'package:packet_inspector/ui/features/inspector/view_models/inspector_view_model.dart';
import 'package:packet_inspector/ui/features/inspector/views/inspector_screen.dart';
import 'package:provider/provider.dart';

import 'mock_llm_backends.dart';
import 'pcap_fixture_builder.dart';

/// Isolated E2E test harness managing temp directories, in-memory shared DB,
/// repository/view-models with single-owner SQLite disposal, and widget pumping.
class E2eTestHarness {
  E2eTestHarness._({
    required this.tempDir,
    required this.protocolStorage,
    required this.aiStorage,
    required this.sharedDb,
    required this.repository,
    required this.aiTools,
    required this.httpServer,
    required this.cliBackend,
    required this.llmService,
  });

  /// Creates a fresh isolated [E2eTestHarness] backed by a unique temp directory
  /// and an in-memory [SharedDeviceDatabase] (or [customSharedDbPath]).
  ///
  /// When [autoTearDown] is true (default), registers [dispose] via `addTearDown`.
  factory E2eTestHarness.create({
    String tempPrefix = 'pkt_e2e_',
    String? customSharedDbPath,
    LlmBackendMode initialBackendMode = LlmBackendMode.deterministicLocal,
    bool autoTearDown = true,
  }) {
    final tempDir = Directory.systemTemp.createTempSync(tempPrefix);
    final protocolStorage = ProtocolLibraryService(storageDirectory: tempDir);
    final aiStorage = AiSettingsStorageService(storageDirectory: tempDir);
    final sharedDb = SharedDeviceDatabase(
      customPath: customSharedDbPath ?? ':memory:',
    );
    final repository = PacketRepository(storageService: protocolStorage);
    final aiTools = PacketAiTools(repository: repository);
    final httpServer = MockHttpLlmServer();
    final cliBackend = MockCliLlmBackend(tempDir: tempDir);
    final llmService = createMockLlmService(
      repository: repository,
      storageService: aiStorage,
      cliBackend: cliBackend,
      backendMode: initialBackendMode,
    );

    final harness = E2eTestHarness._(
      tempDir: tempDir,
      protocolStorage: protocolStorage,
      aiStorage: aiStorage,
      sharedDb: sharedDb,
      repository: repository,
      aiTools: aiTools,
      httpServer: httpServer,
      cliBackend: cliBackend,
      llmService: llmService,
    );

    if (autoTearDown) {
      addTearDown(harness.dispose);
    }

    return harness;
  }

  final Directory tempDir;
  final ProtocolLibraryService protocolStorage;
  final AiSettingsStorageService aiStorage;
  final SharedDeviceDatabase sharedDb;
  final PacketRepository repository;
  final PacketAiTools aiTools;
  final MockHttpLlmServer httpServer;
  final MockCliLlmBackend cliBackend;
  final LlmProviderService llmService;

  InspectorViewModel? _inspectorVm;
  CaptureCompareViewModel? _compareVm;
  bool _disposed = false;

  /// Lazily creates (and owns disposal of) the [InspectorViewModel].
  InspectorViewModel get inspectorVm {
    return _inspectorVm ??= InspectorViewModel(
      repository: repository,
      aiSettingsStorage: aiStorage,
      llmService: llmService,
    );
  }

  /// Lazily creates (and owns disposal of) the [CaptureCompareViewModel].
  CaptureCompareViewModel get compareVm {
    return _compareVm ??= CaptureCompareViewModel();
  }

  /// Writes [bytes] into `<tempDir>/<filename>` and returns the [File].
  File writeTempCaptureFile(String filename, Uint8List bytes) {
    return PcapFixtureBuilder.writeTempCaptureFile(tempDir, filename, bytes);
  }

  /// Creates an isolated child directory inside [tempDir].
  Directory createSubDir(String name) {
    final dir = Directory('${tempDir.path}${Platform.pathSeparator}$name');
    dir.createSync(recursive: true);
    return dir;
  }

  /// Configures a desktop viewport (`1400x900`, DPR `1.0`) and resets on teardown.
  static void configureDesktopViewport(
    WidgetTester tester, {
    Size size = const Size(1400, 900),
  }) {
    tester.view.physicalSize = size;
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });
  }

  /// Pumps [InspectorScreen] inside `MultiProvider` -> `MaterialApp` with
  /// full temp-directory storage isolation and mock AI services.
  ///
  /// Set [includeCompareProvider] to `false` to verify nullable
  /// `CaptureCompareViewModel?` resilience (F11).
  Future<void> pumpInspectorWorkspace(
    WidgetTester tester, {
    bool showAiAssistant = true,
    bool includeCompareProvider = true,
    Size viewportSize = const Size(1400, 900),
    ThemeData? theme,
    InspectorViewModel? overrideInspectorVm,
  }) async {
    configureDesktopViewport(tester, size: viewportSize);

    final ivm = overrideInspectorVm ?? inspectorVm;
    final cvm = includeCompareProvider ? compareVm : null;

    await tester.pumpWidget(
      MultiProvider(
        providers: [
          ChangeNotifierProvider<InspectorViewModel>.value(value: ivm),
          if (cvm != null)
            ChangeNotifierProvider<CaptureCompareViewModel>.value(value: cvm),
        ],
        child: MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: theme ?? AppTheme.darkTheme(),
          home: InspectorScreen(
            showAiAssistant: showAiAssistant,
            aiPanelSlot: showAiAssistant
                ? AiAssistantPanel(
                    llmService:
                        overrideInspectorVm != null ? ivm.llmService : llmService,
                  )
                : null,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
  }

  /// Pumps the top-level [PacketInspectorApp] using the isolated in-memory
  /// [SharedDeviceDatabase] (preventing host `~/.local/share/NetworkSuite` polling).
  Future<void> pumpPacketInspectorApp(
    WidgetTester tester, {
    SharedDeviceDatabase? database,
    Size viewportSize = const Size(1400, 900),
  }) async {
    configureDesktopViewport(tester, size: viewportSize);
    await tester.pumpWidget(
      PacketInspectorApp(database: database ?? sharedDb),
    );
    await tester.pumpAndSettle();
  }

  /// Advances past the 150ms `DualModeFilterBar` search debounce timer and settles.
  static Future<void> pumpAfterSearch(WidgetTester tester) async {
    await tester.pump(const Duration(milliseconds: 200));
    await tester.pumpAndSettle();
  }

  /// Enters [text] into [finder] and flushes the search debounce timer cleanly.
  static Future<void> enterSearchText(
    WidgetTester tester,
    Finder finder,
    String text,
  ) async {
    await tester.enterText(finder, text);
    await pumpAfterSearch(tester);
  }

  /// Parses CSV output produced by `CsvExportService` / `exportFilteredPacketsCsv`
  /// using `package:csv` v8.0.0.
  static List<List<dynamic>> parseCsvRows(String csvContent) {
    if (csvContent.trim().isEmpty) return const [];
    return Csv(autoDetect: false).decode(csvContent);
  }

  /// Disposes all owned resources exactly once in reverse dependency order.
  void dispose() {
    if (_disposed) return;
    _disposed = true;

    _compareVm?.dispose();
    if (_inspectorVm != null) {
      // InspectorViewModel.dispose() closes repository -> PacketDatabaseService.
      _inspectorVm!.dispose();
    } else {
      repository.dispose();
    }
    sharedDb.dispose();

    try {
      if (tempDir.existsSync()) {
        tempDir.deleteSync(recursive: true);
      }
    } catch (_) {}
  }
}
