import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import '../ai/llm_provider_service.dart';

/// Model representing persisted AI settings.
class AiSettings {
  const AiSettings({
    this.backendMode = LlmBackendMode.deterministicLocal,
    this.geminiApiKey = '',
    this.geminiModel = 'gemini-3.8-flash',
    this.ollamaUrl = 'http://localhost:11434',
    this.ollamaModel = 'gemma2:9b',
    this.agyPath = '',
    this.claudePath = '',
    this.codexPath = '',
    this.agyModel = 'gemini-3.8-flash-low',
    this.claudeModel = 'haiku',
    this.codexModel = 'gpt-4o-mini',
  });

  final LlmBackendMode backendMode;
  final String geminiApiKey;
  final String geminiModel;
  final String ollamaUrl;
  final String ollamaModel;
  final String agyPath;
  final String claudePath;
  final String codexPath;
  final String agyModel;
  final String claudeModel;
  final String codexModel;

  AiSettings copyWith({
    LlmBackendMode? backendMode,
    String? geminiApiKey,
    String? geminiModel,
    String? ollamaUrl,
    String? ollamaModel,
    String? agyPath,
    String? claudePath,
    String? codexPath,
    String? agyModel,
    String? claudeModel,
    String? codexModel,
  }) {
    return AiSettings(
      backendMode: backendMode ?? this.backendMode,
      geminiApiKey: geminiApiKey ?? this.geminiApiKey,
      geminiModel: geminiModel ?? this.geminiModel,
      ollamaUrl: ollamaUrl ?? this.ollamaUrl,
      ollamaModel: ollamaModel ?? this.ollamaModel,
      agyPath: agyPath ?? this.agyPath,
      claudePath: claudePath ?? this.claudePath,
      codexPath: codexPath ?? this.codexPath,
      agyModel: agyModel ?? this.agyModel,
      claudeModel: claudeModel ?? this.claudeModel,
      codexModel: codexModel ?? this.codexModel,
    );
  }
}

/// Service responsible for persisting and securely encrypting AI settings,
/// specifically encrypting the Google Gemini API key at rest bound to the local machine.
class AiSettingsStorageService {
  AiSettingsStorageService({this.storageDirectory});

  final Directory? storageDirectory;
  static const String _fileName = 'ai_settings.json';

  File _resolveFile() {
    if (storageDirectory != null) {
      return File('${storageDirectory!.path}/$_fileName');
    }

    // 1. Current working directory
    final cwdFile = File('./$_fileName');
    if (cwdFile.existsSync()) return cwdFile;

    // 2. Next to executable
    try {
      final exeDir = File(Platform.resolvedExecutable).parent;
      final exeFile = File('${exeDir.path}/$_fileName');
      if (exeFile.existsSync()) return exeFile;
    } catch (_) {}

    // 3. Release build path if running in project directory
    final releaseFile = File('build/windows/x64/runner/Release/$_fileName');
    if (releaseFile.existsSync()) return releaseFile;

    try {
      final exeDir = File(Platform.resolvedExecutable).parent;
      return File('${exeDir.path}/$_fileName');
    } catch (_) {
      return cwdFile;
    }
  }

  /// Loads AI settings from disk. Decrypts the Gemini API key if present.
  AiSettings loadSettings() {
    try {
      final file = _resolveFile();
      if (!file.existsSync()) {
        return const AiSettings();
      }

      final jsonStr = file.readAsStringSync();
      final map = jsonDecode(jsonStr) as Map<String, dynamic>;

      final backendIndex = map['backend_mode'] as int? ?? 0;
      final backendMode = backendIndex >= 0 && backendIndex < LlmBackendMode.values.length
          ? LlmBackendMode.values[backendIndex]
          : LlmBackendMode.deterministicLocal;

      final encryptedApiKey = map['gemini_api_key_enc'] as String? ?? '';
      final decryptedKey = encryptedApiKey.isNotEmpty ? decryptSecret(encryptedApiKey) : '';

      final geminiModel = (map['gemini_model'] as String?)?.trim();
      final effectiveGeminiModel = (geminiModel != null && geminiModel.isNotEmpty)
          ? geminiModel
          : 'gemini-3.8-flash';

      final ollamaUrl = map['ollama_url'] as String? ?? 'http://localhost:11434';
      final ollamaModel = map['ollama_model'] as String? ?? 'gemma2:9b';
      final agyPath = map['agy_path'] as String? ?? '';
      final claudePath = map['claude_path'] as String? ?? '';
      final codexPath = map['codex_path'] as String? ?? '';
      final agyModel = map['agy_model'] as String? ?? 'gemini-3.8-flash-low';
      final claudeModel = map['claude_model'] as String? ?? 'haiku';
      final codexModel = map['codex_model'] as String? ?? 'gpt-4o-mini';

      return AiSettings(
        backendMode: backendMode,
        geminiApiKey: decryptedKey,
        geminiModel: effectiveGeminiModel,
        ollamaUrl: ollamaUrl,
        ollamaModel: ollamaModel,
        agyPath: agyPath,
        claudePath: claudePath,
        codexPath: codexPath,
        agyModel: agyModel,
        claudeModel: claudeModel,
        codexModel: codexModel,
      );
    } catch (_) {
      return const AiSettings();
    }
  }

  /// Saves AI settings to disk. Encrypts the Gemini API key before persisting.
  void saveSettings(AiSettings settings) {
    try {
      final file = _resolveFile();
      final encryptedApiKey = settings.geminiApiKey.isNotEmpty
          ? encryptSecret(settings.geminiApiKey)
          : '';

      final map = <String, dynamic>{
        'backend_mode': settings.backendMode.index,
        'gemini_api_key_enc': encryptedApiKey,
        'gemini_model': settings.geminiModel.isNotEmpty ? settings.geminiModel : 'gemini-3.8-flash',
        'ollama_url': settings.ollamaUrl,
        'ollama_model': settings.ollamaModel,
        'agy_path': settings.agyPath,
        'claude_path': settings.claudePath,
        'codex_path': settings.codexPath,
        'agy_model': settings.agyModel,
        'claude_model': settings.claudeModel,
        'codex_model': settings.codexModel,
      };

      file.writeAsStringSync(const JsonEncoder.withIndent('  ').convert(map));
    } catch (_) {}
  }

  // --- Authenticated Machine-Bound Reversible Encryption ---

  /// Derives a 256-bit machine-and-user-bound master key.
  static List<int> _deriveMasterKey() {
    final os = Platform.operatingSystem;
    String host = 'local';
    try {
      host = Platform.localHostname;
    } catch (_) {}

    String user = 'default';
    try {
      user = Platform.environment['USERNAME'] ??
          Platform.environment['USER'] ??
          Platform.environment['LOGNAME'] ??
          'default';
    } catch (_) {}

    final seed = 'pkt_insp_${os}_${host}_${user}_gemini_vault_v1';
    return sha256.convert(utf8.encode(seed)).bytes;
  }

  /// Encrypts a plaintext secret using HMAC-CTR stream cipher + HMAC-SHA256 authentication tag.
  static String encryptSecret(String plaintext) {
    if (plaintext.isEmpty) return '';

    final masterKey = _deriveMasterKey();
    final plainBytes = utf8.encode(plaintext);

    // 16-byte random IV
    final rng = Random.secure();
    final iv = List<int>.generate(16, (_) => rng.nextInt(256));

    // Generate keystream blocks using HMAC-SHA256 in CTR mode
    final ciphertext = <int>[];
    int blockCounter = 0;

    while (ciphertext.length < plainBytes.length) {
      final counterBytes = ByteData(8)..setUint64(0, blockCounter, Endian.big);
      final blockInput = [...iv, ...counterBytes.buffer.asUint8List()];
      final block = Hmac(sha256, masterKey).convert(blockInput).bytes;

      for (int i = 0; i < block.length && ciphertext.length < plainBytes.length; i++) {
        ciphertext.add(plainBytes[ciphertext.length] ^ block[i]);
      }
      blockCounter++;
    }

    // Authenticate: HMAC(masterKey, IV + Ciphertext)
    final macTag = Hmac(sha256, masterKey).convert([...iv, ...ciphertext]).bytes;

    // Pack payload: [IV (16 bytes)] + [MAC (32 bytes)] + [Ciphertext (N bytes)]
    final packed = Uint8List.fromList([...iv, ...macTag, ...ciphertext]);
    return base64.encode(packed);
  }

  /// Decrypts a base64 encoded ciphertext payload. Returns empty string if invalid or tampered.
  static String decryptSecret(String encryptedBase64) {
    if (encryptedBase64.isEmpty) return '';

    try {
      final packed = base64.decode(encryptedBase64);
      if (packed.length < 48) return ''; // 16 bytes IV + 32 bytes MAC tag

      final masterKey = _deriveMasterKey();
      final iv = packed.sublist(0, 16);
      final macTag = packed.sublist(16, 48);
      final ciphertext = packed.sublist(48);

      // Verify MAC
      final expectedMac = Hmac(sha256, masterKey).convert([...iv, ...ciphertext]).bytes;
      if (!_constantTimeEquals(macTag, expectedMac)) {
        return ''; // Authentication failed (corrupted or wrong machine)
      }

      // Decrypt using keystream in CTR mode
      final decryptedBytes = <int>[];
      int blockCounter = 0;

      while (decryptedBytes.length < ciphertext.length) {
        final counterBytes = ByteData(8)..setUint64(0, blockCounter, Endian.big);
        final blockInput = [...iv, ...counterBytes.buffer.asUint8List()];
        final block = Hmac(sha256, masterKey).convert(blockInput).bytes;

        for (int i = 0; i < block.length && decryptedBytes.length < ciphertext.length; i++) {
          decryptedBytes.add(ciphertext[decryptedBytes.length] ^ block[i]);
        }
        blockCounter++;
      }

      return utf8.decode(decryptedBytes);
    } catch (_) {
      return '';
    }
  }

  static bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    int diff = 0;
    for (int i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
