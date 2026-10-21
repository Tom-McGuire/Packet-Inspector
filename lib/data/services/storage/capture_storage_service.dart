import 'dart:io';
import 'dart:convert';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import '../../../domain/models/capture_config.dart';

class CaptureStorageService {
  CaptureStorageService({this.baseDirectory});

  final Directory? baseDirectory;

  Future<Directory> _getStorageDir() async {
    if (baseDirectory != null) {
      if (!baseDirectory!.existsSync()) {
        baseDirectory!.createSync(recursive: true);
      }
      return baseDirectory!;
    }
    try {
      final dir = await getApplicationSupportDirectory();
      if (!dir.existsSync()) {
        dir.createSync(recursive: true);
      }
      return dir;
    } catch (_) {
      final fallback = Directory('./.packet_inspector');
      if (!fallback.existsSync()) {
        fallback.createSync(recursive: true);
      }
      return fallback;
    }
  }

  Future<File> _getSessionFile() async {
    final dir = await _getStorageDir();
    return File(p.join(dir.path, 'active_capture_session.json'));
  }

  Future<File> _getPrefsFile() async {
    final dir = await _getStorageDir();
    return File(p.join(dir.path, 'capture_preferences.json'));
  }

  Future<void> saveActiveSession(ActiveCaptureSession session) async {
    final file = await _getSessionFile();
    await file.writeAsString(jsonEncode(session.toJson()), flush: true);
  }

  Future<ActiveCaptureSession?> loadActiveSession() async {
    try {
      final file = await _getSessionFile();
      if (await file.exists()) {
        final content = await file.readAsString();
        if (content.trim().isNotEmpty) {
          final data = jsonDecode(content) as Map<String, dynamic>;
          return ActiveCaptureSession.fromJson(data);
        }
      }
    } catch (_) {}
    return null;
  }

  Future<void> clearActiveSession() async {
    try {
      final file = await _getSessionFile();
      if (await file.exists()) {
        await file.delete();
      }
    } catch (_) {}
  }

  Future<void> saveDefaultOutputDirectory(String path) async {
    try {
      final file = await _getPrefsFile();
      Map<String, dynamic> prefs = {};
      if (await file.exists()) {
        final content = await file.readAsString();
        if (content.trim().isNotEmpty) {
          prefs = jsonDecode(content) as Map<String, dynamic>;
        }
      }
      prefs['lastOutputDirectory'] = path;
      await file.writeAsString(jsonEncode(prefs), flush: true);
    } catch (_) {}
  }

  Future<String?> loadDefaultOutputDirectory() async {
    try {
      final file = await _getPrefsFile();
      if (await file.exists()) {
        final content = await file.readAsString();
        if (content.trim().isNotEmpty) {
          final prefs = jsonDecode(content) as Map<String, dynamic>;
          final dir = prefs['lastOutputDirectory'] as String?;
          if (dir != null && dir.isNotEmpty && Directory(dir).existsSync()) {
            return dir;
          }
        }
      }
    } catch (_) {}

    // Default to user Documents/PacketCaptures
    try {
      final docs = await getApplicationDocumentsDirectory();
      final defaultCaptures = p.join(docs.path, 'PacketCaptures');
      return defaultCaptures;
    } catch (_) {
      return p.join(Directory.current.path, 'captures');
    }
  }
}
