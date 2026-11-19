import 'dart:io';
import 'dart:convert';
import 'package:path/path.dart' as p;
import '../../../domain/models/custom_protocol_rule.dart';
import '../../../domain/models/baseline_profile.dart';
import '../../../domain/models/endpoint_rule.dart';
import 'shared_device_database.dart';

class ProtocolLibraryService {
  ProtocolLibraryService({this.storageDirectory});

  final Directory? storageDirectory;

  static const String _protocolsFileName = 'custom_protocols.json';
  static const String _baselinesFileName = 'baseline_profiles.json';
  static const String _sendersFileName = 'sender_library.json';
  static const String _receiversFileName = 'receiver_library.json';

  /// Canonical writable file path for a library JSON [filename].
  String resolveWritePath(String filename) => _resolveWriteFile(filename).path;

  File _resolveWriteFile(String filename) {
    if (storageDirectory != null) {
      return File(p.join(storageDirectory!.path, filename));
    }
    return File(
      p.join(SharedDeviceDatabase.getDefaultDirectoryPath(), filename),
    );
  }

  File _resolveReadFile(String filename) {
    if (storageDirectory != null) {
      return File(p.join(storageDirectory!.path, filename));
    }

    // 1. Canonical cross-platform user data directory
    final userFile = File(
      p.join(SharedDeviceDatabase.getDefaultDirectoryPath(), filename),
    );
    if (userFile.existsSync()) return userFile;

    // 2. Legacy read-only fallback for v0.6.0 upgrades
    final cwdFile = File(p.join('.', filename));
    if (cwdFile.existsSync()) return cwdFile;

    try {
      final exeDir = File(Platform.resolvedExecutable).parent;
      final exeFile = File(p.join(exeDir.path, filename));
      if (exeFile.existsSync()) return exeFile;
    } catch (_) {}

    final releaseFile = File(
      p.join('build', 'windows', 'x64', 'runner', 'Release', filename),
    );
    if (releaseFile.existsSync()) return releaseFile;

    return userFile;
  }

  List<CustomProtocolRule> loadCustomProtocols() {
    try {
      final file = _resolveReadFile(_protocolsFileName);
      if (file.existsSync()) {
        final content = file.readAsStringSync();
        return CustomProtocolRule.deserializeList(content);
      }
    } catch (_) {}
    return [];
  }

  void saveCustomProtocols(List<CustomProtocolRule> rules) {
    try {
      final file = _resolveWriteFile(_protocolsFileName);
      if (!file.parent.existsSync()) {
        file.parent.createSync(recursive: true);
      }
      final jsonStr = CustomProtocolRule.serializeList(rules);
      file.writeAsStringSync(jsonStr);
    } catch (_) {}
  }

  BaselineProfile loadBaselineProfile() {
    try {
      final file = _resolveReadFile(_baselinesFileName);
      if (file.existsSync()) {
        final content = file.readAsStringSync();
        return BaselineProfile.deserialize(content);
      }
    } catch (_) {}
    return const BaselineProfile(
      id: 'default',
      name: 'Default Baseline Profile',
      silenceLanChatter: true,
    );
  }

  void saveBaselineProfile(BaselineProfile profile) {
    try {
      final file = _resolveWriteFile(_baselinesFileName);
      if (!file.parent.existsSync()) {
        file.parent.createSync(recursive: true);
      }
      final jsonStr = BaselineProfile.serialize(profile);
      file.writeAsStringSync(jsonStr);
    } catch (_) {}
  }

  List<EndpointRule> loadSenders() {
    try {
      final file = _resolveReadFile(_sendersFileName);
      if (file.existsSync()) {
        final content = file.readAsStringSync();
        return EndpointRule.deserializeList(content);
      }
    } catch (_) {}
    return [];
  }

  void saveSenders(List<EndpointRule> senders) {
    try {
      final file = _resolveWriteFile(_sendersFileName);
      if (!file.parent.existsSync()) {
        file.parent.createSync(recursive: true);
      }
      final jsonStr = EndpointRule.serializeList(senders);
      file.writeAsStringSync(jsonStr);
    } catch (_) {}
  }

  List<EndpointRule> loadReceivers() {
    try {
      final file = _resolveReadFile(_receiversFileName);
      if (file.existsSync()) {
        final content = file.readAsStringSync();
        return EndpointRule.deserializeList(content);
      }
    } catch (_) {}
    return [];
  }

  void saveReceivers(List<EndpointRule> receivers) {
    try {
      final file = _resolveWriteFile(_receiversFileName);
      if (!file.parent.existsSync()) {
        file.parent.createSync(recursive: true);
      }
      final jsonStr = EndpointRule.serializeList(receivers);
      file.writeAsStringSync(jsonStr);
    } catch (_) {}
  }

  String exportLibraryBundleJson({
    required List<CustomProtocolRule> protocols,
    required List<EndpointRule> sources,
    required List<EndpointRule> destinations,
  }) {
    final bundle = {
      'format': 'packet_inspector_library',
      'version': 1,
      'exported_at': DateTime.now().toIso8601String(),
      'protocols': protocols.map((p) => p.toMap()).toList(),
      'sources': sources.map((s) => s.toMap()).toList(),
      'destinations': destinations.map((d) => d.toMap()).toList(),
    };
    return const JsonEncoder.withIndent('  ').convert(bundle);
  }

  Map<String, dynamic> importLibraryBundleJson(String jsonStr) {
    final decoded = jsonDecode(jsonStr);
    final protocols = <CustomProtocolRule>[];
    final sources = <EndpointRule>[];
    final destinations = <EndpointRule>[];

    if (decoded is Map<String, dynamic>) {
      if (decoded['protocols'] is List) {
        for (final item in decoded['protocols']) {
          if (item is Map<String, dynamic>) {
            protocols.add(CustomProtocolRule.fromMap(item));
          }
        }
      }
      final rawSources = decoded['sources'] ?? decoded['senders'];
      if (rawSources is List) {
        for (final item in rawSources) {
          if (item is Map<String, dynamic>) {
            sources.add(EndpointRule.fromMap(item));
          }
        }
      }
      final rawDests = decoded['destinations'] ?? decoded['receivers'];
      if (rawDests is List) {
        for (final item in rawDests) {
          if (item is Map<String, dynamic>) {
            destinations.add(EndpointRule.fromMap(item));
          }
        }
      }
    } else if (decoded is List) {
      for (final item in decoded) {
        if (item is Map<String, dynamic>) {
          if (item.containsKey('ipProtocol') || item.containsKey('magicBytesHex')) {
            protocols.add(CustomProtocolRule.fromMap(item));
          } else if (item.containsKey('type')) {
            final rule = EndpointRule.fromMap(item);
            if (rule.type == EndpointType.sender) {
              sources.add(rule);
            } else {
              destinations.add(rule);
            }
          }
        }
      }
    }

    return {
      'protocols': protocols,
      'sources': sources,
      'destinations': destinations,
    };
  }
}
