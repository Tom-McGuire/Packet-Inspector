import 'dart:io';
import 'dart:convert';
import '../../../domain/models/custom_protocol_rule.dart';
import '../../../domain/models/baseline_profile.dart';
import '../../../domain/models/endpoint_rule.dart';

class ProtocolLibraryService {
  ProtocolLibraryService({this.storageDirectory});

  final Directory? storageDirectory;

  File _resolveFile(String filename) {
    if (storageDirectory != null) {
      return File('${storageDirectory!.path}/$filename');
    }
    // 1. Current working directory
    final cwdFile = File('./$filename');
    if (cwdFile.existsSync()) return cwdFile;

    // 2. Next to executable
    try {
      final exeDir = File(Platform.resolvedExecutable).parent;
      final exeFile = File('${exeDir.path}/$filename');
      if (exeFile.existsSync()) return exeFile;
    } catch (_) {}

    // 3. Release build path if running in project directory
    final releaseFile = File('build/windows/x64/runner/Release/$filename');
    if (releaseFile.existsSync()) return releaseFile;

    try {
      final exeDir = File(Platform.resolvedExecutable).parent;
      return File('${exeDir.path}/$filename');
    } catch (_) {
      return cwdFile;
    }
  }

  File get _protocolsFile => _resolveFile('custom_protocols.json');
  File get _baselinesFile => _resolveFile('baseline_profiles.json');
  File get _sendersFile => _resolveFile('sender_library.json');
  File get _receiversFile => _resolveFile('receiver_library.json');

  List<CustomProtocolRule> loadCustomProtocols() {
    try {
      if (_protocolsFile.existsSync()) {
        final content = _protocolsFile.readAsStringSync();
        return CustomProtocolRule.deserializeList(content);
      }
    } catch (_) {}
    return [];
  }

  void saveCustomProtocols(List<CustomProtocolRule> rules) {
    try {
      final jsonStr = CustomProtocolRule.serializeList(rules);
      _protocolsFile.writeAsStringSync(jsonStr);
    } catch (_) {}
  }

  BaselineProfile loadBaselineProfile() {
    try {
      if (_baselinesFile.existsSync()) {
        final content = _baselinesFile.readAsStringSync();
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
      final jsonStr = BaselineProfile.serialize(profile);
      _baselinesFile.writeAsStringSync(jsonStr);
    } catch (_) {}
  }

  String exportProtocolsJson(List<CustomProtocolRule> rules) =>
      CustomProtocolRule.serializeList(rules);

  List<CustomProtocolRule> importProtocolsJson(String jsonStr) =>
      CustomProtocolRule.deserializeList(jsonStr);

  List<EndpointRule> loadSenders() {
    try {
      if (_sendersFile.existsSync()) {
        final content = _sendersFile.readAsStringSync();
        return EndpointRule.deserializeList(content);
      }
    } catch (_) {}
    return [];
  }

  void saveSenders(List<EndpointRule> senders) {
    try {
      final jsonStr = EndpointRule.serializeList(senders);
      _sendersFile.writeAsStringSync(jsonStr);
    } catch (_) {}
  }

  List<EndpointRule> loadReceivers() {
    try {
      if (_receiversFile.existsSync()) {
        final content = _receiversFile.readAsStringSync();
        return EndpointRule.deserializeList(content);
      }
    } catch (_) {}
    return [];
  }

  void saveReceivers(List<EndpointRule> receivers) {
    try {
      final jsonStr = EndpointRule.serializeList(receivers);
      _receiversFile.writeAsStringSync(jsonStr);
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
