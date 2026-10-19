import 'dart:io';
import '../../../domain/models/custom_protocol_rule.dart';
import '../../../domain/models/baseline_profile.dart';

class ProtocolLibraryService {
  ProtocolLibraryService({this.storageDirectory});

  final Directory? storageDirectory;

  File get _protocolsFile => File('${storageDirectory?.path ?? '.'}/custom_protocols.json');
  File get _baselinesFile => File('${storageDirectory?.path ?? '.'}/baseline_profiles.json');

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
}
