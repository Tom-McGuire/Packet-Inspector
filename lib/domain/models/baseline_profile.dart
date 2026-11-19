import 'dart:convert';
import 'packet_record.dart';

class BaselineProfile {
  const BaselineProfile({
    required this.id,
    required this.name,
    this.expectedIps = const {},
    this.unexpectedIps = const {},
    this.expectedSubnets = const [],
    this.unexpectedSubnets = const [],
    this.expectedProtocols = const {'DNS', 'HTTP', 'TLS', 'TCP', 'UDP', 'NTP'},
    this.silenceLanChatter = true,
  });

  final String id;
  final String name;
  final Set<String> expectedIps;
  final Set<String> unexpectedIps;
  final List<String> expectedSubnets; // e.g. "192.168.1."
  final List<String> unexpectedSubnets; // e.g. "10.99.88."
  final Set<String> expectedProtocols;
  final bool silenceLanChatter;

  TriageStatus evaluateTriage({
    required String srcIp,
    required String dstIp,
    required String detectedProtocol,
    required bool isLanNoise,
    TriageStatus defaultRuleStatus = TriageStatus.unclassified,
  }) {
    // 1. LAN Noise suppression
    if (silenceLanChatter && isLanNoise) {
      return TriageStatus.expected;
    }

    // 2. Explicit Unexpected checks
    if (unexpectedIps.contains(srcIp) || unexpectedIps.contains(dstIp)) {
      return TriageStatus.unexpected;
    }
    for (final subnet in unexpectedSubnets) {
      if (srcIp.startsWith(subnet) || dstIp.startsWith(subnet)) {
        return TriageStatus.unexpected;
      }
    }

    // 3. Explicit Expected checks
    if (expectedIps.contains(srcIp) || expectedIps.contains(dstIp)) {
      return TriageStatus.expected;
    }
    for (final subnet in expectedSubnets) {
      if (srcIp.startsWith(subnet) || dstIp.startsWith(subnet)) {
        return TriageStatus.expected;
      }
    }
    if (expectedProtocols.contains(detectedProtocol)) {
      return TriageStatus.expected;
    }

    // 4. Default rule status if custom protocol provided one, else unclassified
    return defaultRuleStatus;
  }

  BaselineProfile copyWith({
    String? id,
    String? name,
    Set<String>? expectedIps,
    Set<String>? unexpectedIps,
    List<String>? expectedSubnets,
    List<String>? unexpectedSubnets,
    Set<String>? expectedProtocols,
    bool? silenceLanChatter,
  }) {
    return BaselineProfile(
      id: id ?? this.id,
      name: name ?? this.name,
      expectedIps: expectedIps ?? this.expectedIps,
      unexpectedIps: unexpectedIps ?? this.unexpectedIps,
      expectedSubnets: expectedSubnets ?? this.expectedSubnets,
      unexpectedSubnets: unexpectedSubnets ?? this.unexpectedSubnets,
      expectedProtocols: expectedProtocols ?? this.expectedProtocols,
      silenceLanChatter: silenceLanChatter ?? this.silenceLanChatter,
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'expectedIps': expectedIps.toList(),
        'unexpectedIps': unexpectedIps.toList(),
        'expectedSubnets': expectedSubnets,
        'unexpectedSubnets': unexpectedSubnets,
        'expectedProtocols': expectedProtocols.toList(),
        'silenceLanChatter': silenceLanChatter,
      };

  factory BaselineProfile.fromJson(Map<String, dynamic> json) {
    return BaselineProfile(
      id: json['id'] as String,
      name: json['name'] as String,
      expectedIps: ((json['expectedIps'] as List<dynamic>?) ?? [])
          .map((e) => e as String)
          .toSet(),
      unexpectedIps: ((json['unexpectedIps'] as List<dynamic>?) ?? [])
          .map((e) => e as String)
          .toSet(),
      expectedSubnets: ((json['expectedSubnets'] as List<dynamic>?) ?? [])
          .map((e) => e as String)
          .toList(),
      unexpectedSubnets: ((json['unexpectedSubnets'] as List<dynamic>?) ?? [])
          .map((e) => e as String)
          .toList(),
      expectedProtocols: ((json['expectedProtocols'] as List<dynamic>?) ?? [])
          .map((e) => e as String)
          .toSet(),
      silenceLanChatter: json['silenceLanChatter'] as bool? ?? true,
    );
  }

  static String serialize(BaselineProfile profile) =>
      jsonEncode(profile.toJson());

  static BaselineProfile deserialize(String jsonString) =>
      BaselineProfile.fromJson(jsonDecode(jsonString) as Map<String, dynamic>);
}
