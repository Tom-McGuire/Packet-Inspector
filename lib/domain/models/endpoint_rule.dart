import 'dart:convert';

enum EndpointType { sender, receiver }

/// Represents a saved device or endpoint in the Sender or Receiver library.
class EndpointRule {
  const EndpointRule({
    required this.id,
    required this.name,
    required this.ipAddress,
    this.port,
    this.colorHex = 0xFF2196F3,
    this.type = EndpointType.sender,
    this.isVisible = true,
  });

  final String id;
  final String name;
  final String ipAddress;
  final int? port;
  final int colorHex;
  final EndpointType type;
  final bool isVisible;

  String get displayName {
    final addr = port != null ? '$ipAddress:$port' : ipAddress;
    if (name == addr) {
      return name;
    }
    return '$name ($addr)';
  }

  /// Unique key for filtering: "ip:port" or "ip"
  String get filterKey => port != null ? '$ipAddress:$port' : ipAddress;

  bool matches({required String ip, int? packetPort}) {
    if (ip != ipAddress) return false;
    if (port != null && packetPort != null && port != packetPort) return false;
    return true;
  }

  EndpointRule copyWith({
    String? id,
    String? name,
    String? ipAddress,
    int? port,
    int? colorHex,
    EndpointType? type,
    bool? isVisible,
  }) {
    return EndpointRule(
      id: id ?? this.id,
      name: name ?? this.name,
      ipAddress: ipAddress ?? this.ipAddress,
      port: port ?? this.port,
      colorHex: colorHex ?? this.colorHex,
      type: type ?? this.type,
      isVisible: isVisible ?? this.isVisible,
    );
  }

  Map<String, dynamic> toMap() => {
        'id': id,
        'name': name,
        'ipAddress': ipAddress,
        'port': port,
        'colorHex': colorHex,
        'type': type.name,
        'isVisible': isVisible,
      };

  factory EndpointRule.fromMap(Map<String, dynamic> map) {
    return EndpointRule(
      id: map['id'] as String? ?? 'ep_${DateTime.now().millisecondsSinceEpoch}',
      name: map['name'] as String? ?? 'Endpoint',
      ipAddress: map['ipAddress'] as String? ?? '',
      port: map['port'] as int?,
      colorHex: map['colorHex'] as int? ?? 0xFF2196F3,
      type: (map['type'] as String?) == 'receiver'
          ? EndpointType.receiver
          : EndpointType.sender,
      isVisible: map['isVisible'] as bool? ?? true,
    );
  }

  static String serializeList(List<EndpointRule> list) =>
      jsonEncode(list.map((e) => e.toMap()).toList());

  static List<EndpointRule> deserializeList(String jsonStr) {
    try {
      final decoded = jsonDecode(jsonStr);
      if (decoded is List) {
        return decoded
            .map((item) => EndpointRule.fromMap(item as Map<String, dynamic>))
            .toList();
      }
    } catch (_) {}
    return [];
  }
}
