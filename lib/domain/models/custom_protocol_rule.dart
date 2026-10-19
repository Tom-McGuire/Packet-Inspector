import 'dart:convert';
import 'dart:typed_data';
import 'packet_record.dart';

enum FieldDataType {
  uint8,
  uint16Be,
  uint16Le,
  uint32Be,
  uint32Le,
  asciiString,
  hexBytes;

  String get displayName {
    switch (this) {
      case FieldDataType.uint8:
        return 'UInt8 (1B)';
      case FieldDataType.uint16Be:
        return 'UInt16 BE (2B)';
      case FieldDataType.uint16Le:
        return 'UInt16 LE (2B)';
      case FieldDataType.uint32Be:
        return 'UInt32 BE (4B)';
      case FieldDataType.uint32Le:
        return 'UInt32 LE (4B)';
      case FieldDataType.asciiString:
        return 'ASCII String';
      case FieldDataType.hexBytes:
        return 'Hex Bytes';
    }
  }

  static FieldDataType fromString(String? value) {
    switch (value?.toLowerCase()) {
      case 'uint8':
        return FieldDataType.uint8;
      case 'uint16be':
        return FieldDataType.uint16Be;
      case 'uint16le':
        return FieldDataType.uint16Le;
      case 'uint32be':
        return FieldDataType.uint32Be;
      case 'uint32le':
        return FieldDataType.uint32Le;
      case 'asciistring':
      case 'ascii':
        return FieldDataType.asciiString;
      case 'hexbytes':
      case 'hex':
      default:
        return FieldDataType.hexBytes;
    }
  }
}

enum PortMatchDirection {
  src,
  dst,
  either;

  static PortMatchDirection fromString(String? value) {
    switch (value?.toLowerCase()) {
      case 'src':
        return PortMatchDirection.src;
      case 'dst':
        return PortMatchDirection.dst;
      case 'either':
      default:
        return PortMatchDirection.either;
    }
  }
}

class ProtocolFieldSlice {
  const ProtocolFieldSlice({
    required this.name,
    required this.byteOffset,
    required this.byteLength,
    required this.dataType,
  });

  final String name;
  final int byteOffset;
  final int byteLength;
  final FieldDataType dataType;

  dynamic extractValue(List<int> payload) {
    if (byteOffset < 0 || byteOffset >= payload.length) {
      return null;
    }
    final available = payload.length - byteOffset;
    final lengthToRead = byteLength > available ? available : byteLength;
    if (lengthToRead <= 0) return null;

    final slice = payload.sublist(byteOffset, byteOffset + lengthToRead);
    final byteData = ByteData.sublistView(Uint8List.fromList(slice));

    switch (dataType) {
      case FieldDataType.uint8:
        return byteData.getUint8(0);
      case FieldDataType.uint16Be:
        return lengthToRead >= 2 ? byteData.getUint16(0, Endian.big) : null;
      case FieldDataType.uint16Le:
        return lengthToRead >= 2 ? byteData.getUint16(0, Endian.little) : null;
      case FieldDataType.uint32Be:
        return lengthToRead >= 4 ? byteData.getUint32(0, Endian.big) : null;
      case FieldDataType.uint32Le:
        return lengthToRead >= 4 ? byteData.getUint32(0, Endian.little) : null;
      case FieldDataType.asciiString:
        return String.fromCharCodes(slice.where((b) => b >= 32 && b <= 126));
      case FieldDataType.hexBytes:
        return slice.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ');
    }
  }

  Map<String, dynamic> toJson() => {
        'name': name,
        'byteOffset': byteOffset,
        'byteLength': byteLength,
        'dataType': dataType.name,
      };

  factory ProtocolFieldSlice.fromJson(Map<String, dynamic> json) =>
      ProtocolFieldSlice(
        name: json['name'] as String,
        byteOffset: json['byteOffset'] as int,
        byteLength: json['byteLength'] as int,
        dataType: FieldDataType.fromString(json['dataType'] as String?),
      );
}

class CustomProtocolRule {
  const CustomProtocolRule({
    required this.id,
    required this.name,
    required this.colorHex,
    required this.defaultTriageStatus,
    this.ipProtocol, // 6 (TCP) or 17 (UDP)
    this.port,
    this.portDirection = PortMatchDirection.either,
    this.ipAddressFilter,
    this.magicBytesOffset,
    this.magicBytesHex,
    this.fieldSlices = const [],
  });

  final String id;
  final String name;
  final int colorHex;
  final TriageStatus defaultTriageStatus;
  final int? ipProtocol;
  final int? port;
  final PortMatchDirection portDirection;
  final String? ipAddressFilter;
  final int? magicBytesOffset;
  final List<int>? magicBytesHex;
  final List<ProtocolFieldSlice> fieldSlices;

  bool matches({
    required int? ipProto,
    required int? srcPort,
    required int? dstPort,
    required String srcIp,
    required String dstIp,
    required List<int> payload,
  }) {
    // 1. IP Protocol check (e.g. TCP=6, UDP=17)
    if (ipProtocol != null && ipProto != null && ipProto != ipProtocol) {
      return false;
    }

    // 2. Port check
    if (port != null) {
      bool portMatch = false;
      switch (portDirection) {
        case PortMatchDirection.src:
          portMatch = srcPort == port;
          break;
        case PortMatchDirection.dst:
          portMatch = dstPort == port;
          break;
        case PortMatchDirection.either:
          portMatch = srcPort == port || dstPort == port;
          break;
      }
      if (!portMatch) return false;
    }

    // 3. IP check
    if (ipAddressFilter != null && ipAddressFilter!.isNotEmpty) {
      final filter = ipAddressFilter!.trim();
      if (srcIp != filter && dstIp != filter) {
        return false;
      }
    }

    // 4. Magic bytes check
    if (magicBytesHex != null && magicBytesHex!.isNotEmpty) {
      final offset = magicBytesOffset ?? 0;
      if (payload.length < offset + magicBytesHex!.length) {
        return false;
      }
      for (int i = 0; i < magicBytesHex!.length; i++) {
        if (payload[offset + i] != magicBytesHex![i]) {
          return false;
        }
      }
    }

    return true;
  }

  Map<String, dynamic> extractFieldValues(List<int> payload) {
    final values = <String, dynamic>{};
    for (final slice in fieldSlices) {
      final val = slice.extractValue(payload);
      if (val != null) {
        values[slice.name] = val;
      }
    }
    return values;
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'colorHex': colorHex,
        'defaultTriageStatus': defaultTriageStatus.name,
        'ipProtocol': ipProtocol,
        'port': port,
        'portDirection': portDirection.name,
        'ipAddressFilter': ipAddressFilter,
        'magicBytesOffset': magicBytesOffset,
        'magicBytesHex': magicBytesHex,
        'fieldSlices': fieldSlices.map((s) => s.toJson()).toList(),
      };

  factory CustomProtocolRule.fromJson(Map<String, dynamic> json) {
    return CustomProtocolRule(
      id: json['id'] as String,
      name: json['name'] as String,
      colorHex: json['colorHex'] as int? ?? 0xFF888888,
      defaultTriageStatus:
          TriageStatus.fromString(json['defaultTriageStatus'] as String?),
      ipProtocol: json['ipProtocol'] as int?,
      port: json['port'] as int?,
      portDirection:
          PortMatchDirection.fromString(json['portDirection'] as String?),
      ipAddressFilter: json['ipAddressFilter'] as String?,
      magicBytesOffset: json['magicBytesOffset'] as int?,
      magicBytesHex: (json['magicBytesHex'] as List<dynamic>?)
          ?.map((e) => e as int)
          .toList(),
      fieldSlices: (json['fieldSlices'] as List<dynamic>?)
              ?.map((e) =>
                  ProtocolFieldSlice.fromJson(e as Map<String, dynamic>))
              .toList() ??
          const [],
    );
  }

  static String serializeList(List<CustomProtocolRule> rules) {
    return jsonEncode(rules.map((r) => r.toJson()).toList());
  }

  static List<CustomProtocolRule> deserializeList(String jsonString) {
    final list = jsonDecode(jsonString) as List<dynamic>;
    return list
        .map((e) => CustomProtocolRule.fromJson(e as Map<String, dynamic>))
        .toList();
  }
}
