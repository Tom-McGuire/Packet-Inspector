import 'dart:convert';
import 'dart:typed_data';

/// Computes immutable L3/L4/Payload fingerprints (64-bit FNV-1a) for cross-capture
/// packet correlation, ignoring mutable L2 MAC addresses, IP TTL, and checksums.
class CaptureFingerprintService {
  // 64-bit FNV-1a offset basis (0xcbf29ce484222325 as signed 64-bit int)
  static const int _fnvOffsetBasis = -3750763034362895579;
  // 64-bit FNV-1a prime (0x100000001b3)
  static const int _fnvPrime = 1099511628211;

  /// Computes an immutable 64-bit fingerprint hash for a dissected packet.
  ///
  /// For IP packets (IPv4/IPv6), hashes:
  /// - `srcIp`, `dstIp`, `ipProto`
  /// - `srcPort`, `dstPort`, `tcpSeqNum`
  /// - Full L4 payload bytes
  ///
  /// For non-IP / L2 control frames (e.g. LLDP, STP BPDU, ARP), hashes:
  /// - `ethType` and full frame bytes.
  static int computeFingerprint({
    required int ethType,
    required String srcIp,
    required String dstIp,
    required int ipProto,
    required int? srcPort,
    required int? dstPort,
    required int? tcpSeqNum,
    required Uint8List payloadBytes,
    required Uint8List fullFrameBytes,
  }) {
    var hash = _fnvOffsetBasis;

    if ((ethType == 0x0800 || ethType == 0x86DD) && srcIp.isNotEmpty && dstIp.isNotEmpty) {
      hash = _hashString(hash, srcIp);
      hash = _hashByte(hash, 0xFF);
      hash = _hashString(hash, dstIp);
      hash = _hashByte(hash, ipProto & 0xFF);
      hash = _hashUint16(hash, srcPort ?? 0);
      hash = _hashUint16(hash, dstPort ?? 0);
      hash = _hashUint32(hash, tcpSeqNum ?? 0);
      hash = _hashUint32(hash, payloadBytes.length);
      hash = _hashBytes(hash, payloadBytes);
    } else {
      hash = _hashUint16(hash, ethType);
      hash = _hashUint32(hash, fullFrameBytes.length);
      hash = _hashBytes(hash, fullFrameBytes);
    }

    return hash;
  }

  static int _hashByte(int hash, int byte) {
    hash ^= (byte & 0xFF);
    return (hash * _fnvPrime);
  }

  static int _hashBytes(int hash, Uint8List bytes) {
    for (int i = 0; i < bytes.length; i++) {
      hash ^= bytes[i];
      hash *= _fnvPrime;
    }
    return hash;
  }

  static int _hashString(int hash, String value) {
    final encoded = utf8.encode(value);
    for (int i = 0; i < encoded.length; i++) {
      hash ^= encoded[i];
      hash *= _fnvPrime;
    }
    return hash;
  }

  static int _hashUint16(int hash, int value) {
    hash = _hashByte(hash, (value >> 8) & 0xFF);
    hash = _hashByte(hash, value & 0xFF);
    return hash;
  }

  static int _hashUint32(int hash, int value) {
    hash = _hashByte(hash, (value >> 24) & 0xFF);
    hash = _hashByte(hash, (value >> 16) & 0xFF);
    hash = _hashByte(hash, (value >> 8) & 0xFF);
    hash = _hashByte(hash, value & 0xFF);
    return hash;
  }
}
