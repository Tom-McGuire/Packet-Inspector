import 'dart:io';
import 'dart:typed_data';

enum PcapFormat {
  classicMicrosecond,
  classicNanosecond,
  pcapNg,
  unknown,
}

class RawCapturedPacket {
  const RawCapturedPacket({
    required this.packetNo,
    required this.timestampUs,
    required this.capturedLength,
    required this.originalLength,
    required this.linkType,
    required this.fileByteOffset,
    required this.data,
  });

  final int packetNo;
  final int timestampUs;
  final int capturedLength;
  final int originalLength;
  final int linkType; // 1 = Ethernet, 113 = Linux SLL, 0 = Null/Loopback, 101 = Raw IP
  final int fileByteOffset;
  final Uint8List data;
}

class PcapBinaryReader {
  static const int pcapMagicBe = 0xA1B2C3D4;
  static const int pcapMagicLe = 0xD4C3B2A1;
  static const int pcapNanoMagicBe = 0xA1B23C4D;
  static const int pcapNanoMagicLe = 0x4D3CB2A1;
  static const int pcapNgShb = 0x0A0D0D0A;
  static const int pcapNgByteOrder = 0x1A2B3C4D;

  static PcapFormat detectFormat(Uint8List headerBytes) {
    if (headerBytes.length < 4) return PcapFormat.unknown;
    final bd = ByteData.sublistView(headerBytes);
    final magicBe = bd.getUint32(0, Endian.big);

    if (magicBe == pcapMagicBe || magicBe == pcapMagicLe) {
      return PcapFormat.classicMicrosecond;
    }
    if (magicBe == pcapNanoMagicBe || magicBe == pcapNanoMagicLe) {
      return PcapFormat.classicNanosecond;
    }
    if (magicBe == pcapNgShb) {
      return PcapFormat.pcapNg;
    }
    return PcapFormat.unknown;
  }

  /// Parses an in-memory buffer of PCAP or PCAPNG data.
  static List<RawCapturedPacket> parseBytes(Uint8List bytes) {
    final format = detectFormat(bytes);
    switch (format) {
      case PcapFormat.classicMicrosecond:
      case PcapFormat.classicNanosecond:
        return _parseClassicPcap(bytes, format == PcapFormat.classicNanosecond);
      case PcapFormat.pcapNg:
        return _parsePcapNg(bytes);
      case PcapFormat.unknown:
        throw const FormatException('Unsupported or invalid PCAP/PCAPNG header format');
    }
  }

  /// Parses a file from disk synchronously or incrementally.
  static List<RawCapturedPacket> parseFile(File file) {
    final bytes = file.readAsBytesSync();
    return parseBytes(bytes);
  }

  static List<RawCapturedPacket> _parseClassicPcap(Uint8List bytes, bool isNano) {
    if (bytes.length < 24) {
      throw const FormatException('File too short for PCAP global header');
    }
    final bd = ByteData.sublistView(bytes);
    final magic = bd.getUint32(0, Endian.big);
    final Endian endian;
    if (magic == pcapMagicBe || magic == pcapNanoMagicBe) {
      endian = Endian.big;
    } else {
      endian = Endian.little;
    }

    final linkType = bd.getUint32(20, endian);
    int offset = 24;
    int packetNo = 1;
    final packets = <RawCapturedPacket>[];

    while (offset + 16 <= bytes.length) {
      final headerOffset = offset;
      final tsSec = bd.getUint32(offset, endian);
      final tsFraction = bd.getUint32(offset + 4, endian);
      final inclLen = bd.getUint32(offset + 8, endian);
      final origLen = bd.getUint32(offset + 12, endian);
      offset += 16;

      if (offset + inclLen > bytes.length) {
        break; // Truncated final packet
      }

      final int timestampUs;
      if (isNano) {
        timestampUs = (tsSec * 1000000) + (tsFraction ~/ 1000);
      } else {
        timestampUs = (tsSec * 1000000) + tsFraction;
      }

      final packetData = Uint8List.sublistView(bytes, offset, offset + inclLen);
      packets.add(RawCapturedPacket(
        packetNo: packetNo++,
        timestampUs: timestampUs,
        capturedLength: inclLen,
        originalLength: origLen,
        linkType: linkType,
        fileByteOffset: headerOffset,
        data: packetData,
      ));

      offset += inclLen;
    }

    return packets;
  }

  static List<RawCapturedPacket> _parsePcapNg(Uint8List bytes) {
    int offset = 0;
    int packetNo = 1;
    Endian currentEndian = Endian.little;
    int currentLinkType = 1; // Default Ethernet
    int tsResolution = 1000000; // Default microsecond resolution (10^-6)
    final packets = <RawCapturedPacket>[];

    while (offset + 8 <= bytes.length) {
      final blockOffset = offset;
      var bd = ByteData.sublistView(bytes, offset, offset + 8);
      var blockType = bd.getUint32(0, currentEndian);
      var blockTotalLength = bd.getUint32(4, currentEndian);

      if (blockType == pcapNgShb) {
        if (offset + 12 > bytes.length) break;
        final bom = ByteData.sublistView(bytes, offset + 8, offset + 12).getUint32(0, Endian.big);
        if (bom == pcapNgByteOrder) {
          currentEndian = Endian.big;
        } else {
          currentEndian = Endian.little;
        }
        bd = ByteData.sublistView(bytes, offset, offset + 8);
        blockType = bd.getUint32(0, currentEndian);
        blockTotalLength = bd.getUint32(4, currentEndian);
      }

      if (blockTotalLength < 12 || offset + blockTotalLength > bytes.length) {
        break; // Corrupted or truncated block
      }

      final blockBd = ByteData.sublistView(bytes, offset, offset + blockTotalLength);

      if (blockType == 0x00000001) {
        // Interface Description Block (IDB)
        if (blockTotalLength >= 16) {
          currentLinkType = blockBd.getUint16(8, currentEndian);
          // Parse options for if_tsresol
          int optOffset = 16;
          while (optOffset + 4 <= blockTotalLength - 4) {
            final optCode = blockBd.getUint16(optOffset, currentEndian);
            final optLen = blockBd.getUint16(optOffset + 2, currentEndian);
            final optValOffset = optOffset + 4;
            if (optCode == 0) break; // End of options
            if (optCode == 9 && optLen >= 1 && optValOffset < blockTotalLength) {
              // if_tsresol
              final resolCode = blockBd.getUint8(optValOffset);
              final isPowerOfTwo = (resolCode & 0x80) != 0;
              final val = resolCode & 0x7F;
              if (isPowerOfTwo) {
                tsResolution = 1 << val;
              } else {
                int r = 1;
                for (int i = 0; i < val; i++) {
                  r *= 10;
                }
                tsResolution = r;
              }
            }
            final paddedLen = (optLen + 3) & ~3;
            optOffset += 4 + paddedLen;
          }
        }
      } else if (blockType == 0x00000006) {
        // Enhanced Packet Block (EPB)
        if (blockTotalLength >= 32) {
          // final ifId = blockBd.getUint32(8, currentEndian);
          final tsHigh = blockBd.getUint32(12, currentEndian);
          final tsLow = blockBd.getUint32(16, currentEndian);
          final capLen = blockBd.getUint32(20, currentEndian);
          final origLen = blockBd.getUint32(24, currentEndian);

          final rawTs = (tsHigh << 32) | tsLow;
          final int timestampUs;
          if (tsResolution == 1000000) {
            timestampUs = rawTs;
          } else if (tsResolution == 1000000000) {
            timestampUs = rawTs ~/ 1000;
          } else if (tsResolution > 0) {
            timestampUs = ((rawTs * 1000000) / tsResolution).round();
          } else {
            timestampUs = rawTs;
          }

          final dataOffset = offset + 28;
          if (dataOffset + capLen <= bytes.length) {
            final packetData = Uint8List.sublistView(bytes, dataOffset, dataOffset + capLen);
            packets.add(RawCapturedPacket(
              packetNo: packetNo++,
              timestampUs: timestampUs,
              capturedLength: capLen,
              originalLength: origLen,
              linkType: currentLinkType,
              fileByteOffset: blockOffset,
              data: packetData,
            ));
          }
        }
      } else if (blockType == 0x00000003) {
        // Simple Packet Block (SPB)
        if (blockTotalLength >= 16) {
          final origLen = blockBd.getUint32(8, currentEndian);
          final capLen = blockTotalLength - 16;
          final dataOffset = offset + 12;
          if (dataOffset + capLen <= bytes.length) {
            final packetData = Uint8List.sublistView(bytes, dataOffset, dataOffset + capLen);
            packets.add(RawCapturedPacket(
              packetNo: packetNo++,
              timestampUs: 0,
              capturedLength: capLen,
              originalLength: origLen,
              linkType: currentLinkType,
              fileByteOffset: blockOffset,
              data: packetData,
            ));
          }
        }
      }

      final paddedBlockLen = (blockTotalLength + 3) & ~3;
      offset += paddedBlockLen;
    }

    return packets;
  }
}
