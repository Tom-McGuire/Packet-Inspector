import '../../repositories/packet_repository.dart';
import '../../../domain/models/custom_protocol_rule.dart';
import '../../../domain/models/endpoint_rule.dart';
import '../../../domain/models/packet_record.dart';

/// Holds parsed and resolved filter references (/p, /s, /r) from user chat messages.
class AiFilterReferences {
  const AiFilterReferences({
    required this.rawProtocols,
    required this.rawSenders,
    required this.rawReceivers,
    required this.matchedProtocolRules,
    required this.standardProtocols,
    required this.matchedSenders,
    required this.unmatchedSenderIps,
    required this.matchedReceivers,
    required this.unmatchedReceiverIps,
  });

  final List<String> rawProtocols;
  final List<String> rawSenders;
  final List<String> rawReceivers;

  final List<CustomProtocolRule> matchedProtocolRules;
  final List<String> standardProtocols;

  final List<EndpointRule> matchedSenders;
  final List<String> unmatchedSenderIps;

  final List<EndpointRule> matchedReceivers;
  final List<String> unmatchedReceiverIps;

  List<String> get rawSources => rawSenders;
  List<String> get rawDestinations => rawReceivers;
  List<EndpointRule> get matchedSources => matchedSenders;
  List<EndpointRule> get matchedDestinations => matchedReceivers;
  List<String> get unmatchedSourceIps => unmatchedSenderIps;
  List<String> get unmatchedDestinationIps => unmatchedReceiverIps;
  Set<String> get allSourceKeys => allSenderKeys;
  Set<String> get allDestinationKeys => allReceiverKeys;

  bool get hasAnyReferences =>
      rawProtocols.isNotEmpty || rawSenders.isNotEmpty || rawReceivers.isNotEmpty;

  /// Protocol names to pass to database query
  Set<String> get allProtocolNames => {
        ...matchedProtocolRules.map((r) => r.name),
        ...standardProtocols,
      };

  /// Sender filter keys to pass to database query
  Set<String> get allSenderKeys => {
        ...matchedSenders.map((s) => s.filterKey),
        ...unmatchedSenderIps,
      };

  /// Receiver filter keys to pass to database query
  Set<String> get allReceiverKeys => {
        ...matchedReceivers.map((r) => r.filterKey),
        ...unmatchedReceiverIps,
      };

  /// Parses `/p:...`, `/s:...`, and `/r:...` (or with space `/p ...`) from user input
  /// and resolves them against the library in [PacketRepository].
  static AiFilterReferences parse(String text, PacketRepository repository) {
    final rawProtocols = <String>[];
    final rawSenders = <String>[];
    final rawReceivers = <String>[];

    // Pattern matches:
    // /p:(?:"([^"]+)"|([^\s,]+)) OR /p\s+(?:"([^"]+)"|([a-zA-Z0-9_\.\:\-]+))
    final protoRegex = RegExp(r'/p(?::|\s+)(?:"([^"]+)"|([^\s,]+))', caseSensitive: false);
    for (final match in protoRegex.allMatches(text)) {
      final token = match.group(1) ?? match.group(2);
      if (token != null && token.trim().isNotEmpty) {
        rawProtocols.add(token.trim());
      }
    }

    final senderRegex = RegExp(r'/s(?::|\s+)(?:"([^"]+)"|([^\s,]+))', caseSensitive: false);
    for (final match in senderRegex.allMatches(text)) {
      final token = match.group(1) ?? match.group(2);
      if (token != null && token.trim().isNotEmpty) {
        rawSenders.add(token.trim());
      }
    }

    final receiverRegex = RegExp(r'/(?:r|d)(?::|\s+)(?:"([^"]+)"|([^\s,]+))', caseSensitive: false);
    for (final match in receiverRegex.allMatches(text)) {
      final token = match.group(1) ?? match.group(2);
      if (token != null && token.trim().isNotEmpty) {
        rawReceivers.add(token.trim());
      }
    }

    // Resolve Protocols
    final matchedRules = <CustomProtocolRule>[];
    final standardProtos = <String>[];
    final availableCustom = repository.customRules;

    for (final p in rawProtocols) {
      final pLower = p.toLowerCase();
      final match = availableCustom.firstWhere(
        (r) => r.name.toLowerCase() == pLower || r.id.toLowerCase() == pLower,
        orElse: () => availableCustom.firstWhere(
          (r) => r.name.toLowerCase().contains(pLower),
          orElse: () => const CustomProtocolRule(
            id: '',
            name: '',
            colorHex: 0,
            defaultTriageStatus: TriageStatus.expected,
          ),
        ),
      );

      if (match.id.isNotEmpty) {
        if (!matchedRules.any((r) => r.id == match.id)) {
          matchedRules.add(match);
        }
      } else {
        if (!standardProtos.contains(p)) {
          standardProtos.add(p);
        }
      }
    }

    // Resolve Senders
    final matchedSenders = <EndpointRule>[];
    final unmatchedSenderIps = <String>[];
    final availableSenders = repository.senders;

    for (final s in rawSenders) {
      final sLower = s.toLowerCase();
      final match = availableSenders.firstWhere(
        (ep) =>
            ep.name.toLowerCase() == sLower ||
            ep.ipAddress.toLowerCase() == sLower ||
            ep.filterKey.toLowerCase() == sLower ||
            ep.displayName.toLowerCase().contains(sLower),
        orElse: () => const EndpointRule(id: '', name: '', ipAddress: ''),
      );

      if (match.id.isNotEmpty) {
        if (!matchedSenders.any((ep) => ep.id == match.id)) {
          matchedSenders.add(match);
        }
      } else {
        if (!unmatchedSenderIps.contains(s)) {
          unmatchedSenderIps.add(s);
        }
      }
    }

    // Resolve Receivers
    final matchedReceivers = <EndpointRule>[];
    final unmatchedReceiverIps = <String>[];
    final availableReceivers = repository.receivers;

    for (final r in rawReceivers) {
      final rLower = r.toLowerCase();
      final match = availableReceivers.firstWhere(
        (ep) =>
            ep.name.toLowerCase() == rLower ||
            ep.ipAddress.toLowerCase() == rLower ||
            ep.filterKey.toLowerCase() == rLower ||
            ep.displayName.toLowerCase().contains(rLower),
        orElse: () => const EndpointRule(id: '', name: '', ipAddress: ''),
      );

      if (match.id.isNotEmpty) {
        if (!matchedReceivers.any((ep) => ep.id == match.id)) {
          matchedReceivers.add(match);
        }
      } else {
        if (!unmatchedReceiverIps.contains(r)) {
          unmatchedReceiverIps.add(r);
        }
      }
    }

    return AiFilterReferences(
      rawProtocols: rawProtocols,
      rawSenders: rawSenders,
      rawReceivers: rawReceivers,
      matchedProtocolRules: matchedRules,
      standardProtocols: standardProtos,
      matchedSenders: matchedSenders,
      unmatchedSenderIps: unmatchedSenderIps,
      matchedReceivers: matchedReceivers,
      unmatchedReceiverIps: unmatchedReceiverIps,
    );
  }

  /// Formats specifications of the referenced library items into structured text for AI analysis.
  String buildLibraryContextSummary() {
    final sb = StringBuffer();

    if (matchedProtocolRules.isNotEmpty) {
      sb.writeln('Custom Protocol Library Specifications:');
      for (final r in matchedProtocolRules) {
        final proto = r.ipProtocol == 6 ? 'TCP' : (r.ipProtocol == 17 ? 'UDP' : 'IP proto ${r.ipProtocol ?? "*"}');
        final magic = r.magicBytesHex != null && r.magicBytesHex!.isNotEmpty
            ? 'Magic bytes: [0x${r.magicBytesHex!.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ')}] at offset ${r.magicBytesOffset}'
            : 'No magic bytes';
        sb.writeln('• Protocol "${r.name}": $proto port ${r.port ?? "*"} (${r.portDirection.name}), $magic, Specificity priority ${r.specificityScore}, Default triage: ${r.defaultTriageStatus.name}');
      }
    }
    if (standardProtocols.isNotEmpty) {
      sb.writeln('Standard Protocols: ${standardProtocols.join(", ")}');
    }

    if (matchedSenders.isNotEmpty) {
      sb.writeln('Sender Library Specifications:');
      for (final s in matchedSenders) {
        sb.writeln('• Sender "${s.name}": IP ${s.ipAddress}${s.port != null ? ' : Port ${s.port}' : ''}');
      }
    }
    if (unmatchedSenderIps.isNotEmpty) {
      sb.writeln('Referenced Sender IPs: ${unmatchedSenderIps.join(", ")}');
    }

    if (matchedReceivers.isNotEmpty) {
      sb.writeln('Receiver Library Specifications:');
      for (final r in matchedReceivers) {
        sb.writeln('• Receiver "${r.name}": IP ${r.ipAddress}${r.port != null ? ' : Port ${r.port}' : ''}');
      }
    }
    if (unmatchedReceiverIps.isNotEmpty) {
      sb.writeln('Referenced Receiver IPs: ${unmatchedReceiverIps.join(", ")}');
    }

    return sb.toString().trim();
  }
}
