import 'package:material_ui/material_ui.dart';
import 'package:provider/provider.dart';
import '../view_models/inspector_view_model.dart';

class FlaggedPacketsPanel extends StatelessWidget {
  const FlaggedPacketsPanel({super.key});

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<InspectorViewModel>();
    final flagged = vm.flaggedPackets;

    return Container(
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Header Bar
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.6),
              border: Border(
                bottom: BorderSide(
                  color: Theme.of(context).dividerColor.withValues(alpha: 0.4),
                ),
              ),
            ),
            child: Row(
              children: [
                const Icon(Icons.flag, size: 16, color: Colors.amber),
                const SizedBox(width: 8),
                Text(
                  'Flagged Packets (${flagged.length})',
                  style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
                ),
                const Spacer(),
                if (flagged.isNotEmpty)
                  TextButton.icon(
                    style: TextButton.styleFrom(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                      visualDensity: VisualDensity.compact,
                    ),
                    icon: const Icon(Icons.clear_all, size: 14),
                    label: const Text('Clear All', style: TextStyle(fontSize: 11)),
                    onPressed: () => vm.clearAllFlaggedPackets(),
                  ),
              ],
            ),
          ),

          // Body: Empty State or Scrollable Flagged List
          Expanded(
            child: flagged.isEmpty
                ? Center(
                    child: Padding(
                      padding: const EdgeInsets.all(16.0),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(
                            Icons.outlined_flag,
                            size: 28,
                            color: Colors.grey.shade600,
                          ),
                          const SizedBox(height: 8),
                          const Text(
                            'No flagged packets',
                            style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: Colors.grey),
                          ),
                          const SizedBox(height: 4),
                          const Text(
                            'Right-click any packet row or click the flag icon\nto track events and calculate delta intervals.',
                            textAlign: TextAlign.center,
                            style: TextStyle(fontSize: 11, color: Colors.grey),
                          ),
                        ],
                      ),
                    ),
                  )
                : ListView.separated(
                    padding: const EdgeInsets.all(8),
                    itemCount: flagged.length,
                    separatorBuilder: (_, _) => const SizedBox(height: 6),
                    itemBuilder: (context, index) {
                      final packet = flagged[index];
                      final isSelected = vm.selectedPacket?.packetNo == packet.packetNo;

                      // Delta time calculation between sequential flagged packets
                      final String deltaStr;
                      final String? totalElapsedStr;
                      if (index == 0) {
                        deltaStr = 'Δ: Baseline (0.000000s)';
                        totalElapsedStr = null;
                      } else {
                        final prevPacket = flagged[index - 1];
                        final diffUs = packet.timestampUs - prevPacket.timestampUs;
                        final deltaSeconds = diffUs / 1000000.0;
                        deltaStr = 'Δ: +${deltaSeconds.toStringAsFixed(6)}s';

                        final firstPacket = flagged[0];
                        final totalDiffUs = packet.timestampUs - firstPacket.timestampUs;
                        final totalSeconds = totalDiffUs / 1000000.0;
                        totalElapsedStr = 'Total: +${totalSeconds.toStringAsFixed(6)}s';
                      }

                      return InkWell(
                        onTap: () => vm.jumpToPacket(packet),
                        borderRadius: BorderRadius.circular(8),
                        child: Container(
                          padding: const EdgeInsets.all(8),
                          decoration: BoxDecoration(
                            color: isSelected
                                ? Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.35)
                                : Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.25),
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(
                              color: isSelected
                                  ? Theme.of(context).colorScheme.primary
                                  : Theme.of(context).dividerColor.withValues(alpha: 0.3),
                              width: isSelected ? 1.5 : 1.0,
                            ),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              // Top Row: Packet #, Protocol, Delta badge, Unflag button
                              Row(
                                children: [
                                  const Icon(Icons.flag, size: 14, color: Colors.amber),
                                  const SizedBox(width: 6),
                                  Text(
                                    '#${packet.packetNo}',
                                    style: const TextStyle(
                                      fontWeight: FontWeight.bold,
                                      fontSize: 12,
                                      fontFamily: 'monospace',
                                    ),
                                  ),
                                  const SizedBox(width: 8),
                                  Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
                                    decoration: BoxDecoration(
                                      color: Colors.blueAccent.withValues(alpha: 0.15),
                                      borderRadius: BorderRadius.circular(4),
                                      border: Border.all(color: Colors.blueAccent.withValues(alpha: 0.3)),
                                    ),
                                    child: Text(
                                      packet.detectedProtocol,
                                      style: const TextStyle(
                                        fontSize: 10,
                                        fontWeight: FontWeight.w600,
                                        color: Colors.blueAccent,
                                      ),
                                    ),
                                  ),
                                  const Spacer(),
                                  // Delta timing badge
                                  Tooltip(
                                    message: totalElapsedStr != null
                                        ? '$deltaStr\n$totalElapsedStr'
                                        : 'Initial flagged reference packet',
                                    child: Container(
                                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                      decoration: BoxDecoration(
                                        color: Colors.amber.withValues(alpha: 0.15),
                                        borderRadius: BorderRadius.circular(4),
                                        border: Border.all(color: Colors.amber.withValues(alpha: 0.4)),
                                      ),
                                      child: Text(
                                        deltaStr,
                                        style: const TextStyle(
                                          fontSize: 10,
                                          fontFamily: 'monospace',
                                          fontWeight: FontWeight.bold,
                                          color: Colors.amber,
                                        ),
                                      ),
                                    ),
                                  ),
                                  const SizedBox(width: 4),
                                  InkWell(
                                    onTap: () => vm.togglePacketFlag(packet),
                                    borderRadius: BorderRadius.circular(12),
                                    child: const Padding(
                                      padding: EdgeInsets.all(2.0),
                                      child: Icon(Icons.close, size: 14, color: Colors.grey),
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 4),

                              // Date and Time (Formatted identical to the table column)
                              Row(
                                children: [
                                  const Icon(Icons.schedule, size: 11, color: Colors.grey),
                                  const SizedBox(width: 4),
                                  Text(
                                    packet.formattedDateTime,
                                    style: const TextStyle(
                                      fontSize: 11,
                                      fontFamily: 'monospace',
                                      color: Colors.grey,
                                    ),
                                  ),
                                  if (packet.srcIp.isNotEmpty) ...[
                                    const SizedBox(width: 8),
                                    Expanded(
                                      child: Text(
                                        '${packet.srcIp} → ${packet.dstIp}',
                                        style: const TextStyle(fontSize: 11, color: Colors.grey),
                                        overflow: TextOverflow.ellipsis,
                                      ),
                                    ),
                                  ],
                                ],
                              ),

                              // Summary line
                              if (packet.summary.isNotEmpty) ...[
                                const SizedBox(height: 3),
                                Text(
                                  packet.summary,
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                  style: TextStyle(
                                    fontSize: 11,
                                    color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.8),
                                  ),
                                ),
                              ],
                            ],
                          ),
                        ),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}
