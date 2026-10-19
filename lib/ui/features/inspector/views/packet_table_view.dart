import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../../../domain/models/packet_record.dart';
import '../../../../domain/models/custom_protocol_rule.dart';
import '../view_models/inspector_view_model.dart';
import '../../protocol_library/views/add_protocol_dialog.dart';

class PacketTableView extends StatelessWidget {
  const PacketTableView({super.key});

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<InspectorViewModel>();
    final packets = vm.packets;

    if (packets.isEmpty) {
      return Container(
        color: Theme.of(context).colorScheme.surface,
        alignment: Alignment.center,
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.inbox_outlined, size: 48, color: Colors.grey),
            const SizedBox(height: 12),
            const Text(
              'No packets match the current filter or capture',
              style: TextStyle(color: Colors.grey, fontSize: 14),
            ),
            const SizedBox(height: 12),
            FilledButton.tonal(
              onPressed: () => vm.loadDemoCapture(),
              child: const Text('Load Demo Capture'),
            ),
          ],
        ),
      );
    }

    return Container(
      color: Theme.of(context).colorScheme.surface,
      child: Column(
        children: [
          // Table Header
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.8),
            child: const Row(
              children: [
                SizedBox(width: 50, child: Text('No.', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12))),
                SizedBox(width: 80, child: Text('Time (s)', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12))),
                SizedBox(width: 80, child: Text('Global Δt', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12))),
                SizedBox(width: 80, child: Text('Stream Δt', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12))),
                SizedBox(width: 140, child: Text('Source', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12))),
                SizedBox(width: 140, child: Text('Destination', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12))),
                SizedBox(width: 90, child: Text('Protocol', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12))),
                SizedBox(width: 60, child: Text('Len', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12))),
                SizedBox(width: 105, child: Text('Triage', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12))),
                Expanded(child: Text('Summary', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12))),
              ],
            ),
          ),
          const Divider(height: 1),

          // Virtualized rows list
          Expanded(
            child: ListView.separated(
              itemCount: packets.length,
              separatorBuilder: (_, _) => const Divider(height: 1, indent: 8, endIndent: 8),
              itemBuilder: (context, index) {
                final packet = packets[index];
                final isSelected = vm.selectedPacket?.packetNo == packet.packetNo;

                return InkWell(
                  onTap: () => vm.selectPacket(packet),
                  onSecondaryTapUp: (details) => _showContextMenu(context, vm, packet, details.globalPosition),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
                    color: isSelected
                        ? Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.4)
                        : (packet.triageStatus == TriageStatus.unexpected
                            ? Colors.red.withValues(alpha: 0.05)
                            : Colors.transparent),
                    child: Row(
                      children: [
                        SizedBox(
                          width: 50,
                          child: Text(
                            '${packet.packetNo}',
                            style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
                          ),
                        ),
                        SizedBox(
                          width: 80,
                          child: Text(
                            packet.timestampSeconds.toStringAsFixed(4),
                            style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
                          ),
                        ),
                        SizedBox(
                          width: 80,
                          child: _buildDeltaBadge(
                            context,
                            packet.globalDeltaMs,
                            isBurst: packet.globalDeltaMs < 0.05 && packet.globalDeltaMs > 0,
                          ),
                        ),
                        SizedBox(
                          width: 80,
                          child: _buildDeltaBadge(
                            context,
                            packet.streamDeltaMs,
                            isStall: packet.streamDeltaMs > 100.0,
                          ),
                        ),
                        SizedBox(
                          width: 140,
                          child: Text(
                            packet.srcPort != null ? '${packet.srcIp}:${packet.srcPort}' : packet.srcIp,
                            style: const TextStyle(fontSize: 12),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        SizedBox(
                          width: 140,
                          child: Text(
                            packet.dstPort != null ? '${packet.dstIp}:${packet.dstPort}' : packet.dstIp,
                            style: const TextStyle(fontSize: 12),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        SizedBox(
                          width: 90,
                          child: _buildProtocolPill(context, packet.detectedProtocol),
                        ),
                        SizedBox(
                          width: 60,
                          child: Text('${packet.capturedLength}', style: const TextStyle(fontSize: 12)),
                        ),
                        SizedBox(
                          width: 105,
                          child: _buildTriageBadge(packet.triageStatus),
                        ),
                        Expanded(
                          child: Text(
                            packet.summary,
                            style: const TextStyle(fontSize: 12),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
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

  Widget _buildDeltaBadge(BuildContext context, double ms, {bool isBurst = false, bool isStall = false}) {
    if (isBurst) {
      return Container(
        padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
        decoration: BoxDecoration(
          color: Colors.redAccent.withValues(alpha: 0.2),
          borderRadius: BorderRadius.circular(4),
        ),
        child: Text(
          '${ms.toStringAsFixed(3)}ms',
          style: const TextStyle(fontSize: 11, color: Colors.red, fontWeight: FontWeight.bold),
        ),
      );
    }
    if (isStall) {
      return Container(
        padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
        decoration: BoxDecoration(
          color: Colors.orange.withValues(alpha: 0.2),
          borderRadius: BorderRadius.circular(4),
        ),
        child: Text(
          '${ms.toStringAsFixed(1)}ms',
          style: const TextStyle(fontSize: 11, color: Colors.deepOrange, fontWeight: FontWeight.bold),
        ),
      );
    }
    return Text(
      '${ms.toStringAsFixed(2)}ms',
      style: const TextStyle(fontSize: 11, color: Colors.grey),
    );
  }

  Widget _buildProtocolPill(BuildContext context, String protocol) {
    Color bg = Theme.of(context).colorScheme.secondaryContainer;
    Color fg = Theme.of(context).colorScheme.onSecondaryContainer;

    if (protocol == 'DNS') {
      bg = Colors.blue.withValues(alpha: 0.2);
      fg = Colors.blue.shade800;
    } else if (protocol == 'HTTP') {
      bg = Colors.green.withValues(alpha: 0.2);
      fg = Colors.green.shade800;
    } else if (protocol == 'ARP') {
      bg = Colors.grey.withValues(alpha: 0.3);
      fg = Colors.black87;
    } else if (protocol.contains('ACME') || protocol.startsWith('Custom')) {
      bg = Colors.purple.withValues(alpha: 0.2);
      fg = Colors.purple.shade800;
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        protocol,
        style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: fg),
        textAlign: TextAlign.center,
        overflow: TextOverflow.ellipsis,
      ),
    );
  }

  Widget _buildTriageBadge(TriageStatus status) {
    switch (status) {
      case TriageStatus.expected:
        return const Row(
          children: [
            CircleAvatar(backgroundColor: Colors.green, radius: 4),
            SizedBox(width: 4),
            Text('Expected', style: TextStyle(fontSize: 11, color: Colors.green)),
          ],
        );
      case TriageStatus.unclassified:
        return const Row(
          children: [
            CircleAvatar(backgroundColor: Colors.amber, radius: 4),
            SizedBox(width: 4),
            Text('Unclassified', style: TextStyle(fontSize: 11, color: Colors.orange)),
          ],
        );
      case TriageStatus.unexpected:
        return const Row(
          children: [
            CircleAvatar(backgroundColor: Colors.red, radius: 4),
            SizedBox(width: 4),
            Text('Unexpected', style: TextStyle(fontSize: 11, color: Colors.red, fontWeight: FontWeight.bold)),
          ],
        );
    }
  }

  void _showContextMenu(
    BuildContext context,
    InspectorViewModel vm,
    PacketRecord packet,
    Offset position,
  ) {
    final overlay = Overlay.of(context).context.findRenderObject() as RenderBox;

    showMenu<void>(
      context: context,
      position: RelativeRect.fromRect(
        Rect.fromLTWH(position.dx, position.dy, 0, 0),
        Offset.zero & overlay.size,
      ),
      items: <PopupMenuEntry<void>>[
        PopupMenuItem(
          onTap: () async {
            // Schedule dialog after menu closes
            WidgetsBinding.instance.addPostFrameCallback((_) async {
              final rule = await showDialog<CustomProtocolRule>(
                context: context,
                builder: (ctx) => AddProtocolDialog(prefillPacket: packet),
              );
              if (rule != null) {
                vm.addCustomProtocol(rule);
              }
            });
          },
          child: const Row(
            children: [
              Icon(Icons.library_add, size: 16),
              SizedBox(width: 8),
              Text('Add to Protocol Library...'),
            ],
          ),
        ),
        const PopupMenuDivider(),
        PopupMenuItem(
          onTap: () => vm.markIpExpected(packet.srcIp),
          child: Row(
            children: [
              const Icon(Icons.check_circle_outline, size: 16, color: Colors.green),
              const SizedBox(width: 8),
              Text('Mark ${packet.srcIp} as Expected'),
            ],
          ),
        ),
        PopupMenuItem(
          onTap: () => vm.markIpUnexpected(packet.srcIp),
          child: Row(
            children: [
              const Icon(Icons.warning_amber_rounded, size: 16, color: Colors.red),
              const SizedBox(width: 8),
              Text('Flag ${packet.srcIp} as Unexpected'),
            ],
          ),
        ),
        const PopupMenuDivider(),
        PopupMenuItem(
          onTap: () {
            vm.setTriageMode(false);
            vm.setProtocolFilter({packet.detectedProtocol});
            vm.setIpFilter({packet.srcIp, packet.dstIp});
          },
          child: const Row(
            children: [
              Icon(Icons.filter_list, size: 16),
              SizedBox(width: 8),
              Text('Filter by this 5-Tuple Flow'),
            ],
          ),
        ),
      ],
    );
  }
}
