import 'dart:io';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:file_picker/file_picker.dart';
import '../../../../domain/models/packet_record.dart';
import '../../../../domain/models/custom_protocol_rule.dart';
import '../../../../domain/models/endpoint_rule.dart';
import '../view_models/inspector_view_model.dart';
import '../../protocol_library/views/add_protocol_dialog.dart';
import '../../protocol_library/views/add_endpoint_dialog.dart';

enum PacketTableColumn {
  no('No.', 'packet_no', 65.0, 45.0),
  time('Date & Time', 'timestamp_us', 180.0, 110.0),
  globalDelta('Global Δt', 'global_delta_us', 105.0, 65.0),
  streamDelta('Stream Δt', 'stream_delta_us', 105.0, 65.0),
  source('Source', 'src_ip', 150.0, 80.0),
  destination('Destination', 'dst_ip', 150.0, 80.0),
  protocol('Protocol', 'detected_protocol', 100.0, 60.0),
  length('Len', 'captured_length', 65.0, 45.0),
  triage('Triage', 'triage_status', 130.0, 90.0),
  summary('Summary', 'summary', 300.0, 100.0);

  const PacketTableColumn(this.label, this.sortKey, this.defaultWidth, this.minWidth);
  final String label;
  final String sortKey;
  final double defaultWidth;
  final double minWidth;
}

class PacketTableView extends StatefulWidget {
  const PacketTableView({super.key});

  @override
  State<PacketTableView> createState() => _PacketTableViewState();
}

class _PacketTableViewState extends State<PacketTableView> {
  final ScrollController _horizontalScrollController = ScrollController();
  final ScrollController _verticalScrollController = ScrollController();
  final FocusNode _focusNode = FocusNode();
  late Map<PacketTableColumn, double> _columnWidths;

  @override
  void initState() {
    super.initState();
    _columnWidths = {
      for (final col in PacketTableColumn.values) col: col.defaultWidth,
    };
    _verticalScrollController.addListener(_onVerticalScroll);
  }

  void _onVerticalScroll() {
    if (!_verticalScrollController.hasClients) return;
    final maxScroll = _verticalScrollController.position.maxScrollExtent;
    final currentScroll = _verticalScrollController.position.pixels;
    if (maxScroll - currentScroll <= 400) {
      final vm = context.read<InspectorViewModel>();
      if (vm.hasMorePackets && !vm.isLoadingMore) {
        vm.loadMorePackets();
      }
    }
  }

  void _ensureSelectedPacketVisible(InspectorViewModel vm) {
    final selected = vm.selectedPacket;
    if (selected == null || !_verticalScrollController.hasClients) return;
    final index = vm.packets.indexWhere((p) => p.packetNo == selected.packetNo);
    if (index == -1) return;

    const double rowHeight = 35.0;
    final rowTop = index * rowHeight;
    final rowBottom = rowTop + rowHeight;
    final currentScroll = _verticalScrollController.position.pixels;
    final viewportHeight = _verticalScrollController.position.viewportDimension;

    if (rowTop < currentScroll) {
      _verticalScrollController.jumpTo(max(0.0, rowTop));
    } else if (rowBottom > currentScroll + viewportHeight) {
      _verticalScrollController.jumpTo(min(
        _verticalScrollController.position.maxScrollExtent,
        rowBottom - viewportHeight,
      ));
    }
  }

  @override
  void dispose() {
    _verticalScrollController.removeListener(_onVerticalScroll);
    _verticalScrollController.dispose();
    _horizontalScrollController.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<InspectorViewModel>();
    final packets = vm.packets;

    if (packets.isEmpty) {
      final hasCapture = vm.loadedFileName != null;
      return Container(
        color: Theme.of(context).colorScheme.surface,
        alignment: Alignment.center,
        padding: const EdgeInsets.symmetric(horizontal: 24),
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                hasCapture ? Icons.filter_alt_off_outlined : Icons.radar,
                size: 48,
                color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.7),
              ),
              const SizedBox(height: 12),
              Text(
                hasCapture ? 'No Packets Match Filter' : 'No Capture File Loaded',
                style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
              ),
              const SizedBox(height: 6),
              Text(
                hasCapture
                    ? 'Try broadening your triage criteria or clearing protocol/IP filters.'
                    : 'Open a .pcap or .pcapng network traffic file, or load the built-in demo capture.',
                style: const TextStyle(color: Colors.grey, fontSize: 12),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 16),
              if (hasCapture)
                FilledButton.tonalIcon(
                  icon: const Icon(Icons.clear_all, size: 16),
                  label: const Text('Reset Filters'),
                  onPressed: () => vm.resetFilters(),
                )
              else
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    FilledButton.icon(
                      icon: const Icon(Icons.folder_open, size: 16),
                      label: const Text('Open PCAP File'),
                      onPressed: () async {
                        try {
                          final files = await FilePicker.pickFiles(
                            type: FileType.custom,
                            allowedExtensions: ['pcap', 'pcapng', 'cap'],
                          );
                          if (files.isNotEmpty) {
                            final path = files.first.path;
                            final name = files.first.name;
                            if (path != null) {
                              vm.loadFile(File(path));
                            } else {
                              final bytes = await files.first.readAsBytes();
                              vm.loadBytes(bytes, name);
                            }
                          }
                        } catch (_) {}
                      },
                    ),
                    const SizedBox(width: 12),
                    OutlinedButton.icon(
                      icon: const Icon(Icons.play_circle_outline, size: 16),
                      label: const Text('Load Demo Capture'),
                      onPressed: () => vm.loadDemoCapture(),
                    ),
                  ],
                ),
            ],
          ),
        ),
      );
    }

    // Handle jump-to-packet request (e.g., from Flagged Packets panel)
    final requestedNo = vm.requestScrollToPacketNo;
    if (requestedNo != null) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted) return;
        final index = vm.packets.indexWhere((p) => p.packetNo == requestedNo);
        if (index != -1 && _verticalScrollController.hasClients) {
          const double rowHeight = 35.0;
          final target = (index * rowHeight).clamp(
            0.0,
            _verticalScrollController.position.maxScrollExtent,
          );
          _verticalScrollController.animateTo(
            target,
            duration: const Duration(milliseconds: 250),
            curve: Curves.easeOut,
          );
        }
        _focusNode.requestFocus();
        vm.consumeScrollToPacketRequest();
      });
    }

    return Focus(
      focusNode: _focusNode,
      autofocus: true,
      onKeyEvent: (node, event) {
        if (event is KeyDownEvent || event is KeyRepeatEvent) {
          if (event.logicalKey == LogicalKeyboardKey.arrowDown) {
            vm.selectNextPacket();
            _ensureSelectedPacketVisible(vm);
            return KeyEventResult.handled;
          } else if (event.logicalKey == LogicalKeyboardKey.arrowUp) {
            vm.selectPreviousPacket();
            _ensureSelectedPacketVisible(vm);
            return KeyEventResult.handled;
          }
        }
        return KeyEventResult.ignored;
      },
      child: GestureDetector(
        behavior: HitTestBehavior.translucent,
        onTapDown: (_) => _focusNode.requestFocus(),
        child: Container(
          color: Theme.of(context).colorScheme.surface,
          child: LayoutBuilder(
            builder: (context, constraints) {
              final availableWidth = constraints.maxWidth;
              final sumExceptSummary = _columnWidths.entries
                  .where((e) => e.key != PacketTableColumn.summary)
                  .fold(0.0, (acc, e) => acc + e.value);
              // 32px accounts for row padding (16 left + 16 right)
              final baseSummaryWidth = _columnWidths[PacketTableColumn.summary]!;
              final effectiveSummaryWidth = max(baseSummaryWidth, availableWidth - sumExceptSummary - 32.0);

              final effectiveWidths = Map<PacketTableColumn, double>.from(_columnWidths);
              effectiveWidths[PacketTableColumn.summary] = effectiveSummaryWidth;

              final totalContentWidth = effectiveWidths.values.fold(0.0, (acc, w) => acc + w) + 32.0;
              final totalTableWidth = max(availableWidth, totalContentWidth);

              return Scrollbar(
                controller: _horizontalScrollController,
                thumbVisibility: true,
                child: SingleChildScrollView(
                  controller: _horizontalScrollController,
                  scrollDirection: Axis.horizontal,
                  child: SizedBox(
                    width: totalTableWidth,
                    child: Column(
                      children: [
                        // Table Header
                        _buildHeaderRow(context, vm, effectiveWidths),
                        const Divider(height: 1),

                        // Virtualized rows list with infinite scroll pagination
                        Expanded(
                          child: ListView.separated(
                            controller: _verticalScrollController,
                            itemCount: packets.length + (vm.hasMorePackets ? 1 : 0),
                            separatorBuilder: (_, index) {
                              if (index >= packets.length) return const SizedBox.shrink();
                              return const Divider(height: 1, indent: 8, endIndent: 8);
                            },
                            itemBuilder: (context, index) {
                              if (index == packets.length) {
                                return Container(
                                  padding: const EdgeInsets.symmetric(vertical: 14),
                                  alignment: Alignment.center,
                                  child: Row(
                                    mainAxisAlignment: MainAxisAlignment.center,
                                    children: [
                                      const SizedBox(
                                        width: 14,
                                        height: 14,
                                        child: CircularProgressIndicator(strokeWidth: 2),
                                      ),
                                      const SizedBox(width: 8),
                                      Text(
                                        'Loading more packets... (${packets.length} of ${vm.totalPacketCount} loaded)',
                                        style: const TextStyle(fontSize: 12, color: Colors.grey),
                                      ),
                                    ],
                                  ),
                                );
                              }
                              final packet = packets[index];
                              return _buildRow(context, vm, packet, effectiveWidths);
                            },
                          ),
                        ),
                        const Divider(height: 1),
                        _buildStatusBar(context, vm, packets.length),
                      ],
                    ),
                  ),
                ),
              );
            },
          ),
        ),
      ),
    );
  }

  Widget _buildStatusBar(BuildContext context, InspectorViewModel vm, int loadedCount) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 5),
      color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
      child: Row(
        children: [
          Icon(Icons.format_list_numbered, size: 14, color: Theme.of(context).colorScheme.primary),
          const SizedBox(width: 6),
          Text(
            vm.totalPacketCount < vm.rawCapturePacketCount
                ? 'Showing $loadedCount of ${vm.totalPacketCount} matching packets (${vm.rawCapturePacketCount} total in capture)'
                : 'Showing $loadedCount of ${vm.totalPacketCount} packets',
            style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w600),
          ),
          if (vm.hasMorePackets) ...[
            const SizedBox(width: 8),
            const Text(
              '• Scroll down to load next batch of 1,000',
              style: TextStyle(fontSize: 11, color: Colors.grey),
            ),
          ] else if (loadedCount > 0) ...[
            const SizedBox(width: 8),
            const Text(
              '• All matching packets loaded',
              style: TextStyle(fontSize: 11, color: Colors.green, fontWeight: FontWeight.w500),
            ),
          ],
          const Spacer(),
          if (vm.isLoadingMore) ...[
            const SizedBox(
              width: 12,
              height: 12,
              child: CircularProgressIndicator(strokeWidth: 1.5),
            ),
            const SizedBox(width: 6),
            const Text(
              'Loading next 1,000...',
              style: TextStyle(fontSize: 11, color: Colors.grey),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildHeaderRow(
    BuildContext context,
    InspectorViewModel vm,
    Map<PacketTableColumn, double> widths,
  ) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.8),
      child: Row(
        children: PacketTableColumn.values.map((col) {
          return _buildHeaderCell(context, vm, col, widths[col]!);
        }).toList(),
      ),
    );
  }

  Widget _buildHeaderCell(
    BuildContext context,
    InspectorViewModel vm,
    PacketTableColumn col,
    double width,
  ) {
    final isSorted = vm.sortColumn == col.sortKey;
    final isAsc = vm.sortAscending;

    return SizedBox(
      width: width,
      child: Row(
        children: [
          Expanded(
            child: InkWell(
              onTap: () => vm.sortBy(col.sortKey),
              borderRadius: BorderRadius.circular(4),
              child: Padding(
                padding: const EdgeInsets.symmetric(vertical: 4, horizontal: 2),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Flexible(
                      child: Text(
                        col.label,
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 12,
                          color: isSorted
                              ? Theme.of(context).colorScheme.primary
                              : Theme.of(context).colorScheme.onSurface,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    if (isSorted) ...[
                      const SizedBox(width: 4),
                      Icon(
                        isAsc ? Icons.arrow_drop_up : Icons.arrow_drop_down,
                        size: 18,
                        color: Theme.of(context).colorScheme.primary,
                      ),
                    ],
                  ],
                ),
              ),
            ),
          ),
          // Drag handle to resize column
          MouseRegion(
            cursor: SystemMouseCursors.resizeColumn,
            child: GestureDetector(
              behavior: HitTestBehavior.opaque,
              onHorizontalDragUpdate: (details) {
                setState(() {
                  final newWidth = max(
                    col.minWidth,
                    (_columnWidths[col] ?? col.defaultWidth) + details.delta.dx,
                  );
                  _columnWidths[col] = newWidth;
                });
              },
              child: Container(
                width: 12,
                height: 24,
                alignment: Alignment.center,
                child: Container(
                  width: 1.5,
                  height: 14,
                  color: Theme.of(context).dividerColor.withValues(alpha: 0.6),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildRow(
    BuildContext context,
    InspectorViewModel vm,
    PacketRecord packet,
    Map<PacketTableColumn, double> widths,
  ) {
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
              width: widths[PacketTableColumn.no],
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  InkWell(
                    borderRadius: BorderRadius.circular(4),
                    onTap: () => vm.togglePacketFlag(packet),
                    child: Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 2),
                      child: Icon(
                        vm.isPacketFlagged(packet.packetNo) ? Icons.flag : Icons.flag_outlined,
                        size: 13,
                        color: vm.isPacketFlagged(packet.packetNo)
                            ? Colors.amber
                            : Theme.of(context).disabledColor.withValues(alpha: 0.35),
                      ),
                    ),
                  ),
                  const SizedBox(width: 4),
                  Expanded(
                    child: Text(
                      '${packet.packetNo}',
                      style: TextStyle(
                        fontSize: 12,
                        fontFamily: 'monospace',
                        fontWeight: vm.isPacketFlagged(packet.packetNo) ? FontWeight.bold : FontWeight.normal,
                        color: vm.isPacketFlagged(packet.packetNo) ? Colors.amber : null,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ],
              ),
            ),
            SizedBox(
              width: widths[PacketTableColumn.time],
              child: Tooltip(
                message: '${packet.timestampSeconds.toStringAsFixed(6)}s relative/raw\nEpoch: ${packet.timestampUs} µs',
                child: Text(
                  packet.formattedDateTime,
                  style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
            ),
            SizedBox(
              width: widths[PacketTableColumn.globalDelta],
              child: _buildDeltaBadge(
                context,
                packet.globalDeltaUs,
              ),
            ),
            SizedBox(
              width: widths[PacketTableColumn.streamDelta],
              child: _buildDeltaBadge(
                context,
                packet.streamDeltaUs,
              ),
            ),
            SizedBox(
              width: widths[PacketTableColumn.source],
              child: Text(
                packet.srcPort != null ? '${packet.srcIp}:${packet.srcPort}' : packet.srcIp,
                style: const TextStyle(fontSize: 12),
                overflow: TextOverflow.ellipsis,
              ),
            ),
            SizedBox(
              width: widths[PacketTableColumn.destination],
              child: Text(
                packet.dstPort != null ? '${packet.dstIp}:${packet.dstPort}' : packet.dstIp,
                style: const TextStyle(fontSize: 12),
                overflow: TextOverflow.ellipsis,
              ),
            ),
            SizedBox(
              width: widths[PacketTableColumn.protocol],
              child: _buildProtocolPill(context, packet.detectedProtocol),
            ),
            SizedBox(
              width: widths[PacketTableColumn.length],
              child: Text('${packet.capturedLength}', style: const TextStyle(fontSize: 12)),
            ),
            SizedBox(
              width: widths[PacketTableColumn.triage],
              child: _buildTriageBadge(context, vm, packet),
            ),
            SizedBox(
              width: widths[PacketTableColumn.summary],
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
  }

  Widget _buildDeltaBadge(BuildContext context, int deltaUs) {
    final seconds = deltaUs / 1000000.0;
    return Text(
      '${seconds.toStringAsFixed(6)}s',
      style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
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

  Widget _buildTriageBadge(BuildContext context, InspectorViewModel vm, PacketRecord packet) {
    final status = packet.triageStatus;
    final Color color;
    final String label;

    switch (status) {
      case TriageStatus.expected:
        color = Colors.green;
        label = 'Expected';
        break;
      case TriageStatus.unclassified:
        color = Colors.orange;
        label = 'Unclassified';
        break;
      case TriageStatus.unexpected:
        color = Colors.red;
        label = 'Unexpected';
        break;
    }

    return InkWell(
      onTapDown: (details) {
        final position = details.globalPosition;
        showMenu<TriageStatus>(
          context: context,
          position: RelativeRect.fromLTRB(position.dx, position.dy, position.dx, position.dy),
          items: const [
            PopupMenuItem(
              value: TriageStatus.expected,
              child: Row(
                children: [
                  CircleAvatar(backgroundColor: Colors.green, radius: 4),
                  SizedBox(width: 8),
                  Text('Mark Packet as Expected'),
                ],
              ),
            ),
            PopupMenuItem(
              value: TriageStatus.unclassified,
              child: Row(
                children: [
                  CircleAvatar(backgroundColor: Colors.orange, radius: 4),
                  SizedBox(width: 8),
                  Text('Reset Packet to Unclassified'),
                ],
              ),
            ),
            PopupMenuItem(
              value: TriageStatus.unexpected,
              child: Row(
                children: [
                  CircleAvatar(backgroundColor: Colors.red, radius: 4),
                  SizedBox(width: 8),
                  Text('Flag Packet as Unexpected'),
                ],
              ),
            ),
          ],
        ).then((newStatus) {
          if (newStatus != null) {
            vm.setPacketTriage(packet.packetNo, newStatus);
          }
        });
      },
      borderRadius: BorderRadius.circular(4),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 2, horizontal: 2),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircleAvatar(backgroundColor: color, radius: 4),
            const SizedBox(width: 4),
            Flexible(
              child: Text(
                label,
                style: TextStyle(
                  fontSize: 11,
                  color: color,
                  fontWeight: status == TriageStatus.unexpected ? FontWeight.bold : FontWeight.normal,
                ),
                overflow: TextOverflow.ellipsis,
              ),
            ),
            const SizedBox(width: 2),
            Icon(Icons.arrow_drop_down, size: 14, color: color.withValues(alpha: 0.6)),
          ],
        ),
      ),
    );
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
          onTap: () => vm.togglePacketFlag(packet),
          child: Row(
            children: [
              Icon(
                vm.isPacketFlagged(packet.packetNo) ? Icons.flag_outlined : Icons.flag,
                size: 16,
                color: Colors.amber,
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  vm.isPacketFlagged(packet.packetNo)
                      ? 'Unflag Packet #${packet.packetNo}'
                      : 'Flag Packet #${packet.packetNo}',
                ),
              ),
            ],
          ),
        ),
        const PopupMenuDivider(),
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
              Expanded(child: Text('Add to Protocol Library...')),
            ],
          ),
        ),
        PopupMenuItem(
          onTap: () async {
            WidgetsBinding.instance.addPostFrameCallback((_) async {
              final rule = await showDialog<EndpointRule>(
                context: context,
                builder: (ctx) => AddEndpointDialog(
                  type: EndpointType.sender,
                  prefillIp: packet.srcIp,
                  prefillPort: packet.srcPort,
                ),
              );
              if (rule != null) {
                vm.addSender(rule);
              }
            });
          },
          child: Row(
            children: [
              const Icon(Icons.arrow_upward, size: 16, color: Colors.blueAccent),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  'Save Source (${packet.srcPort != null ? '${packet.srcIp}:${packet.srcPort}' : packet.srcIp}) to Source Library...',
                ),
              ),
            ],
          ),
        ),
        if (packet.dstIp.isNotEmpty)
          PopupMenuItem(
            onTap: () async {
              WidgetsBinding.instance.addPostFrameCallback((_) async {
                final rule = await showDialog<EndpointRule>(
                  context: context,
                  builder: (ctx) => AddEndpointDialog(
                    type: EndpointType.receiver,
                    prefillIp: packet.dstIp,
                    prefillPort: packet.dstPort,
                  ),
                );
                if (rule != null) {
                  vm.addReceiver(rule);
                }
              });
            },
            child: Row(
              children: [
                const Icon(Icons.arrow_downward, size: 16, color: Colors.greenAccent),
                const SizedBox(width: 8),
                Expanded(
                child: Text(
                  'Save Destination (${packet.dstPort != null ? '${packet.dstIp}:${packet.dstPort}' : packet.dstIp}) to Destination Library...',
                ),
              ),
              ],
            ),
          ),
        const PopupMenuDivider(),
        // Source IP actions
        PopupMenuItem(
          onTap: () => vm.markIpExpected(packet.srcIp),
          child: Row(
            children: [
              const Icon(Icons.check_circle_outline, size: 16, color: Colors.green),
              const SizedBox(width: 8),
              Expanded(child: Text('Mark Source IP (${packet.srcIp}) as Expected')),
            ],
          ),
        ),
        PopupMenuItem(
          onTap: () => vm.markIpUnexpected(packet.srcIp),
          child: Row(
            children: [
              const Icon(Icons.warning_amber_rounded, size: 16, color: Colors.red),
              const SizedBox(width: 8),
              Expanded(child: Text('Flag Source IP (${packet.srcIp}) as Unexpected')),
            ],
          ),
        ),
        PopupMenuItem(
          onTap: () => vm.resetIpTriage(packet.srcIp),
          child: const Row(
            children: [
              Icon(Icons.refresh, size: 16, color: Colors.amber),
              SizedBox(width: 8),
              Expanded(child: Text('Reset Source IP to Unclassified')),
            ],
          ),
        ),
        // Destination IP actions (if different from source IP)
        if (packet.dstIp.isNotEmpty && packet.dstIp != packet.srcIp) ...[
          const PopupMenuDivider(),
          PopupMenuItem(
            onTap: () => vm.markIpExpected(packet.dstIp),
            child: Row(
              children: [
                const Icon(Icons.check_circle_outline, size: 16, color: Colors.green),
                const SizedBox(width: 8),
                Expanded(child: Text('Mark Dest IP (${packet.dstIp}) as Expected')),
              ],
            ),
          ),
          PopupMenuItem(
            onTap: () => vm.markIpUnexpected(packet.dstIp),
            child: Row(
              children: [
                const Icon(Icons.warning_amber_rounded, size: 16, color: Colors.red),
                const SizedBox(width: 8),
                Expanded(child: Text('Flag Dest IP (${packet.dstIp}) as Unexpected')),
              ],
            ),
          ),
          PopupMenuItem(
            onTap: () => vm.resetIpTriage(packet.dstIp),
            child: const Row(
              children: [
                Icon(Icons.refresh, size: 16, color: Colors.amber),
                SizedBox(width: 8),
                Expanded(child: Text('Reset Dest IP to Unclassified')),
              ],
            ),
          ),
        ],
        const PopupMenuDivider(),
        // Individual packet actions
        PopupMenuItem(
          onTap: () => vm.setPacketTriage(packet.packetNo, TriageStatus.expected),
          child: Row(
            children: [
              const Icon(Icons.bookmark_added_outlined, size: 16, color: Colors.green),
              const SizedBox(width: 8),
              Expanded(child: Text('Set Packet #${packet.packetNo} as Expected')),
            ],
          ),
        ),
        PopupMenuItem(
          onTap: () => vm.setPacketTriage(packet.packetNo, TriageStatus.unexpected),
          child: Row(
            children: [
              const Icon(Icons.report_outlined, size: 16, color: Colors.red),
              const SizedBox(width: 8),
              Expanded(child: Text('Set Packet #${packet.packetNo} as Unexpected')),
            ],
          ),
        ),
        PopupMenuItem(
          onTap: () => vm.setPacketTriage(packet.packetNo, TriageStatus.unclassified),
          child: const Row(
            children: [
              Icon(Icons.help_outline, size: 16, color: Colors.amber),
              SizedBox(width: 8),
              Expanded(child: Text('Set Packet as Unclassified')),
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
              Expanded(child: Text('Filter by this 5-Tuple Flow')),
            ],
          ),
        ),
      ],
    );
  }
}
