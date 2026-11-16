import 'dart:typed_data';

import 'package:material_ui/material_ui.dart';
import 'package:provider/provider.dart';

import '../view_models/capture_compare_view_model.dart';

class HexDiffInspector extends StatelessWidget {
  const HexDiffInspector({super.key});

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<CaptureCompareViewModel>();
    final record = vm.selectedRecord;
    final slots = vm.slots;

    if (record == null || slots.isEmpty) {
      return const Center(
        child: Text(
          'Select a correlated packet row above to inspect byte-level header diffs.',
          style: TextStyle(color: Colors.white54, fontSize: 12),
        ),
      );
    }

    final hopIndex = vm.selectedHopForHexDiff.clamp(1, slots.length - 1);
    final baseMatch = record.hopMatches[0];
    final hopMatch = record.hopMatches[hopIndex];

    final baseBytes = baseMatch != null
        ? vm.getRawBytes(0, baseMatch.frameNumber)
        : null;
    final hopBytes = hopMatch != null
        ? vm.getRawBytes(hopIndex, hopMatch.frameNumber)
        : null;

    final diffOffsets = <int>{};
    if (baseBytes != null && hopBytes != null) {
      final minLen =
          baseBytes.length < hopBytes.length ? baseBytes.length : hopBytes.length;
      for (var i = 0; i < minLen; i++) {
        if (baseBytes[i] != hopBytes[i]) diffOffsets.add(i);
      }
      final maxLen =
          baseBytes.length > hopBytes.length ? baseBytes.length : hopBytes.length;
      for (var i = minLen; i < maxLen; i++) {
        diffOffsets.add(i);
      }
    }

    return Container(
      color: const Color(0xFF0D1117),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            decoration: BoxDecoration(
              color: const Color(0xFF161B22),
              border: Border(
                bottom: BorderSide(color: Colors.white.withValues(alpha: 0.08)),
              ),
            ),
            child: Row(
              children: [
                const Icon(
                  Icons.difference_rounded,
                  size: 15,
                  color: Color(0xFF38BDF8),
                ),
                const SizedBox(width: 8),
                Text(
                  'Hex Diff Inspector — Row #${record.rowIndex + 1} (${record.protocolName})',
                  style: const TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w700,
                    color: Colors.white,
                  ),
                ),
                const SizedBox(width: 12),
                if (diffOffsets.isNotEmpty)
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 2,
                    ),
                    decoration: BoxDecoration(
                      color: const Color(0xFFF59E0B).withValues(alpha: 0.16),
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: Text(
                      '${diffOffsets.length} differing byte(s)',
                      style: const TextStyle(
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                        color: Color(0xFFF59E0B),
                      ),
                    ),
                  ),
                const Spacer(),
                for (var i = 1; i < slots.length; i++) ...[
                  Padding(
                    padding: const EdgeInsets.only(left: 6),
                    child: ChoiceChip(
                      label: Text(
                        'vs ${String.fromCharCode(65 + i)}: ${slots[i].label}',
                        style: const TextStyle(fontSize: 11),
                      ),
                      selected: hopIndex == i,
                      onSelected: (_) => vm.setSelectedHopForHexDiff(i),
                      selectedColor:
                          const Color(0xFF38BDF8).withValues(alpha: 0.25),
                      backgroundColor: const Color(0xFF0D1117),
                      labelStyle: TextStyle(
                        color: hopIndex == i
                            ? const Color(0xFF38BDF8)
                            : Colors.white70,
                      ),
                      visualDensity: VisualDensity.compact,
                    ),
                  ),
                ],
              ],
            ),
          ),
          if (record.statusDetail.isNotEmpty)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
              color: const Color(0xFFF59E0B).withValues(alpha: 0.08),
              child: Text(
                record.statusDetail,
                style: const TextStyle(
                  fontSize: 11,
                  color: Color(0xFFFDE68A),
                ),
              ),
            ),
          Expanded(
            child: Row(
              children: [
                Expanded(
                  child: _buildPane(
                    title: baseMatch != null
                        ? 'A: ${slots[0].label} (Frame #${baseMatch.frameNumber}, DSCP=${baseMatch.dscpValue ?? '-'}, VLAN=${baseMatch.vlanId ?? '-'})'
                        : 'A: ${slots[0].label} (MISSING)',
                    bytes: baseBytes,
                    diffOffsets: diffOffsets,
                  ),
                ),
                VerticalDivider(
                  width: 1,
                  color: Colors.white.withValues(alpha: 0.1),
                ),
                Expanded(
                  child: _buildPane(
                    title: hopMatch != null
                        ? '${String.fromCharCode(65 + hopIndex)}: ${slots[hopIndex].label} (Frame #${hopMatch.frameNumber}, DSCP=${hopMatch.dscpValue ?? '-'}, VLAN=${hopMatch.vlanId ?? '-'})'
                        : '${String.fromCharCode(65 + hopIndex)}: ${slots[hopIndex].label} (DROPPED / MISSING)',
                    bytes: hopBytes,
                    diffOffsets: diffOffsets,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildPane({
    required String title,
    required Uint8List? bytes,
    required Set<int> diffOffsets,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
          color: const Color(0xFF11161E),
          child: Text(
            title,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w600,
              color: Colors.white70,
            ),
          ),
        ),
        Expanded(
          child: bytes == null
              ? const Center(
                  child: Text(
                    'Packet not present at this hop.',
                    style: TextStyle(color: Color(0xFFEF4444), fontSize: 12),
                  ),
                )
              : _HexGrid(bytes: bytes, diffOffsets: diffOffsets),
        ),
      ],
    );
  }
}

class _HexGrid extends StatelessWidget {
  const _HexGrid({required this.bytes, required this.diffOffsets});

  final Uint8List bytes;
  final Set<int> diffOffsets;

  @override
  Widget build(BuildContext context) {
    final rowCount = (bytes.length / 16).ceil();
    return ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: rowCount,
      itemBuilder: (context, rowIndex) {
        final start = rowIndex * 16;
        final end = (start + 16).clamp(0, bytes.length);
        return Padding(
          padding: const EdgeInsets.symmetric(vertical: 1.5),
          child: Row(
            children: [
              SizedBox(
                width: 46,
                child: Text(
                  start.toRadixString(16).padLeft(4, '0'),
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 11,
                    color: Colors.white38,
                  ),
                ),
              ),
              Expanded(
                child: Wrap(
                  spacing: 4,
                  children: [
                    for (var i = start; i < end; i++)
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 2,
                          vertical: 0.5,
                        ),
                        decoration: diffOffsets.contains(i)
                            ? BoxDecoration(
                                color: const Color(0xFFF59E0B)
                                    .withValues(alpha: 0.28),
                                borderRadius: BorderRadius.circular(2),
                                border: Border.all(
                                  color: const Color(0xFFF59E0B)
                                      .withValues(alpha: 0.7),
                                  width: 0.6,
                                ),
                              )
                            : null,
                        child: Text(
                          bytes[i]
                              .toRadixString(16)
                              .padLeft(2, '0')
                              .toUpperCase(),
                          style: TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 11,
                            fontWeight: diffOffsets.contains(i)
                                ? FontWeight.w700
                                : FontWeight.w400,
                            color: diffOffsets.contains(i)
                                ? const Color(0xFFFDE68A)
                                : Colors.white70,
                          ),
                        ),
                      ),
                  ],
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}
