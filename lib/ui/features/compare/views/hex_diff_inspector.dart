import 'dart:typed_data';

import 'package:material_ui/material_ui.dart';
import 'package:provider/provider.dart';

import '../../../../core/theme/app_theme.dart';
import '../view_models/capture_compare_view_model.dart';

class HexDiffInspector extends StatelessWidget {
  const HexDiffInspector({super.key});

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<CaptureCompareViewModel>();
    final record = vm.selectedRecord;
    final slots = vm.slots;
    final accentColor =
        AppTheme.isDark ? const Color(0xFF38BDF8) : AppTheme.accent;

    if (record == null || slots.isEmpty) {
      return Center(
        child: Text(
          'Select a correlated packet row above to inspect byte-level header diffs.',
          style: TextStyle(color: AppTheme.textSecondary, fontSize: 12),
        ),
      );
    }

    final hopIndex = vm.selectedHopForHexDiff.clamp(1, slots.length - 1);
    final hasBaseline = record.baselineCaptureIndex == 0;
    final hopMatch = record.hopMatches[hopIndex];

    final baseBytes = hasBaseline
        ? vm.getRawBytes(0, record.baselineFrameNumber)
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
      color: AppTheme.scaffoldBg,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            decoration: BoxDecoration(
              color: AppTheme.surface,
              border: Border(
                bottom: BorderSide(color: AppTheme.border),
              ),
            ),
            child: Row(
              children: [
                Icon(
                  Icons.difference_rounded,
                  size: 15,
                  color: accentColor,
                ),
                const SizedBox(width: 8),
                Text(
                  'Hex Diff Inspector — Row #${record.rowIndex} (${record.protocolName})',
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w700,
                    color: AppTheme.textPrimary,
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
                      color: AppTheme.warning.withValues(alpha: 0.16),
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: Text(
                      '${diffOffsets.length} differing byte(s)',
                      style: TextStyle(
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                        color: AppTheme.isDark
                            ? AppTheme.warning
                            : const Color(0xFF92400E),
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
                      selectedColor: accentColor.withValues(
                        alpha: AppTheme.isDark ? 0.25 : 0.15,
                      ),
                      backgroundColor: AppTheme.scaffoldBg,
                      side: BorderSide(
                        color: hopIndex == i ? accentColor : AppTheme.border,
                      ),
                      labelStyle: TextStyle(
                        color: hopIndex == i
                            ? accentColor
                            : AppTheme.textSecondary,
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
              color: AppTheme.warning.withValues(alpha: 0.08),
              child: Text(
                record.statusDetail,
                style: TextStyle(
                  fontSize: 11,
                  color: AppTheme.isDark
                      ? const Color(0xFFFDE68A)
                      : const Color(0xFF92400E),
                ),
              ),
            ),
          Expanded(
            child: Row(
              children: [
                Expanded(
                  child: _buildPane(
                    title: hasBaseline
                        ? 'A: ${slots[0].label} (Frame #${record.baselineFrameNumber}, DSCP=${record.baselineDscp ?? '-'}, VLAN=${record.baselineVlanId ?? '-'})'
                        : 'A: ${slots[0].label} (MISSING)',
                    bytes: baseBytes,
                    diffOffsets: diffOffsets,
                  ),
                ),
                VerticalDivider(
                  width: 1,
                  color: AppTheme.border,
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
          color: AppTheme.surfaceHigh,
          child: Text(
            title,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w600,
              color: AppTheme.textSecondary,
            ),
          ),
        ),
        Expanded(
          child: bytes == null
              ? Center(
                  child: Text(
                    'Packet not present at this hop.',
                    style: TextStyle(color: AppTheme.error, fontSize: 12),
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
                  style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 11,
                    color: AppTheme.textMuted,
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
                                color: AppTheme.warning.withValues(alpha: 0.28),
                                borderRadius: BorderRadius.circular(2),
                                border: Border.all(
                                  color: AppTheme.warning.withValues(alpha: 0.7),
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
                                ? (AppTheme.isDark
                                    ? const Color(0xFFFDE68A)
                                    : const Color(0xFF92400E))
                                : AppTheme.textSecondary,
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
