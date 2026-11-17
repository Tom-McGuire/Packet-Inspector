import 'package:material_ui/material_ui.dart';
import 'package:provider/provider.dart';

import '../../../../core/config/feature_flags.dart';
import '../../../../core/theme/app_theme.dart';
import '../../compare/view_models/capture_compare_view_model.dart';
import '../../compare/views/compare_setup_dialog.dart';
import '../../protocol_library/views/custom_library_dialog.dart';
import '../view_models/inspector_view_model.dart';

class InspectorTopControlBar extends StatelessWidget
    implements PreferredSizeWidget {
  const InspectorTopControlBar({
    super.key,
    required this.onOpenFile,
    required this.onExportSelected,
    this.showAiAssistant = FeatureFlags.enableAiAssistant,
    this.zone2And3TourKey,
  });

  final VoidCallback onOpenFile;
  final ValueChanged<String> onExportSelected;
  final bool showAiAssistant;
  final GlobalKey? zone2And3TourKey;

  @override
  Size get preferredSize => const Size.fromHeight(52);

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<InspectorViewModel>();
    final compareVm = Provider.of<CaptureCompareViewModel?>(context);
    final compareAccent =
        AppTheme.isDark ? const Color(0xFF38BDF8) : AppTheme.accent;

    return Container(
      height: 52,
      decoration: BoxDecoration(
        color: AppTheme.surface,
        border: Border(
          bottom: BorderSide(color: AppTheme.border, width: 1),
        ),
      ),
      child: LayoutBuilder(
        builder: (context, constraints) {
          return SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: ConstrainedBox(
              constraints: BoxConstraints(minWidth: constraints.maxWidth),
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    // =========================================================================
                    // Left Cluster: Zone 1 (Branding), Zone 2 (Interface & Target), Zone 3 (Primary Actions)
                    // =========================================================================
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        // ==================== ZONE 1: BRANDING ====================
                        SizedBox(
                          width: 32,
                          height: 32,
                          child: ClipRRect(
                            borderRadius: BorderRadius.circular(6),
                            child: Image.asset(
                              'assets/icons/app_icon.png',
                              width: 32,
                              height: 32,
                              fit: BoxFit.cover,
                              errorBuilder: (_, _, _) => Container(
                                width: 32,
                                height: 32,
                                decoration: BoxDecoration(
                                  color: Colors.indigoAccent.withValues(alpha: 0.2),
                                  borderRadius: BorderRadius.circular(6),
                                ),
                                child: const Icon(
                                  Icons.radar,
                                  color: Colors.indigoAccent,
                                  size: 20,
                                ),
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(width: 10),
                        Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Packet Inspector',
                              style: TextStyle(
                                fontSize: 13,
                                fontWeight: FontWeight.bold,
                                letterSpacing: 0.8,
                                color: AppTheme.textPrimary,
                              ),
                            ),
                            Text(
                              'Deep Packet Inspection & Protocol Dissection',
                              style: TextStyle(
                                fontSize: 10,
                                color: AppTheme.textSecondary,
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(width: 16),

                        // ==================== ZONE 2 & ZONE 3 ====================
                        KeyedSubtree(
                          key: zone2And3TourKey,
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              if (vm.loadedFileName != null) ...[
                                Container(
                                  height: 30,
                                  padding: const EdgeInsets.symmetric(
                                    horizontal: 8,
                                    vertical: 4,
                                  ),
                                  decoration: BoxDecoration(
                                    color: Theme.of(context)
                                        .colorScheme
                                        .primaryContainer
                                        .withValues(alpha: 0.35),
                                    borderRadius: BorderRadius.circular(6),
                                    border: Border.all(
                                      color: Theme.of(context)
                                          .colorScheme
                                          .primary
                                          .withValues(alpha: 0.3),
                                    ),
                                  ),
                                  child: Row(
                                    mainAxisSize: MainAxisSize.min,
                                    children: [
                                      const Icon(
                                        Icons.insert_drive_file_outlined,
                                        size: 13,
                                      ),
                                      const SizedBox(width: 4),
                                      ConstrainedBox(
                                        constraints: const BoxConstraints(
                                          maxWidth: 160,
                                        ),
                                        child: Text(
                                          vm.loadedFileName!,
                                          style: const TextStyle(
                                            fontSize: 11,
                                            fontWeight: FontWeight.w500,
                                          ),
                                          overflow: TextOverflow.ellipsis,
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                                const SizedBox(width: 12),
                              ],

                              // ==================== ZONE 3: PRIMARY ACTIONS ====================
                              FilledButton.icon(
                                onPressed: () {
                                  compareVm?.exitCompareMode();
                                  onOpenFile();
                                },
                                icon: const Icon(Icons.folder_open, size: 16),
                                label: const Text(
                                  'Open PCAP',
                                  style: TextStyle(
                                    fontWeight: FontWeight.bold,
                                    fontSize: 12,
                                  ),
                                ),
                                style: FilledButton.styleFrom(
                                  backgroundColor: AppTheme.success,
                                  foregroundColor: Colors.white,
                                  padding: const EdgeInsets.symmetric(
                                    horizontal: 14,
                                    vertical: 10,
                                  ),
                                  shape: RoundedRectangleBorder(
                                    borderRadius: BorderRadius.circular(6),
                                  ),
                                ),
                              ),
                              const SizedBox(width: 8),
                              if (compareVm != null) ...[
                                OutlinedButton.icon(
                                  onPressed: () => showDialog<bool>(
                                    context: context,
                                    builder: (_) => const CompareSetupDialog(),
                                  ),
                                  icon: const Icon(
                                    Icons.compare_arrows_rounded,
                                    size: 16,
                                  ),
                                  label: Text(
                                    compareVm.isCompareMode
                                        ? 'Re-Compare'
                                        : 'Compare PCAPs',
                                    style: const TextStyle(
                                      fontWeight: FontWeight.w600,
                                      fontSize: 12,
                                    ),
                                  ),
                                  style: OutlinedButton.styleFrom(
                                    foregroundColor: compareAccent,
                                    side: BorderSide(
                                      color: compareAccent.withValues(alpha: 0.55),
                                    ),
                                    padding: const EdgeInsets.symmetric(
                                      horizontal: 12,
                                      vertical: 10,
                                    ),
                                    shape: RoundedRectangleBorder(
                                      borderRadius: BorderRadius.circular(6),
                                    ),
                                  ),
                                ),
                                if (compareVm.isCompareMode) ...[
                                  const SizedBox(width: 8),
                                  FilledButton.icon(
                                    onPressed: compareVm.exitCompareMode,
                                    icon: const Icon(Icons.close_rounded, size: 15),
                                    label: const Text(
                                      'Exit Compare',
                                      style: TextStyle(
                                        fontWeight: FontWeight.bold,
                                        fontSize: 12,
                                      ),
                                    ),
                                    style: FilledButton.styleFrom(
                                      backgroundColor: AppTheme.error,
                                      foregroundColor: Colors.white,
                                      padding: const EdgeInsets.symmetric(
                                        horizontal: 12,
                                        vertical: 10,
                                      ),
                                      shape: RoundedRectangleBorder(
                                        borderRadius: BorderRadius.circular(6),
                                      ),
                                    ),
                                  ),
                                ],
                              ],
                            ],
                          ),
                        ),
                      ],
                    ),

                    const SizedBox(width: 16),

                    // =========================================================================
                    // Right Cluster: Zone 4 (Ecosystem & Demo), Zone 5 (Clear & Export)
                    // =========================================================================
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        // ==================== ZONE 4: ECOSYSTEM & DEMO ====================
                        OutlinedButton.icon(
                          onPressed: vm.isDemoMode
                              ? () => vm.endDemoWalkthrough()
                              : () {
                                  compareVm?.exitCompareMode();
                                  vm.startDemoWalkthrough();
                                },
                          icon: Icon(
                            vm.isDemoMode
                                ? Icons.stop_circle_outlined
                                : Icons.play_circle_outline,
                            size: 15,
                            color: vm.isDemoMode ? AppTheme.warning : null,
                          ),
                          label: Text(
                            vm.isDemoMode ? 'Exit Demo' : 'Load Demo',
                            style: TextStyle(
                              fontSize: 11,
                              color: vm.isDemoMode ? AppTheme.warning : null,
                              fontWeight: vm.isDemoMode
                                  ? FontWeight.w600
                                  : FontWeight.normal,
                            ),
                          ),
                          style: OutlinedButton.styleFrom(
                            side: vm.isDemoMode
                                ? BorderSide(color: AppTheme.warning)
                                : null,
                            padding: const EdgeInsets.symmetric(
                              horizontal: 10,
                              vertical: 8,
                            ),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(6),
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        OutlinedButton.icon(
                          onPressed: () => showDialog(
                            context: context,
                            builder: (ctx) => CustomLibraryDialog(viewModel: vm),
                          ),
                          icon: const Icon(Icons.menu_book, size: 15),
                          label: const Text(
                            'Custom Library',
                            style: TextStyle(fontSize: 11),
                          ),
                          style: OutlinedButton.styleFrom(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 10,
                              vertical: 8,
                            ),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(6),
                            ),
                          ),
                        ),
                        if (showAiAssistant) ...[
                          const SizedBox(width: 8),
                          FilledButton.icon(
                            onPressed: () => vm.toggleAiPanel(),
                            style: FilledButton.styleFrom(
                              backgroundColor:
                                  vm.isAiPanelOpen ? Colors.purple : null,
                              padding: const EdgeInsets.symmetric(
                                horizontal: 10,
                                vertical: 8,
                              ),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(6),
                              ),
                            ),
                            icon: const Icon(Icons.auto_awesome, size: 15),
                            label: const Text(
                              'AI Assistant',
                              style: TextStyle(fontSize: 11),
                            ),
                          ),
                        ],
                        const SizedBox(width: 8),

                        // ==================== ZONE 5: CLEAR & EXPORT ====================
                        OutlinedButton.icon(
                          onPressed: vm.loadedFileName == null
                              ? null
                              : () {
                                  vm.resetFilters();
                                  vm.clearAllFlaggedPackets();
                                },
                          icon: const Icon(Icons.delete_sweep_outlined, size: 15),
                          label: const Text('Clear', style: TextStyle(fontSize: 11)),
                          style: OutlinedButton.styleFrom(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 10,
                              vertical: 8,
                            ),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(6),
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        PopupMenuButton<String>(
                          tooltip: 'Export',
                          onSelected: onExportSelected,
                          itemBuilder: (_) => const [
                            PopupMenuItem(
                              value: 'packets',
                              child: Row(
                                children: [
                                  Icon(Icons.table_rows_outlined, size: 16),
                                  SizedBox(width: 8),
                                  Text('Export Filtered Packets'),
                                ],
                              ),
                            ),
                            PopupMenuItem(
                              value: 'flows',
                              child: Row(
                                children: [
                                  Icon(Icons.swap_horiz, size: 16),
                                  SizedBox(width: 8),
                                  Text('Export 5-Tuple Flows'),
                                ],
                              ),
                            ),
                          ],
                          child: Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 10,
                              vertical: 7,
                            ),
                            decoration: BoxDecoration(
                              borderRadius: BorderRadius.circular(6),
                              border: Border.all(color: AppTheme.border),
                            ),
                            child: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(
                                  Icons.download,
                                  size: 15,
                                  color: AppTheme.textSecondary,
                                ),
                                const SizedBox(width: 6),
                                Text(
                                  'Export',
                                  style: TextStyle(
                                    fontSize: 11,
                                    color: AppTheme.textSecondary,
                                  ),
                                ),
                                Icon(
                                  Icons.arrow_drop_down,
                                  size: 14,
                                  color: AppTheme.textSecondary,
                                ),
                              ],
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
          );
        },
      ),
    );
  }
}
