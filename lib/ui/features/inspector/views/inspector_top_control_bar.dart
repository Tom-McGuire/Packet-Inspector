import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../../../core/config/feature_flags.dart';
import '../view_models/inspector_view_model.dart';
import '../../protocol_library/views/custom_library_dialog.dart';

class InspectorTopControlBar extends StatelessWidget implements PreferredSizeWidget {
  const InspectorTopControlBar({
    super.key,
    required this.onOpenFile,
    required this.onExportSelected,
    this.showAiAssistant = FeatureFlags.enableAiAssistant,
  });

  final VoidCallback onOpenFile;
  final ValueChanged<String> onExportSelected;
  final bool showAiAssistant;

  @override
  Size get preferredSize => const Size.fromHeight(52);

  @override
  Widget build(BuildContext context) {
    final vm = context.watch<InspectorViewModel>();

    return Container(
      height: 52,
      decoration: const BoxDecoration(
        color: Color(0xFF1E1E1E),
        border: Border(bottom: BorderSide(color: Color(0xFF2C2C2C), width: 1)),
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
                                child: const Icon(Icons.radar, color: Colors.indigoAccent, size: 20),
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(width: 10),
                        const Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Packet Inspector',
                              style: TextStyle(
                                fontSize: 13,
                                fontWeight: FontWeight.bold,
                                letterSpacing: 0.8,
                                color: Colors.white,
                              ),
                            ),
                            Text(
                              'Deep Packet Inspection & Protocol Dissection',
                              style: TextStyle(fontSize: 10, color: Colors.white54),
                            ),
                          ],
                        ),
                        const SizedBox(width: 16),

                        // ==================== ZONE 2: TARGET / LOADED FILE ====================
                        if (vm.loadedFileName != null) ...[
                          Container(
                            height: 30,
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                            decoration: BoxDecoration(
                              color: Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.35),
                              borderRadius: BorderRadius.circular(6),
                              border: Border.all(
                                color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
                              ),
                            ),
                            child: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                const Icon(Icons.insert_drive_file_outlined, size: 13),
                                const SizedBox(width: 4),
                                ConstrainedBox(
                                  constraints: const BoxConstraints(maxWidth: 160),
                                  child: Text(
                                    vm.loadedFileName!,
                                    style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w500),
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
                          onPressed: onOpenFile,
                          icon: const Icon(Icons.folder_open, size: 16),
                          label: const Text(
                            'Open PCAP',
                            style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12),
                          ),
                          style: FilledButton.styleFrom(
                            backgroundColor: const Color(0xFF10B981), // Emerald green (from ARP Scout)
                            foregroundColor: Colors.white,
                            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
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
                          onPressed: () => vm.loadDemoCapture(),
                          icon: const Icon(Icons.play_circle_outline, size: 15),
                          label: const Text('Load Demo', style: TextStyle(fontSize: 11)),
                          style: OutlinedButton.styleFrom(
                            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
                          ),
                        ),
                        const SizedBox(width: 8),
                        OutlinedButton.icon(
                          onPressed: () => showDialog(
                            context: context,
                            builder: (ctx) => CustomLibraryDialog(viewModel: vm),
                          ),
                          icon: const Icon(Icons.menu_book, size: 15),
                          label: const Text('Custom Library', style: TextStyle(fontSize: 11)),
                          style: OutlinedButton.styleFrom(
                            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
                          ),
                        ),
                        if (showAiAssistant) ...[
                          const SizedBox(width: 8),
                          FilledButton.icon(
                            onPressed: () => vm.toggleAiPanel(),
                            style: FilledButton.styleFrom(
                              backgroundColor: vm.isAiPanelOpen ? Colors.purple : null,
                              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
                            ),
                            icon: const Icon(Icons.auto_awesome, size: 15),
                            label: const Text('AI Assistant', style: TextStyle(fontSize: 11)),
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
                            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
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
                            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
                            decoration: BoxDecoration(
                              borderRadius: BorderRadius.circular(6),
                              border: Border.all(color: const Color(0xFF2C2C2C)),
                            ),
                            child: const Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(Icons.download, size: 15, color: Colors.white70),
                                SizedBox(width: 6),
                                Text('Export', style: TextStyle(fontSize: 11, color: Colors.white70)),
                                Icon(Icons.arrow_drop_down, size: 14, color: Colors.white70),
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
