import 'package:material_ui/material_ui.dart';
import 'custom_library_dialog.dart';

export 'custom_library_dialog.dart';

/// Legacy alias for [CustomLibraryDialog].
class ProtocolLibraryDialog extends StatelessWidget {
  const ProtocolLibraryDialog({
    super.key,
    required this.viewModel,
    this.initialTab = 0,
  });

  final dynamic viewModel;
  final int initialTab;

  @override
  Widget build(BuildContext context) {
    return CustomLibraryDialog(
      viewModel: viewModel,
      initialTab: initialTab,
    );
  }
}
