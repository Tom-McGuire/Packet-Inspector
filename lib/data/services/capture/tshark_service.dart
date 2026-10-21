import 'dart:io';
import 'package:path/path.dart' as p;
import '../../../domain/models/capture_config.dart';

class CaptureProcessResult {
  const CaptureProcessResult({
    required this.pid,
    required this.targetDirectory,
    required this.targetFilePath,
    this.process,
  });

  final int pid;
  final String targetDirectory;
  final String targetFilePath;
  final Process? process;
}

class TSharkService {
  TSharkService({this.customTSharkPath});

  final String? customTSharkPath;

  /// Attempts to locate the `tshark` executable on the system.
  Future<String?> findTSharkPath() async {
    if (customTSharkPath != null && customTSharkPath!.isNotEmpty) {
      if (await File(customTSharkPath!).exists()) {
        return customTSharkPath;
      }
    }

    if (Platform.isWindows) {
      const candidates = [
        r'C:\Program Files\Wireshark\tshark.exe',
        r'C:\Program Files (x86)\Wireshark\tshark.exe',
      ];
      for (final path in candidates) {
        if (await File(path).exists()) {
          return path;
        }
      }

      // Check via where tshark
      try {
        final res = await Process.run('where', ['tshark']);
        if (res.exitCode == 0 && res.stdout.toString().trim().isNotEmpty) {
          final firstLine = res.stdout.toString().trim().split(RegExp(r'[\r\n]+')).first;
          if (await File(firstLine).exists()) {
            return firstLine;
          }
        }
      } catch (_) {}
    } else {
      const candidates = [
        '/usr/bin/tshark',
        '/usr/local/bin/tshark',
        '/opt/homebrew/bin/tshark',
      ];
      for (final path in candidates) {
        if (await File(path).exists()) {
          return path;
        }
      }

      try {
        final res = await Process.run('which', ['tshark']);
        if (res.exitCode == 0 && res.stdout.toString().trim().isNotEmpty) {
          final found = res.stdout.toString().trim().split(RegExp(r'[\r\n]+')).first;
          if (await File(found).exists()) {
            return found;
          }
        }
      } catch (_) {}
    }

    return null;
  }

  /// Lists available capture interfaces using `tshark -D`.
  Future<List<CaptureInterface>> getInterfaces(String tsharkPath) async {
    try {
      final res = await Process.run(tsharkPath, ['-D']);
      if (res.exitCode != 0) {
        return [];
      }

      final lines = res.stdout.toString().split(RegExp(r'[\r\n]+'));
      final interfaces = <CaptureInterface>[];

      // Format is e.g.:
      // 1. \Device\NPF_{...} (Wi-Fi)
      // 2. eth0
      final lineRegex = RegExp(r'^(\d+)\.\s+(.*?)(?:\s+\((.*?)\))?$');

      for (final rawLine in lines) {
        final line = rawLine.trim();
        if (line.isEmpty) continue;

        final match = lineRegex.firstMatch(line);
        if (match != null) {
          final index = match.group(1)!;
          final name = match.group(2)!.trim();
          final friendly = match.group(3)?.trim();
          interfaces.add(
            CaptureInterface(
              index: index,
              name: name,
              friendlyName: (friendly != null && friendly.isNotEmpty) ? friendly : null,
            ),
          );
        }
      }

      return interfaces;
    } catch (_) {
      return [];
    }
  }

  /// Builds command-line arguments for tshark based on the configuration.
  List<String> buildArguments(CaptureConfig config, String fullOutputPath) {
    final args = <String>[
      '-i', config.interface.index,
    ];

    switch (config.mode) {
      case CaptureMode.quick:
        args.addAll(['-w', fullOutputPath]);
        break;
      case CaptureMode.timed:
        final seconds = config.totalSeconds > 0 ? config.totalSeconds : 600;
        args.addAll([
          '-a', 'duration:$seconds',
          '-w', fullOutputPath,
        ]);
        break;
      case CaptureMode.ringBuffer:
        final seconds = config.totalSeconds > 0 ? config.totalSeconds : 600;
        final files = config.ringFiles > 1 ? config.ringFiles : 5;
        args.addAll([
          '-b', 'duration:$seconds',
          '-b', 'files:$files',
          '-w', fullOutputPath,
        ]);
        break;
    }

    return args;
  }

  /// Starts the TShark capture process.
  Future<CaptureProcessResult> startCapture({
    required String tsharkPath,
    required CaptureConfig config,
    bool detached = false,
  }) async {
    final now = DateTime.now();
    final timestamp = '${now.year}${now.month.toString().padLeft(2, '0')}${now.day.toString().padLeft(2, '0')}_'
        '${now.hour.toString().padLeft(2, '0')}${now.minute.toString().padLeft(2, '0')}${now.second.toString().padLeft(2, '0')}';

    var targetDir = config.outputDirectory;
    if (config.createSubfolder) {
      targetDir = p.join(targetDir, 'Capture_$timestamp');
    }

    final dir = Directory(targetDir);
    if (!dir.existsSync()) {
      dir.createSync(recursive: true);
    }

    final filename = '${config.filePrefix.isNotEmpty ? config.filePrefix : 'capture'}_$timestamp.pcapng';
    final fullOutputPath = p.join(targetDir, filename);

    final args = buildArguments(config, fullOutputPath);

    final mode = detached ? ProcessStartMode.detached : ProcessStartMode.normal;
    final process = await Process.start(
      tsharkPath,
      args,
      mode: mode,
    );

    return CaptureProcessResult(
      pid: process.pid,
      targetDirectory: targetDir,
      targetFilePath: fullOutputPath,
      process: detached ? null : process,
    );
  }

  /// Checks if a process with the given PID is currently active and belongs to tshark/dumpcap.
  Future<bool> isProcessAlive(int pid) async {
    try {
      if (Platform.isWindows) {
        final res = await Process.run('tasklist', ['/FI', 'PID eq $pid', '/FO', 'CSV', '/NH']);
        if (res.exitCode == 0) {
          final out = res.stdout.toString().toLowerCase();
          return out.contains(pid.toString()) && (out.contains('tshark') || out.contains('dumpcap'));
        }
        return false;
      } else {
        final res = await Process.run('kill', ['-0', pid.toString()]);
        return res.exitCode == 0;
      }
    } catch (_) {
      return false;
    }
  }

  /// Terminates a running capture process cleanly.
  Future<bool> stopCapture(int pid) async {
    try {
      if (Platform.isWindows) {
        // Using taskkill /T /F ensures both tshark and child dumpcap are stopped
        final res = await Process.run('taskkill', ['/PID', pid.toString(), '/T', '/F']);
        return res.exitCode == 0;
      } else {
        final res = await Process.run('kill', ['-15', pid.toString()]);
        return res.exitCode == 0;
      }
    } catch (_) {
      try {
        return Process.killPid(pid);
      } catch (_) {
        return false;
      }
    }
  }

  /// Opens the target folder in the system file manager.
  Future<void> openFolder(String folderPath) async {
    try {
      if (!Directory(folderPath).existsSync()) return;
      if (Platform.isWindows) {
        await Process.run('explorer.exe', [folderPath]);
      } else if (Platform.isMacOS) {
        await Process.run('open', [folderPath]);
      } else if (Platform.isLinux) {
        await Process.run('xdg-open', [folderPath]);
      }
    } catch (_) {}
  }
}
