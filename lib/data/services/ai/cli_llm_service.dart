import 'dart:async';
import 'dart:convert';
import 'dart:io';

enum CliType {
  antigravity,
  claudeCode,
  codex,
}

class CliModelInfo {
  const CliModelInfo({
    required this.id,
    required this.name,
    this.isEconomical = false,
  });

  final String id;
  final String name;
  final bool isEconomical;

  @override
  String toString() => '$name ($id)';
}

class CliStatus {
  const CliStatus({
    required this.type,
    required this.isInstalled,
    required this.executablePath,
    required this.isAuthenticated,
    required this.message,
    this.version,
  });

  final CliType type;
  final bool isInstalled;
  final String? executablePath;
  final bool isAuthenticated;
  final String message;
  final String? version;

  @override
  String toString() =>
      'CliStatus(type: $type, isInstalled: $isInstalled, path: $executablePath, authenticated: $isAuthenticated, msg: $message)';
}

typedef ProcessRunner = Future<ProcessResult> Function(
  String executable,
  List<String> arguments, {
  bool runInShell,
  Duration? timeout,
});

/// Service for discovering, health-checking, and invoking CLI-based LLMs
/// (Antigravity CLI `agy` and Claude Code `claude`) to leverage user subscriptions.
class CliLlmService {
  CliLlmService({ProcessRunner? processRunner})
      : _processRunner = processRunner ?? _defaultProcessRunner;

  final ProcessRunner _processRunner;

  static Future<ProcessResult> _defaultProcessRunner(
    String executable,
    List<String> arguments, {
    bool runInShell = false,
    Duration? timeout,
  }) async {
    final effectiveTimeout = timeout ?? const Duration(seconds: 45);
    try {
      return await Process.run(
        executable,
        arguments,
        runInShell: runInShell,
      ).timeout(effectiveTimeout);
    } on TimeoutException {
      return ProcessResult(-1, -1, '', 'Command timed out after ${effectiveTimeout.inSeconds} seconds');
    } catch (e) {
      return ProcessResult(-1, -1, '', e.toString());
    }
  }

  /// Locates the CLI executable on the system.
  Future<String?> findExecutable(CliType type, {String? customPath}) async {
    final isWindows = Platform.isWindows;

    if (customPath != null && customPath.trim().isNotEmpty) {
      final trimmed = customPath.trim();
      final file = File(trimmed);
      if (await file.exists()) {
        return file.path;
      }
      // If user specified a bare command name without path separators, try looking it up
      if (!trimmed.contains(Platform.pathSeparator) && !trimmed.contains('/')) {
        final lookupCmd = isWindows ? 'where' : 'which';
        try {
          final res = await _processRunner(
            lookupCmd,
            [trimmed],
            runInShell: isWindows,
            timeout: const Duration(seconds: 5),
          );
          if (res.exitCode == 0 && res.stdout.toString().trim().isNotEmpty) {
            return res.stdout.toString().trim().split(RegExp(r'[\r\n]+')).first.trim();
          }
        } catch (_) {}
      }
      return null;
    }
    final home = Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'] ?? '';

    final candidates = <String>[];
    if (type == CliType.antigravity) {
      if (!isWindows) {
        candidates.addAll([
          '/snap/bin/agy',
          '/usr/local/bin/agy',
          '/usr/bin/agy',
          if (home.isNotEmpty) '$home/.local/bin/agy',
        ]);
      } else {
        final localAppData = Platform.environment['LOCALAPPDATA'] ?? '';
        if (localAppData.isNotEmpty) {
          candidates.add('$localAppData\\Programs\\agy\\agy.exe');
        }
      }
    } else if (type == CliType.claudeCode) {
      // Claude Code
      if (!isWindows) {
        candidates.addAll([
          '/usr/local/bin/claude',
          '/usr/bin/claude',
          if (home.isNotEmpty) '$home/.npm-global/bin/claude',
          if (home.isNotEmpty) '$home/.nvm/versions/node/current/bin/claude',
        ]);
      } else {
        final appData = Platform.environment['APPDATA'] ?? '';
        if (appData.isNotEmpty) {
          candidates.add('$appData\\npm\\claude.cmd');
        }
      }
    } else {
      // OpenAI Codex CLI
      if (!isWindows) {
        candidates.addAll([
          '/usr/local/bin/codex',
          '/usr/bin/codex',
          if (home.isNotEmpty) '$home/.npm-global/bin/codex',
          if (home.isNotEmpty) '$home/.nvm/versions/node/current/bin/codex',
          if (home.isNotEmpty) '$home/.local/bin/codex',
        ]);
      } else {
        final appData = Platform.environment['APPDATA'] ?? '';
        if (appData.isNotEmpty) {
          candidates.add('$appData\\npm\\codex.cmd');
        }
      }
    }

    for (final candidate in candidates) {
      if (await File(candidate).exists()) {
        return candidate;
      }
    }

    // Try system path lookup via `which` or `where`
    final lookupCmd = isWindows ? 'where' : 'which';
    final binaryName = type == CliType.antigravity
        ? 'agy'
        : (type == CliType.claudeCode ? 'claude' : 'codex');
    try {
      final res = await _processRunner(
        lookupCmd,
        [binaryName],
        runInShell: isWindows,
        timeout: const Duration(seconds: 5),
      );
      if (res.exitCode == 0) {
        final out = res.stdout.toString().trim();
        if (out.isNotEmpty) {
          final firstLine = out.split(RegExp(r'[\r\n]+')).first.trim();
          if (await File(firstLine).exists()) {
            return firstLine;
          }
          return firstLine;
        }
      }
    } catch (_) {}

    return null;
  }

  /// Checks whether the CLI is installed and authenticated.
  Future<CliStatus> checkStatus(CliType type, {String? customPath}) async {
    final exec = await findExecutable(type, customPath: customPath);
    if (exec == null) {
      final String name;
      final String installTip;
      switch (type) {
        case CliType.antigravity:
          name = 'Antigravity CLI (agy)';
          installTip = 'Ensure agy is installed in your PATH or specify its path in settings.';
          break;
        case CliType.claudeCode:
          name = 'Claude Code (claude)';
          installTip = 'Install with "npm install -g @anthropic-ai/claude-code"';
          break;
        case CliType.codex:
          name = 'OpenAI Codex CLI (codex)';
          installTip = 'Install with "npm install -g @openai/codex"';
          break;
      }
      return CliStatus(
        type: type,
        isInstalled: false,
        executablePath: null,
        isAuthenticated: false,
        message: '$name not found. $installTip',
      );
    }

    // Check version
    String? version;
    try {
      final verRes = await _processRunner(
        exec,
        ['--version'],
        runInShell: Platform.isWindows,
        timeout: const Duration(seconds: 5),
      );
      if (verRes.exitCode == 0) {
        version = verRes.stdout.toString().trim();
      }
    } catch (_) {}

    // Check authentication with a test print
    if (type == CliType.antigravity) {
      try {
        final testRes = await _processRunner(
          exec,
          [
            '-p',
            'ping',
            '--dangerously-skip-permissions',
            '--disable-slash-commands',
          ],
          runInShell: Platform.isWindows,
          timeout: const Duration(seconds: 15),
        );

        final combined = '${testRes.stdout}\n${testRes.stderr}';
        if (combined.contains('Authentication required') ||
            combined.contains('Waiting for authentication') ||
            combined.contains('OAuth') ||
            combined.contains('Please visit the URL to log in')) {
          return CliStatus(
            type: type,
            isInstalled: true,
            executablePath: exec,
            isAuthenticated: false,
            version: version,
            message: 'CLI installed at $exec, but authentication required. Open a terminal and run "agy" to sign into your subscription.',
          );
        }

        if (testRes.exitCode == 0) {
          return CliStatus(
            type: type,
            isInstalled: true,
            executablePath: exec,
            isAuthenticated: true,
            version: version,
            message: 'Connected to Antigravity CLI (${version ?? "ready"}). Active subscription ready.',
          );
        } else {
          return CliStatus(
            type: type,
            isInstalled: true,
            executablePath: exec,
            isAuthenticated: false,
            version: version,
            message: 'CLI returned code ${testRes.exitCode}: ${testRes.stderr.toString().trim()}',
          );
        }
      } catch (e) {
        return CliStatus(
          type: type,
          isInstalled: true,
          executablePath: exec,
          isAuthenticated: false,
          version: version,
          message: 'Error verifying agy status: $e',
        );
      }
    } else if (type == CliType.claudeCode) {
      // Claude Code
      try {
        final testRes = await _processRunner(
          exec,
          ['-p', 'ping'],
          runInShell: Platform.isWindows,
          timeout: const Duration(seconds: 15),
        );

        final combined = '${testRes.stdout}\n${testRes.stderr}';
        if (combined.contains('login') ||
            combined.contains('authentication') ||
            combined.contains('Unauthorized')) {
          return CliStatus(
            type: type,
            isInstalled: true,
            executablePath: exec,
            isAuthenticated: false,
            version: version,
            message: 'Claude Code installed at $exec, but authentication required. Run "claude" in your terminal to log in.',
          );
        }

        if (testRes.exitCode == 0) {
          return CliStatus(
            type: type,
            isInstalled: true,
            executablePath: exec,
            isAuthenticated: true,
            version: version,
            message: 'Connected to Claude Code (${version ?? "ready"}). Subscription ready.',
          );
        } else {
          return CliStatus(
            type: type,
            isInstalled: true,
            executablePath: exec,
            isAuthenticated: false,
            version: version,
            message: 'Claude Code returned exit code ${testRes.exitCode}: ${testRes.stderr.toString().trim()}',
          );
        }
      } catch (e) {
        return CliStatus(
          type: type,
          isInstalled: true,
          executablePath: exec,
          isAuthenticated: false,
          version: version,
          message: 'Error verifying claude status: $e',
        );
      }
    } else {
      // OpenAI Codex CLI
      try {
        final testRes = await _processRunner(
          exec,
          ['exec', 'ping', '--ephemeral'],
          runInShell: Platform.isWindows,
          timeout: const Duration(seconds: 15),
        );

        final combined = '${testRes.stdout}\n${testRes.stderr}';
        if (combined.contains('login') ||
            combined.contains('authentication') ||
            combined.contains('Sign in with ChatGPT') ||
            combined.contains('Unauthorized')) {
          return CliStatus(
            type: type,
            isInstalled: true,
            executablePath: exec,
            isAuthenticated: false,
            version: version,
            message: 'Codex CLI installed at $exec, but authentication required. Open a terminal and run "codex" to link your ChatGPT subscription.',
          );
        }

        if (testRes.exitCode == 0) {
          return CliStatus(
            type: type,
            isInstalled: true,
            executablePath: exec,
            isAuthenticated: true,
            version: version,
            message: 'Connected to Codex CLI (${version ?? "ready"}). ChatGPT subscription ready.',
          );
        } else {
          return CliStatus(
            type: type,
            isInstalled: true,
            executablePath: exec,
            isAuthenticated: false,
            version: version,
            message: 'Codex CLI returned exit code ${testRes.exitCode}: ${testRes.stderr.toString().trim()}',
          );
        }
      } catch (e) {
        return CliStatus(
          type: type,
          isInstalled: true,
          executablePath: exec,
          isAuthenticated: false,
          version: version,
          message: 'Error verifying codex status: $e',
        );
      }
    }
  }

  /// Queries Antigravity CLI for available models via `agy models`.
  /// Populates dynamically so the UI stays up-to-date as models evolve.
  Future<List<CliModelInfo>> listAgyModels({
    String? customPath,
    Duration timeout = const Duration(seconds: 15),
  }) async {
    final exec = await findExecutable(CliType.antigravity, customPath: customPath);
    if (exec == null) {
      return defaultAgyModels();
    }

    try {
      final res = await _processRunner(
        exec,
        ['models'],
        runInShell: Platform.isWindows,
        timeout: timeout,
      );

      if (res.exitCode != 0) {
        return defaultAgyModels();
      }

      final lines = LineSplitter.split(res.stdout.toString());
      final models = <CliModelInfo>[];

      for (final line in lines) {
        final trimmed = line.trim();
        if (trimmed.isEmpty ||
            trimmed.startsWith('Fetching') ||
            trimmed.startsWith('Usage:') ||
            trimmed.startsWith('Flags:')) {
          continue;
        }

        // Tab or multi-space separated: <id>\t<name>
        final parts = trimmed.split(RegExp(r'\t+|\s{2,}'));
        if (parts.isNotEmpty) {
          final id = parts[0].trim();
          if (id.isEmpty) continue;
          final name = parts.length > 1 ? parts[1].trim() : id;
          final lower = id.toLowerCase();
          final isEcon = lower.contains('flash') ||
              lower.contains('-low') ||
              lower.contains('low') && !lower.contains('flow') ||
              lower.contains('-mini') ||
              lower.endsWith('mini') ||
              lower.contains('haiku');
          models.add(CliModelInfo(id: id, name: name, isEconomical: isEcon));
        }
      }

      if (models.isEmpty) {
        return defaultAgyModels();
      }
      return models;
    } catch (_) {
      return defaultAgyModels();
    }
  }

  /// Default model catalog for Antigravity CLI when offline or unindexed.
  static List<CliModelInfo> defaultAgyModels() {
    return const [
      CliModelInfo(id: 'gemini-3.8-flash-low', name: 'Gemini 3.8 Flash (Low) - Recommended', isEconomical: true),
      CliModelInfo(id: 'gemini-3.8-flash-medium', name: 'Gemini 3.8 Flash (Medium)', isEconomical: true),
      CliModelInfo(id: 'gemini-3.8-flash-high', name: 'Gemini 3.8 Flash (High)', isEconomical: true),
      CliModelInfo(id: 'gemini-4-argon-low', name: 'Gemini 4 Argon (Low)', isEconomical: false),
      CliModelInfo(id: 'gemini-4-argon-medium', name: 'Gemini 4 Argon (Medium)', isEconomical: false),
      CliModelInfo(id: 'gemini-4-argon-high', name: 'Gemini 4 Argon (High)', isEconomical: false),
      CliModelInfo(id: 'claude-sonnet-5-5-low', name: 'Claude Sonnet 5.5 (Low)', isEconomical: false),
      CliModelInfo(id: 'claude-sonnet-5-5-high', name: 'Claude Sonnet 5.5 (High)', isEconomical: false),
      CliModelInfo(id: 'claude-opus-5-5-high', name: 'Claude Opus 5.5 (High)', isEconomical: false),
      CliModelInfo(id: 'default', name: 'Default (CLI Profile Default)', isEconomical: false),
    ];
  }

  /// Supported models for Claude Code CLI.
  List<CliModelInfo> listClaudeModels() {
    return const [
      CliModelInfo(id: 'haiku', name: 'Claude Haiku (Fast & Economical - Recommended)', isEconomical: true),
      CliModelInfo(id: 'sonnet', name: 'Claude Sonnet (Balanced)', isEconomical: false),
      CliModelInfo(id: 'opus', name: 'Claude Opus (Deep Reasoning)', isEconomical: false),
      CliModelInfo(id: 'claude-3-5-haiku-latest', name: 'claude-3-5-haiku-latest', isEconomical: true),
      CliModelInfo(id: 'claude-3-7-sonnet-latest', name: 'claude-3-7-sonnet-latest', isEconomical: false),
      CliModelInfo(id: 'default', name: 'Default (CLI Config Default)', isEconomical: false),
    ];
  }

  /// Supported models for OpenAI Codex CLI.
  List<CliModelInfo> listCodexModels() {
    return const [
      CliModelInfo(id: 'gpt-4o-mini', name: 'GPT-4o Mini (Fast & Economical - Recommended)', isEconomical: true),
      CliModelInfo(id: 'gpt-4o', name: 'GPT-4o (Standard)', isEconomical: false),
      CliModelInfo(id: 'o3-mini', name: 'o3-mini (Reasoning)', isEconomical: false),
      CliModelInfo(id: 'o1', name: 'o1 (Deep Reasoning)', isEconomical: false),
      CliModelInfo(id: 'default', name: 'Default (CLI Config Default)', isEconomical: false),
    ];
  }

  /// Sends a prompt to the Antigravity CLI in non-interactive print mode.
  Future<String> queryAgy(
    String prompt, {
    String? model,
    String? customPath,
    Duration timeout = const Duration(seconds: 60),
  }) async {
    final exec = await findExecutable(CliType.antigravity, customPath: customPath);
    if (exec == null) {
      throw Exception(
        'Antigravity CLI (agy) executable not found. Make sure agy is installed or configure its exact path in AI Settings.',
      );
    }

    final args = <String>[
      '-p',
      prompt,
      '--dangerously-skip-permissions',
      '--disable-slash-commands',
    ];
    if (model != null && model.trim().isNotEmpty && model.trim() != 'default') {
      args.addAll(['--model', model.trim()]);
    }

    final res = await _processRunner(
      exec,
      args,
      runInShell: Platform.isWindows,
      timeout: timeout,
    );

    if (res.exitCode != 0) {
      final combined = '${res.stdout}\n${res.stderr}'.trim();
      if (combined.contains('Authentication required') ||
          combined.contains('Waiting for authentication') ||
          combined.contains('Please visit the URL to log in')) {
        throw Exception(
          'Antigravity CLI is not logged in. Open your terminal and run "agy" to authenticate your subscription.',
        );
      }
      throw Exception('agy failed (exit code ${res.exitCode}): ${res.stderr.toString().trim()}');
    }

    final output = res.stdout.toString().trim();
    if (output.isEmpty) {
      throw Exception('Antigravity CLI completed with empty output.');
    }
    return output;
  }

  /// Sends a prompt to the Claude Code CLI in non-interactive print mode.
  Future<String> queryClaude(
    String prompt, {
    String? model,
    String? customPath,
    Duration timeout = const Duration(seconds: 60),
  }) async {
    final exec = await findExecutable(CliType.claudeCode, customPath: customPath);
    if (exec == null) {
      throw Exception(
        'Claude Code (claude) executable not found. Install it with "npm install -g @anthropic-ai/claude-code" or configure its path in AI Settings.',
      );
    }

    final args = <String>['-p', prompt];
    if (model != null && model.trim().isNotEmpty && model.trim() != 'default') {
      args.addAll(['--model', model.trim()]);
    }

    final res = await _processRunner(
      exec,
      args,
      runInShell: Platform.isWindows,
      timeout: timeout,
    );

    if (res.exitCode != 0) {
      final combined = '${res.stdout}\n${res.stderr}'.trim();
      if (combined.contains('login') ||
          combined.contains('authentication') ||
          combined.contains('Unauthorized')) {
        throw Exception(
          'Claude Code is not authenticated. Open your terminal and run "claude" to sign into your Claude subscription.',
        );
      }
      throw Exception('claude failed (exit code ${res.exitCode}): ${res.stderr.toString().trim()}');
    }

    final output = res.stdout.toString().trim();
    if (output.isEmpty) {
      throw Exception('Claude Code completed with empty output.');
    }
    return output;
  }

  /// Sends a prompt to the OpenAI Codex CLI in non-interactive exec mode.
  Future<String> queryCodex(
    String prompt, {
    String? model,
    String? customPath,
    Duration timeout = const Duration(seconds: 60),
  }) async {
    final exec = await findExecutable(CliType.codex, customPath: customPath);
    if (exec == null) {
      throw Exception(
        'OpenAI Codex CLI (codex) executable not found. Install it with "npm install -g @openai/codex" or configure its path in AI Settings.',
      );
    }

    final args = <String>['exec', prompt, '--ephemeral'];
    if (model != null && model.trim().isNotEmpty && model.trim() != 'default') {
      args.addAll(['--model', model.trim()]);
    }

    final res = await _processRunner(
      exec,
      args,
      runInShell: Platform.isWindows,
      timeout: timeout,
    );

    if (res.exitCode != 0) {
      final combined = '${res.stdout}\n${res.stderr}'.trim();
      if (combined.contains('login') ||
          combined.contains('authentication') ||
          combined.contains('Sign in with ChatGPT') ||
          combined.contains('Unauthorized')) {
        throw Exception(
          'Codex CLI is not authenticated. Open your terminal and run "codex" to link your ChatGPT subscription.',
        );
      }
      throw Exception('codex failed (exit code ${res.exitCode}): ${res.stderr.toString().trim()}');
    }

    final output = res.stdout.toString().trim();
    if (output.isEmpty) {
      throw Exception('Codex CLI completed with empty output.');
    }
    return output;
  }
}
