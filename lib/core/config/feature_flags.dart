/// Application-wide feature flags and build configurations.
abstract final class FeatureFlags {
  /// Controls whether the experimental AI Assistant toolbar button and drawer
  /// are visible in the application.
  ///
  /// Can be enabled at compile time by passing:
  /// ```bash
  /// flutter run --dart-define=ENABLE_AI_ASSISTANT=true
  /// flutter build windows --release --dart-define=ENABLE_AI_ASSISTANT=true
  /// ```
  /// (Also accepts `--dart-define=ENABLE_AI=true`).
  ///
  /// Defaults to `false` to keep the AI assistant hidden from users during general testing.
  static const bool enableAiAssistant = bool.fromEnvironment(
        'ENABLE_AI_ASSISTANT',
        defaultValue: false,
      ) ||
      bool.fromEnvironment(
        'ENABLE_AI',
        defaultValue: false,
      );
}
