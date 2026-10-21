enum CaptureMode {
  quick,
  timed,
  ringBuffer;

  String get displayName {
    switch (this) {
      case CaptureMode.quick:
        return 'Quick Capture';
      case CaptureMode.timed:
        return 'Timed Capture';
      case CaptureMode.ringBuffer:
        return 'Ring Buffer Capture';
    }
  }
}

class CaptureInterface {
  const CaptureInterface({
    required this.index,
    required this.name,
    this.friendlyName,
  });

  final String index;
  final String name;
  final String? friendlyName;

  String get displayName => friendlyName != null && friendlyName!.isNotEmpty
      ? '$index. $friendlyName'
      : '$index. $name';

  @override
  String toString() => displayName;
}

class CaptureConfig {
  const CaptureConfig({
    required this.interface,
    required this.outputDirectory,
    this.filePrefix = 'capture',
    this.createSubfolder = true,
    this.mode = CaptureMode.quick,
    this.hours = 0,
    this.minutes = 10,
    this.ringFiles = 5,
  });

  final CaptureInterface interface;
  final String outputDirectory;
  final String filePrefix;
  final bool createSubfolder;
  final CaptureMode mode;
  final int hours;
  final int minutes;
  final int ringFiles;

  int get totalSeconds => (hours * 3600) + (minutes * 60);

  Map<String, dynamic> toJson() => {
        'interfaceIndex': interface.index,
        'interfaceName': interface.name,
        'interfaceFriendlyName': interface.friendlyName,
        'outputDirectory': outputDirectory,
        'filePrefix': filePrefix,
        'createSubfolder': createSubfolder,
        'mode': mode.name,
        'hours': hours,
        'minutes': minutes,
        'ringFiles': ringFiles,
      };

  factory CaptureConfig.fromJson(Map<String, dynamic> json) {
    return CaptureConfig(
      interface: CaptureInterface(
        index: json['interfaceIndex'] as String? ?? '1',
        name: json['interfaceName'] as String? ?? '',
        friendlyName: json['interfaceFriendlyName'] as String?,
      ),
      outputDirectory: json['outputDirectory'] as String? ?? '',
      filePrefix: json['filePrefix'] as String? ?? 'capture',
      createSubfolder: json['createSubfolder'] as bool? ?? true,
      mode: CaptureMode.values.firstWhere(
        (m) => m.name == json['mode'],
        orElse: () => CaptureMode.quick,
      ),
      hours: json['hours'] as int? ?? 0,
      minutes: json['minutes'] as int? ?? 10,
      ringFiles: json['ringFiles'] as int? ?? 5,
    );
  }
}

class ActiveCaptureSession {
  const ActiveCaptureSession({
    required this.pid,
    required this.startedAt,
    required this.outputDirectory,
    required this.targetFilePath,
    required this.mode,
    required this.interfaceName,
    this.hours = 0,
    this.minutes = 10,
    this.ringFiles = 5,
  });

  final int pid;
  final DateTime startedAt;
  final String outputDirectory;
  final String targetFilePath;
  final CaptureMode mode;
  final String interfaceName;
  final int hours;
  final int minutes;
  final int ringFiles;

  Duration get elapsed => DateTime.now().difference(startedAt);

  Map<String, dynamic> toJson() => {
        'pid': pid,
        'startedAt': startedAt.toIso8601String(),
        'outputDirectory': outputDirectory,
        'targetFilePath': targetFilePath,
        'mode': mode.name,
        'interfaceName': interfaceName,
        'hours': hours,
        'minutes': minutes,
        'ringFiles': ringFiles,
      };

  factory ActiveCaptureSession.fromJson(Map<String, dynamic> json) {
    return ActiveCaptureSession(
      pid: json['pid'] as int,
      startedAt: DateTime.parse(json['startedAt'] as String),
      outputDirectory: json['outputDirectory'] as String,
      targetFilePath: json['targetFilePath'] as String? ?? json['outputDirectory'] as String,
      mode: CaptureMode.values.firstWhere(
        (m) => m.name == json['mode'],
        orElse: () => CaptureMode.quick,
      ),
      interfaceName: json['interfaceName'] as String? ?? 'Interface',
      hours: json['hours'] as int? ?? 0,
      minutes: json['minutes'] as int? ?? 10,
      ringFiles: json['ringFiles'] as int? ?? 5,
    );
  }
}
