import 'package:flutter_test/flutter_test.dart';
import 'package:packet_inspector/domain/models/capture_config.dart';
import 'package:packet_inspector/data/services/capture/tshark_service.dart';

void main() {
  group('TSharkService & CaptureConfig tests', () {
    final service = TSharkService();
    const mockInterface = CaptureInterface(
      index: '2',
      name: r'\Device\NPF_{12345678-ABCD-EF01-2345-6789ABCDEF01}',
      friendlyName: 'Wi-Fi 6E',
    );

    test('CaptureInterface formats displayName with friendly name', () {
      expect(mockInterface.displayName, '2. Wi-Fi 6E');

      const fallbackInterface = CaptureInterface(
        index: '3',
        name: 'eth0',
      );
      expect(fallbackInterface.displayName, '3. eth0');
    });

    test('buildArguments generates correct flags for Quick Capture', () {
      const config = CaptureConfig(
        interface: mockInterface,
        outputDirectory: 'C:/Captures',
        mode: CaptureMode.quick,
      );

      final args = service.buildArguments(config, 'C:/Captures/test.pcapng');
      expect(args, ['-i', '2', '-w', 'C:/Captures/test.pcapng']);
    });

    test('buildArguments generates correct flags for Timed Capture', () {
      const config = CaptureConfig(
        interface: mockInterface,
        outputDirectory: 'C:/Captures',
        mode: CaptureMode.timed,
        hours: 1,
        minutes: 30, // 90 minutes = 5400 seconds
      );

      final args = service.buildArguments(config, 'C:/Captures/test.pcapng');
      expect(args, [
        '-i', '2',
        '-a', 'duration:5400',
        '-w', 'C:/Captures/test.pcapng',
      ]);
    });

    test('buildArguments generates correct flags for Ring Buffer Capture', () {
      const config = CaptureConfig(
        interface: mockInterface,
        outputDirectory: 'C:/Captures',
        mode: CaptureMode.ringBuffer,
        hours: 0,
        minutes: 10, // 600 seconds
        ringFiles: 6,
      );

      final args = service.buildArguments(config, 'C:/Captures/test.pcapng');
      expect(args, [
        '-i', '2',
        '-b', 'duration:600',
        '-b', 'files:6',
        '-w', 'C:/Captures/test.pcapng',
      ]);
    });

    test('ActiveCaptureSession serializes and deserializes correctly', () {
      final now = DateTime.now();
      final session = ActiveCaptureSession(
        pid: 9876,
        startedAt: now,
        outputDirectory: 'C:/Captures/Session_01',
        targetFilePath: 'C:/Captures/Session_01/capture.pcapng',
        mode: CaptureMode.ringBuffer,
        interfaceName: '2. Wi-Fi 6E',
        hours: 1,
        minutes: 0,
        ringFiles: 5,
      );

      final json = session.toJson();
      final restored = ActiveCaptureSession.fromJson(json);

      expect(restored.pid, 9876);
      expect(restored.outputDirectory, 'C:/Captures/Session_01');
      expect(restored.targetFilePath, 'C:/Captures/Session_01/capture.pcapng');
      expect(restored.mode, CaptureMode.ringBuffer);
      expect(restored.interfaceName, '2. Wi-Fi 6E');
      expect(restored.ringFiles, 5);
      expect(restored.hours, 1);
    });
  });
}
