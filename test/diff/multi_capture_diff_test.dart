import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:packet_inspector/data/repositories/packet_repository.dart';
import 'package:packet_inspector/data/services/ai/packet_ai_tools.dart';
import 'package:packet_inspector/data/services/diff/demo_diff_generator.dart';
import 'package:packet_inspector/data/services/diff/multi_capture_diff_engine.dart';
import 'package:packet_inspector/data/services/parser/pcap_binary_reader.dart';
import 'package:packet_inspector/domain/models/packet_diff_record.dart';
import 'package:packet_inspector/ui/features/compare/view_models/capture_compare_view_model.dart';
import 'package:packet_inspector/ui/features/compare/views/compare_setup_dialog.dart';
import 'package:packet_inspector/ui/features/compare/views/compare_summary_bar.dart';
import 'package:packet_inspector/ui/features/compare/views/diff_packet_table.dart';
import 'package:packet_inspector/ui/features/inspector/view_models/inspector_view_model.dart';
import 'package:packet_inspector/ui/features/inspector/views/inspector_screen.dart';
import 'package:provider/provider.dart';

Uint8List _buildUdpTestFrame({
  required String srcIp,
  required String dstIp,
  required int srcPort,
  required int dstPort,
  required int dscp,
  required Uint8List payload,
}) {
  final ipTotalLen = 20 + 8 + payload.length;
  final frame = Uint8List(14 + ipTotalLen);
  final bd = ByteData.sublistView(frame);

  // Ethernet header
  frame[12] = 0x08;
  frame[13] = 0x00;

  // IPv4 header
  frame[14] = 0x45;
  frame[15] = (dscp & 0x3F) << 2;
  bd.setUint16(16, ipTotalLen, Endian.big);
  frame[22] = 64; // TTL
  frame[23] = 17; // UDP

  final srcParts = srcIp.split('.').map(int.parse).toList();
  final dstParts = dstIp.split('.').map(int.parse).toList();
  for (var i = 0; i < 4; i++) {
    frame[26 + i] = srcParts[i];
    frame[30 + i] = dstParts[i];
  }

  // UDP header
  bd.setUint16(34, srcPort, Endian.big);
  bd.setUint16(36, dstPort, Endian.big);
  bd.setUint16(38, 8 + payload.length, Endian.big);

  frame.setRange(42, 42 + payload.length, payload);
  return frame;
}

RawCapturedPacket _rawPkt(int no, int tsUs, Uint8List data) {
  return RawCapturedPacket(
    packetNo: no,
    timestampUs: tsUs,
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    fileByteOffset: 0,
    data: data,
  );
}

void main() {
  group('MultiCaptureDiffEngine', () {
    test('correlates 3-hop synthetic demo with clock skew, drops, OOO, DSCP strip, and noise filtering', () async {
      final engine = MultiCaptureDiffEngine();
      addTearDown(engine.dispose);

      final inputs = DemoDiffGenerator.buildDemoCaptures();
      await engine.ingestCaptures(inputs, latencySpikeThresholdUs: 5000);

      expect(engine.slots.length, 3);
      // Capture 1 has +42.35ms + ~350us transit offset; calibrated offset should be ~+42.7ms
      expect(engine.slots[1].clockOffsetUs, inInclusiveRange(40000, 46000));
      // Capture 2 has -18.70ms + ~620us transit offset; calibrated offset should be ~-18.1ms
      expect(engine.slots[2].clockOffsetUs, inInclusiveRange(-21000, -16000));

      // Shared flows should filter out the 6 ARP noise packets in Capture 1
      final sharedRecords = engine.queryDiffRecords(
        filterMode: DiffFilterMode.sharedFlowsOnly,
      );
      final fullRecords = engine.queryDiffRecords(
        filterMode: DiffFilterMode.fullDiff,
      );
      expect(fullRecords.length, greaterThan(sharedRecords.length));
      expect(
        sharedRecords.any((r) => r.primaryStatus == DiffStatus.injected),
        isFalse,
      );
      expect(
        fullRecords.where((r) => r.primaryStatus == DiffStatus.injected).length,
        6,
      );

      // Dropped packets (sACN seq 18 and 25)
      final dropped = sharedRecords
          .where((r) => r.statuses.contains(DiffStatus.dropped))
          .toList();
      expect(dropped.length, 2);

      // DSCP stripped packets (Dante seq 12 and 24 -> 6 and 12)
      final mutated = sharedRecords
          .where((r) => r.statuses.contains(DiffStatus.qosVlanMutated))
          .toList();
      expect(mutated.length, 2);

      // Out-of-order packets (sACN seq 32/33 at Dimmer Rack)
      final ooo = sharedRecords
          .where((r) => r.statuses.contains(DiffStatus.outOfOrder))
          .toList();
      expect(ooo, isNotEmpty);

      // Latency spike (sACN seq 28)
      final spikes = sharedRecords
          .where((r) => r.statuses.contains(DiffStatus.latencySpike))
          .toList();
      expect(spikes, isNotEmpty);

      // AI Tool summary
      final aiTools = PacketAiTools(repository: PacketRepository());
      final aiResult = aiTools.compareCapturesSummary(engine);
      expect(aiResult.toolName, 'compare_captures_summary');
      expect(aiResult.data['firstDropRowIndex'], isNotNull);
      expect(aiResult.data['firstDropFrameNumber'], isNotNull);
      expect(aiResult.summaryText, contains('Multi-Capture Path Comparison Summary:'));
    });

    test('handles 2-capture 5% drops, identical payloads with occurrence index, and DSCP zeroing', () async {
      final engine = MultiCaptureDiffEngine();
      addTearDown(engine.dispose);

      const baseTs = 1794000000000000;
      const clockSkewUs = 15000; // +15 ms
      final cap0 = <RawCapturedPacket>[];
      final cap1 = <RawCapturedPacket>[];

      // 40 identical-payload UDP packets (200 bytes) + 2 drops (5%) + 1 DSCP strip + 2 OOO
      final identicalPayload = Uint8List.fromList(List.generate(32, (i) => i));
      RawCapturedPacket? buffered;

      for (var i = 0; i < 40; i++) {
        final ts = baseTs + i * 10000;
        final frame0 = _buildUdpTestFrame(
          srcIp: '10.0.0.10',
          dstIp: '10.0.0.20',
          srcPort: 9000,
          dstPort: 9000,
          dscp: 46,
          payload: identicalPayload,
        );
        cap0.add(_rawPkt(i + 1, ts, frame0));

        // Drop indices 10 and 30 (5% of 40)
        if (i == 10 || i == 30) continue;

        final dscp1 = (i == 15) ? 0 : 46;
        final frame1 = _buildUdpTestFrame(
          srcIp: '10.0.0.10',
          dstIp: '10.0.0.20',
          srcPort: 9000,
          dstPort: 9000,
          dscp: dscp1,
          payload: identicalPayload,
        );
        final pkt1 = _rawPkt(cap1.length + 1, ts + clockSkewUs + 200, frame1);

        if (i == 20) {
          buffered = pkt1;
        } else if (i == 21) {
          cap1.add(pkt1);
          if (buffered != null) {
            cap1.add(_rawPkt(cap1.length + 1, buffered.timestampUs, buffered.data));
            buffered = null;
          }
        } else {
          cap1.add(pkt1);
        }
      }

      await engine.ingestCaptures([
        CaptureSourceInput(
          label: 'Sender',
          filePath: 'sender.pcap',
          rawPackets: cap0,
        ),
        CaptureSourceInput(
          label: 'Receiver',
          filePath: 'receiver.pcap',
          rawPackets: cap1,
        ),
      ]);

      final records = engine.queryDiffRecords(
        filterMode: DiffFilterMode.sharedFlowsOnly,
      );
      expect(records.length, 40);
      expect(
        records.where((r) => r.statuses.contains(DiffStatus.dropped)).length,
        2,
      );
      expect(
        records.where((r) => r.statuses.contains(DiffStatus.qosVlanMutated)).length,
        1,
      );
    });
  });

  group('Compare UI Widgets', () {
    testWidgets('CompareSetupDialog loads synthetic demo diff and enters Compare mode', (tester) async {
      final inspectorVm = InspectorViewModel(repository: PacketRepository());
      final compareVm = CaptureCompareViewModel();
      addTearDown(compareVm.dispose);

      await tester.pumpWidget(
        MultiProvider(
          providers: [
            ChangeNotifierProvider.value(value: inspectorVm),
            ChangeNotifierProvider.value(value: compareVm),
          ],
          child: const MaterialApp(
            home: Scaffold(body: CompareSetupDialog()),
          ),
        ),
      );

      expect(find.text('Multi-Capture Diff & Path Comparison'), findsOneWidget);
      expect(find.text('Load Synthetic Demo Diff'), findsOneWidget);

      await tester.tap(find.text('Load Synthetic Demo Diff'));
      await tester.pumpAndSettle();

      expect(compareVm.isCompareMode, isTrue);
      expect(compareVm.slots.length, 3);
    });

    testWidgets('CompareSummaryBar and DiffPacketTable render correlated diff rows in InspectorScreen', (tester) async {
      tester.view.physicalSize = const Size(1400, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);

      final inspectorVm = InspectorViewModel(repository: PacketRepository());
      final compareVm = CaptureCompareViewModel();
      addTearDown(compareVm.dispose);

      await compareVm.loadDemoDiff();

      await tester.pumpWidget(
        MultiProvider(
          providers: [
            ChangeNotifierProvider.value(value: inspectorVm),
            ChangeNotifierProvider.value(value: compareVm),
          ],
          child: const MaterialApp(
            home: InspectorScreen(),
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.byType(CompareSummaryBar), findsOneWidget);
      expect(find.byType(DiffPacketTable), findsOneWidget);
      expect(find.text('Exit Compare'), findsOneWidget);
      expect(find.text('Jump to First Drop'), findsOneWidget);

      await tester.tap(find.text('Jump to First Drop'));
      await tester.pumpAndSettle();
      expect(compareVm.selectedRecord?.primaryStatus, DiffStatus.dropped);
    });
  });
}
