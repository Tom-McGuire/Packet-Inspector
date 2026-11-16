import 'package:sqlite3/sqlite3.dart';

/// SQLite schema and lifecycle management for multi-capture diff & correlation.
class DiffDatabaseSchema {
  static void initializeSchema(Database db) {
    db.execute('''
      CREATE TABLE IF NOT EXISTS capture_sessions (
        capture_index INTEGER PRIMARY KEY,
        label TEXT NOT NULL,
        file_path TEXT NOT NULL,
        packet_count INTEGER NOT NULL,
        clock_offset_us INTEGER DEFAULT 0
      );
    ''');

    db.execute('''
      CREATE TABLE IF NOT EXISTS diff_packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        capture_index INTEGER NOT NULL,
        frame_number INTEGER NOT NULL,
        timestamp_us INTEGER NOT NULL,
        flow_hash INTEGER NOT NULL,
        fingerprint_hash INTEGER NOT NULL,
        occurrence_index INTEGER NOT NULL,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        protocol_name TEXT,
        extracted_seq INTEGER,
        dscp_value INTEGER,
        vlan_id INTEGER,
        packet_length INTEGER,
        raw_bytes BLOB
      );
    ''');

    db.execute('''
      CREATE INDEX IF NOT EXISTS idx_diff_match
      ON diff_packets(flow_hash, fingerprint_hash, occurrence_index, capture_index);
    ''');

    db.execute('''
      CREATE INDEX IF NOT EXISTS idx_diff_seq
      ON diff_packets(capture_index, flow_hash, extracted_seq);
    ''');

    db.execute('''
      CREATE INDEX IF NOT EXISTS idx_diff_capture_flow
      ON diff_packets(capture_index, flow_hash);
    ''');
  }

  static void clearTables(Database db) {
    db.execute('DELETE FROM diff_packets;');
    db.execute('DELETE FROM capture_sessions;');
  }
}
