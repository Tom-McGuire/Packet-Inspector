# Packet Inspector — Proposed Enhancements & Suite Integrations

---

## Issue 1: Built-In Entertainment Lighting & AV Protocol Signatures

### Summary
Bundle read-only, built-in protocol definitions in the **Custom Protocol Library** for common entertainment lighting and ProAV protocols (**Art-Net**, **sACN / E1.31**, and **Dante / PTPv2**).

### Motivation
Packet Inspector already features a two-tier Custom Protocol Library (Transport/Port + fixed-offset Magic Bytes + named field slices) with `<50ms` SQLite retroactive re-labeling. Shipping pre-built definitions for standard show-control and ProAV protocols eliminates manual rule setup on site.

### Proposed Protocol Definitions
1. **Art-Net**
   - **Transport / Port:** UDP `6454` (Either)
   - **Magic Bytes:** ASCII `"Art-Net\0"` at offset `0`
   - **Field Slices:** `OpCode` (`uint16Le` @ offset `8`), `ProtocolVersion` (`uint16Be` @ offset `10`), `Sequence` (`uint8` @ offset `12`), `Physical` (`uint8` @ offset `13`), `Universe` (`uint16Le` @ offset `14`)
2. **sACN (ANSI E1.31)**
   - **Transport / Port:** UDP `5568` (Either)
   - **Magic Bytes:** ASCII `"ASC-E1.17\0\0\0"` at offset `4`
   - **Field Slices:** `RootVector` (`uint32Be` @ offset `18`), `Priority` (`uint8` @ offset `108`), `Sequence` (`uint8` @ offset `111`), `Universe` (`uint16Be` @ offset `113`)
3. **PTPv2 / Dante Clock Sync**
   - **Transport / Port:** UDP `319` & `320` (Either)
   - **Field Slices:** `MessageType` (`uint8` @ offset `0`), `DomainNumber` (`uint8` @ offset `4`)

### Acceptance Criteria
- [ ] Built-in definitions appear in the Custom Protocol Library marked as `Built-in` (read-only, toggleable).
- [ ] Captures containing Art-Net, sACN, or PTPv2 automatically decode and display field slices in the Hex & ASCII Byte Inspector.

---

## Issue 2: CLI & IPC File Open Support (`--open-pcap`)

### Summary
Support opening `.pcap` / `.pcapng` files directly via CLI argument or loopback IPC so companion tools (such as **TShark Interface**) can launch Packet Inspector straight into an active investigation.

### Proposed Implementation
- Parse `--open-pcap <filepath>` in `main.dart` on startup and trigger the `PcapBinaryReader` ingestion pipeline automatically.
- Optional: Expose a lightweight loopback IPC endpoint matching the Network Suite convention (`ARP-Scout` / `Net-Route-Scout`) to load a file into an already-running instance.

### Acceptance Criteria
- [ ] Running `packet_inspector --open-pcap /path/to/file.pcapng` opens directly into the indexed capture view.
- [ ] Invalid or missing file paths surface a clean error banner without crashing.
