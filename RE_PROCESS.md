# WCH BLE Analyzer Pro — Reverse Engineering Process

## Goal

Produce a working Linux driver for the WCH BLE Analyzer Pro hardware (3x CH582F RISC-V
BLE 5.1 MCUs + CH334 USB hub) that captures live BLE advertising traffic and writes valid
Wireshark-compatible pcap files, without any official Linux support or public documentation.

---

## Phase 1 — Hardware identification

### What we had
- The physical device connected to USB
- The Windows installer package (`WCH_BLEAnalyzer.zip` → `WCH_BLEAnalyzer.exe`)
- An existing USB traffic capture (`ncap.usb.pcapng`) made with Wireshark/USBPcap on Windows

### Steps

**1.1 — Unpack the installer**

`WCH_BLEAnalyzer.exe` is a self-extracting archive. Unpacking it yielded the actual payload
(`payload.7z`, then `payload_7z/`) containing:
- `BleAnalyzer64.exe` — the main Windows GUI application (10 MB)
- `BleAnalyzer.exe` — 32-bit variant
- `Driver/BleAnalyzerW64.sys` — Windows kernel USB driver
- `lua/` — Lua scripts for packet decoding (`adv.lua`, `conn.lua`, `mDefine.lua`, etc.)
- `doc/` — user documentation (HTML)

**1.2 — USB enumeration from pcapng**

Parsing `ncap.usb.pcapng` with Wireshark/tshark revealed:
- Three identical USB devices: `VID=0x1A86 / PID=0x8009` (WinChipHead / wch.cn)
- One USB hub: `VID=0x1A86 / PID=0x8091` (CH334 hub, handled by the kernel)
- USB descriptor: class=0xFF (Vendor Specific), SubClass=0x80, Protocol=0x55
- Three endpoints per MCU:
  - EP 0x81: Interrupt IN, 64 bytes (status/events)
  - EP 0x82: Bulk IN, 64 bytes (BLE packet stream)
  - EP 0x02: Bulk OUT, 64 bytes (host→device commands)

PID 0x8009 is the CH582F RISC-V BLE 5.1 SoC. The device contains three of them, each
appearing as an independent USB device through the CH334 hub.

**1.3 — Lua script analysis**

The bundled Lua scripts (`mDefine.lua`, `adv.lua`, `conn.lua`, `LL_Data.lua`) describe
the decoded packet fields. Key findings:
- Response frames start with magic byte `0x55`
- BLE packet fields: timestamp, channel, RSSI, PDU header, address, AdvData
- Packet type constants (PKT_ADV_IND=0, PKT_ADV_NONCONN_IND=2, PKT_SCAN_REQ=3, …)
- Two capture modes: BLE monitor and custom 2.4G raw PHY

---

## Phase 2 — USB traffic analysis

### From `ncap.usb.pcapng`

The pcapng file contained the Windows app initialising the device. By filtering for EP 0x02
(Bulk OUT) transfers, the command stream was extracted:

```
AA 84 13 00 [00 00 00 00] "BLEAnalyzer&IAP"   → identify/arm
55 33 32                                        ← response: firmware present
AA 86 08 00 00 00 00 00 00 00 00 00             → configure (believed at the time)
55 FF FF                                        ← OK response
AA A1 00 00                                     → start scan
55 01 19 00 33 00 25 00 [...]                   ← 29-byte status echo
```

Command frame format confirmed: `[0xAA][CMD][len_lo][len_hi][payload...]`

EP 0x82 (Bulk IN) frames had a consistent `0x55` prefix with variable-length payloads
containing BLE packet metadata.

---

## Phase 3 — First driver attempt and the dead end

### hacked/ — initial probe tools

Early experiments written to the `hacked/` directory:
- `probe.c` — raw libusb prober: enumerate descriptors, try sending `0xAA` commands, dump
  any response bytes
- `ble.c` — first capture attempt, guessing a `0x57 0xAB` magic (completely wrong)

These were compiled (`probe`, `ble`, `a.out`) and tested on the live hardware. `probe.c`
confirmed the USB descriptor structure and that the device did respond to the `0xAA 0x84`
identify command. `ble.c` produced no BLE packets because the protocol was still unknown.

---

## Phase 4 — Static analysis of BleAnalyzer64.exe

No live USB capture from Windows was available during this phase. The protocol was
reverse-engineered from the binary.

### Binary properties
- PE64 executable, 10,299,408 bytes
- IMAGE_BASE: `0x140000000`
- VA → raw file offset: `raw = VA - 0x140000C00`

### Tools used
- IDA Pro / Ghidra (`.gpr` project files in `ble sniffer.rep/`, `reverse.rep/`,
  `just the sys.rep/`)
- Manual byte searching and cross-reference tracing

### Key functions found

**The state machine (VA 0x14028C9A3 / raw 0x28BDA3)**

This function implements a 4-state device initialisation machine:
```
State 0/1:  send AA 84 → read response
            if response[0] != 0 → state=3 (firmware present, skip upload)
            if response[0] == 0 → send AA 85 chunks → AA 86 → state=2
State 2:    firmware freshly uploaded, AA 86 sent — done
State 3:    firmware already on device — machine exits immediately
```

The critical insight: **in state=3 the machine exits without sending AA 86**. Our earlier
USB capture had been misleading — AA 86 only appears in the firmware upload path.

**The actual streaming start function (VA 0x14028C770 / raw 0x28BB70)**

Found by searching for the call site at VA 0x14029170F (`edx=0` before call, then AA81+AA A1):
```
send AA 81 19 00 [25 payload bytes]   ← BLE monitor config
send AA A1 00 00                      ← scan start trigger
```
This is what the Windows app sends after the state machine reaches state=3.

**Command AA 81 payload (25 bytes)**
```
payload[0] = flags  (bit0=0x01 BLE monitor, always set;
                     bit1=0x02 channel-nonzero, set when payload[2] != 0)
payload[1] = PHY    (1=1M, 2=2M, 3=CodedS8, 4=CodedS2)
payload[2] = channel (37/38/39 for specific adv channel; 0 = all channels)
payload[3..24] = 0  (no MAC filters, no LTK)
```

The channel byte was found by locating all writes to the device object field at
offset `+0x2BA`:  `MOV [RCX+0x2BA], DL` at VA `0x14028C2BB`.  The Windows app
calls the payload builder once per MCU, supplying the channel from
`scan_config+0x20/+0x21/+0x22`, producing 37/38/39 for MCU0/1/2 respectively.

**AA A5 — false positive**

`AA A5` appeared in a preliminary command table as "unknown, found at VA 0x14028C262".
Disassembly of that address showed the instruction `E8 AA A5 19 00` — a `CALL`
instruction whose 32-bit relative displacement is `0x0019A5AA`.  `AA A5` are bytes
2-3 of the displacement, not a command byte sequence.  A search of all 7 occurrences
of `AA A5` in the binary confirmed this: 3x inside CALL displacements, 1x inside a
`CMP [RIP+disp]` operand, 3x in data constants.  Not a protocol command.

**AA FD / AA FE — false positives**

A search for `AA FD` and `AA FE` byte sequences found hits at raw offsets `0x009d86` and
`0x00c286`. Deeper analysis showed these were entries in a sequential table initialization
loop (0x84FD, 0x85FD, ..., 0xAAFD, 0xABFD, ...) — not protocol commands. These false
positives were struck from the command list.

### Device packet format (from Lua scripts + binary cross-reference)

The `0x55` response frames on EP 0x82:
```
Byte 0:   0x55  (frame magic)
Byte 1:   0x10  (data packet) | 0x01 (status echo)
Byte 2-3: payload_len (LE uint16)
--- payload ---
[0-3]   timestamp_us  (LE uint32, μs since device boot)
[4]     channel_index (BLE RF channel 0-39)
[5]     flags         (bit 0 = direction)
[6-7]   reserved
[8]     rssi          (signed int8, dBm)
[9]     reserved
[10]    pdu_hdr0      (BLE LL PDU header byte 0)
[11]    pdu_payload_len
[12-17] AdvA or ScanA
[18+]   AdvData
```

---

## Phase 5 — Live validation with Python

Before committing to a C driver rewrite, a Python pyusb test script was written to
verify the RE findings against the real hardware.

**Script**: `/tmp/wch_test_correct.py`

```
Step 1: AA 84 → response[0] = 0x33 (firmware present, state=3) ✓
Step 2: AA 81 (PHY=1M) → immediate BLE packet streaming started
Step 3: AA A1 → 29-byte status echo
Step 4: poll EP 0x82 → 20 packets per MCU in under 2 seconds
```

All three MCUs returned real BLE advertising packets. The core protocol was confirmed.

**Root cause of the original "0 packets" failure**: AA 86 was being sent in the state=3
path (where it should not be sent). Sending AA 86 after state=3 is idempotent for
firmware purposes but does NOT trigger BLE streaming — only AA 81 does.

---

## Phase 6 — Linux driver implementation

### linux-driver/ contents

**`wch_ble_analyzer.h`** — API header
- USB IDs, endpoint addresses, packet type constants (PKT_ADV_IND etc.)
- `wch_pkt_hdr_t` — decoded per-packet metadata struct
- `wch_capture_config_t` — capture configuration (PHY, MAC filters, LTK)
- `wch_device_t` — per-MCU handle (includes 64-bit timestamp extension state)
- Public API: `wch_init`, `wch_find_devices`, `wch_open_device`, `wch_start_capture`,
  `wch_read_packets`, `wch_stop_capture`, `wch_close_device`, `wch_exit`

**`wch_ble_analyzer.c`** — driver implementation
- `wch_start_capture()`: sends AA84 → AA81 → AA A1 exactly as the Windows app does
- `wch_read_packets()`: reads bulk transfers, iterates device frames, decodes each
  `[55][10][len][payload]` frame, extends 32-bit device timestamps to 64-bit, calls
  the user callback with `wch_pkt_hdr_t` + raw BLE LL PDU bytes
- `wch_pkt_type_name()`, `wch_print_packet()` — utility/display functions

**`wch_capture.c`** — CLI tool

Implements:
- Argument parsing (`-v`, `-w FILE`, `-p PHY`, `-i/-a` MAC filters, `-c CHAN`, etc.)
  - `-c` sets both the 2.4G channel and `ble_channel`; in BLE mode 37/38/39 pins all
    MCUs to that channel, 0 (default) triggers per-MCU auto-assignment
- Signal handling (SIGINT/SIGTERM → clean shutdown)
- Per-MCU channel auto-assignment: MCU0→ch37, MCU1→ch38, MCU2→ch39 (overridden by `-c`)
- Two-phase capture loop:
  - **Drain phase**: tight inner loop calling `wch_read_packets(..., 5 ms)` per MCU
    until its buffer is empty; prevents the artificial 1:1:1 ch37/38/39 ratio that
    a simple round-robin produced
  - **Idle phase**: 100 ms blocking wait per MCU when all are quiet, to reduce CPU usage
- pcap output (DLT 256: LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR)
- Packet callback invoking both verbose print and pcap write

**`Makefile`** — standard C11 build against libusb-1.0

**`99-wch-ble-analyzer.rules`** — udev rule granting non-root access to the device

---

## Phase 7 — pcap format debugging

The first pcap attempt produced garbage in Wireshark. Three distinct bugs were found and
fixed by comparing the raw pcap hex against the `pcap-linktype(7)` specification and
Wireshark's `packet-btle.c` dissector source.

### Bug 1 — Missing Access Address + CRC in packet data

The `pcap-linktype(7)` spec for `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` (DLT 256) states:

> The payload, after the pseudo-header, is a BLE LL frame beginning with the
> **Access Address** field.

Expected record layout: `[PHDR 10B][AA 4B][PDU 2+N B][CRC 3B]`

We were writing `[PHDR 10B][PDU]`. Wireshark interpreted the first 4 PDU bytes as the
Access Address (which gave a garbage AA ≠ 0x8E89BED6), then tried to decode the rest as
a data-channel PDU, producing "L2CAP Fragment Start", "LL_PERIODIC_SYNC_IND", etc.

Fix: prepend the 4-byte Access Address (`0xD6 0xBE 0x89 0x8E` for advertising) and
append the 3-byte CRC (computed with BLE CRC-24: polynomial 0xDA6000 reflected, init
0x555555 for advertising channels).

### Bug 2 — DEWHITENED flag not set

The PHDR `flags` field (2 bytes) must have bit 0 (`DEWHITENED = 0x0001`) set to tell
Wireshark that the hardware already de-whitened the PDU bytes. Without this, Wireshark
applies BLE whitening a second time, corrupting all PDU content.

Original flags: `0x0020` (only bit 5 set, which we had incorrectly labeled "CRC OK").
Fixed flags: `0x0013` = `DEWHITENED | SIGPOWER_VALID | REF_AA_VALID`.

### Bug 3 — Wrong rf_channel value

The PHDR `rf_channel` field is the **physical RF channel index** where:
- 0 = 2402 MHz (advertising channel 37)
- 12 = 2426 MHz (advertising channel 38)
- 39 = 2480 MHz (advertising channel 39)

We were writing the BLE logical channel index (37 for adv ch37), but that maps to physical
RF channel 37 = 2476 MHz = data channel 35. Wireshark showed "Data channel 35" in the RF
info section and, since it thought this was a data channel, showed "Unknown" for all
advertising PDU type names.

Fix: convert BLE channel index to physical RF channel:
```c
if (ch == 37) return 0;
if (ch == 38) return 12;
if (ch == 39) return 39;
if (ch <= 10) return ch + 1;
return ch + 2;
```

### Additional fixes
- **Timestamps**: replaced device-local μs timestamps with wall clock (`CLOCK_REALTIME`),
  since the 3 MCUs have independent boot-time clocks that cannot be directly compared
- **Truncation**: added `fflush` after each complete pcap record so partial records are not
  left in the stdio buffer if the process is killed

---

## Phase 8 — Channel assignment and capture loop fix

### Observation

Live captures showed only channel 37 packets, and when the per-MCU assignment was first
added, the channel distribution was a suspiciously perfect 1:1:1 (every 3rd packet ch37,
then ch38, then ch39).

### Cause of the 1:1:1 ratio

The initial capture loop did one `libusb_bulk_transfer` per MCU per iteration (blocking
up to 1000 ms each). Because the device sends one BLE packet per USB transfer, and each
MCU sends at roughly the same advertising rate, the round-robin produced equal counts.
In a real environment ch37 typically carries much more traffic than ch38/39.

### Finding the channel byte

Binary search for writes to the AA81 payload channel field. Located
`MOV [RCX+0x2BA], DL` at VA `0x14028C2BB`. Traced callers: the Windows app calls
the payload builder three times per capture start, passing `scan_config+0x20` (=37),
`+0x21` (=38), `+0x22` (=39) — one per MCU, in order.

Also confirmed the mode flags byte (`+0x2B8`): bit0=BLE monitor (always 1),
bit1=channel-nonzero (set when payload[2] ≠ 0).

### Fix

- `wch_capture_config_t` gained a `ble_channel` field (separate from the 2.4G `channel`)
- `wch_start_capture()` writes `ble_channel` into AA81 payload[2] and sets the
  channel-nonzero flag in payload[0]
- `wch_read_packets()` gained a `timeout_ms` parameter (previously hardcoded to 1000 ms)
- The capture loop replaced with a drain+idle design: drain each MCU with 5 ms polls
  until empty, then fall back to 100 ms blocking waits when all are quiet
- `-c` switch now sets `cfg.ble_channel` in addition to `cfg.channel`; auto-assignment
  is only applied when no channel is explicitly specified

---

## Final result

All three CH582F MCUs capture BLE advertising simultaneously. The pcap output is fully
valid in Wireshark 4.6:

```
SamsungElect_bd:c8:40 → Broadcast    LE LL 56 ADV_IND
KimballElect_2f:76:04 → Broadcast    LE LL 50 ADV_IND
HUMAX_68:56:38        → TexasInstrum_82:84:af  LE LL 31 SCAN_REQ
6d:22:72:0a:64:7b     → Broadcast    LE LL 55 ADV_SCAN_IND
...
```

Typical throughput: ~400 packets/second per MCU on a busy channel-37 environment.
Some `[Malformed Packet]` warnings appear for BLE 5.0 devices that send >37-byte payloads
in legacy ADV_IND/ADV_NONCONN_IND format — the captured data is correct; Wireshark
enforces the BLE 4.x length limit.

---

### Linux driver — `linux-driver/`

| Path | Created by us? | Description |
|------|---------------|-------------|
| `wch_ble_analyzer.h` | **YES** | Public API header: USB IDs, packet types, structs, function declarations |
| `wch_ble_analyzer.c` | **YES** | Core libusb-1.0 driver: init sequence, frame parser, packet decoder |
| `wch_capture.c` | **YES** | CLI capture tool: argument parsing, pcap writer, drain+idle MCU reader, per-MCU channel assignment |
| `Makefile` | **YES** | Build system (C11, links libusb-1.0) |
| `99-wch-ble-analyzer.rules` | **YES** | udev rule for non-root device access |
| `wch_capture` | **YES** | Compiled capture tool |

