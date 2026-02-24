# WCH BLE Analyzer Pro — macOS Capture Tool

> **Note**: This is a fork of the original Linux driver repository created by **Xecaz** ([https://github.com/xecaz/BLE-Analyzer-pro-linux-capture](https://github.com/xecaz/BLE-Analyzer-pro-linux-capture)).
> Modded for macOS with real-time Wireshark FIFO streaming by **Jadkorr** ([https://x.com/jadkorr](https://x.com/jadkorr)).

A macOS-compatible libusb-1.0 driver for the **WCH BLE Analyzer Pro** — a $30 USB BLE 5.1 sniffer built around three CH582F RISC-V MCUs and a CH334 hub. Each MCU gets its own advertising channel (37 / 38 / 39), so you capture the entire BLE advertising spectrum simultaneously. Output is a standard PCAP that Wireshark decodes natively.

---

## Hardware

```text
┌─────────────────────────────────────┐
│         WCH BLE Analyzer Pro        │
│                                     │
│  [CH582F ch37]  VID 0x1A86          │
│  [CH582F ch38]  PID 0x8009  × 3     │
│  [CH582F ch39]                      │
│  [CH334 hub  ]  PID 0x8091          │
└─────────────────────────────────────┘
```

The device shows up as three independent USB devices through the hub.

---

## Requirements

To run this on macOS, you need `libusb` and `pkg-config` (required for compilation):

```bash
brew install libusb pkg-config
```

---

## Build

Compile the project using the included Makefile:

```bash
make clean
make
```

---

## Usage

Run the compiled executable. You may not need root privileges (`sudo`) on macOS depending on your system's USB entitlement policies, but keep it in mind if no devices are found.

### Standard Capture

```bash
# Capture and write to a PCAP file
./wch_capture -w capture.pcap
```

### Real-Time Wireshark Streaming

You can stream packets directly into Wireshark in real-time using a UNIX FIFO pipe:

```bash
# Automatically create a FIFO, start streaming, and launch Wireshark:
./wch_capture -ws
```

By default, the FIFO pipe is created at `/tmp/blepipe`. You can specify a custom location:

```bash
# Stream via custom FIFO and launch Wireshark
./wch_capture -ffn /tmp/my_custom_pipe -ws
```

### Additional Options

```text
Options:
  -v            Print packets to stdout
  -w FILE.pcap  Write PCAP (DLT 256, BLE LL + phdr)
  -p PHY        PHY: 1=1M (default), 2=2M, 3=CodedS8, 4=CodedS2
  -i ADDR       Central/Phone MAC filter (Initiator)  (AA:BB:CC:DD:EE:FF)
  -a ADDR       Peripheral/Device MAC filter (Advertiser) (AA:BB:CC:DD:EE:FF)
  -k KEY        LTK, 32 hex chars
  -K PASSKEY    BLE passkey (6-digit decimal)
  -2            Custom 2.4G mode (default: BLE monitor)
  -c CHAN       Channel 0-39: BLE adv 37/38/39 or 0=all (auto per MCU); 2.4G raw
  -A AADDR      2.4G access addr (hex, e.g. 8E89BED6)
  -C CRCINIT    2.4G CRC init (6 hex chars, e.g. 555555)
  -W WHITEN     2.4G whitening init (hex byte)
  -ff           Enable FIFO pipeline to communicate with Wireshark
  -ffn NAME     FIFO file name (default: /tmp/blepipe)
  -ws           Open Wireshark reading from FIFO
  -h            Show this help
```

---

## License

This project is licensed under the **MIT License**.

- **WCH Reverse Engineering & Original Linux Base:** Copyright (c) 2024-2026 Xecaz.
- **macOS Port & FIFO Integration:** Copyright (c) 2026 Jadkorr (https://x.com/jadkorr).

See the [LICENSE](LICENSE) file for complete details.
