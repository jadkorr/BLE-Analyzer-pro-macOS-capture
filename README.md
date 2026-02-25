# WCH BLE Analyzer Pro — macOS Capture Tool

> **Credits & Acknowledgements**: 
> This tool is based on the initial reverse engineering and Linux driver baseline created by **Xecaz** ([https://github.com/xecaz/BLE-Analyzer-pro-linux-capture](https://github.com/xecaz/BLE-Analyzer-pro-linux-capture)). We extend our deep gratitude to Xecaz for the foundation of this project.
> 
> The **macOS Port and Advanced Tracking Architecture** were extensively developed and implemented by **Jadkorr** ([https://x.com/jadkorr](https://x.com/jadkorr)). This includes completely custom software-driven frequency hopping, Phase-Locked Loop (PLL) USB latency compensation, real-time Wireshark FIFO pipelines, and robust MAC filtering logic.

A macOS-compatible libusb-1.0 driver for the **WCH BLE Analyzer Pro** — a $30 USB BLE 5.1 sniffer built around three CH582F RISC-V MCUs and a CH334 hub. Each MCU gets its own advertising channel (37 / 38 / 39), allowing you to capture the entire BLE advertising spectrum simultaneously. Output is standard PCAP that Wireshark decodes natively.

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

## Build & Install

Compile the project using the included Makefile:

```bash
make clean
make
```

You can optionally install the compiled binary globally to run it from anywhere on your Mac:

```bash
sudo make install
```

---

## Usage

Run the compiled executable. You may not need root privileges (`sudo`) on macOS depending on your system's USB entitlement policies, but keep it in mind if no devices are found.

### 1. Passive Device Discovery & Environmental Mapping (Default)
By default, running the tool without connection following (`-f`) turns the three CH582F chips into a powerful, passive, multi-channel Advertising Monitor. It will sit permanently on channels 37, 38, and 39 to log *all* broadcasts, beacons, and connection requests in the room. It acts as an environmental radar without missing a beat.

```bash
# Capture all ambient BLE traffic in real-time
./wch_capture -ws
```

### 2. Targeted Connection Following
To actively track a specific device once it connects, use the `-f` (Follow) flag combined with a MAC Address filter (`-a` for peripherals or `-i` for centrals). The tool's newly implemented Phase-Locked Loop (PLL) synchronization will align with the peripheral's clock and instruct the hardware to hop through Data Channels (0-36) seamlessly.

```bash
# Follow the connection of a specific smart device
sudo ./wch_capture -ws -f -a E7:13:58:4D:5B:52
```

### 3. Decrypting Traffic On-The-Fly
If you have the 32-character Hex Long Term Key (LTK) or the numeric pairing passkey (PIN), you can provide it to instantly decrypt the AES-CCM Data Payloads through the hardware's cryptographic engine.

```bash
# Decrypt a connection actively using the LTK
sudo ./wch_capture -ws -f -k YOUR_32_CHAR_HEX_LTK_HERE

# Decrypt using a standard numeric PIN
sudo ./wch_capture -ws -f -K 123456
```

### 4. Background Standard Capture
If you prefer not to open Wireshark immediately, you can silently stream to a standard PCAP file for later analysis.

```bash
# Capture and write directly to a PCAP file
./wch_capture -w capture.pcap
```

### Real-Time Wireshark Streaming (Under the Hood)

You can manually control the UNIX FIFO pipe behavior if you don't want to use `-ws`:

```bash
# Enable FIFO pipeline at a custom file without auto-launching Wireshark
./wch_capture -ffn /tmp/my_custom_pipe
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
  -f            Follow connections dynamically (auto jump to data channels)
  -ff           Enable FIFO pipeline to communicate with Wireshark
  -ffn NAME     FIFO file name (default: /tmp/blepipe)
  -ws           Open Wireshark reading from FIFO
  -h            Show this help
```

### Advanced Tracing & Debugging

If you are developing your own firmware or debugging the raw hardware capture stream before it hits the Wireshark FIFO, you can dump the raw parsed Hex directly to a text file using `--debuglog`. This is extremely useful for verifying the CH582F silicon's unadulterated state.

```bash
# Dump raw Hex Payload packets alongside C-level debug statements
./wch_capture -ws -f -a AA:BB:CC:DD:EE:FF -debuglog raw_dump.txt
```

---

## FAQ & Known Protocol Behaviors

### Why does Wireshark show `Unknown Data` or `UNKNOWN_OPCODE` instead of `LL_START_ENC_REQ`?
If you successfully track a device using `-f` and it begins the security handshake, you will clearly see `LL_ENC_REQ` (0x03) and `LL_ENC_RSP` (0x04) in plaintext. However, the connection will suddenly seem to switch to `Unknown Data` containing random opcodes (e.g., 0x36, 0xCE) jumping across channels.

**This is not a bug; this is by design.** According to the **Bluetooth Core Specification V5.0 (Vol 6, Part B, Section 5.1.3 - Encryption Function)**:

> *"When the Slave's Link Layer sends the `LL_ENC_RSP` PDU, it shall initialize its encryption engine. Then, the Slave shall send the `LL_START_ENC_REQ` PDU. This PDU, and all subsequent PDUs sent by the Slave, **shall be encrypted**."*

The `LL_START_ENC_REQ` packet is intentionally the first fully AES-CCM encrypted packet sent during the handshake. Without providing the LTK (`-k`) to the sniffer, the hardware physically cannot decipher the packet. Wireshark will attempt to decode the random ciphertext byte as an opcode, resulting in false positives or "Unknown" labels. 

---

## License

This project is licensed under the **MIT License**.

- **Original Foundation & Protocol Reverse Engineering:** Copyright (c) 2024 Xecaz. We sincerely thank Xecaz for the initial groundwork that made this project possible.
- **macOS Architecture, Software Hopping Engine, & Real-Time Sync:** Copyright (c) 2026 Jadkorr (https://x.com/jadkorr).

See the [LICENSE](LICENSE) file for complete details.
