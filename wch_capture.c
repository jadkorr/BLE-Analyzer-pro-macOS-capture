/*
 * wch_capture – CLI BLE packet capture tool for the WCH BLE Analyzer Pro
 *
 * _POSIX_C_SOURCE 200112L is required for sigaction(2) under -std=c11.
 */
#define _POSIX_C_SOURCE 200112L

/*
 *
 * Usage:
 *   wch_capture [OPTIONS]
 *
 * Options:
 *   -v            Verbose: print every packet to stdout
 *   -w FILE.pcap  Write captured packets to a PCAP file
 *   -p PHY        PHY mode: 1=1M (default), 2=2M, 3=CodedS8, 4=CodedS2
 *   -i ADDR       Initiator MAC filter  (e.g. AA:BB:CC:DD:EE:FF)
 *   -a ADDR       Advertiser MAC filter (e.g. AA:BB:CC:DD:EE:FF)
 *   -k KEY        LTK for decryption    (32 hex chars)
 *   -K PASSKEY    BLE pass key (6-digit decimal)
 *   -2            Custom 2.4G mode (default: BLE monitor)
 *   -c CHAN       2.4G channel 0-39     (default 37)
 *   -A AADDR      2.4G access address   (hex, e.g. 8E89BED6)
 *   -C CRCINIT    2.4G CRC init         (6 hex chars, e.g. 555555)
 *   -W WHITEN     2.4G whitening init   (hex byte)
 *   -h            Show this help
 *
 * Signals:
 *   SIGINT / SIGTERM   Stop capture and exit cleanly.
 *
 * PCAP output uses DLT_BLUETOOTH_LE_LL_WITH_PHDR (256), which Wireshark
 * decodes natively.  The pseudo-header is 10 bytes:
 *
 *   uint8_t  rf_channel          (0-39)
 *   int8_t   signal_power        (RSSI dBm, or 0x80 = invalid)
 *   int8_t   noise_power         (0x80 = invalid)
 *   uint8_t  access_address_offenses
 *   uint32_t reference_access_address (LE)
 *   uint16_t flags               (LE)
 *
 * Flags bit assignments (Wireshark packet-btle.h):
 *   bit 0: DEWHITENED      – data already de-whitened by hardware (MUST be 1)
 *   bit 1: SIGPOWER_VALID  – signal_power field is valid
 *   bit 2: NOISE_VALID     – noise_power field is valid
 *   bit 3: DECRYPTED       – payload was decrypted
 *   bit 4: REF_AA_VALID    – reference_access_address is valid
 *   bit 5: AA_OFFENSES_VALID
 *   bit 6: LE_PHYS_CODING_VALID
 *   bit 7: MIC_CHECKED_OK
 */

#include "wch_ble_analyzer.h"
#include <errno.h> // Added back as it was in the original and is likely needed
#include <fcntl.h> // Fixed and added back as it was in the original and is likely needed
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <fcntl.h>

/* ── BLE channel → RF channel conversion ────────────────────────────────── */

/*
 * DLT_BLUETOOTH_LE_LL_WITH_PHDR rf_channel field is the PHYSICAL RF channel
 * index where 0 = 2402 MHz, 1 = 2404 MHz, ..., n = 2402+2n MHz.
 * This is NOT the same as the BLE logical channel index (0-39):
 *   BLE ch 37 → RF ch  0  (2402 MHz, advertising)
 *   BLE ch 38 → RF ch 12  (2426 MHz, advertising)
 *   BLE ch 39 → RF ch 39  (2480 MHz, advertising)
 *   BLE ch  0 → RF ch  1  (2404 MHz, data)
 *   BLE ch 1-10 → RF ch 2-11
 *   BLE ch 11-36 → RF ch 13-38
 */
static uint8_t ble_ch_to_rf_ch(uint8_t ch) {
  if (ch == 37)
    return 0;
  if (ch == 38)
    return 12;
  if (ch == 39)
    return 39;
  if (ch <= 10)
    return ch + 1;
  return ch + 2;
}

/* ── BLE CRC-24 ─────────────────────────────────────────────────────────── */

/*
 * BLE uses CRC-24 with polynomial x^24+x^10+x^9+x^6+x^4+x^3+x+1 (= 0x65B),
 * processed LSB-first (reflected polynomial = 0xDA6000).
 * Advertising channel CRC init: 0x555555.
 * CRC covers the PDU only (not the access address).
 */
static uint32_t ble_crc24(uint32_t init, const uint8_t *buf, int len) {
  uint32_t lfsr = init & 0xFFFFFF;
  for (int i = 0; i < len; i++) {
    uint8_t byte = buf[i];
    for (int j = 0; j < 8; j++) {
      int in = (byte ^ (int)lfsr) & 1;
      lfsr >>= 1;
      byte >>= 1;
      if (in)
        lfsr ^= 0xDA6000u; /* reflected BLE polynomial */
    }
  }
  return lfsr;
}

/* ── PCAP file format ───────────────────────────────────────────────────── */

#define PCAP_MAGIC 0xa1b2c3d4u
#define PCAP_VERSION_MAJ 2
#define PCAP_VERSION_MIN 4
#define PCAP_SNAPLEN 65535
#define PCAP_DLT_BLE_LL_WITH_PHDR 256 /* Wireshark DLT for BLE LL + phdr */

#pragma pack(push, 1)
typedef struct {
  uint32_t magic;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
} pcap_file_hdr_t;

typedef struct {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
} pcap_rec_hdr_t;

/* DLT_BLUETOOTH_LE_LL_WITH_PHDR pseudo-header (10 bytes) */
typedef struct {
  uint8_t rf_channel;
  int8_t signal_power;
  int8_t noise_power;
  uint8_t access_address_offenses;
  uint32_t reference_access_address;
  uint16_t flags;
} ble_phdr_t;
#pragma pack(pop)

/* ── Globals ────────────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_stop = 0;

static void sig_handler(int sig) {
  (void)sig;
  g_stop = 1;
}

static FILE *g_pcap_file = NULL;
static bool g_verbose = false;
static uint64_t g_pkt_count = 0;
static uint8_t g_phy = PHY_1M;

/* FIFO and Wireshark */
static bool g_use_fifo = false;
static char *g_fifo_name = "/tmp/blepipe";
static bool g_launch_ws = false;

/* ── PCAP helpers ───────────────────────────────────────────────────────── */

static bool pcap_open(const char *path, bool is_fifo) {
  if (is_fifo) {
    if (access(path, F_OK) == -1) {
      if (mkfifo(path, 0666) != 0) {
        perror("mkfifo");
        return false;
      }
    }
  }
  g_pcap_file = fopen(path, "wb");
  if (!g_pcap_file) {
    perror(path);
    return false;
  }

  pcap_file_hdr_t fh = {
      .magic = PCAP_MAGIC,
      .version_major = PCAP_VERSION_MAJ,
      .version_minor = PCAP_VERSION_MIN,
      .thiszone = 0,
      .sigfigs = 0,
      .snaplen = PCAP_SNAPLEN,
      .network = PCAP_DLT_BLE_LL_WITH_PHDR,
  };
  fwrite(&fh, sizeof(fh), 1, g_pcap_file);
  fflush(g_pcap_file);
  return true;
}

static void pcap_write_packet(const wch_pkt_hdr_t *hdr, const uint8_t *pdu,
                              int pdu_len) {
  if (!g_pcap_file)
    return;

  /*
   * Build the BLE LL pseudo-header.
   * DEWHITENED (0x0001) MUST be set: the CH582F hardware de-whitens all
   * received PDUs before sending them over USB.  Without this bit Wireshark
   * would try to re-apply whitening, producing garbled PDU type fields.
   * SIGPOWER_VALID (0x0002): RSSI from device is always valid.
   * REF_AA_VALID   (0x0010): reference_access_address is 0x8E89BED6 (adv AA).
   */
  uint16_t flags = 0x0001    /* DEWHITENED      */
                   | 0x0002  /* SIGPOWER_VALID  */
                   | 0x0010; /* REF_AA_VALID    */

  ble_phdr_t ph = {
      .rf_channel = ble_ch_to_rf_ch(hdr->channel_index),
      .signal_power = (int8_t)hdr->rssi,
      .noise_power = (int8_t)0x80, /* unknown */
      .access_address_offenses = 0,
      .reference_access_address = hdr->access_addr,
      .flags = flags,
  };

  /*
   * Use wall-clock time for pcap timestamps so that packets from all three
   * MCUs have monotonically increasing, comparable timestamps.  The device's
   * own 32-bit μs clock (hdr->timestamp_us) is per-MCU-boot and cannot be
   * compared across devices without synchronisation.
   */
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  uint32_t ts_sec = (uint32_t)now.tv_sec;
  uint32_t ts_usec = (uint32_t)(now.tv_nsec / 1000);

  /*
   * Per pcap-linktype(7) for LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR (256),
   * the packet data after the 10-byte PHDR is:
   *   [Access Address 4 B] [BLE LL PDU 2+N B] [CRC 3 B]
   * Wireshark uses the Access Address to determine advertising vs. data
   * channel and routes to the correct dissector.
   */
  uint32_t aa_le = hdr->access_addr; /* already LE uint32 */

  /* Compute BLE CRC-24 over the PDU bytes.
   * Advertising CRC init = 0x555555 (all three adv channels use this). */
  uint32_t crc_val = ble_crc24(0x555555, pdu, pdu_len);
  uint8_t crc[3] = {
      (uint8_t)(crc_val),
      (uint8_t)(crc_val >> 8),
      (uint8_t)(crc_val >> 16),
  };

  uint32_t data_len = (uint32_t)(sizeof(ph) + 4 + pdu_len + 3);

  pcap_rec_hdr_t rh = {
      .ts_sec = ts_sec,
      .ts_usec = ts_usec,
      .incl_len = data_len,
      .orig_len = data_len,
  };

  fwrite(&rh, sizeof(rh), 1, g_pcap_file);
  fwrite(&ph, sizeof(ph), 1, g_pcap_file);
  fwrite(&aa_le, 4, 1, g_pcap_file); /* access address */
  if (pdu && pdu_len > 0)
    fwrite(pdu, 1, pdu_len, g_pcap_file); /* BLE LL PDU     */
  fwrite(crc, 3, 1, g_pcap_file);         /* CRC-24         */
  fflush(g_pcap_file); /* ensure each complete record hits disk */
}

/* ── Packet callback ────────────────────────────────────────────────────── */

struct cb_ctx {
  wch_device_t *dev;
  wch_capture_config_t *cfg;
};

static void on_packet(const wch_pkt_hdr_t *hdr, const uint8_t *pdu, int pdu_len,
                      void *ctx_arg) {
  struct cb_ctx *cctx = (struct cb_ctx *)ctx_arg;
  wch_capture_config_t *cfg = cctx ? cctx->cfg : NULL;
  wch_device_t *dev = cctx ? cctx->dev : NULL;

  /* Auto-follow logic */
  if (cfg && cfg->follow_conn && hdr->pkt_type == PKT_CONNECT_REQ) {
    if (pdu_len == 34) {
      memcpy(cfg->conn_req_data, pdu + 12, 22);
      if (dev) {
        fprintf(stderr,
                "[wch bus=%d addr=%d] Following CONNECT_IND! Reconfiguring "
                "sniffer...\n",
                dev->bus, dev->addr);
        wch_start_capture(dev, cfg);
      }
    }
  }

  if (cfg) {
    uint8_t zero_mac[6] = {0};
    bool has_adv_filter = memcmp(cfg->adv_addr, zero_mac, 6) != 0;
    bool has_init_filter = memcmp(cfg->initiator_addr, zero_mac, 6) != 0;

    if (has_adv_filter || has_init_filter) {
      bool match = false;

      if (has_adv_filter) {
        if (memcmp(hdr->src_addr, cfg->adv_addr, 6) == 0 ||
            memcmp(hdr->dst_addr, cfg->adv_addr, 6) == 0)
          match = true;
      }

      if (has_init_filter) {
        if (memcmp(hdr->src_addr, cfg->initiator_addr, 6) == 0 ||
            memcmp(hdr->dst_addr, cfg->initiator_addr, 6) == 0)
          match = true;
      }

      /* Data PDUs (like LL_ENC_REQ) do not contain MAC addresses in their
       * headers. If it's a data packet (type >= 0x0F), we bypass the MAC filter
       * so the user can still see control opcodes when the sniffer happens to
       * be on the right channel.
       */
      if (hdr->pkt_type >= PKT_DATA_PDU_RESERVED &&
          hdr->pkt_type <= PKT_LL_CTRL_TERMINATE_IND) {
        match = true;
      }

      if (!match)
        return; /* Drop packet quietly */
    }
  }

  g_pkt_count++;

  if (g_verbose)
    wch_print_packet(hdr, pdu, pdu_len);

  pcap_write_packet(hdr, pdu, pdu_len);
}

/* ── MAC address parsing ─────────────────────────────────────────────────── */

static bool parse_mac(const char *str, uint8_t out[6]) {
  /* Accept "AA:BB:CC:DD:EE:FF" or "AABBCCDDEEFF" */
  unsigned v[6];
  if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x", &v[0], &v[1], &v[2], &v[3],
             &v[4], &v[5]) == 6 ||
      sscanf(str, "%02x%02x%02x%02x%02x%02x", &v[0], &v[1], &v[2], &v[3], &v[4],
             &v[5]) == 6) {
    /* Convert from display order (MSB first) to wire order (LSB first) */
    for (int i = 0; i < 6; i++)
      out[5 - i] = (uint8_t)v[i];
    return true;
  }
  return false;
}

static bool parse_ltk(const char *str, uint8_t out[16]) {
  if (strlen(str) != 32)
    return false;
  for (int i = 0; i < 16; i++) {
    unsigned v;
    if (sscanf(str + i * 2, "%02x", &v) != 1)
      return false;
    out[i] = (uint8_t)v;
  }
  return true;
}

static void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s [OPTIONS]\n"
          "\n"
          "Options:\n"
          "  -v            Print packets to stdout\n"
          "  -w FILE.pcap  Write PCAP (DLT 256, BLE LL + phdr)\n"
          "  -p PHY        PHY: 1=1M (default), 2=2M, 3=CodedS8, 4=CodedS2\n"
          "  -i ADDR       Central/Phone MAC filter (Initiator)  "
          "(AA:BB:CC:DD:EE:FF)\n"
          "  -a ADDR       Peripheral/Device MAC filter (Advertiser) "
          "(AA:BB:CC:DD:EE:FF)\n"
          "  -k KEY        LTK, 32 hex chars\n"
          "  -K PASSKEY    BLE passkey (6-digit decimal)\n"
          "  -2            Custom 2.4G mode (default: BLE monitor)\n"
          "  -c CHAN       Channel 0-39: BLE adv 37/38/39 or 0=all (auto per "
          "MCU); 2.4G raw\n"
          "  -A AADDR      2.4G access addr (hex, e.g. 8E89BED6)\n"
          "  -C CRCINIT    2.4G CRC init (6 hex chars, e.g. 555555)\n"
          "  -W WHITEN     2.4G whitening init (hex byte)\n"
          "  -f            Follow connections dynamically (auto jump to data "
          "channels)\n"
          "  -ff           Enable FIFO pipeline to communicate with Wireshark\n"
          "  -ffn NAME     FIFO file name (default: /tmp/blepipe)\n"
          "  -ws           Open Wireshark reading from FIFO\n"
          "  -h            Show this help\n"
          "\n"
          "Capture stops on SIGINT (Ctrl+C) or SIGTERM.\n",
          prog);
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
  fprintf(stderr, "\n"
                  "WCH BLE Analyzer PRO macOS Capture tool\n"
                  "Author: Xecaz\n"
                  "Modded for MacOS by Jadkorr (https://x.com/jadkorr)\n"
                  "---------------------------------------\n"
                  "\n");

  wch_capture_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.mode = MODE_BLE_MONITOR;
  cfg.phy = PHY_1M;

  const char *pcap_path = NULL;
  int opt;

  // Manual parsing for -ff, -ffn, -ws before getopt
  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-ff") == 0) {
      g_use_fifo = true;
      // Remove this argument from argv for getopt
      for (int j = i; j < argc - 1; j++)
        argv[j] = argv[j + 1];
      argc--;
      i--; // Re-check the current index
    } else if (strcmp(argv[i], "-ffn") == 0) {
      g_use_fifo = true;
      if (i + 1 < argc) {
        g_fifo_name = argv[i + 1];
        // Remove -ffn and its argument from argv for getopt
        for (int j = i; j < argc - 2; j++)
          argv[j] = argv[j + 2];
        argc -= 2;
        i--; // Re-check the current index
      } else {
        fprintf(stderr, "Error: -ffn requires a file name.\n");
        usage(argv[0]);
        return 1;
      }
    } else if (strcmp(argv[i], "-ws") == 0) {
      g_launch_ws = true;
      g_use_fifo = true; // -ws implies -ff
      // Remove this argument from argv for getopt
      for (int j = i; j < argc - 1; j++)
        argv[j] = argv[j + 1];
      argc--;
      i--; // Re-check the current index
    }
  }

  while ((opt = getopt(argc, argv, "vw:p:i:a:k:K:2c:A:C:W:fh")) != -1) {
    switch (opt) {
    case 'f':
      cfg.follow_conn = true;
      break;
    case 'v':
      g_verbose = true;
      break;
    case 'w':
      pcap_path = optarg;
      break;
    case 'p':
      cfg.phy = (uint8_t)atoi(optarg);
      if (cfg.phy < 1 || cfg.phy > 4) {
        fprintf(stderr, "Invalid PHY %d (1-4)\n", cfg.phy);
        return 1;
      }
      g_phy = cfg.phy;
      break;
    case 'i':
      if (!parse_mac(optarg, cfg.initiator_addr)) {
        fprintf(stderr, "Invalid initiator MAC: %s\n", optarg);
        return 1;
      }
      break;
    case 'a':
      if (!parse_mac(optarg, cfg.adv_addr)) {
        fprintf(stderr, "Invalid advertiser MAC: %s\n", optarg);
        return 1;
      }
      break;
    case 'k':
      if (!parse_ltk(optarg, cfg.ltk)) {
        fprintf(stderr, "Invalid LTK (need 32 hex chars): %s\n", optarg);
        return 1;
      }
      break;
    case 'K':
      cfg.pass_key = (uint32_t)atol(optarg);
      break;
    case '2':
      cfg.mode = MODE_CUSTOM_2G4;
      break;
    case 'c': {
      int v = atoi(optarg);
      if (v < 0 || v > 39) {
        fprintf(stderr, "Channel out of range (0-39)\n");
        return 1;
      }
      cfg.channel = (uint8_t)v;     /* 2.4G mode */
      cfg.ble_channel = (uint8_t)v; /* BLE monitor mode */
      break;
    }
    case 'A': {
      unsigned long v;
      if (sscanf(optarg, "%lx", &v) != 1) {
        fprintf(stderr, "Invalid access address: %s\n", optarg);
        return 1;
      }
      cfg.access_addr_24g = (uint32_t)v;
      break;
    }
    case 'C': {
      unsigned v[3];
      if (sscanf(optarg, "%02x%02x%02x", &v[0], &v[1], &v[2]) != 3) {
        fprintf(stderr, "Invalid CRC init (need 6 hex chars): %s\n", optarg);
        return 1;
      }
      cfg.crc_init[0] = (uint8_t)v[0];
      cfg.crc_init[1] = (uint8_t)v[1];
      cfg.crc_init[2] = (uint8_t)v[2];
      break;
    }
    case 'W': {
      unsigned v;
      if (sscanf(optarg, "%x", &v) != 1) {
        fprintf(stderr, "Invalid whitening: %s\n", optarg);
        return 1;
      }
      cfg.whitening = (uint8_t)v;
      break;
    }
    case 'h':
    default:
      usage(argv[0]);
      return opt == 'h' ? 0 : 1;
    }
  }

  if (!g_verbose && !pcap_path && !g_use_fifo) {
    fprintf(stderr, "Nothing to do – use -v, -w FILE.pcap, or -ff\n");
    usage(argv[0]);
    return 1;
  }

  fprintf(stderr, "Active Configuration:\n");
  fprintf(stderr, "  PHY:         %s\n",
          cfg.phy == 1   ? "1M"
          : cfg.phy == 2 ? "2M"
          : cfg.phy == 3 ? "Coded S8"
                         : "Coded S2");

  if (cfg.mode == MODE_CUSTOM_2G4) {
    fprintf(stderr, "  Mode:        Custom 2.4G (Ch %d)\n", cfg.channel);
  } else {
    if (cfg.ble_channel) {
      fprintf(stderr, "  Channel:     %d\n", cfg.ble_channel);
    } else {
      fprintf(stderr, "  Channel:     Auto-Hopping (37, 38, 39)\n");
    }
  }

  uint8_t zero_mac[6] = {0};
  if (memcmp(cfg.initiator_addr, zero_mac, 6) != 0) {
    fprintf(
        stderr,
        "  Filter (C):  %02X:%02X:%02X:%02X:%02X:%02X (Central/Initiator)\n",
        cfg.initiator_addr[5], cfg.initiator_addr[4], cfg.initiator_addr[3],
        cfg.initiator_addr[2], cfg.initiator_addr[1], cfg.initiator_addr[0]);
  }
  if (memcmp(cfg.adv_addr, zero_mac, 6) != 0) {
    fprintf(stderr,
            "  Filter (P):  %02X:%02X:%02X:%02X:%02X:%02X "
            "(Peripheral/Advertiser)\n",
            cfg.adv_addr[5], cfg.adv_addr[4], cfg.adv_addr[3], cfg.adv_addr[2],
            cfg.adv_addr[1], cfg.adv_addr[0]);
  }
  fprintf(stderr, "---------------------------------------\n");

  /* Set up signal handlers */
  struct sigaction sa = {.sa_handler = sig_handler};
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Initialise libusb */
  libusb_context *ctx = NULL;
  int r = wch_init(&ctx);
  if (r != 0) {
    fprintf(stderr, "libusb_init: %s\n", libusb_error_name(r));
    return 1;
  }

  /* Find MCU devices */
  wch_device_t devs[MAX_MCU_DEVICES];
  int ndev = wch_find_devices(ctx, devs);
  if (ndev <= 0) {
    fprintf(stderr,
            "No WCH BLE Analyzer MCUs found "
            "(VID 0x%04X / PID 0x%04X).\n"
            "Check USB connection and udev rules.\n",
            WCH_VID, WCH_PID_BLE_MCU);
    wch_exit(ctx);
    return 1;
  }
  fprintf(stderr, "Found %d MCU device(s).\n", ndev);

  /* Open all found devices */
  int opened = 0;
  for (int i = 0; i < ndev; i++) {
    r = wch_open_device(&devs[i]);
    if (r != 0) {
      fprintf(stderr, "open bus=%d addr=%d: %s\n", devs[i].bus, devs[i].addr,
              libusb_error_name(r));
    } else {
      fprintf(stderr, "Opened bus=%d addr=%d\n", devs[i].bus, devs[i].addr);
      opened++;
    }
  }
  if (opened == 0) {
    fprintf(stderr, "Could not open any device.\n");
    wch_exit(ctx);
    return 1;
  }

  if (g_use_fifo) {
    pcap_path = g_fifo_name;
  }

  if (g_launch_ws && g_use_fifo) {
    fprintf(stderr, "Launching Wireshark...\n");
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "wireshark -k -i %s &", g_fifo_name);
    if (system(cmd) == -1) {
      perror("system");
    }
  } else if (g_use_fifo) {
    fprintf(stderr, "FIFO mode enabled. Awaiting reader on %s...\n",
            g_fifo_name);
  }

  /* Open PCAP output file */
  if (pcap_path && !pcap_open(pcap_path, g_use_fifo)) {
    for (int i = 0; i < ndev; i++)
      wch_close_device(&devs[i]);
    wch_exit(ctx);
    return 1;
  }

  /*
   * Send start command to all open devices.
   *
   * Channel assignment for BLE monitor mode:
   *   The hardware has 3 independent CH582F MCUs, one per BLE advertising
   *   channel (37 / 38 / 39).  Assign a different channel to each MCU so
   *   all three advertising channels are captured simultaneously.
   *   Confirmed by RE of BleAnalyzer64.exe (AA81 payload byte [2] = channel).
   */
  static const uint8_t adv_ch[3] = {37, 38, 39};

  for (int i = 0; i < ndev; i++) {
    if (!devs[i].is_open)
      continue;

    wch_capture_config_t dev_cfg = cfg;
    /* Auto-assign one adv channel per MCU unless user pinned a channel */
    if (cfg.mode == MODE_BLE_MONITOR && ndev > 1 && cfg.ble_channel == 0)
      dev_cfg.ble_channel = (i < 3) ? adv_ch[i] : 0;

    r = wch_start_capture(&devs[i], &dev_cfg);
    if (r != 0)
      fprintf(stderr, "start_capture bus=%d addr=%d: %s\n", devs[i].bus,
              devs[i].addr, libusb_error_name(r));
    else if (cfg.mode == MODE_BLE_MONITOR)
      fprintf(stderr, "  MCU %d (bus=%d addr=%d): BLE ch%d\n", i, devs[i].bus,
              devs[i].addr, dev_cfg.ble_channel ? dev_cfg.ble_channel : 37);
  }

  /* Allocate bulk read buffers – one per device */
  uint8_t *bufs[MAX_MCU_DEVICES];
  for (int i = 0; i < ndev; i++) {
    bufs[i] = NULL;
    if (devs[i].is_open) {
      bufs[i] = malloc(BULK_TRANSFER_SIZE);
      if (!bufs[i]) {
        fprintf(stderr, "Out of memory\n");
        g_stop = 1;
        break;
      }
    }
  }

  fprintf(stderr, "Capturing… press Ctrl+C to stop.\n");

  /*
   * Main capture loop.
   *
   * Strategy: drain each MCU's USB buffer completely before moving on.
   * This prevents the artificial 1:1:1 channel ratio caused by reading
   * exactly one bulk transfer per MCU per loop iteration.
   *
   * DRAIN_POLL_MS: short timeout used to drain buffered packets quickly.
   *   Returning 0 (timeout) means the MCU's kernel buffer is empty.
   *
   * IDLE_WAIT_MS: longer timeout used when all MCUs are quiet to avoid
   *   busy-looping while still waking up promptly when traffic arrives.
   */
#define DRAIN_POLL_MS 5 /* quick drain: check for already-buffered data  */
#define IDLE_WAIT_MS                                                           \
  100 /* idle wait: block until traffic arrives (per MCU)                      \
       */

  while (!g_stop) {
    bool any_data = false;

    /* Phase 1: drain each MCU until its buffer is empty */
    for (int i = 0; i < ndev && !g_stop; i++) {
      if (!devs[i].is_open || !bufs[i])
        continue;
      struct cb_ctx cctx = {&devs[i], &cfg};
      for (;;) {
        int n = wch_read_packets(&devs[i], bufs[i], on_packet, &cctx,
                                 DRAIN_POLL_MS);
        if (n > 0) {
          any_data = true;
          continue;
        }
        break; /* n == 0 → timeout, buffer empty */
      }
    }

    /* Phase 2: when all MCUs are idle, do a longer blocking wait
     * on each MCU to reduce CPU usage until traffic resumes. */
    if (!any_data && !g_stop) {
      for (int i = 0; i < ndev && !g_stop; i++) {
        if (!devs[i].is_open || !bufs[i])
          continue;
        struct cb_ctx cctx = {&devs[i], &cfg};
        wch_read_packets(&devs[i], bufs[i], on_packet, &cctx, IDLE_WAIT_MS);
      }
    }
  }

  /* Stop and clean up */
  fprintf(stderr, "\nStopping capture (%llu packets)…\n",
          (unsigned long long)g_pkt_count);

  for (int i = 0; i < ndev; i++) {
    if (!devs[i].is_open)
      continue;
    wch_stop_capture(&devs[i]);
    fprintf(stderr, "  bus=%d addr=%d: rx=%llu err=%llu\n", devs[i].bus,
            devs[i].addr, (unsigned long long)devs[i].rx_count,
            (unsigned long long)devs[i].err_count);
    wch_close_device(&devs[i]);
    free(bufs[i]);
  }

  if (g_pcap_file) {
    fflush(g_pcap_file);
    fclose(g_pcap_file);
    fprintf(stderr, "PCAP written to %s\n", pcap_path);
  }

  wch_exit(ctx);
  return 0;
}
