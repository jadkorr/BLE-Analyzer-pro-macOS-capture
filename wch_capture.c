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

// Follow globals for PCAP headers
bool g_following = false;
uint32_t g_follow_aa = 0x8E89BED6;
static uint32_t g_follow_crcinit = 0x555555;

/* Set to true by on_packet when CONNECT_IND is seen.
 * The MAIN LOOP reads this flag and performs the USB reconfig after
 * the current bulk_read returns, avoiding re-entrant USB access. */
static volatile bool g_need_reconfig = false;

FILE *g_debuglog_file = NULL;

#include <pthread.h>

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

/* globals for Host-Side Connection Frequency Hopping */
static pthread_t g_hop_thread;
static uint16_t g_hop_interval_us = 0;
static uint8_t g_hop_increment = 0;
static uint64_t g_channel_map = 0;
static uint8_t g_last_unmapped_ch = 0;
static uint8_t g_remapped_channels[37];
static int g_num_used_channels = 0;
static wch_device_t *g_devs_ptr = NULL;
static int g_ndevs = 0;
static wch_capture_config_t g_active_cfg;
static uint32_t g_win_offset_us = 0; /* WinOffset * 1250 µs */
static uint64_t g_conn_req_hw_ts = 0;
static uint64_t g_active_host_hw_offset_us = 0;

static inline uint8_t wch_ble_channel_to_rf_index(uint8_t ble_ch) {
  if (ble_ch == 37)
    return 0;
  if (ble_ch == 38)
    return 12;
  if (ble_ch == 39)
    return 39;
  if (ble_ch <= 10)
    return ble_ch + 1;
  return ble_ch + 2;
}

static void *hop_thread_func(void *arg) {
  (void)arg;

  /*
   * Start our HW-time anchor precisely at the hardware's
   * timestamp of the CONNECT_IND packet plus the WinOffset.
   */
  uint64_t next_hop_hw_us = g_conn_req_hw_ts + g_win_offset_us;
  bool is_event_0 = true;

  while (g_following && !g_stop) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t host_now_us = ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;

    /* Map the hardware anchor to the current host monotonic timeline */
    uint64_t abs_next_hop_host_us = next_hop_hw_us + g_active_host_hw_offset_us;
    int64_t diff_us = (int64_t)(abs_next_hop_host_us - host_now_us);

    if (diff_us < 0) {
      /* Event is in the past! We missed the window entirely (USB latency).
       * Fast-Forward the channel math to the next interval without hitting USB.
       */
      g_last_unmapped_ch = (g_last_unmapped_ch + g_hop_increment) % 37;
      uint8_t next_ch = g_last_unmapped_ch;
      if (!(g_channel_map & (1ULL << next_ch))) {
        if (g_num_used_channels > 0)
          next_ch =
              g_remapped_channels[g_last_unmapped_ch % g_num_used_channels];
        else
          next_ch = 0;
      }
      g_active_cfg.ble_channel = next_ch;
      g_active_cfg.channel = wch_ble_channel_to_rf_index(next_ch);
      next_hop_hw_us += g_hop_interval_us;

      if (is_event_0) {
        fprintf(
            stderr,
            "[hop] Event 0 MISSED (diff %lld us), fast-forwarding math...\n",
            (long long)diff_us);
        is_event_0 = false;
      }
      continue;
    }

    /* We are on time. Calculate how long to sleep before firing the command.
     * Give the USB stack and MCU a lead time. Cap it at min(15ms, interval/2).
     */
    int64_t lead_us = g_hop_interval_us / 2;
    if (lead_us > 15000LL)
      lead_us = 15000LL;

    int64_t sleep_us = diff_us - lead_us;

    if (sleep_us > 0)
      usleep((useconds_t)sleep_us);

    if (!g_following || g_stop)
      break;

    /* Issue retune for the currently scheduled channel */
    for (int i = 0; i < g_ndevs; i++) {
      if (g_devs_ptr[i].is_open)
        wch_reconfig_capture(&g_devs_ptr[i], &g_active_cfg);
    }

    if (is_event_0) {
      fprintf(stderr,
              "[hop] Event 0: scheduled BLE ch %d (WinOffset %lld us diff)\n",
              g_active_cfg.ble_channel, (long long)diff_us);
      is_event_0 = false;
    }

    /* BLE Channel Selection Algorithm #1 (Core Spec 5.0 Vol 6 Part B §4.5.8) */
    g_last_unmapped_ch = (g_last_unmapped_ch + g_hop_increment) % 37;
    uint8_t next_ch_calc = g_last_unmapped_ch;

    if (!(g_channel_map & (1ULL << next_ch_calc))) {
      /* Remap to a used channel */
      if (g_num_used_channels > 0)
        next_ch_calc =
            g_remapped_channels[g_last_unmapped_ch % g_num_used_channels];
      else
        next_ch_calc = 0;
    }

    /* Stage the next channel to be fired on the next wakeup */
    g_active_cfg.ble_channel = next_ch_calc;
    g_active_cfg.channel = wch_ble_channel_to_rf_index(next_ch_calc);

    /* Advance the hardware clock anchor by exactly one connection interval */
    next_hop_hw_us += g_hop_interval_us;
  }
  return NULL;
}

/* ── PCAP helpers ─────────────────────────────────────────────────────────
 */

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
      .reference_access_address = g_following ? g_follow_aa : 0x8E89BED6,
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
   * If the frame's Access Address is the Adv AA, use standard CRC.
   * Otherwise, use the dynamic Connection CRC.
   */
  bool is_adv_frame = (hdr->access_addr == 0x8E89BED6);
  uint32_t crc_val =
      ble_crc24(is_adv_frame ? 0x555555 : g_follow_crcinit, pdu, pdu_len);
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

/* ── Packet callback ──────────────────────────────────────────────────────
 */

struct cb_ctx {
  wch_device_t *dev;  /* this MCU */
  wch_device_t *devs; /* all MCUs */
  int ndev;           /* MCU count */
  wch_capture_config_t *cfg;
};

static void on_packet(const wch_pkt_hdr_t *hdr, const uint8_t *pdu, int pdu_len,
                      void *ctx_arg) {
  struct cb_ctx *cctx = (struct cb_ctx *)ctx_arg;
  wch_capture_config_t *cfg = cctx ? cctx->cfg : NULL;
  wch_device_t *dev = cctx ? cctx->dev : NULL;

  if (g_debuglog_file) {
    fprintf(g_debuglog_file,
            "[wch bus=%d addr=%d] CH=%d RSSI=%d TYPE=0x%02X LEN=%d PDU=",
            dev ? dev->bus : 0, dev ? dev->addr : 0, hdr->channel_index,
            hdr->rssi, hdr->pkt_type, pdu_len);
    for (int i = 0; i < pdu_len; i++) {
      fprintf(g_debuglog_file, "%02X", pdu[i]);
    }
    fprintf(g_debuglog_file, "\n");
    fflush(g_debuglog_file);
  }

  /*
   * Phase-Locked Loop (PLL) Time offset compensator.
   * Every valid packet gives us a pair of (Host Now, HW Now) times.
   * Minimum offset perfectly tracks the lowest USB latency, thereby filtering
   * out arbitrary USB bulk-read delays.
   * We track this PER-DEVICE because each MCU has its own independent clock.
   * MUST BE EXECUTED BEFORE ANY FILTER DROPS to keep it primed and accurate!
   */
  if (dev) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t host_now_us = ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
    uint64_t current_offset = host_now_us - hdr->timestamp_us;

    if (dev->host_hw_offset_us == 0 ||
        current_offset < dev->host_hw_offset_us) {
      dev->host_hw_offset_us = current_offset;
    }
  }

  /* Auto-follow logic:
   * CONNECT_IND only appears on advertising channels (37/38/39).
   * LL_DATA packets on data channels share the same pkt_type byte value,
   * so we must guard against false positives using the channel index. */
  bool is_adv_channel = (hdr->channel_index == 37 || hdr->channel_index == 38 ||
                         hdr->channel_index == 39);
  if (cfg && cfg->follow_conn && is_adv_channel &&
      hdr->pkt_type == PKT_CONNECT_REQ && !g_following) {
    /*
     * Strict CONNECT_IND validation:
     * 1. pdu[1] MUST be exactly 34 (legacy CONNECT_IND is always
     *    34 bytes: InitA(6)+AdvA(6)+LLData(22)). Anything else is
     *    a corrupt read or a different PDU type.
     * 2. pdu_len must be >= 36 (to safely read pdu[0..35]).
     * 3. If an AdvA filter is configured (-a flag), pdu[8..13] must
     *    match — we only want the connection TO OUR target device.
     */
    bool valid_llength = (pdu_len >= 36 && pdu[1] == 34);
    uint8_t zero_mac[6] = {0};
    bool has_adv_filter = (memcmp(cfg->adv_addr, zero_mac, 6) != 0);
    bool adva_match = !has_adv_filter ||
                      (pdu_len >= 14 && memcmp(pdu + 8, cfg->adv_addr, 6) == 0);
    if (valid_llength && adva_match) {
      /*
       * CONNECT_IND PDU layout:
       *   pdu[0..1]   = PDU header (type + length)
       *   pdu[2..7]   = InitA  (Initiator MAC, 6 bytes)
       *   pdu[8..13]  = AdvA   (Advertiser MAC, 6 bytes)
       *   pdu[14..35] = LLData (22 bytes) ← what the firmware needs
       *
       * LLData layout:
       *   [14..17] = Access Address (4 bytes)
       *   [18..20] = CRCInit (3 bytes)
       *   [21..35] = WinSize, WinOffset, Interval, Latency, Timeout, ChMap,
       * Hop
       *
       * g_following is a one-shot latch: once the first MCU sets it,
       * all other MCUs skip their CONNECT_IND processing (prevents race where
       * two MCUs detect different connections and overwrite g_follow_aa).
       */
      /* Retain original Little-Endian layout for hardware Access-Address
       * filtering */
      memcpy(cfg->conn_req_data, pdu + 14, 22);

      /* Latch AA and CRCInit */
      memcpy(&g_follow_aa, pdu + 14, 4);
      g_follow_crcinit =
          pdu[18] | ((uint32_t)pdu[19] << 8) | ((uint32_t)pdu[20] << 16);

      /* Calculate Software Hopping parameters (Core Spec 5.0 Vol 6 Part B
       * §4.5.8)
       *
       * CONNECT_IND LLData offsets (relative to pdu[0]):
       *   pdu[21]      = WinSize   (1 byte, units of 1.25 ms)
       *   pdu[22..23]  = WinOffset (2 bytes LE, units of 1.25 ms)
       *   pdu[24..25]  = Interval  (2 bytes LE, units of 1.25 ms)
       *   pdu[30..34]  = ChM       (5 bytes, 37-bit channel map)
       *   pdu[35]      = HopIncrement (5 LSBs) | SCA (3 MSBs)
       */
      uint16_t win_offset = pdu[22] | ((uint16_t)pdu[23] << 8);
      g_win_offset_us = (uint32_t)win_offset * 1250;
      uint16_t interval = pdu[24] | ((uint16_t)pdu[25] << 8);
      g_hop_interval_us = interval * 1250;
      g_hop_increment = pdu[35] & 0x1F;

      g_channel_map = 0;
      for (int i = 0; i < 5; i++) {
        g_channel_map |= ((uint64_t)pdu[30 + i]) << (i * 8);
      }

      g_num_used_channels = 0;
      for (int i = 0; i < 37; i++) {
        if (g_channel_map & (1ULL << i)) {
          g_remapped_channels[g_num_used_channels++] = i;
        }
      }

      /*
       * BLE CSA#1 (Core Spec Vol.6 Part B §4.5.8):
       * Event 0 first channel = (lastUnmapped + HopIncrement) % 37
       * lastUnmapped starts at 0 before any events, so:
       *   unmapped_event0 = (0 + hop_increment) % 37
       */
      uint8_t unmapped0 = (uint8_t)(g_hop_increment % 37);
      g_last_unmapped_ch = unmapped0; /* seed for next hop */
      uint8_t first_ch = unmapped0;
      if (!(g_channel_map & (1ULL << first_ch))) {
        /* Remap unused channel */
        if (g_num_used_channels > 0)
          first_ch = g_remapped_channels[unmapped0 % g_num_used_channels];
        else
          first_ch = 0;
      }
      /* Store so thread's first loop iteration advances correctly */
      g_last_unmapped_ch = unmapped0;

      g_active_cfg = *cfg;
      g_active_cfg.ble_channel = first_ch;
      g_active_cfg.channel = wch_ble_channel_to_rf_index(first_ch);

      /* Set g_following last to act as a write barrier */
      g_following = true;

      /* Record the exact hardware timestamp of the CONNECT_REQ */
      g_conn_req_hw_ts = hdr->timestamp_us;
      if (dev && dev->host_hw_offset_us == 0) {
        struct timespec ts_init;
        clock_gettime(CLOCK_MONOTONIC, &ts_init);
        dev->host_hw_offset_us =
            (ts_init.tv_sec * 1000000ULL + ts_init.tv_nsec / 1000ULL) -
            hdr->timestamp_us;
      }
      g_active_host_hw_offset_us = dev ? dev->host_hw_offset_us : 0;

      fprintf(stderr,
              "[wch bus=%d addr=%d] Following CONNECT_IND! AA=%08X "
              "CRCInit=%06X interval=%d us WinOffset=%d us ch_map=0x%010llX "
              "hop=%d\n",
              dev ? dev->bus : -1, dev ? dev->addr : -1, g_follow_aa,
              g_follow_crcinit, g_hop_interval_us, g_win_offset_us,
              (unsigned long long)g_channel_map, g_hop_increment);

      /* Spawn POSIX Timer Thread to track channel hopping */
      pthread_create(&g_hop_thread, NULL, hop_thread_func, NULL);
      pthread_detach(g_hop_thread);

      /* Signal the main loop to reconfig all MCUs.
       * We CANNOT call wch_reconfig_capture here: on_packet runs inside
       * wch_read_packets (a bulk_read context) — doing another bulk_write
       * on the same handle is re-entrant USB access and corrupts the read. */
      g_need_reconfig = true;
    } else {
      fprintf(stderr,
              "[wch debug] CONNECT_IND dropped! pdu_len=%d, pdu[1]=%d\n"
              "            valid_llength=%d, adva_match=%d\n",
              pdu_len, pdu[1], valid_llength, adva_match);
      if (!adva_match) {
        fprintf(stderr,
                "            AdvA in packet: %02X:%02X:%02X:%02X:%02X:%02X\n"
                "            Target filter:  %02X:%02X:%02X:%02X:%02X:%02X\n",
                pdu[13], pdu[12], pdu[11], pdu[10], pdu[9], pdu[8],
                cfg->adv_addr[5], cfg->adv_addr[4], cfg->adv_addr[3],
                cfg->adv_addr[2], cfg->adv_addr[1], cfg->adv_addr[0]);
      }
    }
  }

  if (cfg) {
    uint8_t zero_mac[6] = {0};
    bool has_adv_filter = memcmp(cfg->adv_addr, zero_mac, 6) != 0;
    bool has_init_filter = memcmp(cfg->initiator_addr, zero_mac, 6) != 0;

    bool match = false;
    if (has_adv_filter || has_init_filter) {

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
       * headers. If it's a data packet (channel <= 36), we bypass the MAC
       * filter so the user can still see control opcodes when the sniffer
       * happens to be on the right channel.
       */
      if (hdr->channel_index <= 36) {
        match = true;
      }
    } else {
      /* If no filters were specified, implicitly accept all unencrypted packets
       */
      match = true;
    }

    if (!match)
      return; /* Drop packet quietly */
  }

  g_pkt_count++;

  if (g_verbose)
    wch_print_packet(hdr, pdu, pdu_len);

  /* User requested Real-Time Control Opcode Logging */
  if (g_following && hdr->channel_index <= 36 && pdu_len > 2) {
    uint8_t llid = pdu[0] & 0x03;
    if (llid == 0x03) {                  /* LL Control PDU */
      uint8_t cp = (pdu[0] & 0x20) >> 5; /* CTE Info Present bit */
      uint8_t opcode_offset = 2 + cp;    /* Opcode shifts if CTE byte exists */

      if (pdu_len > opcode_offset) {
        uint8_t opcode = pdu[opcode_offset];
        const char *op_name = "UNKNOWN_OPCODE";
        switch (opcode) {
        case 0x00:
          op_name = "LL_CONNECTION_UPDATE_IND";
          break;
        case 0x01:
          op_name = "LL_CHANNEL_MAP_IND";
          break;
        case 0x02:
          op_name = "LL_TERMINATE_IND";
          break;
        case 0x03:
          op_name = "LL_ENC_REQ";
          break;
        case 0x04:
          op_name = "LL_ENC_RSP";
          break;
        case 0x05:
          op_name = "LL_START_ENC_REQ";
          break;
        case 0x06:
          op_name = "LL_START_ENC_RSP";
          break;
        case 0x07:
          op_name = "LL_UNKNOWN_RSP";
          break;
        case 0x08:
          op_name = "LL_FEATURE_REQ";
          break;
        case 0x09:
          op_name = "LL_FEATURE_RSP";
          break;
        case 0x0A:
          op_name = "LL_PAUSE_ENC_REQ";
          break;
        case 0x0B:
          op_name = "LL_PAUSE_ENC_RSP";
          break;
        case 0x0C:
          op_name = "LL_VERSION_IND";
          break;
        case 0x0D:
          op_name = "LL_REJECT_IND";
          break;
        case 0x0E:
          op_name = "LL_SLAVE_FEATURE_REQ";
          break;
        case 0x0F:
          op_name = "LL_CONNECTION_PARAM_REQ";
          break;
        case 0x10:
          op_name = "LL_CONNECTION_PARAM_RSP";
          break;
        case 0x11:
          op_name = "LL_REJECT_EXT_IND";
          break;
        case 0x12:
          op_name = "LL_PING_REQ";
          break;
        case 0x13:
          op_name = "LL_PING_RSP";
          break;
        case 0x14:
          op_name = "LL_LENGTH_REQ";
          break;
        case 0x15:
          op_name = "LL_LENGTH_RSP";
          break;
        case 0x16:
          op_name = "LL_PHY_REQ";
          break;
        case 0x17:
          op_name = "LL_PHY_RSP";
          break;
        case 0x18:
          op_name = "LL_PHY_UPDATE_IND";
          break;
        case 0x19:
          op_name = "LL_MIN_USED_CHANNELS_IND";
          break;
        case 0x1A:
          op_name = "LL_CTE_REQ";
          break;
        case 0x1B:
          op_name = "LL_CTE_RSP";
          break;
        case 0x24:
          op_name = "LL_CS_CAPABILITIES_REQ";
          break;
        case 0x25:
          op_name = "LL_CS_CAPABILITIES_RSP";
          break;
        case 0x2A:
          op_name = "LL_CS_REQ";
          break;
        case 0x2B:
          op_name = "LL_CS_RSP";
          break;
        case 0x2C:
          op_name = "LL_CS_IND";
          break;
        case 0x2E:
          op_name = "LL_CS_FAA_IND";
          break;
        }

        fprintf(stderr,
                "\033[1;32m[wch bus=%d addr=%d] * Control Opcode Captured: %s "
                "(0x%02X) on ch%d\033[0m\n",
                dev ? dev->bus : -1, dev ? dev->addr : -1, op_name, opcode,
                hdr->channel_index);
      }
    }
  }

  pcap_write_packet(hdr, pdu, pdu_len);
}

/* ── MAC address parsing ───────────────────────────────────────────────────
 */

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
          "  -debuglog LOG Write raw unfiltered packets to LOG file\n"
          "  -h            Show this help\n"
          "\n"
          "Capture stops on SIGINT (Ctrl+C) or SIGTERM.\n",
          prog);
}

/* ── main ──────────────────────────────────────────────────────────────────
 */

int main(int argc, char *argv[]) {
  fprintf(stderr, "\n"
                  "WCH BLE Analyzer PRO macOS Capture tool\n"
                  "Author: Jadkorr (https://x.com/jadkorr)\n"
                  "Based on original research and Linux reversing by Xecaz\n"
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
    } else if (strcmp(argv[i], "-debuglog") == 0) {
      if (i + 1 < argc) {
        g_debuglog_file = fopen(argv[i + 1], "w");
        if (!g_debuglog_file) {
          fprintf(stderr, "Error opening debuglog file %s: %s\n", argv[i + 1],
                  strerror(errno));
          return 1;
        }
        for (int j = i; j < argc - 2; j++)
          argv[j] = argv[j + 2];
        argc -= 2;
        i--;
      } else {
        fprintf(stderr, "Error: -debuglog requires a file name.\n");
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

  /* Expose device array to the hop thread BEFORE entering the main loop */
  g_devs_ptr = devs;
  g_ndevs = ndev;

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

    /* Phase 1: drain all MCUs round-robin until their buffers are empty */
    do {
      any_data = false;
      for (int i = 0; i < ndev && !g_stop; i++) {
        if (!devs[i].is_open || !bufs[i])
          continue;
        struct cb_ctx cctx = {&devs[i], devs, ndev, &cfg};
        int n = wch_read_packets(&devs[i], bufs[i], on_packet, &cctx,
                                 DRAIN_POLL_MS);
        if (n > 0) {
          any_data = true;
        }
      }
    } while (any_data && !g_stop);

    /* After draining all MCUs, check if a CONNECT_IND was detected.
     * Reconfig all MCUs here (outside any bulk_read context) so USB
     * access is safe and not re-entrant. */
    if (g_need_reconfig && !g_stop) {
      g_need_reconfig = false;
      if (!g_following) {
        /* Only retune from main loop when no hop thread is running.
         * When g_following is true the pthread manages all retunes. */
        fprintf(stderr,
                "[wch] Reconfiguring all MCUs for connection follow...\n");
        for (int i = 0; i < ndev; i++) {
          if (!devs[i].is_open)
            continue;
          wch_reconfig_capture(&devs[i], &g_active_cfg);
        }
      }
    }

    /* Phase 2: when all MCUs are idle, do a longer blocking wait
     * on each MCU to reduce CPU usage until traffic resumes. */
    if (!any_data && !g_stop) {
      for (int i = 0; i < ndev && !g_stop; i++) {
        if (!devs[i].is_open || !bufs[i])
          continue;
        struct cb_ctx cctx = {&devs[i], devs, ndev, &cfg};
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
