// ap_wiiu.cpp — devourer impersonating a Wii U console's GamePad AP, so a real
// Wii U GamePad associates to THIS PC instead of its console (toward Cemu use).
// Forked from tests/ap_wpa2.cpp (the completed WPA2-PSK AP: beacon -> probe ->
// auth -> assoc -> 4-way -> CCMP data). Only the Wii-U-specific deltas are new:
//
//   1. Identity = the real console. BSSID, PSK and SSID come from the Vanilla
//      capture (secrets/vanilla-config.xml), NOT hardcoded. SSID is hidden in
//      the beacon (16 zero bytes, matching the console) and answered in full to
//      the GamePad's directed probe. The GamePad scans 5 GHz channels; channel
//      161 was validated with the real console switched off.
//
//   2. The PSK is 64 hex chars = the raw 256-bit PMK. It is decoded straight to
//      the PMK; PBKDF2 is NOT run (that is only for ASCII passphrases). This is
//      the single most important correctness fix vs. ap_wpa2.cpp.
//
//   3. THE Wii U QUIRK: the PTK is rotated left by 3 bytes (first 3 bytes moved
//      to the end). Standard WPA2 up to PTK derivation, then the rotation.
//      Full-PTK rotation is confirmed by the real GamePad handshake and data,
//      and by Vanilla's drc-hostap wpa_pmk_to_ptk patch. DEVOURER_WIIU_ROT:
//        ptk3 (default) — rotate the whole 48-byte PTK, so KCK (EAPOL MIC),
//                         KEK (msg3 key wrap) AND TK (CCMP) all shift. Correct
//                         on the tested GamePad (use this).
//        tk3            — standard handshake keys, rotate ONLY the 16-byte CCMP
//                         TK. Correct IF the GamePad's EAPOL MICs are standard
//                         and only the data-plane key is mangled.
//        off            — no rotation (plain WPA2; sanity/control).
//      A failed MIC alone does not identify the cause: also check the current
//      session, declared EAPOL length, QoS AAD/nonce, and trailing adapter FCS.
//
//   4. Nintendo cipher-suite OUI a4:c0:e1 in the RSN IE (vs standard 00:0f:ac),
//      in BOTH the beacon/probe/assoc AND msg3 key data. DEVOURER_WIIU_STD_OUI=1
//      falls back to 00:0f:ac to test whether the GamePad actually cares.
//
//   5. Console-shaped IE tail (hidden SSID, OFDM-only rates, TIM, RSN, HT Cap,
//      HT Operation with the primary channel, Broadcom + WMM vendor IEs). The
//      HT/vendor bytes are RECONSTRUCTED from the partial capture; if the
//      GamePad is picky, drop the exact captured IE tail (everything after the
//      capability field of the console's beacon) into secrets/wiiu-ie-tail.hex
//      (hex, whitespace ok) and it is used verbatim for the beacon.
//
// DHCP/ARP run in-process; HID reports feed a loopback DSU endpoint for Cemu.
// Video/audio and calibrated motion are not implemented. See docs/wiiu-gamepad.md.
// Build:
//   cmake --build build --config Release --target ap_wiiu
// Run (Developer PowerShell, VM powered off so the Alfa is free):
//   $env:DEVOURER_VID="0x0bda"; $env:DEVOURER_PID="0x8812"
//   $env:DEVOURER_CHANNEL="161"
//   $env:DEVOURER_TX_WITH_RX="thread"; $env:DEVOURER_BCN_TU="25"
//   build\Release\ap_wiiu.exe 120
// Passive scan: build\Release\ap_wiiu.exe --scan 30
#include "wiiu_dsu.h"
#include "wiiu_stream.h"
#ifdef _WIN32
#include <mmsystem.h>
#endif
#include <atomic>
#include <array>
#include <chrono>
#include <csignal>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <libusb.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "RadiotapBuilder.h"
#include "RxPacket.h"
#include "SelectedChannel.h"
#include "TxMode.h"
#include "UsbOpen.h"
#include "WiFiDriver.h"
#include "env_config.h"
#include "logger.h"
#include "sta/Ccmp.h"
#include "ccmp_software.h"
#include "ccmp_kernel_vectors.h"
#include "openssl_crypto_ops.h"
#include "wiiu_network.h"

// ---- identity (filled from secrets/vanilla-config.xml at startup) ----------
static uint8_t g_bssid[6];
static std::string g_ssid;              // e.g. "WiiU9ce6353e4cd1"
static uint8_t g_pmk[32];               // the 256-bit PMK (decoded from the PSK)
static uint8_t g_chan = 157;

enum RotMode { ROT_OFF, ROT_TK3, ROT_PTK3 };
static RotMode g_rot = ROT_PTK3;
static bool g_std_oui = false;          // true -> standard 00:0f:ac instead of Nintendo
static std::vector<uint8_t> g_ie_override;  // exact captured IE tail for the beacon, if provided
static bool g_scan = false;
static std::atomic<unsigned> g_probe_count{0};
static volatile std::sig_atomic_t g_stop = 0;

static IRadio* g_dev = nullptr;
static std::vector<uint8_t> g_rt;
static std::vector<uint8_t> g_data_rt;
static std::atomic<uint64_t> g_sent{0};
static std::mutex g_q_mu;
static std::recursive_mutex g_session_mu;
static uint32_t g_epoch = 0;
static bool g_enable_video = false, g_hid_seen = false;
struct PendingFrame { std::vector<uint8_t> bytes; uint32_t epoch; bool encrypted; };
static std::vector<PendingFrame> g_q;
static std::atomic<uint64_t> g_queue_drops{0};

// ---- hex helpers -----------------------------------------------------------
static int hexval(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  c |= 0x20;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}
// Decode all hex digits in s (ignoring any non-hex: colons, spaces, newlines).
static std::vector<uint8_t> hex_decode(const std::string& s) {
  std::vector<uint8_t> out; int hi = -1;
  for (char ch : s) {
    int v = hexval((unsigned char)ch);
    if (v < 0) continue;
    if (hi < 0) hi = v; else { out.push_back((uint8_t)((hi << 4) | v)); hi = -1; }
  }
  return out;
}
static std::string extract_tag(const std::string& xml, const char* tag) {
  std::string open = std::string("<") + tag + ">", close = std::string("</") + tag + ">";
  size_t a = xml.find(open); if (a == std::string::npos) return "";
  a += open.size();
  size_t b = xml.find(close, a); if (b == std::string::npos) return "";
  return xml.substr(a, b - a);
}

// ---- RSN IE (Nintendo a4:c0:e1 by default; GTK KDE selector stays standard) -
static std::vector<uint8_t> rsn_ie() {
  const uint8_t ninten[3] = {0xa4, 0xc0, 0xe1};
  const uint8_t standrd[3] = {0x00, 0x0f, 0xac};
  const uint8_t* oui = g_std_oui ? standrd : ninten;
  std::vector<uint8_t> r = {0x30, 0x14, 0x01, 0x00};        // tag, len 20, version 1
  r.insert(r.end(), {oui[0], oui[1], oui[2], 0x04});        // group = CCMP
  r.insert(r.end(), {0x01, 0x00, oui[0], oui[1], oui[2], 0x04});   // 1 pairwise = CCMP
  r.insert(r.end(), {0x01, 0x00, oui[0], oui[1], oui[2], 0x02});   // 1 akm = PSK
  r.insert(r.end(), {0x00, 0x00});                          // RSN capabilities
  return r;
}

// ---- console-shaped IE builders --------------------------------------------
static void emit_rates(std::vector<uint8_t>& m) {   // 5 GHz OFDM: 6,9,12,18,24,36,48,54
  m.insert(m.end(), {0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c});
}
static void emit_tim(std::vector<uint8_t>& m) {     // matches the console capture
  m.insert(m.end(), {0x05, 0x04, 0x02, 0x03, 0x00, 0x00});
}
// HT Capabilities (tag 0x2d, len 26). Reconstructed single-stream HT20; the
// capture prefix was 2d 1a 1c 00 19 ff. MCS set = MCS0-7 (one spatial stream).
static void emit_htcap(std::vector<uint8_t>& m) {
  m.insert(m.end(), {0x2d, 0x1a,
      0x1c, 0x00,                 // HT Cap Info (HT20, as captured)
      0x19,                       // A-MPDU params
      0xff, 0x00, 0x00, 0x00,     // Supported MCS: MCS0-7
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00,                 // HT Extended Cap
      0x00, 0x00, 0x00, 0x00,     // TxBF
      0x00});                     // ASEL
}
// HT Operation (tag 0x3d, len 22). Primary channel = g_chan; 20 MHz. Capture
// was 3d 16 9d 08 (9d = 157 primary). Basic MCS set left zero.
static void emit_htop(std::vector<uint8_t>& m) {
  m.insert(m.end(), {0x3d, 0x16, g_chan, 0x08, 0x00, 0x00, 0x00, 0x00});
  for (int i = 0; i < 16; ++i) m.push_back(0x00);   // basic MCS set
}
static void emit_vendors(std::vector<uint8_t>& m) {
  // Broadcom (dd09 00:10:18 ...) and WMM/Microsoft (dd18 00:50:f2 02 ...),
  // reconstructed; harmless to a station and present so the IE profile matches.
  m.insert(m.end(), {0xdd, 0x09, 0x00, 0x10, 0x18, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00});
  m.insert(m.end(), {0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01,
      0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00,
      0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00});
}
// SSID IE: hidden form in the beacon (16 zero bytes, as the console sends),
// real name everywhere the GamePad expects to see it answered (probe resp).
static void emit_ssid(std::vector<uint8_t>& m, bool hidden) {
  if (hidden) { m.push_back(0x00); m.push_back(0x10);
    for (int i = 0; i < 16; ++i) m.push_back(0x00); }
  else { m.push_back(0x00); m.push_back((uint8_t)g_ssid.size());
    m.insert(m.end(), g_ssid.begin(), g_ssid.end()); }
}

static void enqueue(std::vector<uint8_t> mpdu, bool encrypted = false) {
  const auto& rt = encrypted && !g_data_rt.empty() ? g_data_rt : g_rt;
  std::vector<uint8_t> f; f.reserve(rt.size() + mpdu.size());
  f.insert(f.end(), rt.begin(), rt.end());
  f.insert(f.end(), mpdu.begin(), mpdu.end());
  std::lock_guard<std::mutex> lk(g_q_mu);
  if (g_q.size() < 2048) g_q.push_back({std::move(f), g_epoch, encrypted});
  else g_queue_drops.fetch_add(1);
}
static std::vector<uint8_t> mgmt_hdr(uint8_t fc, const uint8_t* sta) {
  return {fc, 0, 0, 0, sta[0],sta[1],sta[2],sta[3],sta[4],sta[5],
      g_bssid[0],g_bssid[1],g_bssid[2],g_bssid[3],g_bssid[4],g_bssid[5],
      g_bssid[0],g_bssid[1],g_bssid[2],g_bssid[3],g_bssid[4],g_bssid[5], 0,0};
}

// ---- 4-way state -----------------------------------------------------------
static uint8_t g_anonce[32], g_snonce[32], g_ptk[48], g_tk[16], g_gtk[16];
static uint8_t g_replay[8];
static uint8_t g_sta[6];
static int g_state = 0;  // 0 idle, 1 sent msg1, 2 keyed
static std::atomic<uint64_t> g_decok{0}, g_decfail{0};
static devourer::test::OpenSslCryptoOps g_crypto;
static wiiu::Network g_network;
static wiiu::DsuEndpoint g_dsu;
static wiiu::DrcStream g_stream;
static wiiu::VideoIngress g_video_ingress;
static uint64_t g_txpn = 1;
static uint16_t g_data_seq = 0;

// ---- WPA2 crypto (openssl) -------------------------------------------------
static void prf(const uint8_t* key, int klen, const char* label,
                const uint8_t* data, int dlen, uint8_t* out, int olen) {
  int ll = (int)strlen(label);
  for (int i = 0, gen = 0; gen < olen; ++i, gen += 20) {
    std::vector<uint8_t> b(ll + 1 + dlen + 1);
    memcpy(b.data(), label, ll); b[ll] = 0;
    memcpy(b.data()+ll+1, data, dlen); b[ll+1+dlen] = (uint8_t)i;
    unsigned int l; uint8_t d[20];
    HMAC(EVP_sha1(), key, klen, b.data(), b.size(), d, &l);
    int c = (olen-gen < 20) ? olen-gen : 20; memcpy(out+gen, d, c);
  }
}
static void rotl3(uint8_t* p, int n) {   // first 3 bytes -> end; rest shift down
  uint8_t t[3] = {p[0], p[1], p[2]};
  memmove(p, p + 3, n - 3);
  p[n-3] = t[0]; p[n-2] = t[1]; p[n-1] = t[2];
}
static void compute_ptk() {
  const uint8_t *aa = g_bssid, *sa = g_sta;
  uint8_t b[76]; int p = 0;
  const uint8_t* mn = memcmp(aa,sa,6) < 0 ? aa : sa;
  const uint8_t* mx = memcmp(aa,sa,6) < 0 ? sa : aa;
  memcpy(b+p, mn, 6); p+=6; memcpy(b+p, mx, 6); p+=6;
  const uint8_t* nn = memcmp(g_anonce,g_snonce,32) < 0 ? g_anonce : g_snonce;
  const uint8_t* nx = memcmp(g_anonce,g_snonce,32) < 0 ? g_snonce : g_anonce;
  memcpy(b+p, nn, 32); p+=32; memcpy(b+p, nx, 32); p+=32;
  prf(g_pmk, 32, "Pairwise key expansion", b, p, g_ptk, 48);   // PMK used directly
  // Wii U rotation. ptk3 rotates the whole PTK (KCK/KEK/TK shift); tk3 rotates
  // only the CCMP TK; off leaves everything standard.
  if (g_rot == ROT_PTK3) rotl3(g_ptk, 48);
  memcpy(g_tk, g_ptk + 32, 16);
  if (g_rot == ROT_TK3) rotl3(g_tk, 16);
}
static void set_mic(std::vector<uint8_t>& e) {       // KCK = g_ptk[0..15]
  memset(e.data()+81, 0, 16);
  unsigned int l; uint8_t d[20];
  HMAC(EVP_sha1(), g_ptk, 16, e.data(), e.size(), d, &l);
  memcpy(e.data()+81, d, 16);
}
static bool check_mic(const uint8_t* e, int len) {
  std::vector<uint8_t> t(e, e+len);
  uint8_t got[16]; memcpy(got, t.data()+81, 16);
  memset(t.data()+81, 0, 16);
  unsigned int l; uint8_t d[20];
  HMAC(EVP_sha1(), g_ptk, 16, t.data(), t.size(), d, &l);
  return memcmp(got, d, 16) == 0;
}
static int aes_wrap(const uint8_t* kek, const uint8_t* in, int inlen, uint8_t* out) {
  EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_set_flags(c, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
  EVP_EncryptInit_ex(c, EVP_aes_128_wrap(), NULL, kek, NULL);
  int ol = 0, tmp = 0;
  EVP_EncryptUpdate(c, out, &ol, in, inlen);
  EVP_EncryptFinal_ex(c, out+ol, &tmp); ol += tmp;
  EVP_CIPHER_CTX_free(c);
  return ol;
}
static std::vector<uint8_t> eapol_frame(uint16_t keyinfo, const uint8_t* nonce,
                                        const uint8_t* keydata, int kdlen, bool mic) {
  std::vector<uint8_t> e(99, 0);
  e[0]=2; e[1]=3;
  int blen = 95 + kdlen; e[2]=blen>>8; e[3]=blen&0xff;
  e[4]=2;
  e[5]=keyinfo>>8; e[6]=keyinfo&0xff;
  e[7]=0; e[8]=16;
  memcpy(e.data()+9, g_replay, 8);
  if (nonce) memcpy(e.data()+17, nonce, 32);
  e[97]=kdlen>>8; e[98]=kdlen&0xff;
  if (keydata && kdlen) e.insert(e.end(), keydata, keydata+kdlen);
  if (mic) set_mic(e);
  std::vector<uint8_t> m = {0x08,0x02,0,0,
      g_sta[0],g_sta[1],g_sta[2],g_sta[3],g_sta[4],g_sta[5],
      g_bssid[0],g_bssid[1],g_bssid[2],g_bssid[3],g_bssid[4],g_bssid[5],
      g_bssid[0],g_bssid[1],g_bssid[2],g_bssid[3],g_bssid[4],g_bssid[5], 0,0,
      0xaa,0xaa,0x03,0x00,0x00,0x00, 0x88,0x8e};
  m.insert(m.end(), e.begin(), e.end());
  return m;
}
static void send_msg1() {
  ++g_epoch; g_hid_seen = false; g_stream.reset(); g_video_ingress.reset_session();
  g_txpn = 1; // fresh ANonce derives a fresh key; never reset on msg4 retries
  RAND_bytes(g_anonce, 32);
  for (int i=7;i>=0;--i) if (++g_replay[i]) break;
  enqueue(eapol_frame(0x008a, g_anonce, nullptr, 0, false));
  g_state = 1;
  fprintf(stderr, "  WPA2: sent msg1 (ANonce) to %02x:%02x:%02x:%02x:%02x:%02x\n",
          g_sta[0],g_sta[1],g_sta[2],g_sta[3],g_sta[4],g_sta[5]);
}
static void send_msg3() {
  RAND_bytes(g_gtk, 16);
  std::vector<uint8_t> rsn = rsn_ie();
  std::vector<uint8_t> kd(rsn.begin(), rsn.end());              // RSN IE (Nintendo OUI)
  uint8_t gtkkde[24] = {0xdd,0x16,0x00,0x0f,0xac,0x01,0x01,0x00};  // GTK KDE selector
  memcpy(gtkkde+8, g_gtk, 16);
  kd.insert(kd.end(), gtkkde, gtkkde+24);
  if (kd.size() % 8) { kd.push_back(0xdd); while (kd.size() % 8) kd.push_back(0x00); }
  std::vector<uint8_t> wrapped(kd.size()+8);
  int wl = aes_wrap(g_ptk+16, kd.data(), kd.size(), wrapped.data());   // KEK = g_ptk[16..31]
  for (int i=7;i>=0;--i) if (++g_replay[i]) break;
  enqueue(eapol_frame(0x13ca, g_anonce, wrapped.data(), wl, true));
  fprintf(stderr, "  WPA2: sent msg3 (GTK, MIC) — 4-way in progress\n");
}

// ---- CCMP (software AES-CCM), TK = g_tk -------------------------------------
static bool ccm(bool enc, const uint8_t* key, const uint8_t* nonce, const uint8_t* aad,
                int aadlen, const uint8_t* in, int inlen, uint8_t* out, uint8_t* tag) {
  return devourer::test::ccmp_software(enc, key, nonce, aad, aadlen,
                                      in, inlen, out, tag);
}

static void send_plain(uint16_t eth, const std::vector<uint8_t>& payload) {
  std::lock_guard<std::recursive_mutex> session(g_session_mu);
  if (g_state != 2) return;
  std::vector<uint8_t> plain = {0xaa,0xaa,3,0,0,0,uint8_t(eth >> 8),uint8_t(eth)};
  plain.insert(plain.end(), payload.begin(), payload.end());
  auto hdr = mgmt_hdr(0x08, g_sta); hdr[1] = 0x42;
  const uint16_t seq = uint16_t((g_data_seq++ & 4095) << 4);
  hdr[22] = uint8_t(seq); hdr[23] = uint8_t(seq >> 8);
  std::vector<uint8_t> frame(devourer::sta::ccmp_encrypted_len(hdr.size(), plain.size()));
  if (devourer::sta::ccmp_encrypt(g_crypto, g_tk, hdr.data(), hdr.size(), g_bssid,
                                 g_txpn++, 0, plain.data(), plain.size(),
                                 frame.data(), frame.size()))
    enqueue(std::move(frame), true);
}
static void send_udp(uint16_t source, uint16_t dest, const std::vector<uint8_t>& data) {
  send_plain(0x0800, wiiu::udp_packet(source, dest, data));
}

static void handle_plain(const std::vector<uint8_t>& plain) {
  auto offers = g_network.offers, acks = g_network.acks, arps = g_network.arps;
  g_network.receive(g_bssid, g_sta, plain.data(), plain.size(), send_plain,
    [](uint16_t sport, uint16_t dport, const uint8_t* hid, size_t n) {
      if (sport == 50122 && dport == 50022 && n == 128) {
        g_dsu.update(hid, n, g_sta); g_hid_seen = true;
      }
      if (g_enable_video) g_stream.receive(sport, dport, hid, n, send_udp);
      if (g_network.udp_packets <= 16)
        fprintf(stderr, "  GamePad UDP %u -> %u, %zu bytes\n", sport, dport, n);
    });
  if (g_network.offers != offers) fprintf(stderr, "  DHCP OFFER: 192.168.1.11\n");
  if (g_network.acks != acks) fprintf(stderr, "  DHCP ACK: GamePad leased 192.168.1.11\n");
  if (g_network.arps != arps) fprintf(stderr, "  ARP reply: console is 192.168.1.10\n");
}

static void on_rx(const Packet& raw) {
  std::lock_guard<std::recursive_mutex> session(g_session_mu);
  Packet p = raw;
  if (p.RxAtrib.fcs_present) {
    if (p.Data.size() < 4) return;
    p.Data = p.Data.first(p.Data.size() - 4);
  }
  if (p.Data.size() < 24 || p.RxAtrib.crc_err) return;
  const uint8_t fc0 = p.Data[0], fc1 = p.Data[1];
  const uint8_t* a1 = p.Data.data() + 4;
  const uint8_t* sta = p.Data.data() + 10;
  bool to_us = std::memcmp(a1, g_bssid, 6) == 0;
  bool bcast = (a1[0] & 0x01) != 0;

  if (g_scan) {
    if (fc0 != 0x40) return;
    size_t off = 24;
    while (off + 2 <= p.Data.size()) {
      const size_t n = p.Data[off + 1];
      if (off + 2 + n > p.Data.size()) break;
      if (p.Data[off] == 0 && n == g_ssid.size() &&
          memcmp(p.Data.data() + off + 2, g_ssid.data(), n) == 0) {
        g_probe_count.fetch_add(1);
        fprintf(stderr, "SCAN: GamePad probe on ch%u from "
                        "%02x:%02x:%02x:%02x:%02x:%02x for '%s'\n",
                g_dev->GetSelectedChannel().Channel,
                sta[0],sta[1],sta[2],sta[3],sta[4],sta[5],g_ssid.c_str());
      }
      off += 2 + n;
    }
    return;
  }

  if (fc0 == 0x40) {                                   // probe-req
    if (!bcast && !to_us) return;
    auto m = mgmt_hdr(0x50, sta);
    m.insert(m.end(), {0,0,0,0,0,0,0,0, 0x64,0x00, 0x11,0x00});  // ts, bcn int, cap ESS+Privacy
    emit_ssid(m, false);                               // answer with the real SSID
    emit_rates(m); emit_htcap(m); emit_htop(m);
    { auto r = rsn_ie(); m.insert(m.end(), r.begin(), r.end()); }
    emit_vendors(m);
    enqueue(std::move(m));
  } else if (fc0 == 0xb0 && to_us) {                   // auth (open)
    auto m = mgmt_hdr(0xb0, sta);
    m.insert(m.end(), {0,0, 0x02,0x00, 0,0}); enqueue(std::move(m));
    fprintf(stderr, "  AUTH from %02x:%02x:%02x:%02x:%02x:%02x\n",
            sta[0],sta[1],sta[2],sta[3],sta[4],sta[5]);
  } else if ((fc0 == 0x00 || fc0 == 0x20) && to_us) {  // (re)assoc
    auto m = mgmt_hdr(fc0 == 0x20 ? 0x30 : 0x10, sta);
    m.insert(m.end(), {0x11,0x00, 0x00,0x00, 0x01,0xc0});   // cap, status 0, AID 1
    emit_rates(m); emit_htcap(m); emit_htop(m);
    { auto r = rsn_ie(); m.insert(m.end(), r.begin(), r.end()); }
    emit_vendors(m);
    enqueue(std::move(m));
    memcpy(g_sta, sta, 6); memset(g_replay, 0, 8); g_state = 0;
    fprintf(stderr, "  ASSOC from %02x:%02x:%02x:%02x:%02x:%02x -> start 4-way\n",
            sta[0],sta[1],sta[2],sta[3],sta[4],sta[5]);
    send_msg1();
  } else if ((fc0 == 0x08 || fc0 == 0x88) && (fc1 & 0x01) && to_us) {  // data to-DS
    if ((fc1 & 0x03) != 0x01 || memcmp(sta, g_sta, 6) != 0) return;
    int hlen = (int)devourer::sta::data_hdr_len(fc0, fc1);
    if ((fc1 & 0x40) && g_state == 2) {                // PROTECTED (CCMP) data
      int len = (int)p.Data.size();
      if (len < hlen + 8 + 8) return;
      const uint8_t* d = p.Data.data();
      const uint8_t* cc = d + hlen;
      if (!(cc[3] & 0x20) || devourer::sta::ccmp_key_id(cc) != 0) return;
      uint64_t pn = devourer::sta::ccmp_header_pn(cc);
      int ctlen = len - hlen - 8 - 8;
      const uint8_t* ct = d + hlen + 8; const uint8_t* mic = ct + ctlen;
      uint8_t aad[32], nonce[13], tag[8]; int aadlen;
      aadlen = (int)devourer::sta::ccmp_aad(d, hlen, aad);
      if (!aadlen || !devourer::sta::ccmp_nonce(d, hlen, sta, pn, nonce)) return;
      memcpy(tag, mic, 8);
      std::vector<uint8_t> pt(ctlen);
      if (ccm(false, g_tk, nonce, aad, aadlen, ct, ctlen, pt.data(), tag)) {
        uint64_t n = g_decok.fetch_add(1);
        if (n < 8) {
          uint16_t eth = ctlen >= 8 ? (pt[6]<<8)|pt[7] : 0;
          fprintf(stderr, "  DECRYPT OK from GamePad — rotation '%s' is correct. "
                          "ethertype=0x%04x ctlen=%d first=%02x%02x%02x%02x\n",
                  g_rot==ROT_PTK3?"ptk3":g_rot==ROT_TK3?"tk3":"off", eth, ctlen,
                  ctlen>0?pt[0]:0, ctlen>1?pt[1]:0, ctlen>2?pt[2]:0, ctlen>3?pt[3]:0);
        }
        handle_plain(pt);
      } else {
        uint64_t n = g_decfail.fetch_add(1);
        if (n < 4)
          fprintf(stderr, "  decrypt FAIL (CCMP MIC; check session, framing or TK, rot='%s') pn=%llu\n",
                  g_rot==ROT_PTK3?"ptk3":g_rot==ROT_TK3?"tk3":"off",
                  (unsigned long long)pn);
      }
      return;
    }
    if ((int)p.Data.size() < hlen + 8) return;
    const uint8_t* llc = p.Data.data() + hlen;
    if (!(llc[0]==0xaa && llc[6]==0x88 && llc[7]==0x8e)) return;  // EAPOL only
    const uint8_t* e = llc + 8; int elen = (int)p.Data.size() - (hlen + 8);
    if (elen < 99 || e[1] != 3) return;
    const int declared_len = 4 + ((e[2] << 8) | e[3]);
    if (declared_len < 99 || declared_len > elen ||
        99 + ((e[97] << 8) | e[98]) != declared_len) return;
    elen = declared_len;  // trailing 802.11 padding is not part of the MIC
    uint16_t ki = (e[5]<<8) | e[6];
    if ((ki & 0x0008) && (ki & 0x0100) && !(ki & 0x0040) && !(ki & 0x0200)) {   // msg2
      memcpy(g_snonce, e+17, 32);
      compute_ptk();
      if (!check_mic(e, elen)) {
        fprintf(stderr, "  WPA2: msg2 MIC FAIL (rotation '%s'; check credentials, "
                        "session and EAPOL framing before changing rotation)\n",
                g_rot==ROT_PTK3?"ptk3":g_rot==ROT_TK3?"tk3":"off");
        return;
      }
      fprintf(stderr, "  WPA2: msg2 OK (SNonce, MIC verified) — PTK derived\n");
      send_msg3();
    } else if ((ki & 0x0100) && (ki & 0x0200)) {       // msg4
      if (check_mic(e, elen)) {
        g_state = 2;
        fprintf(stderr, "  WPA2: msg4 OK — 4-WAY HANDSHAKE COMPLETE (GamePad keyed). "
                        "Now watching for an encrypted GamePad frame...\n");
      }
    }
  }
}

// Verify the actual receive path against frames encrypted by Linux, including
// every QoS TID. A local encrypt/decrypt round trip would miss shared errors.
static int self_test() {
  int failures = 0;
  auto require = [&](bool ok, const char* name) {
    if (!ok) { fprintf(stderr, "FAIL: %s\n", name); ++failures; }
  };
  memcpy(g_tk, devourer::test::kKernelTk, 16);
  g_state = 2;
  for (const auto& v : devourer::test::kKernelCcmpVectors) {
    const auto* d = v.mpdu;
    const int n = (int)(v.mpdu_len - v.hdr_len - 16);
    uint8_t aad[32], nonce[13], tag[8];
    int alen = (int)devourer::sta::ccmp_aad(d, v.hdr_len, aad);
    const uint64_t pn = devourer::sta::ccmp_header_pn(d + v.hdr_len);
    require(devourer::sta::ccmp_nonce(d, v.hdr_len, d + 10, pn, nonce), v.name);
    memcpy(tag, d + v.mpdu_len - 8, 8);
    std::vector<uint8_t> plain(n);
    require(ccm(false, g_tk, nonce, aad, alen, d + v.hdr_len + 8,
                n, plain.data(), tag), v.name);
    tag[0] ^= 1;
    require(!ccm(false, g_tk, nonce, aad, alen, d + v.hdr_len + 8,
                 n, plain.data(), tag), "corrupt CCMP MIC rejected");
    if ((d[1] & 3) == 1) {
      memcpy(g_bssid, d + 4, 6); memcpy(g_sta, d + 10, 6);
      std::vector<uint8_t> frame(d, d + v.mpdu_len);
      Packet p{};
      p.RxAtrib.fcs_present = false;
      p.Data = frame;
      auto before = g_decok.load();
      on_rx(p);
      require(g_decok.load() == before + 1, v.name);
      frame.insert(frame.end(), {0x12, 0x34, 0x56, 0x78});
      p.Data = frame;
      p.RxAtrib.fcs_present = true;
      before = g_decok.load();
      on_rx(p);
      require(g_decok.load() == before + 1, "receive path strips adapter FCS");
      frame.resize(frame.size() - 4);
      p.Data = frame;
      p.RxAtrib.fcs_present = false;
      p.Data.back() ^= 1;
      before = g_decfail.load();
      on_rx(p);
      require(g_decfail.load() == before + 1, "receive path rejects corrupt MIC");
      p.Data = p.Data.first(24);
      before = g_decok.load();
      on_rx(p);
      require(g_decok.load() == before, "truncated QoS frame ignored");
    }
  }
  std::vector<uint8_t> ies;
  g_ssid = "WiiU001122334455";
  emit_ssid(ies, true); emit_rates(ies); emit_tim(ies);
  auto rsn = rsn_ie(); ies.insert(ies.end(), rsn.begin(), rsn.end());
  emit_htcap(ies); emit_htop(ies); emit_vendors(ies);
  size_t pos = 0;
  while (pos + 2 <= ies.size() && pos + 2 + ies[pos + 1] <= ies.size())
    pos += 2 + ies[pos + 1];
  require(pos == ies.size(), "beacon IE lengths consume the exact tail");
  require(wiiu::crc32(reinterpret_cast<const uint8_t*>("123456789"), 9) == 0xcbf43926,
          "DSU CRC32 independent known answer");
  std::array<uint8_t,128> hid{};
  for (int i = 0; i < 4; ++i) wiiu::put_le(hid.data() + 6 + 2*i, 2050, 2);
  hid[2] = 0x80; // GamePad A -> DSU Circle
  auto dsu = wiiu::dsu_packet(0x100002, 100);
  wiiu::encode_dsu_input(dsu, hid.data());
  require(dsu[37] == 32 && dsu[50] == 255 && dsu[40] == 128 && dsu[41] == 128,
          "DSU A button and neutral sticks");
  wiiu::put_le(hid.data() + 6, 3200, 2);
  wiiu::put_le(hid.data() + 8, 900, 2);
  dsu = wiiu::dsu_packet(0x100002, 100); wiiu::encode_dsu_input(dsu, hid.data());
  require(dsu[40] == 255 && dsu[41] == 1, "DSU stick limits");
  for (int i = 0; i < 10; ++i) {
    wiiu::put_le(hid.data() + 36 + 4*i, 195, 2);
    wiiu::put_le(hid.data() + 38 + 4*i, 3818, 2);
  }
  hid[37] |= 0x10;
  dsu = wiiu::dsu_packet(0x100002, 100); wiiu::encode_dsu_input(dsu, hid.data());
  require(dsu[39] == 1 && dsu[56] == 1 && dsu[58] == 45 && dsu[60] == 39,
          "DSU touch calibration and contact");
  wiiu::Network net;
  const uint8_t ap[6] = {2,0,0,0,0,1}, sta[6] = {2,0,0,0,0,2};
  std::vector<uint8_t> request(8 + 28 + 244, 0);
  memcpy(request.data(), "\xaa\xaa\x03\x00\x00\x00\x08\x00", 8);
  auto* ip = request.data() + 8;
  ip[0] = 0x45; ip[8] = 64; ip[9] = 17;
  wiiu::put16(ip + 2, uint16_t(request.size() - 8));
  memset(ip + 16, 255, 4);
  wiiu::put16(ip + 10, wiiu::checksum(ip, 20));
  wiiu::put16(ip + 20, 68); wiiu::put16(ip + 22, 67);
  wiiu::put16(ip + 24, 8 + 244);
  auto* dh = ip + 28;
  dh[0] = 1; dh[1] = 1; dh[2] = 6;
  dh[4] = 0x12; dh[5] = 0x34; dh[6] = 0x56; dh[7] = 0x78;
  memcpy(dh + 28, sta, 6);
  const uint8_t options[] = {99,130,83,99,53,1,1,255};
  memcpy(dh + 236, options, sizeof options);
  std::vector<uint8_t> reply;
  auto sink = [&](uint16_t eth, const std::vector<uint8_t>& p) {
    require(eth == 0x0800, "DHCP reply ethertype"); reply = p;
  };
  auto ignore_udp = [](uint16_t, uint16_t, const uint8_t*, size_t) {};
  net.receive(ap, sta, request.data(), request.size(), sink, ignore_udp);
  require(net.offers == 1 && reply.size() >= 271, "DHCP DISCOVER produces OFFER");
  if (reply.size() >= 271) {
    require(!wiiu::checksum(reply.data(), 20), "DHCP reply IPv4 checksum");
    require(!memcmp(reply.data() + 28 + 4, dh + 4, 4), "DHCP transaction retained");
    require(!memcmp(reply.data() + 28 + 16, wiiu::gamepad_ip, 4), "GamePad lease address");
    require(reply[28 + 242] == 2, "DHCP OFFER message type");
  }
  dh[242] = 3;
  net.receive(ap, sta, request.data(), request.size(), sink, ignore_udp);
  require(net.acks == 1 && reply[28 + 242] == 5, "DHCP REQUEST produces ACK");
  dh[241] = 255; // option length extends past datagram
  net.receive(ap, sta, request.data(), request.size(), sink, ignore_udp);
  require(net.acks == 1, "malformed DHCP options ignored");
  request.resize(12);
  net.receive(ap, sta, request.data(), request.size(), sink, ignore_udp);
  require(net.acks == 1, "truncated IPv4 ignored");
  fprintf(stderr, "ap_wiiu self-test: %zu kernel CCMP vectors, QoS receive path, "
                  "FCS, corrupt/truncated frames, beacon IEs, DHCP, DSU: %s\n",
          devourer::test::kKernelCcmpVectorCount, failures ? "FAIL" : "PASS");
  return failures ? 1 : 0;
}

static bool load_identity() {
  std::string path = "secrets/vanilla-config.xml";
  if (const char* c = std::getenv("DEVOURER_WIIU_CONFIG")) path = c;
  std::string bssid_s, psk_s;
  std::ifstream f(path);
  if (f) {
    std::stringstream ss; ss << f.rdbuf(); std::string xml = ss.str();
    bssid_s = extract_tag(xml, "bssid");
    psk_s   = extract_tag(xml, "psk");
  } else {
    fprintf(stderr, "note: %s not found; falling back to DEVOURER_WIIU_* env\n", path.c_str());
  }
  if (const char* b = std::getenv("DEVOURER_WIIU_BSSID")) bssid_s = b;
  if (const char* k = std::getenv("DEVOURER_WIIU_PSK"))   psk_s = k;

  auto bb = hex_decode(bssid_s);
  if (bb.size() != 6) { fprintf(stderr, "ERROR: need a 6-byte BSSID, got %zu bytes from '%s'\n",
                                bb.size(), bssid_s.c_str()); return false; }
  memcpy(g_bssid, bb.data(), 6);
  if (g_bssid[0] & 0x01) fprintf(stderr, "WARNING: BSSID is multicast (I/G bit set) — "
                                         "a station will refuse to auth to it\n");

  // SSID = "WiiU" + bssid hex, no colons, lowercase (what the console advertises).
  char s[5+12+1]; snprintf(s, sizeof s, "WiiU%02x%02x%02x%02x%02x%02x",
      g_bssid[0],g_bssid[1],g_bssid[2],g_bssid[3],g_bssid[4],g_bssid[5]);
  g_ssid = s;
  if (const char* o = std::getenv("DEVOURER_WIIU_SSID")) g_ssid = o;

  auto pk = hex_decode(psk_s);
  if (pk.size() == 32) {                 // 64 hex chars -> the PMK, used directly
    memcpy(g_pmk, pk.data(), 32);
    fprintf(stderr, "PMK: using the 256-bit PSK directly (no PBKDF2)\n");
  } else if (!psk_s.empty()) {           // ASCII passphrase fallback
    PKCS5_PBKDF2_HMAC(psk_s.c_str(), psk_s.size(),
        (const unsigned char*)g_ssid.c_str(), g_ssid.size(), 4096, EVP_sha1(), 32, g_pmk);
    fprintf(stderr, "PMK: derived via PBKDF2 from a %zu-char passphrase (unexpected for Wii U)\n",
            psk_s.size());
  } else {
    fprintf(stderr, "ERROR: no PSK found in config or DEVOURER_WIIU_PSK\n"); return false;
  }
  return true;
}

int main(int argc, char** argv) {
  if (argc > 1 && !strcmp(argv[1], "--self-test")) return self_test();
  g_scan = argc > 1 && !strcmp(argv[1], "--scan");
  int sec = g_scan ? (argc > 2 ? atoi(argv[2]) : 30) : (argc > 1 ? atoi(argv[1]) : 60);
  if (sec < 1 || sec > 3600) { fprintf(stderr, "Duration must be 1..3600 seconds\n"); return 1; }
  std::signal(SIGINT, [](int) { g_stop = 1; });
  std::signal(SIGTERM, [](int) { g_stop = 1; });
  if (const char* c = std::getenv("DEVOURER_CHANNEL")) g_chan = (uint8_t)atoi(c);
  if (const char* r = std::getenv("DEVOURER_WIIU_ROT")) {
    if (!strcmp(r, "off")) g_rot = ROT_OFF;
    else if (!strcmp(r, "tk3")) g_rot = ROT_TK3;
    else if (!strcmp(r, "ptk3")) g_rot = ROT_PTK3;
    else fprintf(stderr, "WARNING: DEVOURER_WIIU_ROT='%s' unknown; using ptk3\n", r);
  }
  if (const char* o = std::getenv("DEVOURER_WIIU_STD_OUI")) g_std_oui = atoi(o) != 0;
  if (const char* h = std::getenv("DEVOURER_WIIU_IE_TAIL")) {   // path to exact captured tail
    std::ifstream hf(h); if (hf) { std::stringstream ss; ss << hf.rdbuf();
      g_ie_override = hex_decode(ss.str());
      fprintf(stderr, "beacon IE tail: using %zu captured bytes from %s\n", g_ie_override.size(), h); }
  }
  if (!load_identity()) return 1;
  if (const char* v = std::getenv("DEVOURER_WIIU_VIDEO")) g_enable_video = atoi(v) != 0;
  if (!g_scan && !g_dsu.start()) {
    fprintf(stderr, "ERROR: could not bind the local DSU endpoint on port 26760\n"); return 1;
  }
  if (!g_scan && g_enable_video && !g_video_ingress.start()) {
    fprintf(stderr, "ERROR: could not bind video ingress on port 26762\n"); return 1;
  }
  if (!std::getenv("DEVOURER_CHANNEL"))
    fprintf(stderr, "DEVOURER_CHANNEL unset, using %d; GamePad scans for the AP\n", g_chan);

  fprintf(stderr, "Impersonating console %02x:%02x:%02x:%02x:%02x:%02x  SSID '%s'  ch%d  "
                  "rot=%s  oui=%s\n",
          g_bssid[0],g_bssid[1],g_bssid[2],g_bssid[3],g_bssid[4],g_bssid[5],
          g_ssid.c_str(), g_chan, g_rot==ROT_PTK3?"ptk3":g_rot==ROT_TK3?"tk3":"off",
          g_std_oui?"00:0f:ac":"a4:c0:e1");

  auto logger = std::make_shared<Logger>(); apply_logging_env(*logger);
  libusb_context* ctx = nullptr; libusb_init(&ctx);
  libusb_set_option(ctx, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_WARNING);
  uint16_t vid = 0x0bda, pid = 0x8812;
  if (const char* v = std::getenv("DEVOURER_VID")) vid = (uint16_t)strtoul(v, 0, 0);
  if (const char* pp = std::getenv("DEVOURER_PID")) pid = (uint16_t)strtoul(pp, 0, 0);
  auto* h = libusb_open_device_with_vid_pid(ctx, vid, pid);
  if (!h) { fprintf(stderr, "open %04x:%04x fail\n", vid, pid); return 1; }
  std::shared_ptr<devourer::UsbDeviceLock> lk;
  if (devourer::claim_interface_then_reset(h, devourer::find_wifi_interface(h), logger, true, lk) != 0) return 1;
  WiFiDriver wifi(logger);
  auto dev = wifi.CreateRadio(h, ctx, lk, devourer_config_from_env());
  g_dev = dev.get(); if (!g_dev) return 1;
  g_rt = devourer::build_stream_radiotap(devourer::parse_tx_mode_str("6M"));
  if (g_enable_video) {
    const char* rate = std::getenv("DEVOURER_WIIU_DATA_RATE");
    const char* no_ack_env = std::getenv("DEVOURER_WIIU_NOACK");
    const bool no_ack = !no_ack_env || strcmp(no_ack_env, "0");
    g_data_rt = devourer::build_stream_radiotap(devourer::parse_tx_mode_str(rate ? rate : "24M"), no_ack);
    fprintf(stderr, "Encrypted data rate: %s\n", rate ? rate : "24M");
  }
  g_dev->InitWrite(SelectedChannel{g_chan, 0, CHANNEL_WIDTH_20});

  if (g_scan) {
    std::thread rx([&]{ g_dev->StartRxLoop(on_rx); });
    fprintf(stderr, "Passive GamePad scan for %ds; keep the GamePad trying to connect.\n", sec);
    const uint8_t channels[] = {149,153,157,161,165,36,40,44,48};
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(sec);
    size_t i = 0;
    while (!g_stop && std::chrono::steady_clock::now() < end) {
      g_dev->FastRetune(channels[i++ % (sizeof channels)], true);
      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    g_dev->StopRxLoop(); rx.join();
    g_dev->Stop();
    fprintf(stderr, "SCAN complete: %u matching GamePad probes.\n", g_probe_count.load());
    std::_Exit(g_probe_count.load() ? 0 : 2);
  }

  int tu = 100; if (const char* i = std::getenv("DEVOURER_BCN_TU")) tu = atoi(i);
  std::vector<uint8_t> bcn = {0,0,0x0a,0,0,0x80,0,0,0x08,0,       // radiotap
      0x80,0,0,0, 0xff,0xff,0xff,0xff,0xff,0xff,                  // beacon, bcast DA
      g_bssid[0],g_bssid[1],g_bssid[2],g_bssid[3],g_bssid[4],g_bssid[5],
      g_bssid[0],g_bssid[1],g_bssid[2],g_bssid[3],g_bssid[4],g_bssid[5],
      0,0, 0,0,0,0,0,0,0,0, (uint8_t)(tu&0xff),(uint8_t)(tu>>8), 0x11,0x00};  // cap ESS+Privacy
  if (!g_ie_override.empty()) {
    bcn.insert(bcn.end(), g_ie_override.begin(), g_ie_override.end());   // exact captured tail
  } else {
    emit_ssid(bcn, true);                              // hidden, like the console
    emit_rates(bcn); emit_tim(bcn);
    { auto r = rsn_ie(); bcn.insert(bcn.end(), r.begin(), r.end()); }
    emit_htcap(bcn); emit_htop(bcn); emit_vendors(bcn);
  }
  bool bok = g_dev->StartBeacon(bcn.data(), bcn.size(), tu);
  std::thread rx([&]{ g_dev->StartRxLoop(on_rx); });
  fprintf(stderr, "ap_wiiu up (beacon=%s, %d TU). %ds. Power on the GamePad.\n",
          bok ? "OK" : "FAIL", tu, sec);

  #ifdef _WIN32
  timeBeginPeriod(1);
  #endif
  auto clock_host = std::chrono::steady_clock::now(), next_clock = clock_host;
  uint64_t clock_tsf = 0;
  int64_t clock_error_us = 0;
  auto next_stats = clock_host + std::chrono::seconds(5);
  auto end = std::chrono::steady_clock::now() + std::chrono::seconds(sec);
  while (!g_stop && std::chrono::steady_clock::now() < end) {
    g_dsu.pump();
    if (g_enable_video) {
      const auto now = std::chrono::steady_clock::now();
      // libusb control transfers dispatch RX callbacks. Never hold a callback's
      // session lock across a device operation, or synchronous completion stalls.
      if (now >= next_clock) {
        try {
          const uint64_t sampled = g_dev->ReadTsf();
          const auto sampled_host = std::chrono::steady_clock::now();
          if (clock_tsf) clock_error_us = int64_t(sampled - clock_tsf) -
            std::chrono::duration_cast<std::chrono::microseconds>(sampled_host - clock_host).count();
          clock_tsf = sampled; clock_host = sampled_host;
        }
        catch (const std::exception&) { /* keep the last good clock sample */ }
        next_clock = now + std::chrono::milliseconds(200);
      }
      std::lock_guard<std::recursive_mutex> session(g_session_mu);
      const bool ready = g_state == 2 && g_hid_seen && clock_tsf != 0;
      wiiu::VideoFrame video;
      bool frame_ready = g_video_ingress.pump(ready, g_stream.need_idr, g_epoch, video);
      if (ready) {
        const uint32_t ts = uint32_t(clock_tsf + std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - clock_host).count());
        // libdrc timestamps a frame before encoding, then transmits it on the
        // following 59.94-Hz tick. Match that one-frame age at transmission.
        if (frame_ready) g_stream.video(video, ts - 16683, send_udp);
        g_stream.pump(ts, send_udp);
      }
      if (now >= next_stats) {
        fprintf(stderr, "video: ready=%d frames=%llu packets=%llu cmd_replies=%llu resyncs=%llu queue_drops=%llu clock_error_us=%lld\n",
          ready, (unsigned long long)g_stream.frames, (unsigned long long)g_stream.video_packets,
          (unsigned long long)g_stream.replies, (unsigned long long)g_stream.resyncs,
          (unsigned long long)g_queue_drops.load(), (long long)clock_error_us);
        next_stats = now + std::chrono::seconds(5);
      }
    }
    std::vector<PendingFrame> batch;
    { std::lock_guard<std::mutex> l(g_q_mu); batch.swap(g_q); }
    std::vector<TxPacketView> views;
    for (auto& f : batch) {
      {
        std::lock_guard<std::recursive_mutex> session(g_session_mu);
        if (f.encrypted && (f.epoch != g_epoch || g_state != 2)) continue;
      }
      views.push_back({f.bytes.data(), f.bytes.size()});
    }
    if (!views.empty()) {
      const auto submitted = g_dev->send_packets(views.data(), views.size());
      g_sent.fetch_add(submitted);
      if (submitted != views.size() && g_enable_video) {
        std::lock_guard<std::recursive_mutex> session(g_session_mu);
        g_stream.need_idr = true;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  g_dev->StopRxLoop(); rx.join();
  fprintf(stderr, "network: offers=%u acks=%u arps=%u udp=%u\n",
          g_network.offers, g_network.acks, g_network.arps, g_network.udp_packets);
  fprintf(stderr, "sent=%llu 4way_state=%d decrypt_ok=%llu decrypt_fail=%llu\n",
          (unsigned long long)g_sent.load(), g_state,
          (unsigned long long)g_decok.load(), (unsigned long long)g_decfail.load());
  if (g_dev) {
    bool silenced = false;
    for (int i = 0; i < 3 && !silenced; ++i) silenced = g_dev->StopBeacon();
    if (!silenced)
      fprintf(stderr, "WARNING: the beacon could not be stopped - it is still "
                      "airing; power-cycle the adapter\n");
  }
  g_dev->Stop();
  g_video_ingress.stop();
  g_dsu.stop();
  #ifdef _WIN32
  timeEndPeriod(1);
  #endif
  std::_Exit(0);
}
