// ap_wiiu.cpp — devourer impersonating a Wii U console's GamePad AP, so a real
// Wii U GamePad associates to THIS PC instead of its console (toward Cemu use).
// Forked from tests/ap_wpa2.cpp (the completed WPA2-PSK AP: beacon -> probe ->
// auth -> assoc -> 4-way -> CCMP data). Only the Wii-U-specific deltas are new:
//
//   1. Identity = the real console. BSSID, PSK and SSID come from the Vanilla
//      capture (secrets/vanilla-config.xml), NOT hardcoded. SSID is hidden in
//      the beacon (16 zero bytes, matching the console) and answered in full to
//      the GamePad's directed probe. Channel is 5 GHz (set DEVOURER_CHANNEL to
//      the console's CURRENT channel — it is re-picked at each console boot).
//
//   2. The PSK is 64 hex chars = the raw 256-bit PMK. It is decoded straight to
//      the PMK; PBKDF2 is NOT run (that is only for ASCII passphrases). This is
//      the single most important correctness fix vs. ap_wpa2.cpp.
//
//   3. THE Wii U QUIRK: the PTK is rotated left by 3 bytes (first 3 bytes moved
//      to the end). Standard WPA2 up to PTK derivation, then the rotation.
//      WHERE it applies is the one unknown (your PROJECT_STATUS calls this the
//      likely stuck point), so it is one env var, DEVOURER_WIIU_ROT:
//        ptk3 (default) — rotate the whole 48-byte PTK, so KCK (EAPOL MIC),
//                         KEK (msg3 key wrap) AND TK (CCMP) all shift. Correct
//                         IF the GamePad rotates before carving KCK/KEK/TK.
//        tk3            — standard handshake keys, rotate ONLY the 16-byte CCMP
//                         TK. Correct IF the GamePad's EAPOL MICs are standard
//                         and only the data-plane key is mangled.
//        off            — no rotation (plain WPA2; sanity/control).
//      DECISION TREE on first connect, from the log:
//        * "msg2 MIC FAIL" under ptk3  -> the handshake keys are standard;
//          switch to tk3.
//        * "msg2 OK ... 4-WAY COMPLETE" then a decrypted GamePad frame
//          ("DECRYPT OK") -> ptk3 is right, done.
//        * "4-WAY COMPLETE" but every GamePad data frame fails to decrypt ->
//          handshake keys standard but TK wrong; try tk3.
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
// Build (add the CMake target below, then):
//   cmake --build build --target ap_wiiu
// Run (Developer PowerShell, VM powered off so the Alfa is free):
//   $env:DEVOURER_VID="0x0bda"; $env:DEVOURER_PID="0x8812"
//   $env:DEVOURER_CHANNEL="161"        # <-- re-check the console's channel first
//   $env:DEVOURER_TX_WITH_RX="thread"; $env:DEVOURER_BCN_TU="25"
//   build\ap_wiiu.exe 120
#include <atomic>
#include <array>
#include <chrono>
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

// ---- identity (filled from secrets/vanilla-config.xml at startup) ----------
static uint8_t g_bssid[6];
static std::string g_ssid;              // e.g. "WiiU9ce6353e4cd1"
static uint8_t g_pmk[32];               // the 256-bit PMK (decoded from the PSK)
static uint8_t g_chan = 157;

enum RotMode { ROT_OFF, ROT_TK3, ROT_PTK3 };
static RotMode g_rot = ROT_PTK3;
static bool g_std_oui = false;          // true -> standard 00:0f:ac instead of Nintendo
static std::vector<uint8_t> g_ie_override;  // exact captured IE tail for the beacon, if provided

static IRadio* g_dev = nullptr;
static std::vector<uint8_t> g_rt;
static std::atomic<uint64_t> g_sent{0};
static std::mutex g_q_mu;
static std::vector<std::vector<uint8_t>> g_q;

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
  m.insert(m.end(), {0x3d, 0x16, g_chan, 0x08, 0x00, 0x00, 0x00});
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

static void enqueue(std::vector<uint8_t> mpdu) {
  std::vector<uint8_t> f; f.reserve(g_rt.size() + mpdu.size());
  f.insert(f.end(), g_rt.begin(), g_rt.end());
  f.insert(f.end(), mpdu.begin(), mpdu.end());
  std::lock_guard<std::mutex> lk(g_q_mu);
  if (g_q.size() < 128) g_q.push_back(std::move(f));
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
static void ccmp_aad_nonce(const uint8_t* hdr, uint64_t pn, const uint8_t* a2,
                           uint8_t* aad, int* aadlen, uint8_t* nonce) {
  uint16_t fc = hdr[0] | (hdr[1] << 8);
  fc &= ~0x0070; fc &= ~(0x0800|0x1000|0x2000); fc |= 0x4000;
  aad[0]=fc&0xff; aad[1]=fc>>8;
  memcpy(aad+2, hdr+4, 18);
  uint16_t seq = (hdr[22]|(hdr[23]<<8)) & 0x000f;
  aad[20]=seq&0xff; aad[21]=seq>>8; *aadlen=22;
  nonce[0]=0; memcpy(nonce+1, a2, 6);
  for (int i=0;i<6;i++) nonce[7+i] = (pn >> (8*(5-i))) & 0xff;
}
static bool ccm(bool enc, const uint8_t* key, const uint8_t* nonce, const uint8_t* aad,
                int aadlen, const uint8_t* in, int inlen, uint8_t* out, uint8_t* tag) {
  EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new(); int l; bool ok=true;
  if (enc) {
    EVP_EncryptInit_ex(c, EVP_aes_128_ccm(), 0,0,0);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 13, 0);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 8, 0);
    EVP_EncryptInit_ex(c, 0,0,key,nonce);
    EVP_EncryptUpdate(c, 0,&l,0,inlen); EVP_EncryptUpdate(c,0,&l,aad,aadlen);
    EVP_EncryptUpdate(c, out,&l,in,inlen); EVP_EncryptFinal_ex(c,out+l,&l);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 8, tag);
  } else {
    EVP_DecryptInit_ex(c, EVP_aes_128_ccm(), 0,0,0);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 13, 0);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 8, tag);
    EVP_DecryptInit_ex(c, 0,0,key,nonce);
    EVP_DecryptUpdate(c, 0,&l,0,inlen); EVP_DecryptUpdate(c,0,&l,aad,aadlen);
    ok = EVP_DecryptUpdate(c, out,&l,in,inlen) > 0;
  }
  EVP_CIPHER_CTX_free(c); return ok;
}

static void on_rx(const Packet& p) {
  if (p.Data.size() < 24 || p.RxAtrib.crc_err) return;
  const uint8_t fc0 = p.Data[0], fc1 = p.Data[1];
  const uint8_t* a1 = p.Data.data() + 4;
  const uint8_t* sta = p.Data.data() + 10;
  bool to_us = std::memcmp(a1, g_bssid, 6) == 0;
  bool bcast = (a1[0] & 0x01) != 0;

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
    auto m = mgmt_hdr(0x10, sta);
    m.insert(m.end(), {0x11,0x00, 0x00,0x00, 0x01,0xc0});   // cap, status 0, AID 1
    emit_rates(m); emit_htcap(m); emit_htop(m);
    enqueue(std::move(m));
    memcpy(g_sta, sta, 6); memset(g_replay, 0, 8); g_state = 0;
    fprintf(stderr, "  ASSOC from %02x:%02x:%02x:%02x:%02x:%02x -> start 4-way\n",
            sta[0],sta[1],sta[2],sta[3],sta[4],sta[5]);
    send_msg1();
  } else if ((fc0 == 0x08 || fc0 == 0x88) && (fc1 & 0x01) && to_us) {  // data to-DS
    int hlen = 24 + (fc0 == 0x88 ? 2 : 0);
    if ((fc1 & 0x40) && g_state == 2) {                // PROTECTED (CCMP) data
      int len = (int)p.Data.size();
      if (len < hlen + 8 + 8) return;
      const uint8_t* d = p.Data.data();
      const uint8_t* cc = d + hlen;
      uint64_t pn = cc[0] | (cc[1]<<8) | ((uint64_t)cc[4]<<16) | ((uint64_t)cc[5]<<24)
                  | ((uint64_t)cc[6]<<32) | ((uint64_t)cc[7]<<40);
      int ctlen = len - hlen - 8 - 8;
      const uint8_t* ct = d + hlen + 8; const uint8_t* mic = ct + ctlen;
      uint8_t aad[32], nonce[13], tag[8]; int aadlen;
      ccmp_aad_nonce(d, pn, sta, aad, &aadlen, nonce);
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
      } else {
        uint64_t n = g_decfail.fetch_add(1);
        if (n < 4)
          fprintf(stderr, "  decrypt FAIL (rotation '%s' wrong for the TK?) pn=%llu\n",
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
    uint16_t ki = (e[5]<<8) | e[6];
    if ((ki & 0x0008) && (ki & 0x0100) && !(ki & 0x0040) && !(ki & 0x0200)) {   // msg2
      memcpy(g_snonce, e+17, 32);
      compute_ptk();
      if (!check_mic(e, elen)) {
        fprintf(stderr, "  WPA2: msg2 MIC FAIL (rotation '%s' — if this is ptk3, "
                        "the handshake keys are standard: retry with "
                        "DEVOURER_WIIU_ROT=tk3)\n",
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
  int sec = argc > 1 ? atoi(argv[1]) : 60;
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
  if (!std::getenv("DEVOURER_CHANNEL"))
    fprintf(stderr, "WARNING: DEVOURER_CHANNEL unset, assuming %d — re-check the "
                    "console's CURRENT channel first (it changes at boot)\n", g_chan);

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
  g_dev->InitWrite(SelectedChannel{g_chan, 0, CHANNEL_WIDTH_20});

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

  auto end = std::chrono::steady_clock::now() + std::chrono::seconds(sec);
  while (std::chrono::steady_clock::now() < end) {
    std::vector<std::vector<uint8_t>> batch;
    { std::lock_guard<std::mutex> l(g_q_mu); batch.swap(g_q); }
    for (auto& f : batch) if (g_dev->send_packet(f.data(), f.size())) g_sent.fetch_add(1);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
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
  _exit(0);
}
