#pragma once

#include <cstdint>
#include <cstring>
#include <functional>
#include <vector>

// A small, isolated console-side IPv4 endpoint. It does not alter Windows
// routes or bridge the GamePad onto the user's ordinary LAN.
namespace wiiu {
inline constexpr uint8_t console_ip[4] = {192,168,1,10};
inline constexpr uint8_t gamepad_ip[4] = {192,168,1,11};
inline uint16_t be16(const uint8_t* p) { return uint16_t((p[0] << 8) | p[1]); }
inline void put16(uint8_t* p, uint16_t n) { p[0] = uint8_t(n >> 8); p[1] = uint8_t(n); }
inline uint16_t checksum(const uint8_t* p, size_t n) {
  uint32_t sum = 0;
  for (size_t i = 0; i + 1 < n; i += 2) sum += be16(p + i);
  if (n & 1) sum += uint32_t(p[n - 1]) << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return uint16_t(~sum);
}

struct Network {
  using Send = std::function<void(uint16_t, const std::vector<uint8_t>&)>;
  using Udp = std::function<void(uint16_t, uint16_t, const uint8_t*, size_t)>;
  unsigned offers = 0, acks = 0, arps = 0, udp_packets = 0;

  static std::vector<uint8_t> dhcp_reply(const uint8_t* mac,
                                       const uint8_t* request, uint8_t type) {
    std::vector<uint8_t> bootp(236, 0);
    bootp[0] = 2; bootp[1] = 1; bootp[2] = 6;
    memcpy(bootp.data() + 4, request + 4, 4);
    memcpy(bootp.data() + 10, request + 10, 2); // broadcast flag
    memcpy(bootp.data() + 16, gamepad_ip, 4);
    memcpy(bootp.data() + 20, console_ip, 4);
    memcpy(bootp.data() + 28, mac, 6);
    const uint8_t options[] = {
      99,130,83,99, 53,1,type, 54,4,192,168,1,10,
      51,4,0,1,81,128, 1,4,255,255,255,0,
      3,4,192,168,1,10, 6,4,192,168,1,10, 255
    };
    bootp.insert(bootp.end(), options, options + sizeof options);
    std::vector<uint8_t> ip(28, 0);
    ip[0] = 0x45; put16(ip.data() + 2, uint16_t(28 + bootp.size()));
    ip[8] = 64; ip[9] = 17;
    memcpy(ip.data() + 12, console_ip, 4);
    memset(ip.data() + 16, 255, 4);
    put16(ip.data() + 10, checksum(ip.data(), 20));
    put16(ip.data() + 20, 67); put16(ip.data() + 22, 68);
    put16(ip.data() + 24, uint16_t(8 + bootp.size()));
    ip.insert(ip.end(), bootp.begin(), bootp.end());
    return ip; // UDP checksum zero is valid for IPv4
  }

  void receive(const uint8_t* ap_mac, const uint8_t* sta_mac,
               const uint8_t* llc, size_t n, const Send& send, const Udp& udp_cb) {
    const uint8_t snap[] = {0xaa,0xaa,3,0,0,0};
    if (n < 8 || memcmp(llc, snap, 6)) return;
    const auto eth = be16(llc + 6);
    const auto* p = llc + 8; n -= 8;
    if (eth == 0x0806) {
      if (n < 28 || be16(p) != 1 || be16(p + 2) != 0x0800 ||
          p[4] != 6 || p[5] != 4 || be16(p + 6) != 1 ||
          memcmp(p + 24, console_ip, 4)) return;
      std::vector<uint8_t> reply(p, p + 28);
      put16(reply.data() + 6, 2);
      memcpy(reply.data() + 18, p + 8, 10);
      memcpy(reply.data() + 8, ap_mac, 6);
      memcpy(reply.data() + 14, console_ip, 4);
      ++arps; send(0x0806, reply); return;
    }
    if (eth != 0x0800 || n < 20 || (p[0] >> 4) != 4) return;
    const size_t ihl = (p[0] & 15) * 4;
    const size_t total = be16(p + 2);
    if (ihl < 20 || ihl > n || total < ihl || total > n ||
        (be16(p + 6) & 0x3fff) || checksum(p, ihl)) return;
    if (p[9] != 17 || total < ihl + 8) return;
    const auto* u = p + ihl;
    const uint16_t sport = be16(u), dport = be16(u + 2);
    const size_t ulen = be16(u + 4);
    if (ulen < 8 || ulen > total - ihl) return;
    const auto* body = u + 8; const size_t blen = ulen - 8;
    if (sport == 68 && dport == 67) {
      const uint8_t cookie[] = {99,130,83,99};
      if (blen < 240 || body[0] != 1 || body[1] != 1 || body[2] != 6 ||
          memcmp(body + 28, sta_mac, 6) || memcmp(body + 236, cookie, 4)) return;
      uint8_t message = 0;
      size_t off = 240;
      while (off < blen) {
        const uint8_t tag = body[off++];
        if (tag == 255) break;
        if (tag == 0) continue;
        if (off >= blen) return;
        const size_t len = body[off++];
        if (len > blen - off) return;
        if (tag == 53 && len == 1) message = body[off];
        if (tag == 54 && (len != 4 || memcmp(body + off, console_ip, 4))) return;
        if (tag == 50 && (len != 4 || memcmp(body + off, gamepad_ip, 4))) return;
        off += len;
      }
      const uint8_t reply_type = message == 1 ? 2 : message == 3 ? 5 : 0;
      if (!reply_type) return;
      if (reply_type == 2) ++offers; else ++acks;
      send(0x0800, dhcp_reply(sta_mac, body, reply_type));
    } else if ((!memcmp(p + 16, console_ip, 4) ||
               (dport == 50010 && p[16] == 255 && p[17] == 255 && p[18] == 255 && p[19] == 255)) &&
               !memcmp(p + 12, gamepad_ip, 4)) {
      ++udp_packets; udp_cb(sport, dport, body, blen);
    }
  }
};
} // namespace wiiu
