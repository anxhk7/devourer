#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#endif
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>

namespace wiiu {
inline uint32_t le32(const uint8_t* p) {
  return uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
         (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
inline void put_le(uint8_t* p, uint64_t v, size_t n) {
  for (size_t i = 0; i < n; ++i) p[i] = uint8_t(v >> (8 * i));
}
inline uint32_t crc32(const uint8_t* p, size_t n) {
  uint32_t crc = 0xffffffff;
  for (size_t i = 0; i < n; ++i) {
    crc ^= p[i];
    for (int b = 0; b < 8; ++b) crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return ~crc;
}
inline std::vector<uint8_t> dsu_packet(uint32_t type, size_t n) {
  std::vector<uint8_t> p(n, 0);
  memcpy(p.data(), "DSUS", 4); put_le(p.data() + 4, 1001, 2);
  put_le(p.data() + 6, n - 16, 2); put_le(p.data() + 12, 0x57494955, 4);
  put_le(p.data() + 16, type, 4); return p;
}
inline void finalize_dsu(std::vector<uint8_t>& p) {
  put_le(p.data() + 8, 0, 4); put_le(p.data() + 8, crc32(p.data(), p.size()), 4);
}

// HID button and touch layout follows libdrc's documented wire protocol.
// The default touchscreen calibration is the fallback used by libdrc;
// device-specific UIC calibration and sensor calibration are still pending.
inline void encode_dsu_input(std::vector<uint8_t>& p, const uint8_t* hid) {
  const uint32_t b = (uint32_t(hid[80]) << 16) | (hid[2] << 8) | hid[3];
  auto bit = [&](uint32_t mask, uint8_t value) { return (b & mask) ? value : uint8_t(0); };
  p[36] = bit(0x800,128) | bit(0x100,64) | bit(0x400,32) | bit(0x200,16) |
          bit(8,8) | bit(0x400000,4) | bit(0x800000,2) | bit(4,1);
  p[37] = bit(0x1000,128) | bit(0x4000,64) | bit(0x8000,32) | bit(0x2000,16) |
          bit(0x10,8) | bit(0x20,4) | bit(0x40,2) | bit(0x80,1);
  p[38] = bit(2,1);
  for (int i = 0; i < 4; ++i) {
    const int raw = hid[6 + 2*i] | (hid[7 + 2*i] << 8);
    const float v = std::clamp((raw - 2050.0f) / 1150.0f, -1.0f, 1.0f);
    p[40 + i] = uint8_t(std::lround((std::abs(v) < .1f ? 0.0f : v) * 127.0f + 128.0f));
  }
  const uint32_t masks[] = {0x800,0x100,0x400,0x200,0x1000,0x4000,0x8000,0x2000,
                            0x10,0x20,0x40,0x80};
  for (int i = 0; i < 12; ++i) p[44 + i] = bit(masks[i],255);
  const int pressure = ((hid[37] >> 4) & 7) | (((hid[39] >> 4) & 7) << 3) |
                       (((hid[41] >> 4) & 7) << 6) | (((hid[43] >> 4) & 7) << 9);
  if (pressure) {
    float x = 0, y = 0;
    for (int i = 0; i < 10; ++i) {
      const int off = 36 + 4*i;
      x += hid[off] | ((hid[off + 1] & 15) << 8);
      y += hid[off + 2] | ((hid[off + 3] & 15) << 8);
    }
    x = std::clamp((20.0f + (x / 10 - 195) * 814 / 3682) / 853, 0.0f, 1.0f);
    y = std::clamp((20.0f + (y / 10 - 3818) * 440 / -3445) / 479, 0.0f, 1.0f);
    p[39] = p[56] = 1;
    put_le(p.data() + 58, uint16_t(std::lround(x * 1920)), 2);
    put_le(p.data() + 60, uint16_t(std::lround(y * 942)), 2);
  }
  // Motion timestamp and values remain zero until units/biases are validated.
}

class DsuEndpoint {
  using Clock = std::chrono::steady_clock;
#ifdef _WIN32
  using Socket = SOCKET;
  static constexpr Socket invalid = INVALID_SOCKET;
#else
  using Socket = int;
  static constexpr Socket invalid = -1;
#endif
  Socket socket_ = invalid;
  std::mutex mutex_;
  std::array<uint8_t,128> hid_{};
  std::array<uint8_t,6> mac_{};
  Clock::time_point last_input_{};
  uint32_t count_ = 0;
  struct Client { sockaddr_in address; Clock::time_point expires; };
  std::vector<Client> clients_;
  Clock::time_point next_send_{};
  bool connected() const { return count_ && Clock::now() - last_input_ < std::chrono::milliseconds(250); }
  std::vector<uint8_t> state_packet(uint32_t type, uint8_t index) {
    auto p = dsu_packet(type, type == 0x100002 ? 100 : 32);
    p[20] = index;
    std::lock_guard<std::mutex> lock(mutex_);
    const bool live = index == 0 && connected();
    if (live) {
      p[21] = 2; p[22] = 1; p[23] = 2;
      memcpy(p.data() + 24, mac_.data(), 6);
      p[30] = (hid_[4] & 0x40) ? 0xee : 0; // battery scale not yet validated
    }
    if (type == 0x100002) {
      p[31] = live ? 1 : 0; put_le(p.data() + 32, count_, 4);
      p[40] = p[41] = p[42] = p[43] = 128;
      if (live) encode_dsu_input(p, hid_.data());
    }
    finalize_dsu(p); return p;
  }
  void send(const sockaddr_in& dst, const std::vector<uint8_t>& p) {
    sendto(socket_, reinterpret_cast<const char*>(p.data()), int(p.size()), 0,
           reinterpret_cast<const sockaddr*>(&dst), sizeof dst);
  }
public:
  ~DsuEndpoint() { stop(); }
  bool start(uint16_t port = 26760) {
#ifdef _WIN32
    WSADATA data;
    if (WSAStartup(MAKEWORD(2,2), &data)) return false;
#endif
    socket_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ == invalid) return false;
    sockaddr_in addr{}; addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); addr.sin_port = htons(port);
    if (bind(socket_, reinterpret_cast<sockaddr*>(&addr), sizeof addr)) { stop(); return false; }
#ifdef _WIN32
    u_long one = 1;
    if (ioctlsocket(socket_, FIONBIO, &one)) { stop(); return false; }
#else
    if (fcntl(socket_, F_SETFL, O_NONBLOCK) < 0) { stop(); return false; }
#endif
    fprintf(stderr, "DSU input endpoint: 127.0.0.1:%u (buttons/sticks/touch; motion pending)\n", port);
    return true;
  }
  void stop() {
    if (socket_ == invalid) return;
#ifdef _WIN32
    closesocket(socket_); WSACleanup();
#else
    close(socket_);
#endif
    socket_ = invalid;
  }
  void update(const uint8_t* hid, size_t n, const uint8_t* mac) {
    if (n != hid_.size()) return;
    std::lock_guard<std::mutex> lock(mutex_);
    memcpy(hid_.data(), hid, n); memcpy(mac_.data(), mac, 6);
    last_input_ = Clock::now(); ++count_;
  }
  void pump() {
    if (socket_ == invalid) return;
    for (int i = 0; i < 16; ++i) {
      std::array<uint8_t,512> buf{}; sockaddr_in peer{};
#ifdef _WIN32
      int addrlen = sizeof peer;
#else
      socklen_t addrlen = sizeof peer;
#endif
      const int got = recvfrom(socket_, reinterpret_cast<char*>(buf.data()), int(buf.size()), 0,
                               reinterpret_cast<sockaddr*>(&peer), &addrlen);
      if (got < 20) break;
      size_t n = 16 + buf[6] + (size_t(buf[7]) << 8);
      if (n < 20 || n > size_t(got) || memcmp(buf.data(), "DSUC", 4) ||
          (buf[4] | (buf[5] << 8)) != 1001) continue;
      const auto crc = le32(buf.data() + 8); put_le(buf.data() + 8, 0, 4);
      if (crc != crc32(buf.data(), n)) continue;
      const auto type = le32(buf.data() + 16);
      if (type == 0x100000) {
        auto p = dsu_packet(type, 24); put_le(p.data() + 20, 1001, 2);
        finalize_dsu(p); send(peer, p);
      } else if (type == 0x100001 && n >= 24) {
        auto count = le32(buf.data() + 20);
        if (count > 4 || 24 + count > n) continue;
        for (uint32_t j = 0; j < count; ++j)
          if (buf[24 + j] < 4) send(peer, state_packet(type, buf[24 + j]));
      } else if (type == 0x100002 && n >= 28) {
        const auto flags = buf[20];
        if (flags & ~3 || ((flags & 1) && buf[21] != 0)) continue;
        if (flags & 2) {
          std::lock_guard<std::mutex> lock(mutex_);
          if (memcmp(buf.data() + 22, mac_.data(), 6)) continue;
        }
        const auto expiry = Clock::now() + std::chrono::seconds(5);
        auto c = std::find_if(clients_.begin(), clients_.end(), [&](const Client& v) {
          return v.address.sin_addr.s_addr == peer.sin_addr.s_addr && v.address.sin_port == peer.sin_port;
        });
        if (c != clients_.end()) c->expires = expiry;
        else if (clients_.size() < 8) clients_.push_back({peer, expiry});
      }
    }
    const auto now = Clock::now();
    clients_.erase(std::remove_if(clients_.begin(), clients_.end(),
      [&](const Client& c) { return c.expires < now; }), clients_.end());
    if (now >= next_send_ && !clients_.empty()) {
      auto p = state_packet(0x100002, 0);
      for (const auto& c : clients_) send(c.address, p);
      next_send_ = now + std::chrono::milliseconds(5);
    }
  }
};
} // namespace wiiu
