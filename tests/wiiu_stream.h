#pragma once
#include "wiiu_dsu.h"
#include "wiiu_network.h"

// Wire layouts and encoder constraints follow libdrc (Mema Hacking, 2013).
// See docs/wiiu-gamepad.md for source revisions and the encoder build.
namespace wiiu {
struct VideoFrame {
  bool idr = false;
  std::array<std::vector<uint8_t>,5> chunks;
};
inline std::vector<uint8_t> udp_packet(uint16_t source, uint16_t dest,
                                      const std::vector<uint8_t>& data) {
  if (data.size() > 65000) return {};
  std::vector<uint8_t> p(28 + data.size(), 0);
  p[0] = 0x45; p[8] = 64; p[9] = 17;
  put16(p.data() + 2, uint16_t(p.size()));
  memcpy(p.data() + 12, console_ip, 4); memcpy(p.data() + 16, gamepad_ip, 4);
  put16(p.data() + 10, checksum(p.data(), 20));
  put16(p.data() + 20, source); put16(p.data() + 22, dest);
  put16(p.data() + 24, uint16_t(8 + data.size()));
  memcpy(p.data() + 28, data.data(), data.size());
  return p;
}
class DrcStream {
  uint16_t video_seq_ = 0, audio_seq_ = 0, command_seq_ = 0;
  bool initialized_ = false;
  uint16_t pending_seq_ = 0;
  unsigned retries_ = 0;
  std::vector<uint8_t> query_;
  std::chrono::steady_clock::time_point next_command_{}, next_audio_{};
public:
  using Send = std::function<void(uint16_t, uint16_t, const std::vector<uint8_t>&)>;
  uint64_t frames = 0, video_packets = 0, replies = 0, resyncs = 0;
  bool need_idr = true;
  void reset() {
    initialized_ = false; need_idr = true; query_.clear();
    next_command_ = {}; next_audio_ = {};
  }
  bool video(const VideoFrame& f, uint32_t ts, const Send& send) {
    // Continue delivering P frames while requesting an IDR. Dropping them
    // creates further reference gaps and makes recovery requests self-sustain.
    if (!initialized_ && !f.idr) return false;
    for (const auto& chunk : f.chunks) if (chunk.empty() || chunk.size() > 60000) return false;
    std::vector<uint8_t> format(32, 0);
    format[0] = 4; format[3] = 24;
    put_le(format.data() + 4, 0x100000, 4);
    put_le(format.data() + 8, ts, 4);
    for (int off = 12; off < 28; off += 4) put_le(format.data() + off, 16000, 4);
    send(50021, 50121, format);
    for (size_t c = 0; c < 5; ++c) {
      const auto& chunk = f.chunks[c];
      for (size_t off = 0; off < chunk.size(); off += 1400) {
        const size_t n = (std::min)(size_t(1400), chunk.size() - off);
        const bool last = off + n == chunk.size();
        std::vector<uint8_t> p(16 + n, 0);
        p[0] = uint8_t(0xf0 | (video_seq_ >> 8)); p[1] = uint8_t(video_seq_);
        video_seq_ = (video_seq_ + 1) & 1023;
        p[2] = uint8_t(8 | (n >> 8) | (!initialized_ ? 128 : 0) |
                    (c == 0 && off == 0 ? 64 : 0) | (last ? 32 : 0) |
                    (c == 4 && last ? 16 : 0));
        p[3] = uint8_t(n);
        p[4] = uint8_t(ts >> 24); p[5] = uint8_t(ts >> 16);
        p[6] = uint8_t(ts >> 8); p[7] = uint8_t(ts);
        p[8] = 0x83; p[9] = 0x85; p[10] = 6;
        size_t ext = 11; if (f.idr) p[ext++] = 0x80;
        p[ext++] = 0x82; p[ext] = 0; // 59.94 Hz
        memcpy(p.data() + 16, chunk.data() + off, n);
        send(50020, 50120, p); ++video_packets;
      }
    }
    initialized_ = true; if (f.idr) need_idr = false; ++frames; return true;
  }
  void receive(uint16_t source, uint16_t dest, const uint8_t* p, size_t n, const Send& send) {
    const uint8_t sync[4] = {1,0,0,0};
    if (dest == 50010 && n == 4 && !memcmp(p, sync, 4)) {
      need_idr = true; ++resyncs;
    }
    if (source != 50123 || dest != 50023 || n < 8) return;
    const unsigned type = p[0] | (p[1] << 8), query_type = p[2] | (p[3] << 8);
    const unsigned len = p[4] | (p[5] << 8);
    const unsigned seq = p[6] | (p[7] << 8);
    if (len != n - 8 || query_type != 1 || type > 3) return;
    if (type == 2) {
      std::vector<uint8_t> ack(p, p + 8); ack[0] = 3; ack[4] = ack[5] = 0;
      send(50023, 50123, ack);
      if (!query_.empty() && seq == pending_seq_) {
        ++replies; query_.clear();
        next_command_ = std::chrono::steady_clock::now() + std::chrono::seconds(1);
      }
    }
  }
  void pump(uint32_t ts, const Send& send) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= next_audio_) {
      std::vector<uint8_t> audio(8 + 1536, 0);
      audio[0] = uint8_t(0x20 | (audio_seq_ >> 8)); audio[1] = uint8_t(audio_seq_);
      audio[2] = 6; put_le(audio.data() + 4, ts, 4);
      audio_seq_ = (audio_seq_ + 1) & 1023;
      send(50021, 50121, audio);
      next_audio_ = now + std::chrono::milliseconds(8);
    }
    if (now < next_command_) return;
    if (query_.empty() || retries_ >= 5) {
      pending_seq_ = command_seq_++; retries_ = 0;
      query_.assign(56, 0); query_[2] = 1; query_[4] = 48;
      put_le(query_.data() + 6, pending_seq_, 2);
      query_[8 + 12] = 0x3e; query_[8 + 13] = 0x80; // mic rate 16000, BE
    }
    send(50023, 50123, query_); ++retries_;
    next_command_ = now + std::chrono::milliseconds(100);
  }
};

// Separate encoder process feeds five CABAC chunks per frame over loopback.
// It never sees pairing credentials or handles the Wi-Fi adapter.
class VideoIngress {
#ifdef _WIN32
  SOCKET socket_ = INVALID_SOCKET;
#else
  int socket_ = -1;
#endif
  sockaddr_in peer_{};
  uint32_t frame_id_ = 0;
  uint32_t accepted_id_ = 0;
  bool accepted_valid_ = false;
  unsigned mask_ = 0;
  VideoFrame frame_;
public:
  ~VideoIngress() { stop(); }
  bool start(uint16_t port = 26762) {
    socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ == decltype(socket_)(-1)) return false;
    sockaddr_in addr{}; addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); addr.sin_port = htons(port);
    if (bind(socket_, reinterpret_cast<sockaddr*>(&addr), sizeof addr)) { stop(); return false; }
    int buffer = 2 * 1024 * 1024;
    setsockopt(socket_, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&buffer), sizeof buffer);
#ifdef _WIN32
    u_long one = 1; ioctlsocket(socket_, FIONBIO, &one);
    // Ignore ICMP from an encoder which has just exited.
    DWORD bytes = 0; BOOL reset = FALSE;
    WSAIoctl(socket_, _WSAIOW(IOC_VENDOR,12), &reset, sizeof reset, nullptr, 0, &bytes, nullptr, nullptr);
#else
    fcntl(socket_, F_SETFL, O_NONBLOCK);
#endif
    fprintf(stderr, "Video ingress: 127.0.0.1:%u\n", unsigned(bound_port())); return true;
  }
  uint16_t bound_port() const {
    sockaddr_in address{};
#ifdef _WIN32
    int length = sizeof address;
#else
    socklen_t length = sizeof address;
#endif
    return getsockname(socket_, reinterpret_cast<sockaddr*>(&address), &length) ? 0 : ntohs(address.sin_port);
  }
  void stop() {
    if (socket_ == decltype(socket_)(-1)) return;
#ifdef _WIN32
    closesocket(socket_);
#else
    close(socket_);
#endif
    socket_ = decltype(socket_)(-1);
  }
  void reset() { mask_ = 0; frame_ = {}; }
  void reset_session() { reset(); accepted_valid_ = false; }
  bool pump(bool ready, bool need_idr, uint32_t epoch, VideoFrame& out) {
    for (int i = 0; i < 64; ++i) {
      std::array<uint8_t, 65536> b{}; sockaddr_in from{};
#ifdef _WIN32
      int len = sizeof from;
#else
      socklen_t len = sizeof from;
#endif
      const int n = recvfrom(socket_, reinterpret_cast<char*>(b.data()), int(b.size()), 0,
                             reinterpret_cast<sockaddr*>(&from), &len);
      if (n < 0) return false;
      if (n == 4 && !memcmp(b.data(), "WUV?", 4)) {
        const uint8_t status[16] = {'W','U','V','S',uint8_t(ready),uint8_t(need_idr),
          uint8_t(accepted_valid_),2,
          uint8_t(epoch),uint8_t(epoch >> 8),uint8_t(epoch >> 16),uint8_t(epoch >> 24),
          uint8_t(accepted_id_),uint8_t(accepted_id_ >> 8),uint8_t(accepted_id_ >> 16),uint8_t(accepted_id_ >> 24)};
        sendto(socket_, reinterpret_cast<const char*>(status), sizeof status, 0,
               reinterpret_cast<sockaddr*>(&from), sizeof from); continue;
      }
      if (!ready || n <= 12 || n > 60012 || memcmp(b.data(), "WUVC", 4) ||
          b[4] != 1 || b[5] > 1 || b[6] > 4 || b[7] != 0) continue;
      if (from.sin_port != peer_.sin_port) { reset_session(); peer_ = from; }
      const auto id = le32(b.data() + 8);
      if (!mask_ || id != frame_id_) {
        mask_ = 0; frame_id_ = id; frame_.idr = b[5] != 0;
      }
      if (frame_.idr != (b[5] != 0)) { reset(); continue; }
      frame_.chunks[b[6]].assign(b.data() + 12, b.data() + n);
      mask_ |= 1 << b[6];
      if (mask_ == 31) {
        accepted_id_ = id; accepted_valid_ = true;
        out = std::move(frame_); reset(); return true;
      }
    }
    return false;
  }
};
} // namespace wiiu
