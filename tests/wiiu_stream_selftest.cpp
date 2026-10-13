#include "wiiu_stream.h"
#include <cstdlib>
#include <thread>

static void require(bool ok, const char* message) {
  if (!ok) { fprintf(stderr, "FAIL: %s\n", message); std::exit(1); }
}
struct Sent { uint16_t source, dest; std::vector<uint8_t> bytes; };
int main() {
  wiiu::DrcStream stream;
  std::vector<Sent> sent;
  auto send = [&](uint16_t source, uint16_t dest, const std::vector<uint8_t>& bytes) {
    sent.push_back({source, dest, bytes});
  };
  wiiu::VideoFrame frame;
  for (auto& chunk : frame.chunks) chunk = {0xaa,0xbb,0xcc};
  require(!stream.video(frame, 0x12345678, send) && sent.empty(), "first frame must be IDR");
  frame.idr = true; frame.chunks[0].resize(1401, 0xaa);
  require(stream.video(frame, 0x12345678, send) && sent.size() == 7, "split large chunk into two packets");
  // Wire fixtures checked against libdrc VstrmPacket/AstrmPacket setters.
  const uint8_t format[] = {4,0,0,24,0,0,16,0,0x78,0x56,0x34,0x12,
    0x80,0x3e,0,0,0x80,0x3e,0,0,0x80,0x3e,0,0,0x80,0x3e,0,0,0,0,0,0};
  require(sent[0].source == 50021 && sent[0].dest == 50121 &&
    sent[0].bytes == std::vector<uint8_t>(format, format + sizeof format), "video-format fixture");
  const uint8_t first[] = {0xf0,0,0xcd,0x78,0x12,0x34,0x56,0x78,0x83,0x85,6,0x80,0x82,0,0,0};
  const uint8_t second[] = {0xf0,1,0xa8,1,0x12,0x34,0x56,0x78,0x83,0x85,6,0x80,0x82,0,0,0};
  require(!memcmp(sent[1].bytes.data(), first, 16) && sent[1].bytes.size() == 1416, "first packet fixture");
  require(!memcmp(sent[2].bytes.data(), second, 16) && sent[2].bytes.size() == 17, "chunk-ending fixture");
  require(sent.back().bytes[2] == 0xb8 && sent.back().bytes[1] == 5, "final packet flags");
  auto ip = wiiu::udp_packet(50020, 50120, sent[1].bytes);
  require(!wiiu::checksum(ip.data(), 20) && wiiu::be16(ip.data()+2) == ip.size() &&
    wiiu::be16(ip.data()+24) == sent[1].bytes.size()+8, "IPv4/UDP lengths and checksum");
  require(wiiu::udp_packet(1, 2, std::vector<uint8_t>(65001)).empty(), "oversize datagram rejected");
  const uint8_t resync[] = {1,0,0,0};
  stream.receive(50110, 50010, resync, sizeof resync, send);
  require(stream.need_idr && stream.resyncs == 1, "resync requests IDR");
  frame.idr = false;
  sent.clear(); require(stream.video(frame, 1, send), "P frames continue during IDR recovery");
  require(stream.need_idr && !(sent[1].bytes[2] & 128) && sent[1].bytes[11] == 0x82, "P-frame recovery flags");
  frame.idr = true; require(stream.video(frame, 2, send) && !stream.need_idr, "IDR resolves request");
  auto broken = frame; broken.chunks[4].clear(); sent.clear();
  require(!stream.video(broken, 3, send) && sent.empty(), "invalid frame emits no partial packets");
  for (auto& chunk : frame.chunks) chunk = {0xff};
  sent.clear();
  for (int i = 0; i < 210; ++i) require(stream.video(frame, 4, send), "sequence-wrap frame");
  unsigned seq = 18;
  for (const auto& p : sent) if (p.dest == 50120) {
    require(((p.bytes[0] & 3) * 256 + p.bytes[1]) == (seq++ & 1023), "10-bit sequence wrap");
  }
  stream.reset(); sent.clear(); stream.pump(0x12345678, send);
  require(sent.size() == 2 && sent[0].dest == 50121 && sent[0].bytes.size() == 1544 &&
    sent[0].bytes[0] == 0x20 && sent[0].bytes[2] == 6, "silent 48-kHz audio");
  require(sent[1].dest == 50123 && sent[1].bytes.size() == 56 &&
    sent[1].bytes[2] == 1 && sent[1].bytes[4] == 48 &&
    sent[1].bytes[20] == 0x3e && sent[1].bytes[21] == 0x80, "UVC heartbeat fixture");
  auto reply = sent[1].bytes; reply.resize(8); reply[0] = 2; reply[4] = 0;
  sent.clear(); stream.receive(50123, 50023, reply.data(), reply.size(), send);
  require(stream.replies == 1 && sent.size() == 1 && sent[0].bytes[0] == 3 && sent[0].bytes.size() == 8,
    "command reply acknowledged");
  stream.receive(50123, 50023, reply.data(), reply.size(), send);
  require(stream.replies == 1 && sent.size() == 2, "duplicate reply re-ACKed without double counting");
  reply[4] = 1; stream.receive(50123, 50023, reply.data(), reply.size(), send);
  require(sent.size() == 2, "malformed command length rejected");
#ifdef _WIN32
  WSADATA data{}; require(!WSAStartup(MAKEWORD(2,2), &data), "Winsock initialization");
  using Socket = SOCKET;
#else
  using Socket = int;
#endif
  wiiu::VideoIngress ingress; require(ingress.start(0), "ephemeral loopback ingress");
  Socket client = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  sockaddr_in address{}; address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons(ingress.bound_port());
  require(!connect(client, reinterpret_cast<sockaddr*>(&address), sizeof address), "loopback producer connection");
#ifdef _WIN32
  DWORD timeout = 100;
#else
  timeval timeout{0,100000};
#endif
  setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof timeout);
  auto status = [&]() {
    require(::send(client, "WUV?", 4, 0) == 4, "status query sent");
    wiiu::VideoFrame out;
    for (int i = 0; i < 5; ++i) { ingress.pump(true, false, 42, out); std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    std::array<uint8_t,32> bytes{};
    require(recv(client, reinterpret_cast<char*>(bytes.data()), int(bytes.size()), 0) == 16 &&
      !memcmp(bytes.data(), "WUVS", 4) && bytes[7] == 2 && wiiu::le32(bytes.data()+8) == 42,
      "versioned status and epoch");
    return bytes;
  };
  require(!status()[6], "fresh session has no completed frame credit");
  const uint8_t order[] = {4,2,0,1,3};
  for (uint8_t chunk : order) {
    uint8_t packet[] = {'W','U','V','C',1,1,chunk,0,9,0,0,0,chunk};
    require(::send(client, reinterpret_cast<const char*>(packet), sizeof packet, 0) == sizeof packet, "chunk sent");
  }
  wiiu::VideoFrame out; bool complete = false;
  for (int i = 0; i < 5 && !complete; ++i) {
    complete = ingress.pump(true, true, 42, out);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  require(complete && out.idr && out.chunks[4] == std::vector<uint8_t>{4}, "reordered chunks form one complete frame");
  auto accepted = status(); require(accepted[6] && wiiu::le32(accepted.data()+12) == 9, "completed frame credit");
  ingress.reset_session(); require(!status()[6], "rekey invalidates frame credit");
  ingress.stop();
#ifdef _WIN32
  closesocket(client); WSACleanup();
#else
  close(client);
#endif
  fprintf(stderr, "Wii U stream fixtures: packetization, flags, sequence wrap, IPv4, recovery, audio and commands passed.\n");
}
