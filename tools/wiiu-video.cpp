// SPDX-License-Identifier: GPL-2.0-or-later
// Windows encoder companion. Settings follow libdrc's H264Encoder (2013,
// Mema Hacking); five raw CABAC row chunks are sent to the local radio bridge.
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <windows.h>
#include <mmsystem.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <array>
#include <vector>
#include <algorithm>
#include <atomic>
extern "C" {
#include <x264.h>
}
constexpr int width = 864, height = 480;
struct Encoded {
  std::array<std::vector<uint8_t>,5> chunks;
  std::array<const uint8_t*,5> pointers{};
  std::array<int,5> sizes{};
  unsigned mask = 0;
  bool idr = false, invalid = false;
};
static void nal_ready(x264_t*, x264_nal_t* nal, void* context) {
  if (nal->i_type != NAL_SLICE && nal->i_type != NAL_SLICE_IDR) return;
  auto& e = *static_cast<Encoded*>(context);
  int index = nal->i_first_mb / 324;
  if (index < 0 || index >= 5 || nal->i_payload <= 0 || nal->i_payload > 60000) {
    e.invalid = true; return;
  }
  // CABAC carry propagation can still change the preceding chunk's last byte.
  // Keep x264's pointers until the entire frame has finished encoding.
  e.pointers[index] = nal->p_payload; e.sizes[index] = nal->i_payload;
  e.mask |= 1 << index; e.idr = nal->i_type == NAL_SLICE_IDR;
}
static uint64_t micros() {
  LARGE_INTEGER ticks, frequency;
  QueryPerformanceCounter(&ticks); QueryPerformanceFrequency(&frequency);
  return uint64_t(ticks.QuadPart / frequency.QuadPart) * 1000000 +
         uint64_t(ticks.QuadPart % frequency.QuadPart) * 1000000 / frequency.QuadPart;
}
static uint8_t clamp(int x) { return uint8_t(std::max(0, std::min(255, x))); }
static void rgb_to_yuv(const uint8_t* rgb, std::vector<uint8_t>& yuv) {
  for (int y = 0; y < height; ++y) for (int x = 0; x < width; ++x) {
    const auto* p = rgb + 4 * (y * width + x);
    int b = p[0], g = p[1], r = p[2];
    yuv[y * width + x] = clamp(((66*r + 129*g + 25*b + 128) >> 8) + 16);
    if (!(x & 1) && !(y & 1)) {
      int rb = 0, gb = 0, bb = 0;
      for (int dy = 0; dy < 2; ++dy) for (int dx = 0; dx < 2; ++dx) {
        const auto* q = rgb + 4 * ((y + dy) * width + x + dx);
        bb += q[0]; gb += q[1]; rb += q[2];
      }
      rb /= 4; gb /= 4; bb /= 4;
      int pos = (y/2) * (width/2) + x/2;
      yuv[width*height + pos] = clamp(((-38*rb - 74*gb + 112*bb + 128) >> 8) + 128);
      yuv[width*height*5/4 + pos] = clamp(((112*rb - 94*gb - 18*bb + 128) >> 8) + 128);
    }
  }
}
static void pattern(std::vector<uint8_t>& rgb, unsigned frame) {
  const uint8_t bars[8][3] = {{255,255,255},{255,255,0},{0,255,255},{0,255,0},
                             {255,0,255},{255,0,0},{0,0,255},{0,0,0}};
  const int marker = int(frame * 5 % (width - 40));
  for (int y = 0; y < height; ++y) for (int x = 0; x < width; ++x) {
    auto* p = rgb.data() + 4 * (y * width + x);
    const auto& c = bars[x * 8 / width];
    p[0] = c[2]; p[1] = c[1]; p[2] = c[0]; p[3] = 255;
    if (y > height - 80) p[0] = p[1] = p[2] = (x >= marker && x < marker + 40) ? 255 : 16;
  }
}
static bool is_cemu(DWORD pid) {
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return false;
  PROCESSENTRY32 entry{}; entry.dwSize = sizeof entry;
  bool found = false;
  if (Process32First(snapshot, &entry)) do {
    if (entry.th32ProcessID == pid) { found = !lstrcmpiA(entry.szExeFile, "Cemu.exe"); break; }
  } while (Process32Next(snapshot, &entry));
  CloseHandle(snapshot); return found;
}
static BOOL CALLBACK find_pad(HWND window, LPARAM context) {
  char title[256] = {};
  GetWindowTextA(window, title, sizeof title);
  if (!IsWindowVisible(window) || IsIconic(window) || strncmp(title, "GamePad View", 12)) return TRUE;
  DWORD pid = 0; GetWindowThreadProcessId(window, &pid);
  if (!is_cemu(pid)) return TRUE;
  *reinterpret_cast<HWND*>(context) = window; return FALSE;
}
class Capture {
  HDC dc_ = nullptr;
  HBITMAP bitmap_ = nullptr;
  HGDIOBJ old_ = nullptr;
  void* pixels_ = nullptr;
public:
  Capture() {
    dc_ = CreateCompatibleDC(nullptr);
    BITMAPINFO info{}; info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = width; info.bmiHeader.biHeight = -height;
    info.bmiHeader.biPlanes = 1; info.bmiHeader.biBitCount = 32; info.bmiHeader.biCompression = BI_RGB;
    bitmap_ = CreateDIBSection(dc_, &info, DIB_RGB_COLORS, &pixels_, nullptr, 0);
    if (bitmap_) old_ = SelectObject(dc_, bitmap_);
    SetStretchBltMode(dc_, COLORONCOLOR);
  }
  ~Capture() {
    if (old_) SelectObject(dc_, old_);
    if (bitmap_) DeleteObject(bitmap_);
    if (dc_) DeleteDC(dc_);
  }
  bool grab(HWND window, std::vector<uint8_t>& rgb) {
    RECT rect{};
    if (!pixels_ || !IsWindow(window) || IsIconic(window) || !GetClientRect(window, &rect) ||
        rect.right <= 0 || rect.bottom <= 0) return false;
    // GPU swapchains need the composed desktop, not the window's GDI backing
    // store (which can return a successful all-white capture). Capture only
    // this visible Cemu client rectangle; keep it uncovered and on screen.
    POINT origin{};
    if (!ClientToScreen(window, &origin)) return false;
    const int left = GetSystemMetrics(SM_XVIRTUALSCREEN);
    const int top = GetSystemMetrics(SM_YVIRTUALSCREEN);
    if (origin.x < left || origin.y < top ||
        origin.x + rect.right > left + GetSystemMetrics(SM_CXVIRTUALSCREEN) ||
        origin.y + rect.bottom > top + GetSystemMetrics(SM_CYVIRTUALSCREEN)) return false;
    HDC source = GetDC(nullptr);
    bool ok = source && StretchBlt(dc_, 0, 0, width, height, source, origin.x, origin.y,
                                  rect.right, rect.bottom, SRCCOPY | CAPTUREBLT);
    if (source) ReleaseDC(nullptr, source);
    if (ok) { GdiFlush(); memcpy(rgb.data(), pixels_, rgb.size()); }
    return ok;
  }
};
static void put32(uint8_t* p, uint32_t n) {
  for (int i = 0; i < 4; ++i) p[i] = uint8_t(n >> (8*i));
}
// A diagnostic Annex-B stream reconstructs the fixed GamePad SPS/PPS and
// slice header. The radio receives only raw CABAC chunks, never these headers.
static void dump_frame(FILE* file, const Encoded& coded, unsigned& number) {
  if (!file) return;
  const uint8_t start[] = {0,0,0,1};
  uint8_t header[] = {0x21,0xe0,3,0xff};
  if (coded.idr) { number = 0; header[0] = 0x25; header[1] = 0xb8; header[2] = 4; }
  else { number = (number + 1) & 255; header[1] |= number >> 3; header[2] |= number << 5; }
  fwrite(start, 1, 4, file); fwrite(header, 1, 4, file);
  int zeros = 0;
  for (const auto& chunk : coded.chunks) for (uint8_t byte : chunk) {
    if (zeros >= 2 && byte <= 3) { fputc(3, file); zeros = 0; }
    fputc(byte, file); zeros = byte == 0 ? zeros + 1 : 0;
  }
}
static std::atomic<bool> stopping{false};
static BOOL WINAPI stop_handler(DWORD event) {
  if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT) {
    stopping = true; return TRUE;
  }
  return FALSE;
}
int main(int argc, char** argv) {
  setvbuf(stderr, nullptr, _IONBF, 0);
  bool test = false, self_test = false;
  const char* dump_path = nullptr;
  int seconds = 120;
  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--test-pattern")) test = true;
    else if (!strcmp(argv[i], "--self-test")) self_test = test = true;
    else if (!strcmp(argv[i], "--seconds") && i + 1 < argc) seconds = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--dump") && i + 1 < argc) dump_path = argv[++i];
    else { fprintf(stderr, "Usage: wiiu-video [--test-pattern|--self-test] [--seconds 1..3600]\n"); return 1; }
  }
  if (seconds < 1 || seconds > 3600) return 1;
  if (dump_path && !self_test) { fprintf(stderr, "--dump requires --self-test\n"); return 1; }
  FILE* dump = dump_path ? fopen(dump_path, "wb") : nullptr;
  if (dump_path && !dump) return 1;
  if (dump) {
    const uint8_t headers[] = {0,0,0,1,0x67,0x64,0,0x20,0xac,0x2b,0x40,0x6c,0x1e,0xf3,0x68,
      0,0,0,1,0x68,0xee,6,0x0c,0xe8};
    fwrite(headers, 1, sizeof headers, dump);
  }
  unsigned dump_number = 0;
  auto dpi_aware = reinterpret_cast<BOOL (WINAPI*)()>(
      GetProcAddress(GetModuleHandleA("user32.dll"), "SetProcessDPIAware"));
  if (dpi_aware) dpi_aware();
  SetConsoleCtrlHandler(stop_handler, TRUE); timeBeginPeriod(1);
  WSADATA winsock; if (WSAStartup(MAKEWORD(2,2), &winsock)) return 1;
  SOCKET connection = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  sockaddr_in server{}; server.sin_family = AF_INET;
  server.sin_addr.s_addr = htonl(INADDR_LOOPBACK); server.sin_port = htons(26762);
  if (connection == INVALID_SOCKET || connect(connection, reinterpret_cast<sockaddr*>(&server), sizeof server)) return 1;
  u_long nonblocking = 1; ioctlsocket(connection, FIONBIO, &nonblocking);
  BOOL reset = FALSE; DWORD bytes = 0;
  WSAIoctl(connection, _WSAIOW(IOC_VENDOR,12), &reset, sizeof reset, nullptr, 0, &bytes, nullptr, nullptr);
  x264_param_t param;
  if (x264_param_default_preset(&param, "slow", "zerolatency")) return 1;
  param.i_width = width; param.i_height = height; param.i_csp = X264_CSP_I420;
  param.analyse.inter &= ~X264_ANALYSE_PSUB16x16;
  param.i_keyint_min = 10; param.i_keyint_max = 30; param.i_scenecut_threshold = -1;
  param.b_cabac = 1; param.b_interlaced = 0; param.i_bframe = 0; param.i_bframe_pyramid = 0;
  param.i_frame_reference = 1; param.b_constrained_intra = 1; param.b_intra_refresh = 1;
  param.analyse.i_weighted_pred = 0; param.analyse.b_weighted_bipred = 0;
  param.analyse.b_transform_8x8 = 0; param.analyse.i_chroma_qp_offset = 0;
  param.rc.i_rc_method = X264_RC_CQP;
  param.rc.i_qp_constant = param.rc.i_qp_min = param.rc.i_qp_max = 32; param.rc.f_ip_factor = 1;
  param.b_repeat_headers = 0; param.b_aud = 0; param.b_drh_mode = 1;
  param.i_threads = 1; param.b_sliced_threads = 0; param.i_slice_count = 1;
  param.nalu_process = nal_ready; param.i_log_level = X264_LOG_WARNING;
  if (x264_param_apply_profile(&param, "main")) return 1;
  x264_t* encoder = x264_encoder_open(&param);
  if (!encoder || x264_encoder_maximum_delayed_frames(encoder)) return 1;
  std::vector<uint8_t> rgb(width*height*4), yuv(width*height*3/2);
  Capture capture;
  HWND window = nullptr;
  Encoded coded;
  bool ready = self_test, want_idr = true;
  bool awaiting_frame = false;
  uint32_t awaiting_id = 0;
  uint64_t sent_time = 0;
  uint32_t epoch = 0;
  uint64_t status_time = 0, next_query = 0, next_frame = micros(), next_log = micros() + 2000000;
  const uint64_t end = micros() + uint64_t(seconds) * 1000000;
  unsigned frames = 0, skipped = 0;
  uint64_t encode_us = 0, payload_bytes = 0;
  fprintf(stderr, "Encoder: patched x264, 864x480, main/CABAC, five chunks; source=%s\n",
          test ? "test pattern" : "Cemu GamePad View");
  while (!stopping && micros() < end && (!self_test || frames < 60)) {
    uint64_t now = micros();
    if (!self_test && now >= next_query) {
      send(connection, "WUV?", 4, 0); next_query = now + 2000;
    }
    uint8_t status[64];
    int got;
    while ((got = recv(connection, reinterpret_cast<char*>(status), sizeof status, 0)) > 0) {
      if (got != 16 || memcmp(status, "WUVS", 4) || status[7] != 2) continue;
      uint32_t remote_epoch = status[8] | (uint32_t(status[9]) << 8) |
                              (uint32_t(status[10]) << 16) | (uint32_t(status[11]) << 24);
      if (remote_epoch != epoch) { want_idr = true; epoch = remote_epoch; awaiting_frame = false; }
      uint32_t accepted_id = status[12] | (uint32_t(status[13]) << 8) |
        (uint32_t(status[14]) << 16) | (uint32_t(status[15]) << 24);
      if (status[6] && accepted_id == awaiting_id) awaiting_frame = false;
      ready = status[4] != 0; want_idr = want_idr || status[5] != 0; status_time = now;
    }
    if (!self_test && (!ready || now - status_time > 1000000)) { Sleep(10); continue; }
    if (awaiting_frame) {
      if (now - sent_time < 250000) { Sleep(1); continue; }
      // A missing chunk or radio stall must not accumulate seconds of video.
      awaiting_frame = false; want_idr = true;
    }
    if (now < next_frame && !self_test) { Sleep(1); continue; }
    if (test) pattern(rgb, frames);
    else {
      if (!window || !IsWindow(window) || IsIconic(window)) {
        window = nullptr; EnumWindows(find_pad, reinterpret_cast<LPARAM>(&window));
      }
      if (!window || !capture.grab(window, rgb)) {
        if (now >= next_log) {
          fprintf(stderr, "Waiting for Cemu's visible separate GamePad View window.\n"); next_log = now + 2000000;
        }
        Sleep(50); continue;
      }
    }
    rgb_to_yuv(rgb.data(), yuv);
    x264_picture_t input{}, output{};
    input.img.i_csp = X264_CSP_I420; input.img.i_plane = 3;
    input.img.i_stride[0] = width; input.img.i_stride[1] = input.img.i_stride[2] = width/2;
    input.img.plane[0] = yuv.data(); input.img.plane[1] = yuv.data() + width*height;
    input.img.plane[2] = yuv.data() + width*height*5/4;
    input.i_type = want_idr || frames % 120 == 0 ? X264_TYPE_IDR : X264_TYPE_P;
    input.i_pts = frames; input.opaque = &coded; coded = {};
    x264_nal_t* nals = nullptr; int nal_count = 0;
    uint64_t start = micros();
    int encoded = x264_encoder_encode(encoder, &nals, &nal_count, &input, &output);
    encode_us += micros() - start;
    if (encoded < 0 || coded.invalid || coded.mask != 31) {
      ++skipped; want_idr = true;
      fprintf(stderr, "Invalid encoder frame: result=%d mask=%u\n", encoded, coded.mask);
      if (self_test) break;
      continue;
    }
    bool sent = true;
    for (int c = 0; c < 5; ++c) {
      coded.chunks[c].assign(coded.pointers[c], coded.pointers[c] + coded.sizes[c]);
      const auto& chunk = coded.chunks[c]; payload_bytes += chunk.size();
      if (!self_test) {
        std::vector<uint8_t> packet(12 + chunk.size(), 0);
        memcpy(packet.data(), "WUVC", 4); packet[4] = 1;
        packet[5] = coded.idr; packet[6] = uint8_t(c); put32(packet.data() + 8, frames);
        memcpy(packet.data() + 12, chunk.data(), chunk.size());
        sent = send(connection, reinterpret_cast<const char*>(packet.data()), int(packet.size()), 0) == int(packet.size()) && sent;
      }
    }
    dump_frame(dump, coded, dump_number);
    awaiting_frame = !self_test && sent; awaiting_id = frames; sent_time = micros();
    want_idr = !sent; ++frames;
    next_frame += 16683;
    if (next_frame < micros()) next_frame = micros();
    if (!self_test && now >= next_log) {
      unsigned white = 0;
      for (size_t pixel = 0; pixel < rgb.size(); pixel += 4)
        white += rgb[pixel] > 245 && rgb[pixel+1] > 245 && rgb[pixel+2] > 245;
      fprintf(stderr, "encoded=%u skipped=%u avg_encode_ms=%.2f bytes=%llu white_pct=%.1f\n", frames, skipped,
              frames ? encode_us / double(frames) / 1000 : 0, (unsigned long long)payload_bytes,
              100.0 * white / (width * height));
      next_log = now + 2000000;
    }
  }
  x264_encoder_close(encoder); closesocket(connection); WSACleanup(); timeEndPeriod(1);
  if (dump) fclose(dump);
  fprintf(stderr, "Encoder complete: frames=%u skipped=%u avg_encode_ms=%.2f\n",
          frames, skipped, frames ? encode_us / double(frames) / 1000 : 0);
  return skipped || !frames ? 2 : 0;
}
