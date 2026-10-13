# Wii U GamePad / Cemu handoff — 2026-10-12

The user requested a stopping point and detailed notes after the final radio
test. Resume from this file and `docs/wiiu-gamepad.md`. Do not assume video is
stable or restart another long experiment without checking the user's readiness.

## Confirmed outcome and unresolved problem

- Physical buttons and sticks reached Cemu; the user reported buttons working
  in a game. The normal profile is **Physical Wii U GamePad**, direct DSU
  `127.0.0.1:26760`, Controller 1. PlayStation button names in DSU are expected:
  Wii U A/B/X/Y map to Circle/Cross/Triangle/Square.
- Animated color bars and actual Cemu game pictures reached the physical
  screen. Video still froze, glitched and jumped. This is a prototype.
- Timestamp adjustment improved jumping but did not eliminate freezing.
- The one-frame-in-flight / USB batch run eventually showed a **white screen**
  on the physical pad while the PC's GamePad View still showed the game.
  Recovery requests and command replies stopped, despite the bridge continuing
  to send video. Therefore a quiet resync log is NOT evidence of recovery.

## Hardware, applications and credentials

- Alfa AWUS036ACH / RTL8812AU `0bda:8812`, WinUSB, channel 161.
- Keep the real console and VirtualBox VM off. This setup uses Windows only.
- GamePad `40:d2:8a:11:36:31`; emulated console BSSID `9c:e6:35:3e:4c:d1`.
- Pairing configuration is ignored `secrets/vanilla-config.xml`. Never print
  its PSK. The complete 48-byte PTK rotation `ptk3` is required.
- Isolated AP console IP `192.168.1.10`, pad `192.168.1.11`. No LAN bridging.
- Cemu executable: `C:\Users\Angelo K\OneDrive\Desktop\Cemu_2.6\Cemu.exe`.
  Source clone: `C:\Users\Angelo K\cemu`. Active settings/profiles are under
  `%APPDATA%\Cemu`, not the source tree. Do not read or print `keys.txt`.
- Working recent game: `D:\U\Paper Mario - Color Splash (USA) (En,Fr,Es).wux`.
- Fully restart Cemu after restarting the AP: its cached DSU subscription does
  not automatically register with a fresh bridge. `open_pad` was enabled in
  Cemu settings, with backup `build/wiiu/cemu-settings-before-video.xml`.

## Current implementation

- `tests/ap_wiiu.cpp`: Windows AP bring-up, WPA, CCMP, DHCP, HID/DSU, video
  ingress, TSF clock sampling and batched USB TX. The session lock protects
  keys/CCMP packet numbers; never perform synchronous libusb transfers under
  that lock because completion can dispatch RX callbacks and deadlock.
- `tests/wiiu_stream.h`: five-chunk video packetizer, silent audio, UVC
  keepalive/reply ACK, IDR requests, loopback ingress `127.0.0.1:26762`.
  Status protocol version 2 includes accepted frame ID so the encoder keeps
  only one frame in flight. Credit confirms bridge submission, not pad decode.
- `tools/wiiu-video.cpp`: separate 32-bit static patched-x264 encoder, 864x480
  I420, main/CABAC, five 6-macroblock-row chunks, QP32, one reference, no B
  frames/weighted prediction/8x8 transform. Uses upstream slow/zerolatency.
  Retain callback pointers until encoding completes before copying CABAC data:
  carry propagation can alter the previous chunk's last byte.
- Final changes: Jaguar1 honors explicit radiotap NOACK choices for unicast.
  Missing TX_FLAGS retain historical no-ACK; group/short receivers never ACK.
  Video launcher sets USB aggregation 32. See `src/jaguar1/TxAckPolicy.h` and
  `tests/radiotap_noack_selftest.cpp`. The ACK/three-retry physical experiment
  FAILED: no color bars and connection screen persisted. The launcher and AP
  therefore default to the prior no-ACK behavior, retry limit zero.
  `-AckRetries` opts into the failed path for diagnosis; avoid it for normal use.
- Final capture change: sample only the Cemu client rectangle from the composed
  desktop rather than its GDI window backing store. The all-white failure
  suggests the old capture path was unreliable for GPU rendering. This change
  is built but has not yet been tested with Cemu. GamePad View must stay fully
  on screen, visible and uncovered. Logs now include `white_pct` for diagnosis.
- `ready=1` currently means keyed + HID seen at least once + valid TSF. It
  does not guarantee recent HID, UVC replies, or a functioning decoder.

## Build and validation

`tools/build-wiiu-video.ps1` uses existing Git Bash and 32-bit MinGW GCC6.3
in `C:\MinGW\bin`. It pins `opencma/drc-x264` to
`7f1eb42e818519efe339aac77260d0b0e884e6dd`, downloads official Yasm1.3.0 with
SHA256 verification, and fixes upstream Windows dependency-command truncation.
Sources, tools, binaries and logs are ignored under `build/wiiu`.

The six relevant CTests passed after the ACK-policy change:

```powershell
cmake --build build --config Release --target ap_wiiu CcmpSelftest SupplicantSelftest WiiuStreamSelftest RadiotapNoackSelftest RadiotapTxFlagsSelftest
ctest --test-dir build -C Release --output-on-failure -R '^(ap_wiiu_headless|ccmp_framing|supplicant|wiiu_stream|radiotap_noack|radiotap_txflags)$'
```

The final encoder build passed all 60 self-test frames, zero skips, ~1.40 ms
per test-pattern frame. Earlier reconstructed Annex-B output decoded with
FFmpeg without warnings and its image was visually verified. Live in-game
encoding was ~5–6 ms for ordinary frames, ~15 ms when repeated recovery forced
IDRs. SIMD improved encoding but initially worsened physical glitches.
Video packet timestamps currently use interpolated radio TSF minus 16,683 us.

## Resume sequence

1. Confirm readiness and current hardware state. Console/VM off; Alfa plugged
   in; power-cycle the pad if it remains white or does not reconnect.
2. From a normal PowerShell on the user's desktop:
   `./tools/wiiu-gamepad.ps1 -Seconds 120 -Video TestPattern`.
3. After it stops, start `./tools/wiiu-gamepad.ps1 -Seconds 600 -Video Cemu`,
   then open Cemu normally and launch the recent game. Keep **Options >
   Separate GamePad view** visible, uncovered and entirely on screen.
4. Compare actual pad behavior with frame/packet counts, UVC replies, resync
   rates, `white_pct`, and a DSU probe. Do not equate submitted USB packets or
   accepted loopback frames with successful radio delivery.
5. Next isolate ACK/retry effects, capture correctness and packet timing. A
   fixed test pattern helps separate radio/decoder problems from GPU capture.
   Higher compatible PHY rates may be worth testing only after that baseline.

```powershell
python tests/wiiu_dsu_probe.py --seconds 10
```

Automated launches inside the default sandbox use a different desktop and
cannot capture the user's Cemu. Launch capture/Cemu on the actual desktop with
approved external execution, or have the user run the commands normally.
Native computer-use runtime was unavailable; do not use alternate UI-automation
APIs to circumvent that failure. The companion capture is product functionality.

No commit or push was made. Existing modified reference submodules were left
untouched. Motion fields remain zero; game audio is silent; rumble, microphone,
camera and per-device touch calibration remain future work.

## Final radio test and shutdown

Four-minute ACK/retry test-pattern run: the user power-cycled the pad and
reported **no color bars / still searching**. At first, the bridge reached
`ready=1` and submitted frames but received only one UVC reply and no resyncs.
Later UVC replies and resyncs resumed; no later physical-screen observation
was requested because the user wanted a stopping point. Do not claim that
the picture recovered. The default was restored to no-ACK, with ACK/retry
available only as an opt-in diagnostic.

Final counters: 8,864 submitted frames, 44,320 video packets, 64 UVC replies,
1,829 resync requests, zero software queue drops. Network: four DHCP offers,
four ACKs, four ARP responses, 13,251 UDP packets, 13,263 decryptions, one MIC
failure. Encoder: 8,865 frames, zero skipped, average 1.41 ms. These are host
counters, not successful physical decode counts.

Logs: `build/wiiu/ap-video-ack-pattern.log` and preserved
`build/wiiu/video-encoder-ack-pattern.log` (the normal encoder log is overwritten
on the next run). No-ACK `ap_wiiu` and `ap_wiiu_video` binaries were rebuilt;
the capture helper includes the composed-desktop change. Six CTests passed
again after default restoration; both PowerShell scripts parsed without errors.

At **23:04 EDT on 2026-10-12**, the timed run exited with code zero after its
normal StopRx/StopBeacon/Stop teardown. No beacon-stop warning appeared. No
AP, encoder or Cemu process remained. No further radio test or Cemu launch was
started. The pad may remain on; it is fine to turn it off. No commit or push.
