# Physical Wii U GamePad on Windows: current status

Updated 2026-10-12. Goal: physical GamePad input and screen with Cemu, using
the Alfa RTL8812AU on Windows without a Linux device in the final setup.

## Verified on this PC

- `ap_wiiu` builds against the real library with MSVC, libusb and OpenSSL.
- Passive scan saw 68 directed probes from `40:d2:8a:11:36:31` for
  `WiiU9ce6353e4cd1`, across multiple 5 GHz channels.
- The real GamePad completed the WPA handshake and decrypted with **ptk3**.
  The PSK previously captured by Vanilla is valid for this GamePad's pairing.
- Encrypted DHCP OFFER/ACK leased `192.168.1.11`. Encrypted ARP identifies
  the console endpoint as `192.168.1.10`.
- The 60-second network test received 9,081 UDP packets, including 128-byte
  HID reports from port 50122 to port 50022. There were 9,090 successful
  decryptions and one failed MIC; the GamePad associated three times.
- A subsequent five-minute DSU run received 50,646 UDP packets with 50,661
  successful decryptions and three failed MICs; the GamePad associated five times.
- Loopback DSU at `127.0.0.1:26760` exposes slot 0 as Cemu's Controller 1.
  An independent UDP probe validated version, four slot replies, 100-byte
  input packets and CRC32. A/B presses and both sticks reached DSU in a user-led
  20-second test: 1,272 reports, all connected, 1,269 distinct HID counters.
  Cemu detected the controller and the user added it, but manual mapping stalled.
  A complete named profile was installed in the active Cemu profile directory.
  A transparent relay confirmed that Cemu accepted 1,918 input responses and
  renewed its subscription for every response. After fully restarting Cemu,
  the user confirmed both stick indicators move with the normal direct profile.
  At 21:52 EDT on 2026-10-12, the user reported that buttons seem to work in a
  game. Physical GamePad input has therefore reached in-game operation; a full
  per-button, stick-direction and touchscreen validation matrix is still pending.
  The temporary relay profile was removed after the normal profile worked.
- Physical-screen video is now demonstrated: the user saw animated color bars,
  then Cemu's actual game picture. These tests also showed intermittent motion,
  picture jumps, freezes and frequent GamePad resync requests. This is a working
  video prototype, not yet a stable playing setup.
- The Windows companion captures only Cemu's visible separate GamePad View,
  converts to 864x480 I420, and uses patched x264. Yasm acceleration reduced
  color-bar encode time from roughly 10 ms to 1.5 ms and typical game-frame
  encoding from 25–30 ms to 5–6 ms. Faster encoding alone did not fix the
  physical picture; the user reported worse glitches in the first fast run.

## Corrections to the Claude handoff

1. Full 48-byte PTK rotation before splitting KCK/KEK/TK is confirmed, both
   on hardware and in Vanilla's actual [drc-hostap patch](https://github.com/vanilla-wiiu/drc-hostap/blob/a2f705daa143791180754100194c91714f7e8801/src/common/wpa_common.c).
   The ordinary `vanilla-wiiu/hostap` repository is not the patch Vanilla builds.
2. A failed CCMP MIC alone does not imply the wrong key. The old AP omitted
   QoS AAD/TID handling and included the adapter's trailing FCS as ciphertext.
   Both are fixed by reusing the tested CCMP helpers and trimming only when
   `RxAtrib.fcs_present` is set. HT Control header lengths are handled too.
3. The reconstructed HT Operation IE was one byte too short. Fixed and tested.
   Association replies now carry the RSN/WMM IEs and the correct reassoc subtype.
4. The GamePad scans multiple channels. The impersonating AP does not have to
   use the real console's last channel; channel 161 worked with the console off.
5. Cemu's DSU implementation accepts buttons, sticks and touchscreen positions,
   in addition to motion. No ViGEmBus or Wintun is needed for the input prototype.
6. For video, the handoff's constrained-baseline description is inaccurate for
   the libdrc encoder being evaluated. Its [encoder implementation](https://github.com/GaryOderNichts/libdrc/blob/master/src/h264-encoder.cpp)
   selects the main profile and CABAC, and requires patched x264's `b_drh_mode`
   to return macroblock-row chunks without planar prediction. Ordinary FFmpeg
   H.264 output is not a substitute for that encoder interface.

## Run

From the repository root in PowerShell:

```powershell
.\tools\wiiu-gamepad.ps1 -Build -Seconds 600
```

For a later one-hour playing/testing session, use `-Seconds 3600`; omit `-Build`
when the current binary is already built. Start the bridge before opening Cemu.
Run only one bridge process at a time. Each run stops after the chosen duration.

Keep the real console fully off and the VirtualBox VM off. The adapter must
still use WinUSB. Pairing credentials remain in ignored
`secrets/vanilla-config.xml`; they are never printed or put on the command line.
The launcher restores process environment variables after the run.

Passive, non-beaconing scan:

```powershell
.\tools\wiiu-gamepad.ps1 -Scan -Seconds 30
```

In Cemu: Options > Input settings > Controller 1 > Emulated controller:
Wii U GamePad > + > API: DSUController > IP: 127.0.0.1 > Port: 26760 >
Controller: Controller 1 > Add.

For this PC, a ready-made **Physical Wii U GamePad** profile is installed in
`%APPDATA%/Cemu/controllerProfiles`. Reopen Input settings, select Controller 1,
select that profile and click Load. It supplies all 24 button/stick mappings.
The reusable source is `tools/profiles/Physical Wii U GamePad.xml`; on another
installation, copy it into the active Cemu `controllerProfiles` directory.

Release every button and both sticks, then click Calibrate. Cemu ignores buttons
held during calibration until calibrated again. Check that both stick indicators
move, then verify input in a game. The bridge must remain running throughout.
Selecting a controller in the dropdown alone does not prove live input reception.
If the bridge process restarts while Cemu is open, restart Cemu too. Cemu 2.6
requests the next DSU packet upon receiving a reply and caches the connected
state. A restarted bridge loses subscribers, so that exchange can stall even
though the selected controller still looks connected. A fresh Cemu provider
restores the subscription; the one-off diagnostic profile demonstrated this.
DSU uses PlayStation labels: A=Circle, B=Cross, X=Triangle, Y=Square,
L=L, R=R, ZL=ZL, ZR=ZR, Plus=Options, Minus=Share.
Motion is not yet implemented; leave its Cemu setting disabled for this prototype.

## Video prototype

Build the encoder and video bridge on this PC:

```powershell
.\tools\build-wiiu-video.ps1
```

This uses Git for Windows, the existing 32-bit MinGW compiler, and the pinned
`opencma/drc-x264` revision `7f1eb42e818519efe339aac77260d0b0e884e6dd`.
The script downloads official Yasm 1.3.0 into ignored `build/wiiu`, checks its
SHA-256, enables x264 assembly, and rewrites the dependency-generation recipe
into a per-source loop to avoid Windows command truncation. No global tool
installation or PATH change is required. `-RebuildEncoder` forces a clean build.
The companion is statically linked and separate from the MSVC radio process.

Run from a normal PowerShell window on your desktop:

```powershell
.\tools\wiiu-gamepad.ps1 -Seconds 120 -Video TestPattern
.\tools\wiiu-gamepad.ps1 -Seconds 3600 -Video Cemu
```

Run these sequentially. Start the bridge before Cemu. Enable **Options >
Separate GamePad view** and keep that window visible and unminimized. The
capture helper must run on the same Windows desktop as Cemu; a sandboxed helper
could not see the user's window. Keep the entire GamePad View client area on
screen and uncovered: capture now samples its rectangle from the composed
desktop, because the window's GDI backing store can return a white image for a
GPU renderer. Encoder logs include the percentage of near-white pixels.
The default encrypted data rate is 24 Mbps;
`-DataRate 6M` is available for radio diagnosis. Management frames remain 6 Mbps.
Both modes continue exposing DSU input. Encoder diagnostics are written to
`build/wiiu/video-encoder.log`; Ctrl+C stops the bridge and its companion.

The native bridge packetizes five raw CABAC chunks per frame, sends silent
48-kHz audio and UVC keepalives, and handles command acknowledgements and IDR
requests. Loopback encoder ingress is `127.0.0.1:26762`. Frame timestamps use
the radio's TSF clock; a one-frame timestamp age is being tested to match
libdrc's encode-then-send timing. The encoder waits for loopback credit after
each frame, preventing a growing queue of stale video. USB packets are submitted
in batches (up to 32). Jaguar1 now honors explicit
radiotap TX_FLAGS while preserving no-ACK when the field is absent. These are
recovery experiments requiring physical verification, not stability claims.
The ACK/three-retry test failed physically: the user saw no color bars and the
connection screen remained. **No-ACK remains the default**, preserving the
earlier radio behavior. `-AckRetries` enables the failed experimental path for
future diagnosis without rebuilding; it should not be used for normal play.
CABAC buffers are copied after the complete
frame, since later encoding can change an earlier chunk's final byte. USB calls
must execute outside the receive callback's session lock, as synchronous
libusb completion can dispatch that callback.

Read-only independent protocol check while the bridge runs:

```powershell
python tests/wiiu_dsu_probe.py --seconds 10
```

For DSU exchange diagnostics, `tests/wiiu_dsu_relay.py --seconds 600` relays
loopback port 26761 to 26760 without modifying packets. Point a temporary Cemu
profile at 26761 to observe actual requests, input replies and button/stick
changes. The normal profile uses 26760 and does not require this relay.

## Tests

```powershell
cmake --build build --config Release --target ap_wiiu CcmpSelftest SupplicantSelftest WiiuStreamSelftest RadiotapNoackSelftest RadiotapTxFlagsSelftest
ctest --test-dir build -C Release --output-on-failure -R '^(ap_wiiu_headless|ccmp_framing|supplicant|wiiu_stream|radiotap_noack|radiotap_txflags)$'
```

All six passed. ACK tests cover actual radiotap layouts, explicit unicast ACK,
group receivers, missing flags and truncated receiver addresses. AP headless
cells cover 16 Linux-encrypted QoS vectors,
the real receive path, FCS-present/absent frames, corrupt/truncated frames,
IE lengths, DHCP offer/ack and malformed options, DSU CRC32 and control encoding.
Stream fixtures cover packet flags, chunk splitting, sequence wrap, IPv4/UDP
lengths, recovery without dropping P frames, silent audio and command ACKs.
An actual loopback UDP test checks reordered chunks and frame-credit reset.
The encoder's 60-frame self-test returns all five chunks for every frame. Its
diagnostic Annex-B reconstruction decoded without FFmpeg warnings and the
decoded image was visually checked. To reproduce that independent check:

```powershell
build\wiiu\wiiu-video.exe --self-test --seconds 15 --dump build\wiiu\pattern.h264
ffmpeg -hide_banner -v warning -i build\wiiu\pattern.h264 -f null -
```

## Remaining work

- Stabilize video delivery and recovery. Actual Cemu video reached the physical
  screen, but frequent resyncs, glitches and freezing remain under investigation.
  Clock timing and USB/radio scheduling need physical validation. Audio is
  currently silence; game audio capture/encoding is not implemented.
- Validate gyro/accelerometer units, bias and axes; then populate DSU motion.
  Current DSU motion fields are zero, model is DS3/partial motion.
- Touch encoding uses libdrc's approximate default calibration; actual
  per-device UIC calibration and touch accuracy still require validation.
- A 1-ms Windows timer/polling loop replaced the earlier 64-Hz limitation.
  A three-second probe during video received 503 connected input reports with
  valid CRCs and 500 distinct HID counters. End-to-end gaming latency still
  needs measurement. Home/TV, rumble, microphone and camera are pending.
- The AP is still a bring-up harness, not a hardened authenticator. Add replay
  rejection, complete handshake retry/session management and packet checks
  before treating it as a production service.

Logs from this session are in ignored `build/gamepad-*.log`. The external
Claude handoff in Downloads was not changed. Existing modified vendor
submodules were not touched.

Reference protocol: [libdrc network services](https://garyodernichts.github.io/libdrc/docs/re/services.html)
and [Cemuhook DSU](https://v1993.github.io/cemuhook-protocol/).
