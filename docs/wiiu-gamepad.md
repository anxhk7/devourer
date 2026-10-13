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
  Verification of movement and face buttons in a game is pending: the user
  currently has no game installed and will set one up.
  The temporary relay profile was removed after the normal profile worked.

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

## Run

From the repository root in PowerShell:

```powershell
.\tools\wiiu-gamepad.ps1 -Build -Seconds 600
```

For a later one-hour playing/testing session, use `-Seconds 3600`; omit `-Build`
when the current binary is already built. Start the bridge before opening Cemu.
Run only one bridge process at a time. The current session started at 20:34
and is scheduled to stop at about 21:04 local PC time on 2026-10-12.

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
cmake --build build --config Release --target ap_wiiu CcmpSelftest SupplicantSelftest
ctest --test-dir build -C Release --output-on-failure -R '^(ap_wiiu_headless|ccmp_framing|supplicant)$'
```

All three passed. AP headless cells cover 16 Linux-encrypted QoS vectors,
the real receive path, FCS-present/absent frames, corrupt/truncated frames,
IE lengths, DHCP offer/ack and malformed options, DSU CRC32 and control encoding.

## Remaining work

- Video and audio are absent. The physical screen will not mirror Cemu yet.
  The GamePad periodically reconnects; investigate missing stream/command
  initialization and session retransmission handling rather than changing PTK.
- Add the DRC command/stream service, using libdrc's existing packetization
  and encoder requirements. Feed Cemu's separate GamePad view into it.
- Validate gyro/accelerometer units, bias and axes; then populate DSU motion.
  Current DSU motion fields are zero, model is DS3/partial motion.
- Touch encoding uses libdrc's approximate default calibration; actual
  per-device UIC calibration and touch accuracy still require validation.
- DSU runs at about 64 Hz here, despite HID arriving around 180 Hz. Windows
  sleep resolution and the polling loop need latency work before calling this
  a finished gaming setup. Home/TV, rumble, microphone and camera are pending.
- The AP is still a bring-up harness, not a hardened authenticator. Add replay
  rejection, complete handshake retry/session management and packet checks
  before treating it as a production service.

Logs from this session are in ignored `build/gamepad-*.log`. The external
Claude handoff in Downloads was not changed. Existing modified vendor
submodules were not touched.

Reference protocol: [libdrc network services](https://garyodernichts.github.io/libdrc/docs/re/services.html)
and [Cemuhook DSU](https://v1993.github.io/cemuhook-protocol/).
