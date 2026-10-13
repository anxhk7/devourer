"""Read-only DSU protocol check against the live Windows GamePad bridge."""
import argparse
import json
import socket
import struct
import time
import zlib


def request(kind, body=b""):
    p = bytearray(struct.pack("<4sHHIII", b"DSUC", 1001, 4 + len(body), 0, 1234, kind) + body)
    struct.pack_into("<I", p, 8, zlib.crc32(p))
    return p


def validate(p):
    assert len(p) >= 20 and p[:4] == b"DSUS", "invalid DSU header"
    assert struct.unpack_from("<H", p, 4)[0] == 1001, "protocol version"
    assert struct.unpack_from("<H", p, 6)[0] == len(p) - 16, "packet size"
    expected = struct.unpack_from("<I", p, 8)[0]
    zeroed = bytearray(p)
    zeroed[8:12] = b"\0" * 4
    assert zlib.crc32(zeroed) == expected, "DSU CRC32 mismatch"
    return struct.unpack_from("<I", p, 16)[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=float, default=10)
    parser.add_argument("--port", type=int, default=26760)
    args = parser.parse_args()
    target = ("127.0.0.1", args.port)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        s.settimeout(2)
        s.sendto(request(0x100000), target)
        p, _ = s.recvfrom(1024)
        assert validate(p) == 0x100000 and struct.unpack_from("<H", p, 20)[0] == 1001
        s.sendto(request(0x100001, struct.pack("<I4B", 4, 0, 1, 2, 3)), target)
        slots = {}
        for _ in range(4):
            p, _ = s.recvfrom(1024)
            assert validate(p) == 0x100001 and len(p) == 32
            slots[p[20]] = p[21]
        print(json.dumps({"version": 1001, "slots": slots}), flush=True)
        end = time.monotonic() + args.seconds
        next_sub = 0
        packets = connected = 0
        indices, buttons = set(), set()
        previous = None
        while time.monotonic() < end:
            if time.monotonic() >= next_sub:
                s.sendto(request(0x100002, bytes(8)), target)
                next_sub = time.monotonic() + 1
            p, _ = s.recvfrom(1024)
            assert validate(p) == 0x100002 and len(p) == 100
            packets += 1
            if p[31]:
                connected += 1
                indices.add(struct.unpack_from("<I", p, 32)[0])
                buttons.add(p[36] | (p[37] << 8))
                state = {"buttons": f"{p[36]:02x}{p[37]:02x}",
                         "sticks": list(p[40:44]), "touch": bool(p[56]),
                         "xy": list(struct.unpack_from("<HH", p, 58))}
                if state != previous:
                    print(json.dumps(state), flush=True)
                    previous = state
        print(json.dumps({"packets": packets, "connected_packets": connected,
                          "distinct_input_reports": len(indices),
                          "button_states": len(buttons), "crc": "PASS"}), flush=True)
        assert connected and len(indices) > 1, "no live GamePad input in DSU"


if __name__ == "__main__":
    main()
