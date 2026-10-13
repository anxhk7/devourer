"""Temporary loopback-only DSU relay: observe Cemu without altering packets."""
import argparse
import collections
import json
import selectors
import socket
import struct
import time
from wiiu_dsu_probe import validate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--seconds', type=float, default=300)
    parser.add_argument('--port', type=int, default=26761)
    parser.add_argument('--upstream-port', type=int, default=26760)
    args = parser.parse_args()
    counts = collections.Counter()
    seen_requests = set()
    previous = None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as front, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as back, \
         selectors.DefaultSelector() as selector:
        front.bind(('127.0.0.1', args.port))
        back.bind(('127.0.0.1', 0))
        back.connect(('127.0.0.1', args.upstream_port))
        selector.register(front, selectors.EVENT_READ)
        selector.register(back, selectors.EVENT_READ)
        client = None
        client_expires = 0
        end = time.monotonic() + args.seconds
        next_summary = time.monotonic() + 10
        print(json.dumps({'relay': args.port, 'upstream': args.upstream_port}), flush=True)
        while time.monotonic() < end:
            for key, _ in selector.select(timeout=0.25):
                if key.fileobj is front:
                    try:
                        packet, client = front.recvfrom(2048)
                    except ConnectionResetError:
                        # Windows reports ICMP port-unreachable after a client exits.
                        continue
                    client_expires = time.monotonic() + 5
                    kind = struct.unpack_from('<I', packet, 16)[0] if len(packet) >= 20 else 0
                    counts[f'request_{kind:x}'] += 1
                    identity = (client, kind, packet[20:])
                    if identity not in seen_requests:
                        seen_requests.add(identity)
                        print(json.dumps({'client': client, 'request': f'{kind:x}',
                                          'size': len(packet), 'body': packet[20:].hex()}), flush=True)
                    back.send(packet)
                else:
                    packet = back.recv(2048)
                    kind = validate(packet)
                    counts[f'response_{kind:x}'] += 1
                    if client and time.monotonic() < client_expires:
                        front.sendto(packet, client)
                    if kind == 0x100002:
                        state = (packet[21], packet[31], packet[36:44])
                        if state != previous:
                            previous = state
                            print(json.dumps({'state': packet[21], 'active': packet[31],
                                              'buttons': packet[36:38].hex(),
                                              'sticks': list(packet[40:44])}), flush=True)
            if time.monotonic() >= next_summary:
                print(json.dumps(dict(counts)), flush=True)
                next_summary = time.monotonic() + 10
        print(json.dumps(dict(counts)), flush=True)


if __name__ == '__main__':
    main()
