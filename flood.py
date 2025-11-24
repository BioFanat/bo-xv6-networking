# use by python flood.py --dst 127.0.0.1 --port 26500 --pps [] --secs [] --size []

import argparse
import os
import socket
import time

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dst", default="127.0.0.1", help="destination IP (host side)")
    ap.add_argument("--port", type=int, help="destination port (probably 26500 for QEMU)")
    ap.add_argument("--pps", type=int, help="packets per second")
    ap.add_argument("--secs", type=int, help="duration in seconds")
    ap.add_argument("--size", type=int, help="payload size in bytes")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    payload = os.urandom(args.size)
    def next_payload():
        return payload

    interval = 1.0 / args.pps if args.pps > 0 else 0.0
    deadline = time.time() + args.secs
    sent = 0
    next_send = time.time()

    while time.time() < deadline:
        sock.sendto(next_payload(), (args.dst, args.port))
        sent += 1
        if interval > 0:
            next_send += interval
            pause = next_send - time.time()
            if pause > 0:
                time.sleep(pause)

    rate = sent / args.secs if args.secs > 0 else 0
    print(f"sent {sent} packets, size={args.size if not args.nettest else 'varies'} bytes, "
          f"pps≈{rate:.1f}, dst={args.dst}:{args.port}, nettest={args.nettest}")

if __name__ == "__main__":
    main()
