"""Replicate dnsflt's upstream socket: bind 0.0.0.0:0, connect(), send, recv.

dnsflt opens its upstream socket exactly this way (src/upstream.rs::UdpClient::start),
so this tells us whether `connect()`ed UDP plus an nslookup-shaped query is what
the gateway chokes on -- rather than anything WinDivert does.
"""
import binascii
import random
import socket
import struct
import sys
import time


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def build(tid, name):
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack(">HH", 1, 1)


server = sys.argv[1]
port = int(sys.argv[2])
name = sys.argv[3]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 0))
local = sock.getsockname()
sock.connect((server, port))
print(f"local={local[0]}:{local[1]} connected to {server}:{port}", flush=True)

tid = random.randint(1, 0xFFFF)
query = build(tid, name)
print(f"txid=0x{tid:04x} len={len(query)} hex={binascii.hexlify(query).decode()}", flush=True)

start = time.monotonic()
sock.send(query)
try:
    data, peer = sock.recvfrom(4096)
except socket.timeout:
    print(f"TIMEOUT after {time.monotonic() - start:.3f}s")
    sys.exit(1)
elapsed = time.monotonic() - start
rtid = struct.unpack(">H", data[:2])[0]
print(f"rx from {peer} len={len(data)} rtt={elapsed * 1000:.1f}ms tid_ok={rtid == tid}")
print(f"hex={binascii.hexlify(data).decode()}")