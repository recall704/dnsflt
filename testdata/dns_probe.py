"""Minimal DNS A/AAAA probe: dns_probe.py <server> <port> <name> [name...]"""
import random
import socket
import struct
import sys


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("idna")
    return out + b"\x00"


def build(tid, name, qtype, edns=False):
    arcount = 1 if edns else 0
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, arcount)
    msg = header + encode_name(name) + struct.pack(">HH", qtype, 1)
    if edns:
        # OPT pseudo-RR: root name, type 41, udp payload size, DO=0.
        msg += b"\x00" + struct.pack(">HHIH", 41, 1232, 0, 0)
    return msg


def parse_name(data, off):
    parts = []
    while True:
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            sub, _ = parse_name(data, ptr)
            parts.append(sub)
            off += 2
            return ".".join(parts), off
        parts.append(data[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(parts), off


def main():
    server, port = sys.argv[1], int(sys.argv[2])
    names = sys.argv[3:]
    qtypes = [("A", 1), ("AAAA", 28)]
    for name in names:
        for qname, qtype, edns in [("A", 1, False), ("AAAA", 28, False),
                                   ("A+edns", 1, True), ("AAAA+edns", 28, True)]:
            tid = random.randint(1, 0xFFFF)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(4.0)
            try:
                sock.sendto(build(tid, name, qtype, edns), (server, port))
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                print(f"{name:<14} {qname:<10} TIMEOUT")
                sock.close()
                continue
            except OSError as exc:
                print(f"{name:<14} {qname:<10} ERROR {exc}")
                sock.close()
                continue
            sock.close()
            rtid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
            rcode = flags & 0xF
            off = 12
            for _ in range(qd):
                _, off = parse_name(data, off)
                off += 4
            answers = []
            for _ in range(an):
                _, off = parse_name(data, off)
                rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
                off += 10
                rdata = data[off:off + rdlen]
                off += rdlen
                if rtype == 1 and rdlen == 4:
                    answers.append(".".join(str(b) for b in rdata))
                elif rtype == 28 and rdlen == 16:
                    answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
            if an == 0:
                # NOERROR/NODATA means the query really reached a resolver.
                answers.append(f"<no answer rcode={rcode}>")
            print(f"{name:<14} {qname:<10} tid_ok={rtid == tid} rcode={rcode} {' '.join(answers)}")


main()