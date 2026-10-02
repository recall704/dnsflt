"""Minimal fake DNS upstream for dnsflt end-to-end testing.

Answers every A query with a fixed address and logs what it received, so we
can prove dnsflt actually forwarded the client's question (ID + QNAME) rather
than fabricating a reply locally.

    python fake_upstream.py [port]
"""
import binascii
import os
import socket
import struct
import sys

RAW = os.environ.get("UPSTREAM_RAW") == "1"   # log every datagram, valid or not

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 1053
ANSWER_IP = "203.0.113.7"          # TEST-NET-3, RFC 5737: unambiguously fake

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", PORT))
print(f"fake upstream listening on 0.0.0.0:{PORT}, answers A with {ANSWER_IP}",
      flush=True)

def decode_name(data, off):
    """Decode a (possibly compressed) DNS name; return (labels, new_off)."""
    labels, jumped_to = [], None
    while True:
        if off >= len(data):
            raise ValueError("name overruns message")
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:                      # compression pointer
            ptr = struct.unpack_from("!H", data, off)[0] & 0x3FFF
            if jumped_to is None:
                jumped_to = off + 2
            off = ptr
            continue
        off += 1
        labels.append(data[off:off + ln].decode("ascii", "replace"))
        off += ln
    if jumped_to is not None:
        off = jumped_to
    return labels, off

while True:
    try:
        data, peer = sock.recvfrom(65535)
    except KeyboardInterrupt:
        break

    if RAW:
        print(f"[raw] from {peer[0]}:{peer[1]} len={len(data)} "
              f"hex={binascii.hexlify(data).decode()}", flush=True)
    if len(data) < 12:
        print(f"[upstream] runt packet from {peer[0]}:{peer[1]} "
              f"len={len(data)} hex={binascii.hexlify(data).decode()}", flush=True)
        continue
    (txid, flags, qdcount, ancount, nscount, arcount) = struct.unpack_from("!HHHHHH", data, 0)
    if flags & 0x8000:                            # a response, not a query
        continue

    # A parse failure must never take the upstream down: a crash here would
    # masquerade as dnsflt "hijacking then dropping". Dump and keep serving.
    try:
        qname_labels, off = decode_name(data, 12)
        qtype, qclass = struct.unpack_from("!HH", data, off)
        off += 4
        question = data[12:off]
    except Exception as exc:                     # noqa: BLE001 - diagnostic harness
        print(f"[upstream] MALFORMED from {peer[0]}:{peer[1]} len={len(data)} "
              f"id=0x{txid:04x} flags=0x{flags:04x} qd={qdcount} an={ancount} "
              f"err={type(exc).__name__}: {exc}", flush=True)
        print(f"[upstream] MALFORMED hex={binascii.hexlify(data).decode()}", flush=True)
        continue
    qname = ".".join(qname_labels) or "<root>"

    print(f"[upstream] from {peer[0]}:{peer[1]} id=0x{txid:04x} "
          f"qname={qname} qtype={qtype} qclass={qclass} qdcount={qdcount} "
          f"flags=0x{flags:04x}", flush=True)

    # Header: QR=1 RD=1 RA=1, no error. QDCOUNT=1 ANCOUNT=1.
    resp = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    resp += question                                # echo the question verbatim
    resp += b"\xc0\x0c"                             # answer name -> offset 12
    resp += struct.pack("!HH", qtype, qclass)       # type / class
    resp += struct.pack("!II", 60, 4)               # TTL 60, RDLENGTH 4
    resp += socket.inet_aton(ANSWER_IP)             # the A record

    sock.sendto(resp, peer)
    print(f"[upstream] replied 0x{txid:04x} -> {ANSWER_IP} to {peer[0]}:{peer[1]}",
          flush=True)