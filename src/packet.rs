//! IP / UDP / TCP framing: parsing, checksums and packet construction.
//!
//! Everything here is pure and unit-testable — no WinDivert, no sockets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

/// TTL / hop limit stamped on forged replies.
pub const REPLY_TTL: u8 = 64;

/// Largest UDP payload we will build for IPv4 (1500 MTU – 20 IP – 8 UDP).
pub const MAX_UDP_PAYLOAD_V4: usize = 1472;
/// Largest UDP payload we will build for IPv6 (1500 MTU – 40 IP – 8 UDP).
pub const MAX_UDP_PAYLOAD_V6: usize = 1452;

/// TCP flag bits.
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

/// Address family, derived from the packet's first nibble.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// IPv4
    V4,
    /// IPv6
    V6,
}

impl Family {
    /// The `AF_INET` / `AF_INET6` constant.
    pub fn is_v6(self) -> bool {
        matches!(self, Family::V6)
    }

    /// Address family of a socket address.
    pub fn of(addr: &IpAddr) -> Family {
        match addr {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }
}

/// Reasons a packet is not something we can work with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    /// Buffer shorter than the fixed header.
    TooShort,
    /// IP version nibble is neither 4 nor 6.
    BadVersion,
    /// IHL / data-offset smaller than the minimum header.
    BadHeaderLen,
    /// Declared length is inconsistent with the buffer.
    BadLength,
    /// IPv4 and IPv6 addresses were mixed.
    AddressMismatch,
    /// The transport header is not UDP/TCP or lies beyond the packet.
    Unsupported,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            PacketError::TooShort => "packet too short",
            PacketError::BadVersion => "unknown IP version",
            PacketError::BadHeaderLen => "bad header length",
            PacketError::BadLength => "inconsistent length field",
            PacketError::AddressMismatch => "address family mismatch",
            PacketError::Unsupported => "unsupported transport",
        };
        f.write_str(text)
    }
}

impl std::error::Error for PacketError {}

/// Parsed IP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpInfo {
    /// Address family.
    pub family: Family,
    /// Bytes of IP header (including IPv4 options).
    pub header_len: usize,
    /// Total packet length as declared by the header, clamped to the buffer.
    pub total_len: usize,
    /// IP protocol / IPv6 next-header.
    pub protocol: u8,
    /// Source address.
    pub src: IpAddr,
    /// Destination address.
    pub dst: IpAddr,
    /// Set when the packet is an IP fragment (v4 MF/offset, v6 frag header).
    pub fragmented: bool,
}

impl IpInfo {
    /// Length of the transport payload (everything after the IP header).
    pub fn payload_len(&self) -> usize {
        self.total_len.saturating_sub(self.header_len)
    }
}

/// Parse the IP header of `buf`.
pub fn parse_ip(buf: &[u8]) -> Result<IpInfo, PacketError> {
    let Some(first) = buf.first() else {
        return Err(PacketError::TooShort);
    };
    match first >> 4 {
        4 => parse_ipv4(buf),
        6 => parse_ipv6(buf),
        _ => Err(PacketError::BadVersion),
    }
}

fn parse_ipv4(buf: &[u8]) -> Result<IpInfo, PacketError> {
    if buf.len() < 20 {
        return Err(PacketError::TooShort);
    }
    let header_len = ((buf[0] & 0x0f) as usize) * 4;
    if header_len < 20 {
        return Err(PacketError::BadHeaderLen);
    }
    if buf.len() < header_len {
        return Err(PacketError::TooShort);
    }
    let declared = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let total_len = if declared == 0 { buf.len() } else { declared };
    if total_len < header_len {
        return Err(PacketError::BadLength);
    }
    if total_len > buf.len() {
        return Err(PacketError::BadLength);
    }
    let flags_frag = u16::from_be_bytes([buf[6], buf[7]]);
    Ok(IpInfo {
        family: Family::V4,
        header_len,
        total_len,
        protocol: buf[9],
        src: IpAddr::V4(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15])),
        dst: IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19])),
        fragmented: flags_frag & 0x2000 != 0 || flags_frag & 0x1fff != 0,
    })
}

fn parse_ipv6(buf: &[u8]) -> Result<IpInfo, PacketError> {
    if buf.len() < 40 {
        return Err(PacketError::TooShort);
    }
    let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let total_len = if payload_len == 0 {
        buf.len()
    } else {
        40 + payload_len
    };
    if total_len > buf.len() {
        return Err(PacketError::BadLength);
    }
    let next_header = buf[6];
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&buf[8..24]);
    dst.copy_from_slice(&buf[24..40]);
    // We deliberately do not walk IPv6 extension headers; a fragment header
    // (44) is flagged so that the caller passes the packet through untouched.
    Ok(IpInfo {
        family: Family::V6,
        header_len: 40,
        total_len,
        protocol: next_header,
        src: IpAddr::V6(Ipv6Addr::from(src)),
        dst: IpAddr::V6(Ipv6Addr::from(dst)),
        fragmented: next_header == 44,
    })
}

/// Parsed UDP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpDatagram {
    /// Source port.
    pub sport: u16,
    /// Destination port.
    pub dport: u16,
    /// Offset of the UDP payload inside the packet.
    pub payload_off: usize,
    /// Length of the UDP payload.
    pub payload_len: usize,
}

/// Parse the UDP header described by `ip`.
pub fn parse_udp(buf: &[u8], ip: &IpInfo) -> Result<UdpDatagram, PacketError> {
    let off = ip.header_len;
    if ip.total_len < off + 8 || buf.len() < off + 8 {
        return Err(PacketError::TooShort);
    }
    let sport = u16::from_be_bytes([buf[off], buf[off + 1]]);
    let dport = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
    let ulen = u16::from_be_bytes([buf[off + 4], buf[off + 5]]) as usize;
    if ulen < 8 {
        return Err(PacketError::BadLength);
    }
    let payload_off = off + 8;
    let payload_len = (ulen - 8).min(ip.total_len.saturating_sub(payload_off));
    Ok(UdpDatagram {
        sport,
        dport,
        payload_off,
        payload_len,
    })
}

/// Parsed TCP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSeg {
    /// Source port.
    pub sport: u16,
    /// Destination port.
    pub dport: u16,
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgement number.
    pub ack: u32,
    /// Flag bits (see `TCP_*` constants).
    pub flags: u8,
    /// Bytes of TCP header.
    pub header_len: usize,
    /// Offset of the TCP payload inside the packet.
    pub payload_off: usize,
    /// Length of the TCP payload.
    pub payload_len: usize,
}

impl TcpSeg {
    /// `true` when the SYN bit is set.
    pub fn syn(&self) -> bool {
        self.flags & TCP_SYN != 0
    }
    /// `true` when the ACK bit is set.
    pub fn ack_flag(&self) -> bool {
        self.flags & TCP_ACK != 0
    }
}

/// Parse the TCP header described by `ip`.
pub fn parse_tcp(buf: &[u8], ip: &IpInfo) -> Result<TcpSeg, PacketError> {
    let off = ip.header_len;
    if ip.total_len < off + 20 || buf.len() < off + 20 {
        return Err(PacketError::TooShort);
    }
    let header_len = ((buf[off + 12] >> 4) as usize) * 4;
    if header_len < 20 {
        return Err(PacketError::BadHeaderLen);
    }
    if buf.len() < off + header_len {
        return Err(PacketError::TooShort);
    }
    let payload_off = off + header_len;
    Ok(TcpSeg {
        sport: u16::from_be_bytes([buf[off], buf[off + 1]]),
        dport: u16::from_be_bytes([buf[off + 2], buf[off + 3]]),
        seq: u32::from_be_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]),
        ack: u32::from_be_bytes([buf[off + 8], buf[off + 9], buf[off + 10], buf[off + 11]]),
        flags: buf[off + 13],
        header_len,
        payload_off,
        payload_len: ip.total_len.saturating_sub(payload_off),
    })
}

// ---------------------------------------------------------------------------
// checksums
// ---------------------------------------------------------------------------

/// Accumulate `data` into a running one's-complement sum.
#[inline]
pub fn add_bytes(mut acc: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        acc += (*last as u32) << 8;
    }
    acc
}

/// Fold a one's-complement accumulator and complement it.
#[inline]
pub fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// Checksum of a 20-byte (or longer) IPv4 header with the checksum field zeroed.
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    fold(add_bytes(0, header))
}

fn pseudo_header_sum(family: Family, src: &IpAddr, dst: &IpAddr, proto: u8, len: u16) -> u32 {
    let mut acc = 0u32;
    match (family, src, dst) {
        (Family::V4, IpAddr::V4(s), IpAddr::V4(d)) => {
            acc = add_bytes(acc, &s.octets());
            acc = add_bytes(acc, &d.octets());
            acc = add_bytes(acc, &[0, proto]);
            acc = add_bytes(acc, &len.to_be_bytes());
        }
        (Family::V6, IpAddr::V6(s), IpAddr::V6(d)) => {
            acc = add_bytes(acc, &s.octets());
            acc = add_bytes(acc, &d.octets());
            acc = add_bytes(acc, &(len as u32).to_be_bytes());
            acc = add_bytes(acc, &[0, 0, 0, proto]);
        }
        _ => {}
    }
    acc
}

/// UDP checksum over `udp` (header + payload) whose checksum field is zeroed.
/// A computed zero is returned as `0xffff`, as required by RFC 768.
pub fn udp_checksum(family: Family, src: IpAddr, dst: IpAddr, udp: &[u8]) -> u16 {
    let acc = pseudo_header_sum(family, &src, &dst, IPPROTO_UDP, udp.len() as u16);
    let ck = fold(add_bytes(acc, udp));
    if ck == 0 { 0xffff } else { ck }
}

/// TCP checksum over `tcp` (header + payload) whose checksum field is zeroed.
pub fn tcp_checksum(family: Family, src: IpAddr, dst: IpAddr, tcp: &[u8]) -> u16 {
    let acc = pseudo_header_sum(family, &src, &dst, IPPROTO_TCP, tcp.len() as u16);
    let ck = fold(add_bytes(acc, tcp));
    if ck == 0 { 0xffff } else { ck }
}

// ---------------------------------------------------------------------------
// construction
// ---------------------------------------------------------------------------

/// Build a complete `IPv4/IPv6` + `UDP` packet.
///
/// Checksums are fully computed so the packet is valid on its own; every
/// checksum flag in the injected `WINDIVERT_ADDRESS` is left zeroed as well, so
/// the driver recomputes them — the two are idempotent.
pub fn build_udp(
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    ttl: u8,
    payload: &[u8],
) -> Result<Vec<u8>, PacketError> {
    let family = Family::of(&src);
    if family != Family::of(&dst) {
        return Err(PacketError::AddressMismatch);
    }
    let ip_len = if family.is_v6() { 40 } else { 20 };
    let udp_len = 8 + payload.len();
    let mut p = vec![0u8; ip_len + udp_len];
    write_ip_header(&mut p, family, src, dst, ttl, IPPROTO_UDP);
    let u = &mut p[ip_len..];
    u[0..2].copy_from_slice(&sport.to_be_bytes());
    u[2..4].copy_from_slice(&dport.to_be_bytes());
    u[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    u[8..].copy_from_slice(payload);
    let ck = udp_checksum(family, src, dst, &p[ip_len..]);
    p[ip_len + 6..ip_len + 8].copy_from_slice(&ck.to_be_bytes());
    Ok(p)
}

/// Build a complete `IPv4/IPv6` + `TCP` packet (20-byte TCP header, no options).
#[allow(clippy::too_many_arguments)]
pub fn build_tcp(
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    ttl: u8,
    payload: &[u8],
) -> Result<Vec<u8>, PacketError> {
    let family = Family::of(&src);
    if family != Family::of(&dst) {
        return Err(PacketError::AddressMismatch);
    }
    let ip_len = if family.is_v6() { 40 } else { 20 };
    let tcp_len = 20 + payload.len();
    let mut p = vec![0u8; ip_len + tcp_len];
    write_ip_header(&mut p, family, src, dst, ttl, IPPROTO_TCP);
    let t = &mut p[ip_len..];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 5 << 4; // data offset = 5 words
    t[13] = flags;
    t[14..16].copy_from_slice(&64240u16.to_be_bytes()); // a sane window
    t[20..].copy_from_slice(payload);
    let ck = tcp_checksum(family, src, dst, &p[ip_len..]);
    p[ip_len + 16..ip_len + 18].copy_from_slice(&ck.to_be_bytes());
    Ok(p)
}

fn write_ip_header(p: &mut [u8], family: Family, src: IpAddr, dst: IpAddr, ttl: u8, proto: u8) {
    match family {
        Family::V4 => {
            let total = p.len() as u16;
            p[0] = 0x45;
            p[1] = 0;
            p[2..4].copy_from_slice(&total.to_be_bytes());
            p[4..6].copy_from_slice(&0u16.to_be_bytes()); // ID
            p[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
            p[8] = ttl;
            p[9] = proto;
            if let IpAddr::V4(s) = src {
                p[12..16].copy_from_slice(&s.octets());
            }
            if let IpAddr::V4(d) = dst {
                p[16..20].copy_from_slice(&d.octets());
            }
            let ck = ipv4_header_checksum(&p[..20]);
            p[10..12].copy_from_slice(&ck.to_be_bytes());
        }
        Family::V6 => {
            let payload_len = (p.len() - 40) as u16;
            p[0] = 0x60;
            p[4..6].copy_from_slice(&payload_len.to_be_bytes());
            p[6] = proto;
            p[7] = ttl;
            if let IpAddr::V6(s) = src {
                p[8..24].copy_from_slice(&s.octets());
            }
            if let IpAddr::V6(d) = dst {
                p[24..40].copy_from_slice(&d.octets());
            }
        }
    }
}

/// Build a TCP RST that tears down the connection described by `seg`.
///
/// Follows RFC 793 §3.4: when the incoming segment carries an ACK we answer
/// with `seq = incoming.ack, ack = 0, flags = RST`; otherwise we use
/// `seq = 0, ack = incoming.seq + payload_len, flags = RST|ACK`.
pub fn build_tcp_reset(
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    seg: &TcpSeg,
    payload_len: usize,
) -> Result<Vec<u8>, PacketError> {
    let (seq, ack, flags) = if seg.ack_flag() {
        (seg.ack, 0, TCP_RST)
    } else {
        (0, seg.seq.wrapping_add(payload_len as u32), TCP_RST | TCP_ACK)
    };
    build_tcp(src, dst, sport, dport, seq, ack, flags, REPLY_TTL, &[])
}

/// Maximum UDP payload we will build for `family`.
pub fn max_udp_payload(family: Family) -> usize {
    if family.is_v6() {
        MAX_UDP_PAYLOAD_V6
    } else {
        MAX_UDP_PAYLOAD_V4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(ip: &str) -> IpAddr {
        ip.parse().unwrap()
    }

    fn v6(ip: &str) -> IpAddr {
        ip.parse().unwrap()
    }

    #[test]
    fn udp_v4_roundtrip() {
        let pkt = build_udp(v4("10.0.0.5"), v4("8.8.8.8"), 51000, 53, 64, b"hello").unwrap();
        let ip = parse_ip(&pkt).unwrap();
        assert_eq!(ip.family, Family::V4);
        assert_eq!(ip.header_len, 20);
        assert_eq!(ip.total_len, pkt.len());
        assert_eq!(ip.protocol, IPPROTO_UDP);
        assert_eq!(ip.src, v4("10.0.0.5"));
        assert_eq!(ip.dst, v4("8.8.8.8"));
        assert!(!ip.fragmented);

        let udp = parse_udp(&pkt, &ip).unwrap();
        assert_eq!(udp.sport, 51000);
        assert_eq!(udp.dport, 53);
        assert_eq!(&pkt[udp.payload_off..udp.payload_off + udp.payload_len], b"hello");

        // Header checksum must validate.
        assert_eq!(ipv4_header_checksum(&pkt[..20]), 0);
    }

    #[test]
    fn udp_v4_odd_payload_checksum_validates() {
        let pkt = build_udp(v4("1.2.3.4"), v4("5.6.7.8"), 1, 2, 64, b"abc").unwrap();
        // recompute over the datagram with the checksum zeroed
        let mut udp = pkt[20..].to_vec();
        let stored = u16::from_be_bytes([udp[6], udp[7]]);
        udp[6] = 0;
        udp[7] = 0;
        assert_eq!(udp_checksum(Family::V4, v4("1.2.3.4"), v4("5.6.7.8"), &udp), stored);
    }

    #[test]
    fn udp_v6_roundtrip() {
        let pkt = build_udp(
            v6("fe80::1"),
            v6("2001:4860:4860::8888"),
            33333,
            53,
            64,
            b"dns!",
        )
        .unwrap();
        let ip = parse_ip(&pkt).unwrap();
        assert_eq!(ip.family, Family::V6);
        assert_eq!(ip.header_len, 40);
        assert_eq!(ip.total_len, pkt.len());
        let udp = parse_udp(&pkt, &ip).unwrap();
        assert_eq!(udp.dport, 53);
        assert_eq!(&pkt[udp.payload_off..udp.payload_off + udp.payload_len], b"dns!");
    }

    #[test]
    fn mixed_families_rejected() {
        assert_eq!(
            build_udp(v4("1.1.1.1"), v6("::1"), 1, 2, 64, b""),
            Err(PacketError::AddressMismatch)
        );
    }

    #[test]
    fn parse_rejects_garbage() {
        assert_eq!(parse_ip(&[]), Err(PacketError::TooShort));
        assert_eq!(parse_ip(&[0x00; 40]), Err(PacketError::BadVersion));
        assert_eq!(parse_ip(&[0x44; 40]), Err(PacketError::BadHeaderLen));
        let mut pkt = build_udp(v4("1.1.1.1"), v4("2.2.2.2"), 1, 2, 64, b"x").unwrap();
        pkt[2] = 0xff;
        pkt[3] = 0xff; // total length far beyond the buffer
        assert_eq!(parse_ip(&pkt), Err(PacketError::BadLength));
    }

    #[test]
    fn tcp_reset_without_ack() {
        let seg = TcpSeg {
            sport: 1234,
            dport: 53,
            seq: 100,
            ack: 0,
            flags: TCP_SYN,
            header_len: 20,
            payload_off: 40,
            payload_len: 0,
        };
        let rst = build_tcp_reset(v4("9.9.9.9"), v4("10.0.0.5"), 53, 1234, &seg, 0).unwrap();
        let ip = parse_ip(&rst).unwrap();
        let t = parse_tcp(&rst, &ip).unwrap();
        assert_eq!(t.sport, 53);
        assert_eq!(t.dport, 1234);
        assert_eq!(t.seq, 0);
        assert_eq!(t.ack, 100);
        assert_eq!(t.flags, TCP_RST | TCP_ACK);
    }

    #[test]
    fn tcp_reset_with_ack() {
        let seg = TcpSeg {
            sport: 1234,
            dport: 53,
            seq: 500,
            ack: 900,
            flags: TCP_ACK | TCP_PSH,
            header_len: 20,
            payload_off: 40,
            payload_len: 5,
        };
        let rst = build_tcp_reset(v4("9.9.9.9"), v4("10.0.0.5"), 53, 1234, &seg, 5).unwrap();
        let ip = parse_ip(&rst).unwrap();
        let t = parse_tcp(&rst, &ip).unwrap();
        assert_eq!(t.seq, 900);
        assert_eq!(t.ack, 0);
        assert_eq!(t.flags, TCP_RST);
    }

    #[test]
    fn udp_payload_is_addressable() {
        let pkt = build_udp(v4("1.1.1.1"), v4("2.2.2.2"), 5, 53, 64, b"abc").unwrap();
        let ip = parse_ip(&pkt).unwrap();
        let udp = parse_udp(&pkt, &ip).unwrap();
        let payload = &pkt[udp.payload_off..udp.payload_off + udp.payload_len];
        assert_eq!(payload, b"abc");
    }
}
