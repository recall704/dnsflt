//! Hand-rolled DNS wire-format handling.
//!
//! Everything on the capture hot path (parsing the question, validating the
//! packet, checking that an upstream answer really answers the question we
//! asked) is written by hand so that it is allocation-light, panic-free on
//! malformed input, and unit-testable without any network or driver.
//!
//! `hickory-proto` is only used for the human readable dumps printed by
//! `--dump` and `dnsflt check`.

use std::fmt::Write as _;

/// DNS wire header length.
pub const HEADER_LEN: usize = 12;
/// `RecordType::OPT` — EDNS(0) pseudo record.
pub const TYPE_OPT: u16 = 41;
/// `Class::IN`
pub const CLASS_IN: u16 = 1;

const FLAG_QR: u16 = 0x8000;
const FLAG_TC: u16 = 0x0200;
const FLAG_OPCODE_MASK: u16 = 0x7800;

/// Reasons a buffer is rejected as "not a DNS query we handle".
///
/// Mirrors the reject branches of YogaDNS' validation routine
/// (`sub_1400025D8`): too short, QR already set, wrong section counts, an
/// unparsable/oversized QNAME, or a missing question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    /// Fewer than 12 bytes.
    TooShort,
    /// QR bit set: this is a response, not a query.
    NotAQuery,
    /// `QDCOUNT != 1`, or `ANCOUNT`/`NSCOUNT` non-zero.
    BadCounts,
    /// A label length byte exceeded 63 or a compression pointer appeared.
    BadLabel,
    /// Ran off the end of the buffer while reading the QNAME.
    TruncatedName,
    /// QNAME longer than 255 octets.
    NameTooLong,
    /// The question section was cut short (missing QTYPE/QCLASS).
    TruncatedQuestion,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            DnsError::TooShort => "packet shorter than a DNS header",
            DnsError::NotAQuery => "QR bit set (this is a response)",
            DnsError::BadCounts => "unexpected section counts (need QD=1, AN=0, NS=0)",
            DnsError::BadLabel => "malformed label in QNAME",
            DnsError::TruncatedName => "QNAME runs past end of packet",
            DnsError::NameTooLong => "QNAME longer than 255 octets",
            DnsError::TruncatedQuestion => "question section cut short",
        };
        f.write_str(text)
    }
}

impl std::error::Error for DnsError {}

/// A parsed DNS query. The QNAME is kept in wire form (uncompressed, as
/// received) so that replies can re-emit it verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Transaction ID.
    pub id: u16,
    /// Raw flags word.
    pub flags: u16,
    /// QNAME in wire format, original case.
    pub qname: Vec<u8>,
    /// QNAME in wire format, ASCII-lowercased.
    pub qname_lower: Vec<u8>,
    /// QNAME in dotted presentation form (`www.example.com`).
    pub name_text: String,
    /// QTYPE.
    pub qtype: u16,
    /// QCLASS.
    pub qclass: u16,
    /// EDNS0 advertised UDP payload size, when an OPT record was present.
    pub edns_udp_size: Option<u16>,
    /// Offset just past the question section.
    pub question_end: usize,
}

impl Query {
    /// `true` when the requested QTYPE is permitted by `whitelist`
    /// (an empty whitelist permits everything).
    pub fn qtype_allowed(&self, whitelist: &[u16]) -> bool {
        whitelist.is_empty() || whitelist.contains(&self.qtype)
    }

    /// `true` when the spec name equals `other` (ASCII case-insensitive).
    pub fn name_eq(&self, other: &Query) -> bool {
        self.qname_lower == other.qname_lower && self.qtype == other.qtype && self.qclass == other.qclass
    }
}

/// Peek at the transaction ID without parsing anything else.
#[inline]
pub fn peek_id(buf: &[u8]) -> Option<u16> {
    if buf.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([buf[0], buf[1]]))
}

/// Fully parse and validate an outbound DNS query.
pub fn parse_query(buf: &[u8]) -> Result<Query, DnsError> {
    if buf.len() < HEADER_LEN {
        return Err(DnsError::TooShort);
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & FLAG_QR != 0 {
        return Err(DnsError::NotAQuery);
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    let nscount = u16::from_be_bytes([buf[8], buf[9]]);
    let arcount = u16::from_be_bytes([buf[10], buf[11]]);
    if qdcount != 1 || ancount != 0 || nscount != 0 {
        return Err(DnsError::BadCounts);
    }

    let (qname, name_text, question_end) = parse_question_name(buf, HEADER_LEN)?;
    if question_end + 4 > buf.len() {
        return Err(DnsError::TruncatedQuestion);
    }
    let qtype = u16::from_be_bytes([buf[question_end], buf[question_end + 1]]);
    let qclass = u16::from_be_bytes([buf[question_end + 2], buf[question_end + 3]]);
    let question_end = question_end + 4;

    let qname_lower = ascii_lower(&qname);
    let edns_udp_size = if arcount > 0 {
        find_opt_udp_size(buf, question_end, arcount)
    } else {
        None
    };

    Ok(Query {
        id,
        flags,
        qname,
        qname_lower,
        name_text,
        qtype,
        qclass,
        edns_udp_size,
        question_end,
    })
}

/// Walk the QNAME at `off`, rejecting compression pointers and over-long
/// labels / names. Returns the wire QNAME (terminator included), the dotted
/// presentation form, and the offset just past the name.
fn parse_question_name(buf: &[u8], mut off: usize) -> Result<(Vec<u8>, String, usize), DnsError> {
    let start = off;
    let mut text = String::new();
    loop {
        if off >= buf.len() {
            return Err(DnsError::TruncatedName);
        }
        let len = buf[off] as usize;
        if len == 0 {
            off += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            // Compression is illegal in the question section.
            return Err(DnsError::BadLabel);
        }
        if len > 63 {
            return Err(DnsError::BadLabel);
        }
        let label_start = off + 1;
        let label_end = label_start + len;
        if label_end > buf.len() {
            return Err(DnsError::TruncatedName);
        }
        if off + 1 - start + len + 1 > 255 {
            return Err(DnsError::NameTooLong);
        }
        if !text.is_empty() {
            text.push('.');
        }
        push_escaped_label(&mut text, &buf[label_start..label_end]);
        off = label_end;
    }
    Ok((buf[start..off].to_vec(), text, off))
}

/// Escape a label for presentation format the same way `dig` does.
fn push_escaped_label(out: &mut String, label: &[u8]) {
    for &b in label {
        match b {
            b'.' | b'\\' => {
                out.push('\\');
                out.push(b as char);
            }
            0x21..=0x7e => out.push(b as char),
            _ => {
                let _ = write!(out, "\\{b:03}");
            }
        }
    }
}

/// ASCII-lowercase a wire QNAME (length bytes are < 0x40 so they are untouched).
fn ascii_lower(name: &[u8]) -> Vec<u8> {
    name.iter()
        .map(|b| if b.is_ascii_uppercase() { b + 32 } else { *b })
        .collect()
}

/// Scan the additional section for an OPT record and return its CLASS field,
/// which carries the sender's advertised UDP payload size.
fn find_opt_udp_size(buf: &[u8], mut off: usize, count: u16) -> Option<u16> {
    for _ in 0..count {
        skip_name(buf, &mut off).ok()?;
        if off + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let class = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
        let rdlen = u16::from_be_bytes([buf[off + 8], buf[off + 9]]) as usize;
        if rtype == TYPE_OPT {
            return Some(class);
        }
        off = off.checked_add(10 + rdlen)?;
        if off > buf.len() {
            return None;
        }
    }
    None
}

/// Skip a possibly-compressed name.
fn skip_name(buf: &[u8], off: &mut usize) -> Result<(), DnsError> {
    let mut guard = 0usize;
    loop {
        if *off >= buf.len() || guard > 255 {
            return Err(DnsError::TruncatedName);
        }
        let len = buf[*off] as usize;
        if len == 0 {
            *off += 1;
            return Ok(());
        }
        if len & 0xc0 == 0xc0 {
            if *off + 2 > buf.len() {
                return Err(DnsError::TruncatedName);
            }
            *off += 2;
            return Ok(());
        }
        if len > 63 {
            return Err(DnsError::BadLabel);
        }
        *off += 1 + len;
        guard += 1;
    }
}

/// Assert that `response` really answers `query`.
///
/// The transaction ID must match, the QR bit must be set, and — whenever the
/// response carries a question section — the QNAME (case-insensitively) plus
/// QTYPE/QCLASS must agree. Responses with `QDCOUNT == 0` are accepted on the
/// strength of the ID alone; this is what several resolvers do for errors.
pub fn response_matches_query(query: &Query, response: &[u8]) -> bool {
    if response.len() < HEADER_LEN {
        return false;
    }
    if peek_id(response) != Some(query.id) {
        return false;
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & FLAG_QR == 0 {
        return false;
    }
    // We only ever ask standard questions, so a non-zero OPCODE means the
    // reply is not an answer to what we sent (this covers UPDATE, and the
    // legacy/unassigned opcodes a spoofed packet might use to slip past the
    // ID check).
    if flags & FLAG_OPCODE_MASK != 0 {
        return false;
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]);
    if qdcount == 0 {
        return true;
    }
    if qdcount != 1 {
        return false;
    }
    let Ok((qname, _text, end)) = parse_question_name(response, HEADER_LEN) else {
        return false;
    };
    if end + 4 > response.len() {
        return false;
    }
    let qtype = u16::from_be_bytes([response[end], response[end + 1]]);
    let qclass = u16::from_be_bytes([response[end + 2], response[end + 3]]);
    ascii_lower(&qname) == query.qname_lower && qtype == query.qtype && qclass == query.qclass
}

/// `true` when the response has the TC (truncated) bit set.
pub fn is_truncated(msg: &[u8]) -> bool {
    msg.len() >= 4 && u16::from_be_bytes([msg[2], msg[3]]) & FLAG_TC != 0
}

/// Overwrite the transaction ID of a message in place.
pub fn patch_id(msg: &mut [u8], id: u16) {
    if msg.len() >= 2 {
        msg[0..2].copy_from_slice(&id.to_be_bytes());
    }
}

/// Minimal answer count from the header.
pub fn answer_count(msg: &[u8]) -> u16 {
    if msg.len() < 8 {
        return 0;
    }
    u16::from_be_bytes([msg[6], msg[7]])
}

/// Smallest TTL across all answer records, or `None` when the message cannot
/// be walked. Used to size cache entries.
pub fn min_answer_ttl(msg: &[u8]) -> Option<u32> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut off = HEADER_LEN;
    for _ in 0..qdcount {
        skip_name(msg, &mut off).ok()?;
        off = off.checked_add(4)?;
    }
    let mut min: Option<u32> = None;
    for _ in 0..ancount {
        skip_name(msg, &mut off).ok()?;
        if off + 10 > msg.len() {
            return None;
        }
        let ttl = u32::from_be_bytes([msg[off + 4], msg[off + 5], msg[off + 6], msg[off + 7]]);
        let rdlen = u16::from_be_bytes([msg[off + 8], msg[off + 9]]) as usize;
        min = Some(match min {
            Some(m) => m.min(ttl),
            None => ttl,
        });
        off = off.checked_add(10 + rdlen)?;
        if off > msg.len() {
            return None;
        }
    }
    min
}

/// Build a `TC=1` stub answer: header + question only, everything else empty.
///
/// Returned when the real answer would not fit the client's advertised UDP
/// payload size, prompting the client to retry over TCP.
pub fn truncated_response(query: &Query) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + query.qname.len() + 4);
    out.extend_from_slice(&query.id.to_be_bytes());
    // QR=1, RD copied from the query, RA=1, TC=1, RCODE=0.
    let flags = FLAG_QR | FLAG_TC | (query.flags & 0x0100) | 0x0080;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&query.qname);
    out.extend_from_slice(&query.qtype.to_be_bytes());
    out.extend_from_slice(&query.qclass.to_be_bytes());
    out
}

/// Build a `SERVFAIL` response for `query` (used when we must fail fast).
pub fn servfail_response(query: &Query) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + query.qname.len() + 4);
    out.extend_from_slice(&query.id.to_be_bytes());
    let flags = FLAG_QR | (query.flags & 0x0100) | 0x0080 | 0x0002; // RCODE=SERVFAIL
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query.qname);
    out.extend_from_slice(&query.qtype.to_be_bytes());
    out.extend_from_slice(&query.qclass.to_be_bytes());
    out
}

/// One-line summary read straight off the wire, allocation-free except for the
/// QNAME text. Safe on arbitrary input.
pub fn describe_compact(buf: &[u8]) -> String {
    if buf.len() < HEADER_LEN {
        return format!("<{} bytes: too short for DNS>", buf.len());
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qr = if flags & FLAG_QR != 0 { "resp" } else { "query" };
    let tc = if flags & FLAG_TC != 0 { ",tc" } else { "" };
    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    let an = u16::from_be_bytes([buf[6], buf[7]]);
    let ns = u16::from_be_bytes([buf[8], buf[9]]);
    let ar = u16::from_be_bytes([buf[10], buf[11]]);
    let rcode = flags & 0x000f;

    let mut out = format!("id=0x{id:04x} {qr}{tc} rcode={rcode} qd={qd} an={an} ns={ns} ar={ar}");
    if qd == 1 {
        match parse_question_name(buf, HEADER_LEN) {
            Ok((_wire, text, end)) if end + 4 <= buf.len() => {
                let qtype = u16::from_be_bytes([buf[end], buf[end + 1]]);
                let qclass = u16::from_be_bytes([buf[end + 2], buf[end + 3]]);
                let name = if text.is_empty() { ".".to_string() } else { text };
                let _ = write!(out, " [{name} {} {}]", type_name(qtype), class_name(qclass));
            }
            Ok((_wire, text, _)) => {
                let name = if text.is_empty() { ".".to_string() } else { text };
                let _ = write!(out, " [{name} <cut short>]");
            }
            Err(err) => {
                let _ = write!(out, " [QNAME: {err}]");
            }
        }
    }
    out
}

/// Full `dig`-style dump via `hickory-proto`; falls back to the compact form
/// when the message does not parse.
pub fn describe_full(buf: &[u8]) -> String {
    match hickory_proto::op::Message::from_vec(buf) {
        Ok(msg) => msg.to_string(),
        Err(err) => format!("{} (hickory: {err})", describe_compact(buf)),
    }
}

/// Names for the QTYPEs we are most likely to see.
pub fn type_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        13 => "HINFO".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        35 => "NAPTR".into(),
        41 => "OPT".into(),
        43 => "DS".into(),
        46 => "RRSIG".into(),
        48 => "DNSKEY".into(),
        52 => "TLSA".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

/// Names for QCLASS values.
pub fn class_name(c: u16) -> String {
    match c {
        1 => "IN".into(),
        3 => "CH".into(),
        4 => "HS".into(),
        255 => "ANY".into(),
        other => format!("CLASS{other}"),
    }
}

/// Build a canonical query packet for `dnsflt check` / diagnostics.
pub fn build_query(name: &str, qtype: u16, id: u16, edns_udp_size: Option<u16>) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&(if edns_udp_size.is_some() { 1u16 } else { 0 }).to_be_bytes());
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    if let Some(size) = edns_udp_size {
        out.push(0); // root NAME
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // extended RCODE / flags
        out.extend_from_slice(&0u16.to_be_bytes()); // RDLEN
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_simple_query() {
        let pkt = build_query("www.Example.COM", 1, 0x1234, None);
        let q = parse_query(&pkt).expect("valid query");
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.name_text, "www.Example.COM");
        assert_eq!(q.qtype, 1);
        assert_eq!(q.qclass, CLASS_IN);
        assert_eq!(q.qname_lower, vec![3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
        assert!(q.edns_udp_size.is_none());
        assert_eq!(q.question_end, pkt.len());
    }

    #[test]
    fn parses_edns_payload_size() {
        let pkt = build_query("example.com", 28, 1, Some(4096));
        let q = parse_query(&pkt).expect("valid query");
        assert_eq!(q.edns_udp_size, Some(4096));
    }

    #[test]
    fn rejects_responses() {
        let mut pkt = build_query("example.com", 1, 1, None);
        pkt[2] |= 0x80; // set QR
        assert_eq!(parse_query(&pkt), Err(DnsError::NotAQuery));
    }

    #[test]
    fn rejects_bad_counts() {
        let mut pkt = build_query("example.com", 1, 1, None);
        pkt[6] = 0;
        pkt[7] = 1; // ANCOUNT = 1
        assert_eq!(parse_query(&pkt), Err(DnsError::BadCounts));
    }

    #[test]
    fn rejects_short_and_truncated() {
        assert_eq!(parse_query(&[0u8; 4]), Err(DnsError::TooShort));
        let pkt = build_query("example.com", 1, 1, None);
        assert_eq!(parse_query(&pkt[..pkt.len() - 2]), Err(DnsError::TruncatedQuestion));
        assert_eq!(parse_query(&pkt[..HEADER_LEN + 3]), Err(DnsError::TruncatedName));
    }

    #[test]
    fn rejects_compression_in_question() {
        let mut pkt = build_query("example.com", 1, 1, None);
        pkt[HEADER_LEN] = 0xc0;
        assert_eq!(parse_query(&pkt), Err(DnsError::BadLabel));
    }

    #[test]
    fn rejects_oversized_labels() {
        let mut pkt = build_query("example.com", 1, 1, None);
        pkt[HEADER_LEN] = 64;
        assert_eq!(parse_query(&pkt), Err(DnsError::BadLabel));
    }

    #[test]
    fn rejects_overlong_names() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        // 5 labels x 50 bytes = 250 bytes of payload; the 6th pushes past 255
        for _ in 0..6 {
            pkt.push(50);
            pkt.extend(std::iter::repeat_n(b'a', 50));
        }
        pkt.push(0);
        assert_eq!(parse_query(&pkt), Err(DnsError::NameTooLong));
    }

    #[test]
    fn qtype_whitelist() {
        let q = parse_query(&build_query("example.com", 28, 1, None)).unwrap();
        assert!(q.qtype_allowed(&[]));
        assert!(q.qtype_allowed(&[1, 28]));
        assert!(!q.qtype_allowed(&[1, 2]));
    }

    #[test]
    fn matches_query_case_insensitively() {
        let q = parse_query(&build_query("WWW.example.com", 1, 7, None)).unwrap();

        let mut resp = build_query("www.EXAMPLE.com", 1, 7, None);
        resp[2] |= 0x80; // QR
        assert!(response_matches_query(&q, &resp));

        let mut wrong_case_but_different_name = build_query("www.other.com", 1, 7, None);
        wrong_case_but_different_name[2] |= 0x80;
        assert!(!response_matches_query(&q, &wrong_case_but_different_name));

        let mut wrong_type = build_query("www.example.com", 28, 7, None);
        wrong_type[2] |= 0x80;
        assert!(!response_matches_query(&q, &wrong_type));

        let mut wrong_id = build_query("www.example.com", 1, 8, None);
        wrong_id[2] |= 0x80;
        assert!(!response_matches_query(&q, &wrong_id));

        let mut no_question = build_query("www.example.com", 1, 7, None);
        no_question[2] |= 0x80;
        no_question[5] = 0; // QDCOUNT = 0
        no_question.truncate(HEADER_LEN);
        assert!(response_matches_query(&q, &no_question));
    }

    #[test]
    fn truncation_and_servfail_shapes() {
        let q = parse_query(&build_query("example.com", 1, 0xbeef, None)).unwrap();
        let tc = truncated_response(&q);
        assert_eq!(answer_count(&tc), 0);
        assert!(is_truncated(&tc));
        assert!(response_matches_query(&q, &tc));

        let sf = servfail_response(&q);
        assert_eq!(u16::from_be_bytes([sf[2], sf[3]]) & 0x000f, 2);
        assert!(response_matches_query(&q, &sf));
    }

    #[test]
    fn ttl_extraction() {
        // header + 1 question + 2 answers with TTLs 300 and 60
        let mut msg = build_query("example.com", 1, 1, None);
        msg[6] = 0;
        msg[7] = 2; // ANCOUNT = 2
        for ttl in [300u32, 60] {
            msg.push(0xc0);
            msg.push(0x0c); // pointer to the question name
            msg.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
            msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
            msg.extend_from_slice(&ttl.to_be_bytes());
            msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
            msg.extend_from_slice(&[1, 2, 3, 4]);
        }
        assert_eq!(min_answer_ttl(&msg), Some(60));
    }

    #[test]
    fn describe_compact_never_panics() {
        for len in 0..80usize {
            let buf = vec![0xffu8; len];
            let _ = describe_compact(&buf);
        }
        let _ = describe_full(&build_query("example.com", 1, 1, None));
    }
}
