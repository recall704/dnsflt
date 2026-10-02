//! End-to-end check of everything that does *not* require the WinDivert
//! kernel driver: query construction, the real `UpstreamDriver` against a
//! live UDP upstream, anti-spoof validation, ID patching, and forged packet
//! construction/parse-back.
//!
//! This is the part a non-elevated shell can still prove. The capture and
//! injection syscalls remain covered only by the live test.
//!
//! Run with the fake upstream already listening:
//!     python testdata/fake_upstream.py 1053
//!     cargo test --test e2e_pipeline -- --nocapture

use std::sync::Arc;
use std::time::Duration;

use dnsflt::dns;
use dnsflt::packet;
use dnsflt::stats::Counters;
use dnsflt::upstream::{UpstreamDriver, UpstreamRequest};

fn upstream_addr() -> String {
    std::env::var("DNSFLT_TEST_UPSTREAM").unwrap_or_else(|_| "127.0.0.1:1053".into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwards_to_upstream_and_forges_a_reply() -> anyhow::Result<()> {
    let addr = upstream_addr();
    let resolved = dnsflt::config::parse_upstream(&addr)?;

    let counters = Arc::new(Counters::default());
    let (driver, local_port) =
        tokio::task::block_in_place(|| UpstreamDriver::start(&resolved, 0, counters.clone()))?;
    println!("upstream driver bound to local port {local_port}");

    // The application asked for 0xBEEF; a hostile/incorrect upstream would
    // answer with a different ID or a different question.
    let query_id: u16 = 0xBEEF;
    let query = dns::build_query("example.com", 1 /* A */, query_id, None);

    let parsed = dns::parse_query(&query)?;
    assert_eq!(parsed.name_text, "example.com", "QNAME must round-trip");
    assert_eq!(parsed.qname_lower, b"\x07example\x03com\x00");
    println!("parsed query: id=0x{:04x} qname={}", parsed.id, parsed.name_text);

    let answer = match driver
        .dispatch(UpstreamRequest {
            query: query.clone(),
            timeout: Duration::from_secs(3),
        })
        .await
    {
        dnsflt::upstream::UpstreamResult::Ok(bytes) => bytes,
        dnsflt::upstream::UpstreamResult::Timeout => panic!("upstream timed out"),
        dnsflt::upstream::UpstreamResult::Error(e) => panic!("upstream error: {e}"),
    };
    println!("upstream returned {} bytes", answer.len());
    assert_eq!(dns::peek_id(&answer), Some(query_id), "ID must be preserved");
    assert!(!dns::is_truncated(&answer), "answer must not be truncated");

    // Anti-spoof gate.
    assert!(
        dns::response_matches_query(&parsed, &answer),
        "response must match the question we asked"
    );

    let ttl = dns::min_answer_ttl(&answer);
    println!("answer count={} min ttl={ttl:?}", dns::answer_count(&answer));
    assert_eq!(dns::answer_count(&answer), 1);

    // Now forge the reply as seen by the application: the original server is
    // the source, the application is the destination.
    let mut forged_payload = answer.clone();
    dns::patch_id(&mut forged_payload, query_id);

    let app_ip: std::net::IpAddr = "192.168.0.55".parse()?;
    let dns_server_ip: std::net::IpAddr = "8.8.8.8".parse()?;
    let packet_bytes = packet::build_udp(
        dns_server_ip,
        app_ip,
        53,
        54321,
        64,
        &forged_payload,
    )?;
    println!("forged packet: {} bytes", packet_bytes.len());

    // Parse it back exactly as a receiving application would.
    let ip = packet::parse_ip(&packet_bytes)?;
    assert_eq!(ip.src, dns_server_ip, "spoofed source address");
    assert_eq!(ip.dst, app_ip, "destination is the application");

    let udp = packet::parse_udp(&packet_bytes, &ip)?;
    assert_eq!(udp.sport, 53, "source port must look like a DNS server");
    assert_eq!(udp.dport, 54321, "destination port is the application");
    let got_payload = &packet_bytes[udp.payload_off..udp.payload_off + udp.payload_len];
    assert_eq!(
        got_payload, forged_payload,
        "UDP payload must be the patched DNS answer"
    );

    // The forged payload is a DNS *response* (QR bit set), so the strict
    // query-only `parse_query` must reject it — verify the patched ID with
    // the header-only peek instead.
    assert!(
        dns::parse_query(got_payload).is_err(),
        "a response must not pass the query-only parser"
    );
    assert_eq!(
        dns::peek_id(got_payload),
        Some(query_id),
        "patched ID must survive the round-trip"
    );

    // Counters must have moved.
    let snap = counters.snapshot();
    println!("counters: sent={} recv={}", snap.upstream_sent, snap.upstream_recv);
    assert!(snap.upstream_sent >= 1, "one query must have been sent");
    assert!(snap.upstream_recv >= 1, "one answer must have been received");

    println!("\n=== forged reply ===\n{}", dns::describe_full(got_payload));
    Ok(())
}

#[tokio::test]
async fn rejects_a_response_for_a_different_question() {
    // Build a query, then hand the validator a well-formed answer to a
    // *different* name. This must be refused, not injected.
    let query = dns::build_query("example.com", 1, 0x1234, None);
    let parsed = dns::parse_query(&query).expect("parse query");

    let impostor = dns::build_query("victim.example", 1, 0x1234, None);
    // Turn it into a response with one answer so only the question differs.
    let mut resp = impostor;
    resp[2] = 0x81;
    resp[3] = 0x80;
    resp[7] = 1; // ANCOUNT = 1 (body length differs, but the question check
                  // runs first and must already reject it).

    assert!(
        !dns::response_matches_query(&parsed, &resp),
        "validator must reject an answer whose question does not match"
    );
    println!("impostor answer for a different QNAME correctly rejected");
}

#[tokio::test]
async fn rejects_a_mismatched_transaction_id() {
    let query = dns::build_query("example.com", 1, 0x1111, None);
    let parsed = dns::parse_query(&query).expect("parse query");

    let mut resp = dns::build_query("example.com", 1, 0x2222, None);
    resp[2] = 0x81;
    resp[3] = 0x80;

    assert!(
        !dns::response_matches_query(&parsed, &resp),
        "validator must reject an answer carrying the wrong DNS ID"
    );
    println!("answer with wrong transaction ID correctly rejected");
}