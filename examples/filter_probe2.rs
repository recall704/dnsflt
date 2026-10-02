//! Narrow down the minimal correct way to exclude our own upstream socket's
//! source port from the capture filter.
//!
//! Finding from filter_probe v1: WinDivert rejects `not (udp.SrcPort == N)`
//! outright, because it cannot negate a field comparison that may be absent
//! from the packet. `udp.SrcPort != N` is accepted, but only under a `udp`
//! guard. Requires Administrator.
//!
//!     cargo build --release --example filter_probe2
//!     target\release\examples\filter_probe2.exe

use windivert::prelude::*;

fn try_open(label: &str, filter: &str) -> bool {
    match WinDivert::network(filter, 0i16, WinDivertFlags::new()) {
        Ok(h) => {
            println!("  OK    {label}\n          {filter}");
            drop(h);
            true
        }
        Err(e) => {
            println!("  FAIL  {label}\n          {filter}\n          -> {e}");
            false
        }
    }
}

const PORT: u16 = 54080;

fn main() {
    println!("== is the `udp` guard required with `!=`? ==");
    try_open("bare != no guard", "outbound and ip and udp.DstPort == 53 and udp.SrcPort != 54080 and not loopback");
    try_open("with udp guard", "outbound and ip and udp and udp.DstPort == 53 and udp.SrcPort != 54080 and not loopback");
    try_open("inside udp branch, no explicit guard", "outbound and ip and not loopback and ((udp.DstPort == 53 and udp.SrcPort != 54080) or tcp.DstPort == 53)");
    try_open("inside udp branch, explicit udp guard", &format!("outbound and ip and not loopback and ((udp and udp.DstPort == 53 and udp.SrcPort != {PORT}) or (tcp and tcp.DstPort == 53))"));

    println!("\n== does `not (==)` work when the field is guaranteed present? ==");
    try_open("not (==) under explicit udp guard", "outbound and ip and udp and not (udp.SrcPort == 54080)");
    try_open("not (==) under udp.DstPort guard", "outbound and ip and udp.DstPort == 53 and not (udp.SrcPort == 54080)");

    println!("\n== other self-exclusion shapes ==");
    try_open("tcp.SrcPort != in tcp branch", "outbound and ip and not loopback and ((udp and udp.DstPort == 53 and udp.SrcPort != 54080) or (tcp and tcp.DstPort == 53 and tcp.SrcPort != 54080))");
    try_open("exclude via neq on both", &format!("outbound and ip and not loopback and ((udp and udp.DstPort == 53 and udp.SrcPort != {PORT}) or (tcp and tcp.DstPort == 53))"));

    println!("\n== full mode filters with the fix applied ==");
    try_open("HIJACK + block_tcp_53", &format!("outbound and ip and not loopback and ((udp and udp.DstPort == 53 and udp.SrcPort != {PORT}) or (tcp and tcp.DstPort == 53))"));
    try_open("HIJACK udp-only", &format!("outbound and ip and not loopback and udp and udp.DstPort == 53 and udp.SrcPort != {PORT}"));
    try_open("PASSTHROUGH", &format!("outbound and ip and not loopback and ((udp and udp.DstPort == 53 and udp.SrcPort != {PORT}) or (tcp and tcp.DstPort == 53))"));
    try_open("FORWARD (inbound clause included)", &format!("(outbound and ip and not loopback and ((udp and udp.DstPort == 53 and udp.SrcPort != {PORT}) or (tcp and tcp.DstPort == 53))) or (inbound and ip and not loopback and udp and udp.SrcPort == 1053)"));

    println!("\n== ipv6 / v4 variants ==");
    try_open("ipv4+ipv6 hijack", &format!("(outbound and (ip or ipv6) and not loopback and ((udp and udp.DstPort == 53 and udp.SrcPort != {PORT}) or (tcp and tcp.DstPort == 53)))"));
    try_open("v4 hijack + inbound", &format!("(outbound and ip and not loopback and ((udp and udp.DstPort == 53 and udp.SrcPort != {PORT}) or (tcp and tcp.DstPort == 53))) or (inbound and ip and not loopback and udp and udp.SrcPort == 1053 and udp.SrcPort != 60000)"));
    try_open("v6 only", &format!("(outbound and ipv6 and not loopback and ((udp and udp.DstPort == 53 and udp.SrcPort != {PORT}) or (tcp and tcp.DstPort == 53))) or (inbound and ipv6 and not loopback and udp and udp.SrcPort == 1053)"));
}