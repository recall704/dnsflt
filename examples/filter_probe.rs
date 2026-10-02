//! Bisect which clause of the generated filter WinDivert rejects.
//!
//! The driver is the only authority on filter syntax, so this opens a real
//! handle for each candidate and reports what the driver says. Requires
//! Administrator.
//!
//!     cargo build --release --example filter_probe
//!     target\release\examples\filter_probe.exe

use windivert::prelude::*;

fn try_open(label: &str, filter: &str) {
    match WinDivert::network(filter, 0i16, WinDivertFlags::new()) {
        Ok(h) => {
            println!("  OK    {label}\n          {filter}");
            drop(h);
        }
        Err(e) => println!("  FAIL  {label}\n          {filter}\n          -> {e}"),
    }
}

fn main() {
    // The exact filter dnsflt generated (port filled in at runtime).
    let full = "(outbound and ip and (udp.DstPort == 53 or tcp.DstPort == 53) \
                and not (udp.SrcPort == 54080) and not loopback)";

    println!("== generated filter ==");
    try_open("full", full);

    println!("\n== bisect: drop one clause at a time ==");
    try_open("no SrcPort", "(outbound and ip and (udp.DstPort == 53 or tcp.DstPort == 53) and not loopback)");
    try_open("no loopback", "(outbound and ip and (udp.DstPort == 53 or tcp.DstPort == 53) and not (udp.SrcPort == 54080))");
    try_open("udp only", "(outbound and ip and udp.DstPort == 53 and not (udp.SrcPort == 54080) and not loopback)");
    try_open("tcp only", "(outbound and ip and tcp.DstPort == 53 and not (udp.SrcPort == 54080) and not loopback)");
    try_open("no SrcPort, no loopback", "(outbound and ip and (udp.DstPort == 53 or tcp.DstPort == 53))");

    println!("\n== isolate the SrcPort clause ==");
    try_open("bare udp.SrcPort eq", "udp.SrcPort == 54080");
    try_open("not bare udp.SrcPort eq", "not (udp.SrcPort == 54080)");
    try_open("not bare udp.SrcPort eq, with ip", "ip and not (udp.SrcPort == 54080)");
    try_open("not bare udp.SrcPort eq, with outbound", "outbound and not (udp.SrcPort == 54080)");
    try_open("not bare udp.SrcPort eq, outbound+ip", "outbound and ip and not (udp.SrcPort == 54080)");

    println!("\n== isolate the loopback clause ==");
    try_open("bare loopback", "loopback");
    try_open("not bare loopback", "not loopback");
    try_open("not loopback with ip", "ip and not loopback");

    println!("\n== isolate the or-group ==");
    try_open("or-group only", "(udp.DstPort == 53 or tcp.DstPort == 53)");
    try_open("or-group with not SrcPort", "(udp.DstPort == 53 or tcp.DstPort == 53) and not (udp.SrcPort == 54080)");

    println!("\n== candidate fixes ==");
    try_open("fix A: SrcPort guard inside each branch",
        "(outbound and ip and ((udp.DstPort == 53 and not (udp.SrcPort == 54080)) or tcp.DstPort == 53) and not loopback)");
    try_open("fix B: separate udp/tcp groups",
        "(outbound and ip and not loopback and ((udp and udp.DstPort == 53 and not (udp.SrcPort == 54080)) or (tcp and tcp.DstPort == 53)))");
    try_open("fix C: udp.SrcPort comparison inside udp guard",
        "(outbound and ip and not loopback and ((udp and udp.DstPort == 53 and udp.SrcPort != 54080) or (tcp and tcp.DstPort == 53)))");
}