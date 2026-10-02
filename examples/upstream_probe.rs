//! Isolated upstream-driver probe: no WinDivert, no capture.
//!
//! Runs UpstreamDriver against a local UDP echo server three times to prove
//! whether the driver survives multiple dispatches.
//!
//! Run from target/release (WinDivert.dll must sit next to the exe).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

use dnsflt::config::{ResolvedUpstream, UpstreamScheme};
use dnsflt::stats::Counters;
use dnsflt::upstream::{UpstreamDriver, UpstreamRequest};

fn a_query(id: u16, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_target(false)
        .init();
    let up_sock = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let up_addr: SocketAddr = up_sock.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let sock = UdpSocket::from_std(up_sock).unwrap();
        let mut buf = [0u8; 512];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((len, peer)) => {
                    eprintln!("ECHO: got {} bytes id={}", len, u16::from_be_bytes([buf[0], buf[1]]));
                    let mut reply = buf[..len].to_vec();
                    reply[2] = 0x81;
                    reply[3] = 0x80;
                    reply[7] = 1;
                    let _ = sock.send_to(&reply, peer).await;
                    eprintln!("ECHO: replied to {peer}");
                }
                Err(_) => break,
            }
        }
    });

    let ru = ResolvedUpstream {
        scheme: UpstreamScheme::Udp,
        addr: up_addr,
        original: format!("udp://{up_addr}"),
    };
    let counters = Arc::new(Counters::new());
    let (drv, local_port) = UpstreamDriver::start(&ru, 0, counters.clone()).unwrap();
    println!("driver up, local_port={local_port}");

    // Heartbeat: if this stops printing while dispatch hangs, the whole
    // runtime is frozen; if it keeps printing, only some wakeups are lost.
    let hb = tokio::spawn(async {
        let mut n = 0u32;
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            n += 1;
            eprintln!("HEARTBEAT {n}");
        }
    });

    for i in 0..3u16 {
        let req = UpstreamRequest {
            query: a_query(0x1000 + i, "example.com"),
            timeout: Duration::from_secs(2),
        };
        let start = std::time::Instant::now();
        let res = tokio::time::timeout(Duration::from_secs(5), drv.dispatch(req)).await;
        match res {
            Ok(r) => println!("dispatch {i}: OK in {:?} -> {:?}", start.elapsed(), match r {
                dnsflt::upstream::UpstreamResult::Ok(bytes) => format!("{} bytes", bytes.len()),
                other => format!("{other:?}"),
            }),
            Err(_) => println!("dispatch {i}: DISPATCH FUTURE TIMED OUT (driver stuck!)"),
        }
    }
    println!(
        "counters: sent={} recv={} ok={} timeouts={}",
        counters.upstream_sent.get(),
        counters.upstream_recv.get(),
        counters.upstream_ok.get(),
        counters.upstream_timeouts.get()
    );
    echo.abort();
    hb.abort();
}