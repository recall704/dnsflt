//! Minimal tokio freeze repro: one task select!s on UDP recv + interval tick,
//! echoing every datagram; the other sends three and waits for replies.
//! If timers/IO die after the first exchange, this prints nothing further.

use std::time::Duration;

use tokio::net::UdpSocket;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let b = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let std_a = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    // VARIANT: from_std on an UNCONNECTED socket; recv_from/send_to below.
    let a = UdpSocket::from_std(std_a).unwrap();
    let a_addr = a.local_addr().unwrap();
    b.connect(a_addr).await.unwrap();

    eprintln!("A={a_addr} B={}", b.local_addr().unwrap());

    let hb = tokio::spawn(async {
        let mut n = 0u32;
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            n += 1;
            eprintln!("HEARTBEAT {n}");
        }
    });

    // A: echo via select! with a 100ms interval, exactly like run_udp_driver.
    let echo = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut buf = [0u8; 512];
        loop {
            tokio::select! {
                biased;
                r = a.recv_from(&mut buf) => {
                    match r {
                        Ok((len, peer)) => {
                            eprintln!("A: echo {} bytes to {peer}", len);
                            let _ = a.send_to(&buf[..len], peer).await;
                        }
                        Err(e) => eprintln!("A: recv error {e}"),
                    }
                }
                _ = tick.tick() => {
                    eprintln!("A: tick");
                }
            }
        }
    });

    for i in 0..3u32 {
        eprintln!("B: sending {i}");
        b.send(&[i as u8, 0, 0]).await.unwrap();
        let mut buf = [0u8; 16];
        match tokio::time::timeout(Duration::from_secs(2), b.recv(&mut buf)).await {
            Ok(Ok(n)) => eprintln!("B: got reply {i} ({n} bytes)"),
            _ => eprintln!("B: NO REPLY for {i}"),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    echo.abort();
    hb.abort();
    eprintln!("DONE");
}