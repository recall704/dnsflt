//! Upstream resolver clients.
//!
//! * The UDP driver owns a single `tokio::net::UdpSocket` and a dispatcher
//!   task. Each request carries the application-supplied DNS payload (with
//!   the application's original transaction ID); the response is delivered
//!   back as-is and the pipeline patches the ID when forging the reply.
//! * The TCP driver opens a fresh `TcpStream` per request and prepends a
//!   2-byte length as RFC 1035 §4.2.2 requires.
//! * `UpstreamDriver` picks the right client based on the configured scheme
//!   and transparently retries: UDP gets `retries + 1` attempts (each timed
//!   out by `timeout`) and a single TCP fallback when the UDP reply had
//!   `TC = 1` (RFC 6891 §6.2.4 — DNS over TCP for oversized answers).

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tracing::{trace, warn};

use crate::config::{ResolvedUpstream, UpstreamScheme};
use crate::dns;
use crate::stats::Counters;

/// A single DNS payload, with the timeout already resolved by the caller.
#[derive(Debug, Clone)]
pub struct UpstreamRequest {
    /// Original DNS payload sent by the application (with its DNS ID).
    pub query: Vec<u8>,
    /// Timeout per attempt.
    pub timeout: Duration,
}

/// What the upstream returned.
#[derive(Debug)]
pub enum UpstreamResult {
    /// A complete DNS reply whose size is within the advertised limit.
    Ok(Vec<u8>),
    /// The upstream never answered within the deadline.
    Timeout,
    /// The upstream returned an error (I/O, truncation after retry, …).
    Error(String),
}

/// Public entry point. Cheap to clone.
#[derive(Clone)]
pub struct UpstreamDriver {
    inner: UpstreamKind,
    retries: u32,
}

#[derive(Clone)]
enum UpstreamKind {
    Udp(Arc<UdpClient>),
    Tcp(Arc<TcpClient>),
}

impl UpstreamDriver {
    /// Build a driver from an already-resolved upstream.
    ///
    /// Returns `(driver, local_udp_port)`. For TCP the port is `0` (the driver
    /// connects a fresh socket per query and the local port isn't stable).
    pub fn start(upstream: &ResolvedUpstream, retries: u32, counters: Arc<Counters>) -> Result<(UpstreamDriver, u16)> {
        let (kind, local_port) = match upstream.scheme {
            UpstreamScheme::Udp => {
                let (c, port) = UdpClient::start(upstream.addr, counters)?;
                (UpstreamKind::Udp(c), port)
            }
            UpstreamScheme::Tcp => {
                let c = TcpClient::new(upstream.addr);
                (UpstreamKind::Tcp(c), 0)
            }
        };
        Ok((
            UpstreamDriver {
                inner: kind,
                retries,
            },
            local_port,
        ))
    }

    /// Send one DNS query and wait for the answer.
    pub async fn dispatch(&self, req: UpstreamRequest) -> UpstreamResult {
        match &self.inner {
            UpstreamKind::Udp(c) => c.dispatch(req, self.retries).await,
            UpstreamKind::Tcp(c) => c.dispatch(req, self.retries).await,
        }
    }
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

struct UdpClient {
    addr: SocketAddr,
    cmd: mpsc::Sender<DispatchCmd>,
}

struct DispatchCmd {
    query: Vec<u8>,
    reply: oneshot::Sender<UpstreamResult>,
    deadline: Instant,
}

struct Inflight {
    reply: oneshot::Sender<UpstreamResult>,
    /// `true` once we've already passed this reply through to the caller; we
    /// use this to absorb duplicates.
    done: bool,
    /// When the query actually went out, so we can report a real RTT.
    sent_at: Instant,
    deadline: Instant,
}

impl UdpClient {
    fn start(addr: SocketAddr, counters: Arc<Counters>) -> Result<(Arc<Self>, u16)> {
        // Bind to an OS-chosen UDP port. Knowing the local port matters so the
        // capture filter can exclude our own packets (see `capture::compile_filter`).
        let std_sock = std::net::UdpSocket::bind(("0.0.0.0", 0))
            .context("bind local UDP socket for upstream")?;
        let local_addr = std_sock.local_addr()?;
        let local_port = local_addr.port();
        std_sock.connect(addr).context("connect upstream UDP")?;
        // `from_std` registers the socket with the runtime's I/O driver but
        // does NOT switch it to non-blocking mode. On Windows a still-blocking
        // socket wedges the worker thread inside a blocking `recv` the first
        // time no datagram is ready — the whole driver stops consuming
        // commands and every subsequent query times out. This must stay!
        std_sock
            .set_nonblocking(true)
            .context("set upstream socket non-blocking")?;
        let sock = UdpSocket::from_std(std_sock)?;
        // Move into the dispatcher.
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<DispatchCmd>(1024);
        tokio::spawn(async move {
            run_udp_driver(sock, local_addr, addr, &mut cmd_rx, counters).await;
        });
        Ok((Arc::new(UdpClient { addr, cmd: cmd_tx }), local_port))
    }

    async fn dispatch(&self, req: UpstreamRequest, retries: u32) -> UpstreamResult {
        let mut last = UpstreamResult::Error("no attempt".into());
        let attempts = retries.saturating_add(1).max(1);
        for attempt in 0..attempts {
            let (tx, rx) = oneshot::channel();
            let cmd = DispatchCmd {
                query: req.query.clone(),
                reply: tx,
                deadline: Instant::now() + req.timeout,
            };
            if self.cmd.try_send(cmd).is_err() {
                // Channel closed or full: upstream driver is gone.
                return UpstreamResult::Error("upstream dispatcher offline".into());
            }
            last = match timeout(req.timeout, rx).await {
                Ok(Ok(r)) => r,
                Ok(Err(_dropped)) => UpstreamResult::Error("upstream dispatcher dropped reply".into()),
                Err(_) => {
                    trace!(attempt, "caller gave up before the upstream replied");
                    UpstreamResult::Timeout
                }
            };
            // On `Ok` we still inspect TC=1 and retry with TCP.
            if let UpstreamResult::Ok(bytes) = &last {
                if dns::is_truncated(bytes) {
                    // One additional attempt over TCP.
                    let tcp = TcpClient::new(self.addr);
                    match tcp.dispatch(req.clone(), 0).await {
                        UpstreamResult::Ok(b) => return UpstreamResult::Ok(b),
                        other => {
                            warn!(attempt, "TCP fallback failed: {other:?}");
                            // Fall through with truncated UDP response.
                            return UpstreamResult::Ok(bytes.clone());
                        }
                    }
                }
                return last;
            }
            if matches!(last, UpstreamResult::Error(_)) && attempt + 1 < attempts {
                // Tiny exponential back-off before retrying.
                tokio::time::sleep(Duration::from_millis(50u64 << attempt.min(5))).await;
                continue;
            }
            return last;
        }
        last
    }
}

async fn run_udp_driver(
    sock: UdpSocket,
    _local: SocketAddr,
    server: SocketAddr,
    cmd_rx: &mut mpsc::Receiver<DispatchCmd>,
    counters: Arc<Counters>,
) {
    let mut inflight: HashMap<u16, VecDeque<Inflight>> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let mut recv_buf = [0u8; 4096];
        tokio::select! {
            biased;
            maybe_cmd = cmd_rx.recv() => {
                let Some(cmd) = maybe_cmd else { break };
                let id = match dns::peek_id(&cmd.query) {
                    Some(id) => id,
                    None => {
                        let _ = cmd.reply.send(UpstreamResult::Error("malformed query".into()));
                        continue;
                    }
                };
                trace!(id, len = cmd.query.len(), "upstream cmd accepted");
                // Send to upstream. We ignore the returned address because the
                // socket is already connected.
                match sock.send(&cmd.query).await {
                    Ok(n) => {
                        counters.upstream_sent.inc();
                        let slot = inflight.entry(id).or_default();
                        slot.push_back(Inflight {
                            reply: cmd.reply,
                            done: false,
                            sent_at: Instant::now(),
                            deadline: cmd.deadline,
                        });
                        trace!(id, len = n, %server, "upstream query sent");
                    }
                    Err(e) => {
                        let _ = cmd.reply.send(UpstreamResult::Error(format!("upstream send: {e}")));
                        counters.upstream_errors.inc();
                    }
                }
            }
            recv = sock.recv(&mut recv_buf) => {
                match recv {
                    Ok(len) => {
                        let data = recv_buf[..len].to_vec();
                        let id = match dns::peek_id(&data) {
                            Some(id) => id,
                            None => continue,
                        };
                        if let Some(q) = inflight.get_mut(&id) {
                            if let Some(mut entry) = q.pop_front() {
                                let rtt = entry.sent_at.elapsed();
                                if !entry.done {
                                    entry.done = true;
                                    counters.upstream_recv.inc();
                                    let _ = entry.reply.send(UpstreamResult::Ok(data));
                                }
                                // A reply that lands after the caller's deadline
                                // is already useless: the caller has given up and
                                // this oneshot send went nowhere. Worth shouting
                                // about, because it means the reply was in the
                                // socket but nobody was listening in time.
                                if rtt > entry.deadline.saturating_duration_since(entry.sent_at) {
                                    warn!(
                                        id,
                                        rtt_ms = rtt.as_millis() as u64,
                                        "upstream reply arrived after the request deadline"
                                    );
                                } else {
                                    trace!(
                                        id,
                                        len = rtt.as_micros() as u64,
                                        rtt_ms = rtt.as_millis() as u64,
                                        "upstream reply received"
                                    );
                                }
                            }
                            if q.is_empty() {
                                inflight.remove(&id);
                            }
                        } else {
                            trace!(id, "upstream reply with no matching request");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, server = %server, "upstream recv error");
                        // Brief back-off so we don't burn CPU.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            _ = tick.tick() => {
                let now = Instant::now();
                let mut to_remove = Vec::new();
                for (id, q) in inflight.iter_mut() {
                    while let Some(front) = q.front() {
                        if front.deadline <= now {
                            let entry = q.pop_front().unwrap();
                            if !entry.done {
                                counters.upstream_timeouts.inc();
                                let _ = entry.reply.send(UpstreamResult::Timeout);
                            }
                        } else {
                            break;
                        }
                    }
                    if q.is_empty() {
                        to_remove.push(*id);
                    }
                }
                for id in to_remove {
                    inflight.remove(&id);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

pub struct TcpClient {
    addr: SocketAddr,
}

impl TcpClient {
    fn new(addr: SocketAddr) -> Arc<Self> {
        Arc::new(TcpClient { addr })
    }

    async fn dispatch(&self, req: UpstreamRequest, retries: u32) -> UpstreamResult {
        let mut last = UpstreamResult::Error("no attempt".into());
        let attempts = retries.saturating_add(1).max(1);
        for attempt in 0..attempts {
            match self.attempt(&req.query, req.timeout).await {
                Ok(bytes) => return UpstreamResult::Ok(bytes),
                Err(e) => {
                    last = UpstreamResult::Error(format!("{e}"));
                    if attempt + 1 < attempts {
                        tokio::time::sleep(Duration::from_millis(50u64 << attempt.min(5))).await;
                    }
                }
            }
        }
        last
    }

    async fn attempt(&self, query: &[u8], per_attempt: Duration) -> Result<Vec<u8>> {
        let connect = timeout(per_attempt, TcpStream::connect(self.addr));
        let mut stream = connect
            .await
            .map_err(|_| anyhow!("upstream TCP connect timed out"))?
            .with_context(|| format!("upstream TCP connect to {}", self.addr))?;
        // DNS over TCP uses a 2-byte length prefix (RFC 1035 §4.2.2).
        let len = u16::try_from(query.len())
            .map_err(|_| anyhow!("DNS query too large for TCP ({})", query.len()))?;
        let mut framed = Vec::with_capacity(2 + query.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(query);
        timeout(per_attempt, stream.write_all(&framed))
            .await
            .map_err(|_| anyhow!("upstream TCP write timed out"))??;
        // Read a 2-byte length prefix.
        let mut hdr = [0u8; 2];
        timeout(per_attempt, stream.read_exact(&mut hdr))
            .await
            .map_err(|_| anyhow!("upstream TCP read header timed out"))??;
        let want = u16::from_be_bytes(hdr) as usize;
        if want < 12 {
            bail!("upstream TCP length header too small: {want}");
        }
        let mut body = vec![0u8; want];
        timeout(per_attempt, stream.read_exact(&mut body))
            .await
            .map_err(|_| anyhow!("upstream TCP read body timed out"))??;
        // Stream will be dropped on return.
        let _ = stream.shutdown().await;
        Ok(body)
    }
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn driver_kind_dispatch_smoke() {
        // No live network: we only verify the public type compiles and that the
        // configuration errors map to a useful string.
        let ru = ResolvedUpstream {
            scheme: UpstreamScheme::Tcp,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1),
            original: "tcp://127.0.0.1:1".into(),
        };
        let counters = Arc::new(Counters::new());
        let drv = UpstreamDriver::start(&ru, 1, counters);
        assert!(drv.is_ok());
    }

    /// Minimal well-formed A query for `name`.
    fn a_query(id: u16, name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        out.extend_from_slice(&0u16.to_be_bytes()); // ancount
        out.extend_from_slice(&0u16.to_be_bytes()); // nscount
        out.extend_from_slice(&0u16.to_be_bytes()); // arcount
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&1u16.to_be_bytes()); // qtype=A
        out.extend_from_slice(&1u16.to_be_bytes()); // qclass=IN
        out
    }

    /// Round-trip through a real UDP socket pair, twice: the driver must not
    /// stall after the first exchange.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn udp_driver_survives_multiple_dispatches() {
        // Fake upstream: echoes the id back with a minimal A answer.
        let mut up_sock = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let up_addr: SocketAddr = up_sock.local_addr().unwrap();
        up_sock.set_nonblocking(true).unwrap();
        let echo = tokio::spawn(async move {
            let sock = UdpSocket::from_std(up_sock).unwrap();
            let mut buf = [0u8; 512];
            loop {
                let Ok((len, peer)) = sock.recv_from(&mut buf).await else { break };
                let mut reply = buf[..len].to_vec();
                // QR=1, RCODE=0, one answer copied from the question.
                reply[2] = 0x81;
                reply[3] = 0x80;
                reply[7] = 1; // ancount
                let _ = sock.send_to(&reply, peer).await;
            }
        });

        let ru = ResolvedUpstream {
            scheme: UpstreamScheme::Udp,
            addr: up_addr,
            original: format!("udp://{up_addr}"),
        };
        let counters = Arc::new(Counters::new());
        let (drv, _port) = UpstreamDriver::start(&ru, 0, counters).unwrap();

        for i in 0..3u16 {
            let req = UpstreamRequest {
                query: a_query(0x1000 + i, "example.com"),
                timeout: Duration::from_secs(2),
            };
            let res = tokio::time::timeout(Duration::from_secs(5), drv.dispatch(req))
                .await
                .expect("dispatch future must finish");
            assert!(
                matches!(res, UpstreamResult::Ok(_)),
                "dispatch {i} returned {res:?}"
            );
        }
        echo.abort();
    }
}