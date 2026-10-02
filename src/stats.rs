//! Counters and the localhost control socket used by `dnsflt stats`.

use std::io::{BufReader, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

/// One monotonically increasing counter.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// Add one.
    #[inline]
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Add `n`.
    #[inline]
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    /// Current value.
    #[inline]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    /// Overwrite the value. Unlike [`Counter::inc`] this is not monotonic —
    /// only for gauges such as `last_rtt_us`.
    #[inline]
    pub fn store(&self, value: u64) {
        self.0.store(value, Ordering::Relaxed);
    }
}

/// Live counters shared by the capture loop, the pipeline and the control
/// socket. Every field is a plain relaxed atomic: they are statistics, not
/// synchronisation.
#[derive(Debug)]
pub struct Counters {
    /// Packets that matched the WinDivert filter.
    pub captured: Counter,
    /// Packets re-injected untouched (passthrough or unsupported).
    pub passed_through: Counter,
    /// Packets dropped because we could not make sense of them.
    pub dropped: Counter,
    /// Queries absorbed and answered by us.
    pub hijacked: Counter,
    /// Queries rewritten and sent to the upstream from the application's
    /// address (forward/NAT mode).
    pub forwarded: Counter,
    /// Queries routed to a per-rule server instead of the default upstream.
    pub rule_routed: Counter,
    /// Queries dropped because a rule said `block`.
    pub blocked: Counter,
    /// Queries dropped because the QTYPE is not in the whitelist.
    pub qtype_filtered: Counter,
    /// TCP:53 connections reset.
    pub tcp_reset: Counter,
    /// Queries answered straight from the cache.
    pub cache_hits: Counter,
    /// Queries that had to go to the upstream.
    pub cache_misses: Counter,
    /// Upstream answers received.
    pub upstream_ok: Counter,
    /// Upstream attempts that timed out.
    pub upstream_timeouts: Counter,
    /// Upstream attempts that failed for another reason.
    pub upstream_errors: Counter,
    /// One-shot TCP retries triggered by a truncated UDP answer.
    pub upstream_tcp_retries: Counter,
    /// Responses that did not match the question we asked.
    pub upstream_mismatched: Counter,
    /// Injected packets.
    pub injected: Counter,
    /// Injection failures.
    pub inject_errors: Counter,
    /// Answers dropped because they were too large for the client's buffer.
    pub truncated: Counter,
    /// Queries that never got an answer and were handed back to the network.
    pub fallback_forwarded: Counter,
    /// Queries dropped because the pending table was full.
    pub pending_overflow: Counter,
    /// Bytes of DNS payload sent upstream.
    pub bytes_up: Counter,
    /// Bytes of DNS payload received from the upstream.
    pub bytes_down: Counter,
    /// Cache entries currently held.
    pub cache_entries: Counter,
    /// In-flight queries.
    pub pending_entries: Counter,
    /// Samples of the last upstream round-trip time, in microseconds.
    pub last_rtt_us: Counter,
    /// Number of WinDivert flow-established events observed.
    pub flow_added: Counter,
    /// Number of WinDivert flow-deleted events observed.
    pub flow_removed: Counter,
    /// Bytes (or datagrams) sent to the upstream.
    pub upstream_sent: Counter,
    /// Bytes (or datagrams) received back from the upstream.
    pub upstream_recv: Counter,
    /// Interception start time.
    started: Instant,
    /// Wall-clock start time, in milliseconds since the epoch.
    started_epoch_ms: u64,
}

impl Default for Counters {
    fn default() -> Counters {
        Counters {
            captured: Counter::default(),
            passed_through: Counter::default(),
            dropped: Counter::default(),
            hijacked: Counter::default(),
            forwarded: Counter::default(),
            rule_routed: Counter::default(),
            blocked: Counter::default(),
            qtype_filtered: Counter::default(),
            tcp_reset: Counter::default(),
            cache_hits: Counter::default(),
            cache_misses: Counter::default(),
            upstream_ok: Counter::default(),
            upstream_timeouts: Counter::default(),
            upstream_errors: Counter::default(),
            upstream_tcp_retries: Counter::default(),
            upstream_mismatched: Counter::default(),
            injected: Counter::default(),
            inject_errors: Counter::default(),
            truncated: Counter::default(),
            fallback_forwarded: Counter::default(),
            pending_overflow: Counter::default(),
            bytes_up: Counter::default(),
            bytes_down: Counter::default(),
            cache_entries: Counter::default(),
            pending_entries: Counter::default(),
            last_rtt_us: Counter::default(),
            flow_added: Counter::default(),
            flow_removed: Counter::default(),
            upstream_sent: Counter::default(),
            upstream_recv: Counter::default(),
            started: Instant::now(),
            started_epoch_ms: 0,
        }
    }
}

impl Counters {
    /// Create a fresh counter set with the start time stamped.
    pub fn new() -> Counters {
        Counters {
            started: Instant::now(),
            started_epoch_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            ..Counters::default()
        }
    }

    /// Seconds since the interceptor started.
    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    /// Frozen copy of every counter.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            uptime_ms: self.uptime().as_millis() as u64,
            started_epoch_ms: self.started_epoch_ms,
            captured: self.captured.get(),
            passed_through: self.passed_through.get(),
            dropped: self.dropped.get(),
            hijacked: self.hijacked.get(),
            forwarded: self.forwarded.get(),
            rule_routed: self.rule_routed.get(),
            blocked: self.blocked.get(),
            qtype_filtered: self.qtype_filtered.get(),
            tcp_reset: self.tcp_reset.get(),
            cache_hits: self.cache_hits.get(),
            cache_misses: self.cache_misses.get(),
            upstream_ok: self.upstream_ok.get(),
            upstream_timeouts: self.upstream_timeouts.get(),
            upstream_errors: self.upstream_errors.get(),
            upstream_tcp_retries: self.upstream_tcp_retries.get(),
            upstream_mismatched: self.upstream_mismatched.get(),
            injected: self.injected.get(),
            inject_errors: self.inject_errors.get(),
            truncated: self.truncated.get(),
            fallback_forwarded: self.fallback_forwarded.get(),
            pending_overflow: self.pending_overflow.get(),
            bytes_up: self.bytes_up.get(),
            bytes_down: self.bytes_down.get(),
            cache_entries: self.cache_entries.get(),
            pending_entries: self.pending_entries.get(),
            last_rtt_us: self.last_rtt_us.get(),
            flow_added: self.flow_added.get(),
            flow_removed: self.flow_removed.get(),
            upstream_sent: self.upstream_sent.get(),
            upstream_recv: self.upstream_recv.get(),
        }
    }
}

/// A point-in-time view of [`Counters`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Milliseconds since start.
    pub uptime_ms: u64,
    /// Start time, milliseconds since the Unix epoch.
    pub started_epoch_ms: u64,
    /// See [`Counters::captured`].
    pub captured: u64,
    /// See [`Counters::passed_through`].
    pub passed_through: u64,
    /// See [`Counters::dropped`].
    pub dropped: u64,
    /// See [`Counters::hijacked`].
    pub hijacked: u64,
    /// See [`Counters::forwarded`].
    pub forwarded: u64,
    /// See [`Counters::rule_routed`].
    pub rule_routed: u64,
    /// See [`Counters::blocked`].
    pub blocked: u64,
    /// See [`Counters::qtype_filtered`].
    pub qtype_filtered: u64,
    /// See [`Counters::tcp_reset`].
    pub tcp_reset: u64,
    /// See [`Counters::cache_hits`].
    pub cache_hits: u64,
    /// See [`Counters::cache_misses`].
    pub cache_misses: u64,
    /// See [`Counters::upstream_ok`].
    pub upstream_ok: u64,
    /// See [`Counters::upstream_timeouts`].
    pub upstream_timeouts: u64,
    /// See [`Counters::upstream_errors`].
    pub upstream_errors: u64,
    /// See [`Counters::upstream_tcp_retries`].
    pub upstream_tcp_retries: u64,
    /// See [`Counters::upstream_mismatched`].
    pub upstream_mismatched: u64,
    /// See [`Counters::injected`].
    pub injected: u64,
    /// See [`Counters::inject_errors`].
    pub inject_errors: u64,
    /// See [`Counters::truncated`].
    pub truncated: u64,
    /// See [`Counters::fallback_forwarded`].
    pub fallback_forwarded: u64,
    /// See [`Counters::pending_overflow`].
    pub pending_overflow: u64,
    /// See [`Counters::bytes_up`].
    pub bytes_up: u64,
    /// See [`Counters::bytes_down`].
    pub bytes_down: u64,
    /// See [`Counters::cache_entries`].
    pub cache_entries: u64,
    /// See [`Counters::pending_entries`].
    pub pending_entries: u64,
    /// See [`Counters::last_rtt_us`].
    pub last_rtt_us: u64,
    /// See [`Counters::flow_added`].
    pub flow_added: u64,
    /// See [`Counters::flow_removed`].
    pub flow_removed: u64,
    /// See [`Counters::upstream_sent`].
    pub upstream_sent: u64,
    /// See [`Counters::upstream_recv`].
    pub upstream_recv: u64,
}

impl Snapshot {
    /// `(name, value)` pairs in report order.
    fn pairs(&self) -> [(&'static str, u64); 29] {
        [
            ("uptime_ms", self.uptime_ms),
            ("started_epoch_ms", self.started_epoch_ms),
            ("captured", self.captured),
            ("passed_through", self.passed_through),
            ("dropped", self.dropped),
            ("hijacked", self.hijacked),
            ("forwarded", self.forwarded),
            ("rule_routed", self.rule_routed),
            ("blocked", self.blocked),
            ("qtype_filtered", self.qtype_filtered),
            ("tcp_reset", self.tcp_reset),
            ("cache_hits", self.cache_hits),
            ("cache_misses", self.cache_misses),
            ("upstream_sent", self.upstream_sent),
            ("upstream_recv", self.upstream_recv),
            ("upstream_ok", self.upstream_ok),
            ("upstream_timeouts", self.upstream_timeouts),
            ("upstream_errors", self.upstream_errors),
            ("upstream_tcp_retries", self.upstream_tcp_retries),
            ("upstream_mismatched", self.upstream_mismatched),
            ("injected", self.injected),
            ("inject_errors", self.inject_errors),
            ("truncated", self.truncated),
            ("fallback_forwarded", self.fallback_forwarded),
            ("pending_overflow", self.pending_overflow),
            ("bytes_up", self.bytes_up),
            ("bytes_down", self.bytes_down),
            ("cache_entries", self.cache_entries),
            ("pending_entries", self.pending_entries),
        ]
    }

    /// Render as a single-line JSON object.
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push('{');
        for (index, (name, value)) in self.pairs().iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push('"');
            out.push_str(name);
            out.push_str("\":");
            out.push_str(&value.to_string());
        }
        out.push_str(",\"last_rtt_us\":");
        out.push_str(&self.last_rtt_us.to_string());
        out.push('}');
        out
    }

    /// Render as an aligned text table.
    pub fn to_table(&self) -> String {
        let mut out = String::with_capacity(640);
        for (name, value) in self.pairs() {
            let rendered = if name == "bytes_up" || name == "bytes_down" {
                format!("{value} ({})", human_bytes(value))
            } else {
                value.to_string()
            };
            out.push_str(&format!("{name:<22} {rendered}\n"));
        }
        out.push_str(&format!("{:<22} {}\n", "last_rtt_us", format_rtt(self.last_rtt_us)));
        out
    }
}

/// Format a byte count for humans.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Format a microsecond RTT for humans.
pub fn format_rtt(micros: u64) -> String {
    if micros == 0 {
        "n/a".to_string()
    } else if micros < 1_000 {
        format!("{micros} us")
    } else {
        format!("{:.2} ms", micros as f64 / 1000.0)
    }
}

/// Serve the control socket until the shutdown receiver flips.
///
/// The protocol is deliberately tiny: the client writes one line, we answer
/// with one JSON line and close.
pub async fn serve(
    addr: SocketAddr,
    counters: Arc<Counters>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("cannot bind control socket {addr}"))?;
    tracing::info!(%addr, "control socket listening (dnsflt stats)");
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::debug!("control socket shutting down");
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let counters = Arc::clone(&counters);
                        tokio::spawn(async move {
                            if let Err(err) = handle_client(stream, counters).await {
                                tracing::debug!(%peer, "control client error: {err:#}");
                            }
                        });
                    }
                    Err(err) => {
                        tracing::warn!("control socket accept failed: {err}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}

async fn handle_client(mut stream: tokio::net::TcpStream, counters: Arc<Counters>) -> Result<()> {
    use tokio::io::AsyncBufReadExt as _;
    use tokio::io::AsyncWriteExt as _;

    let (read_half, mut write_half) = stream.split();
    let mut reader = tokio::io::BufReader::new(read_half);
    let mut line = String::new();
    let read = tokio::time::timeout(Duration::from_millis(2000), reader.read_line(&mut line)).await;
    let command = match read {
        Ok(Ok(_)) => line.trim().to_ascii_lowercase(),
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => "stats".to_string(),
    };

    let reply = match command.as_str() {
        "" | "stats" | "stats json" | "json" => counters.snapshot().to_json(),
        "table" | "stats table" | "text" => format!("{}\n", counters.snapshot().to_table()),
        "ping" => "pong".to_string(),
        other => format!("{{\"error\":\"unknown command\",\"command\":{}}}", json_string(other)),
    };
    write_half.write_all(reply.as_bytes()).await?;
    write_half.write_all(b"\n").await?;
    write_half.flush().await?;
    Ok(())
}

/// Quote a string as a JSON literal.
pub fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Blocking client used by the `stats` sub-command.
pub fn fetch(addr: SocketAddr, command: &str, timeout: Duration) -> Result<String> {
    let stream = std::net::TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("cannot connect to {addr} — is dnsflt running?"))?;
    stream
        .set_read_timeout(Some(timeout))
        .context("cannot set read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("cannot set write timeout")?;
    let mut writer = stream.try_clone().context("cannot clone control socket")?;
    writer.write_all(command.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;

    // The reply may be a multi-line table, so read until EOF rather than a
    // single line: the server drops the stream as soon as it has replied.
    let mut reader = BufReader::new(stream);
    let mut body = String::new();
    reader
        .read_to_string(&mut body)
        .context("no reply from the control socket")?;
    let body = body.trim_end().to_string();
    if body.is_empty() {
        bail!("empty reply from the control socket");
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_snapshot() {
        let c = Counters::new();
        c.captured.inc();
        c.captured.inc();
        c.bytes_up.add(4096);
        let snap = c.snapshot();
        assert_eq!(snap.captured, 2);
        assert_eq!(snap.bytes_up, 4096);
        let json = snap.to_json();
        assert!(json.starts_with('{') && json.ends_with('}'));
        assert!(json.contains("\"captured\":2"));
        assert!(snap.to_table().contains("bytes_up"));
    }

    #[test]
    fn json_string_escapes() {
        assert_eq!(json_string("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
        assert_eq!(json_string("\u{1}"), "\"\\u0001\"");
    }

    #[test]
    fn human_units() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
        assert_eq!(format_rtt(0), "n/a");
        assert_eq!(format_rtt(500), "500 us");
        assert_eq!(format_rtt(2500), "2.50 ms");
    }

    #[tokio::test]
    async fn control_socket_round_trip() {
        let counters = Arc::new(Counters::new());
        counters.hijacked.inc();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener); // serve() rebinds; pick a free port and reuse it

        let counters_for_server = Arc::clone(&counters);
        let server = tokio::spawn(async move { serve(addr, counters_for_server, rx).await });

        // Give the server a moment to bind.
        for _ in 0..50 {
            if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let reply = tokio::task::spawn_blocking(move || fetch(addr, "stats", Duration::from_secs(2)))
            .await
            .unwrap()
            .expect("stats reply");
        assert!(reply.contains("\"hijacked\":1"), "{reply}");

        // The human-readable table is multi-line: the client must read the
        // whole reply, not just its first line.
        let table = tokio::task::spawn_blocking(move || fetch(addr, "table", Duration::from_secs(2)))
            .await
            .unwrap()
            .expect("table reply");
        assert!(table.lines().count() > 20, "table truncated:\n{table}");
        assert!(table.lines().next().unwrap().starts_with("uptime_ms"), "{table}");
        assert!(table.contains("last_rtt_us"), "{table}");

        let pong = tokio::task::spawn_blocking(move || fetch(addr, "ping", Duration::from_secs(2)))
            .await
            .unwrap()
            .expect("ping reply");
        assert_eq!(pong, "pong");

        let _ = tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }
}
