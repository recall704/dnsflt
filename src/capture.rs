//! WinDivert plumbing: filter construction, the blocking capture loop and the
//! injection helpers.
//!
//! Design constraints (verified against the WinDivert 2.2.2 driver source):
//!
//! * We open a single `Network` handle at priority 0. Self-injected packets are
//!   skipped by the driver because the packet's injected priority (`u32`,
//!   biased from the open priority) is equal to our handle's own encoded
//!   priority (`packet_priority <= handle->priority` ⇒ drop). As a result the
//!   same handle can drive both `recv` and `send` without ever creating a
//!   feedback loop.
//! * Every checksum flag in the injected `WINDIVERT_ADDRESS` is left zeroed:
//!   the driver then re-computes all checksums, so the packets we build do not
//!   have to be correct on their own. We still build them correctly in `packet`
//!   so that `cargo test` works without `WinDivert.dll`.
//! * Because the handle is *diverting* (no `SNIFF`/`RECV_ONLY`) every captured
//!   packet must be re-injected — either forwarded, replaced, or re-injected
//!   untouched — otherwise the stack hangs.

use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, trace, warn};
use windivert::prelude::*;

use crate::config::{Config, Mode};
use crate::stats::Counters;

/// One packet as it came out of the driver. The bytes include the IP header.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// The full frame (IP header + transport header + payload).
    pub data: Vec<u8>,
    /// Interface the packet was seen on.
    pub ifidx: u32,
    /// Sub-interface the packet was seen on.
    pub subifidx: u32,
    /// `true` for an outbound frame, `false` for inbound.
    pub outbound: bool,
    /// Whether the packet was loopback (we exclude loopback from the filter).
    pub loopback: bool,
}

impl RawPacket {
    /// Length of the captured frame in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` when the frame is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// One-shot specification for opening a divert handle.
pub struct DivertSpec<'a> {
    /// The compiled WinDivert filter string.
    pub filter: &'a str,
    /// `WinDivertSetParam(QUEUE_LENGTH, ..)`.
    pub queue_length: u64,
    /// `WinDivertSetParam(QUEUE_TIME, ..)` in milliseconds.
    pub queue_time_ms: u64,
    /// Per-`recv` buffer size in bytes (clamped to `[1280, 65535]`).
    pub buffer_size: usize,
}

/// Owns the network-layer WinDivert handle used to read every intercepted
/// packet.
pub struct Divert {
    handle: Arc<WinDivert<NetworkLayer>>,
    /// Copy of the filter the handle was opened with, for diagnostics.
    pub filter: String,
    /// Buffer size the reader thread allocates for each `recv` call.
    pub buffer_size: usize,
}

impl Divert {
    /// Open the handle and configure driver parameters.
    pub fn open(spec: &DivertSpec) -> Result<Divert> {
        let buffer_size = spec.buffer_size.clamp(1280, 65_535);
        let handle = WinDivert::network(spec.filter, 0i16, WinDivertFlags::new())
            .map_err(|e| open_error(e, spec.filter))?;
        // The driver clamps these to the documented minimum/maximum so we
        // don't have to validate them again.
        handle
            .set_param(WinDivertParam::QueueLength, spec.queue_length)
            .map_err(|e| anyhow!("set WinDivert QueueLength failed: {e}"))?;
        handle
            .set_param(WinDivertParam::QueueTime, spec.queue_time_ms)
            .map_err(|e| anyhow!("set WinDivert QueueTime failed: {e}"))?;
        Ok(Divert {
            handle: Arc::new(handle),
            filter: spec.filter.to_string(),
            buffer_size,
        })
    }

    /// Clone the underlying `Arc` so callers can drive `send` from elsewhere.
    pub fn handle(&self) -> Arc<WinDivert<NetworkLayer>> {
        Arc::clone(&self.handle)
    }

    /// Build an [`Injector`] that shares this handle.
    pub fn injector(&self, counters: Arc<Counters>, ifindex_override: u32) -> Injector {
        Injector {
            handle: Arc::clone(&self.handle),
            counters,
            ifindex_override,
        }
    }
}

/// Shares the underlying `WinDivert` handle and the counters so that the
/// pipeline can `send` packets from many places.
#[derive(Clone)]
pub struct Injector {
    handle: Arc<WinDivert<NetworkLayer>>,
    counters: Arc<Counters>,
    /// When non-zero, outbound injection pins to this interface index instead
    /// of the one we observed on the captured packet.
    ifindex_override: u32,
}

impl Injector {
    /// Inject `data` (a full IP frame) on the path that ends at the given
    /// interface. The driver's checksum re-computation is requested by leaving
    /// all the checksum flags in the address zeroed.
    ///
    /// * `outbound = true`  → `FwpsInjectNetworkSendAsync0` (the packet leaves
    ///   the box as if we had originated it).
    /// * `outbound = false` → `FwpsInjectNetworkReceiveAsync0` (the packet
    ///   appears to have arrived from the network, so the UDP socket the
    ///   application is using picks it up).
    pub fn inject(
        &self,
        data: Vec<u8>,
        outbound: bool,
        ifidx: u32,
        subifidx: u32,
    ) -> Result<()> {
        let idx = if self.ifindex_override != 0 {
            self.ifindex_override
        } else {
            ifidx
        };
        let mut pkt = unsafe { WinDivertPacket::<NetworkLayer>::new(data) };
        let addr = &mut pkt.address;
        addr.set_outbound(outbound);
        if !outbound {
            // The driver only reads IfIdx/SubIfIdx for receive-injection, but
            // we set both unconditionally for clarity.
            addr.set_interface_index(idx);
            addr.set_subinterface_index(subifidx);
        } else {
            addr.set_interface_index(idx);
            addr.set_subinterface_index(subifidx);
        }
        // impostor left as 0 → the driver does *not* decrement the TTL.
        // IP/TCP/UDP checksum flags left as 0 → the driver recomputes them.
        match self.handle.send(&pkt) {
            Ok(_bytes) => {
                self.counters.injected.inc();
                trace!(?outbound, idx, "injected packet");
                Ok(())
            }
            Err(e) => {
                self.counters.inject_errors.inc();
                Err(anyhow!("WinDivertSend failed: {e}"))
            }
        }
    }

    /// Re-inject a previously captured packet untouched.
    pub fn repass(&self, raw: &RawPacket) -> Result<()> {
        self.inject(raw.data.clone(), raw.outbound, raw.ifidx, raw.subifidx)
    }

    /// Build the full UDP/DNS reply packet the *application* will see, with
    /// `src = server`, `dst = app`, sport 53, dport = app port, payload =
    /// `dns_payload`. Returns a vector ready to be handed to [`Self::inject`]
    /// with `outbound = false`.
    pub fn forge_udp_dns(
        server: std::net::SocketAddr,
        app: std::net::SocketAddr,
        dns_payload: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let ttl = 64u8;
        crate::packet::build_udp(server.ip(), app.ip(), server.port(), app.port(), ttl, &dns_payload)
            .map_err(|e| anyhow!("build_udp (reply) failed: {e}"))
    }
}

/// Parameters used by the async reader thread.
pub struct ReaderOpts {
    /// Size of each `recv` buffer.
    pub buffer_size: usize,
    /// Channel capacity.
    pub queue_capacity: usize,
    /// Counter set to bump.
    pub counters: Arc<Counters>,
    /// When set, the loop exits on the next error.
    pub stop: Arc<std::sync::atomic::AtomicBool>,
}

/// Spawn the blocking capture thread. The returned handle is `JoinHandle<()>`
/// for the OS thread; the function returns immediately after the thread is
/// started.
pub fn spawn_reader(
    handle: Arc<WinDivert<NetworkLayer>>,
    opts: ReaderOpts,
    tx: Sender<RawPacket>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("dnsflt-recv".into())
        .spawn(move || reader_loop(handle, opts, tx))
        .expect("failed to spawn dnsflt-recv thread")
}

fn reader_loop(
    handle: Arc<WinDivert<NetworkLayer>>,
    opts: ReaderOpts,
    tx: Sender<RawPacket>,
) {
    let ReaderOpts {
        buffer_size,
        queue_capacity: _,
        counters,
        stop,
    } = opts;
    let mut buf = vec![0u8; buffer_size];
    let backoff = Duration::from_millis(50);
    let mut last_err_log: Option<String> = None;

    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        let pkt = match handle.recv(Some(&mut buf)) {
            Ok(p) => p,
            Err(e) => {
                // Coalesce repeated identical errors so we don't spam the log.
                let desc = format!("{e}");
                if last_err_log.as_deref() != Some(desc.as_str()) {
                    warn!(error = %desc, "WinDivertRecv error");
                    last_err_log = Some(desc);
                }
                std::thread::sleep(backoff);
                continue;
            }
        };
        last_err_log = None;
        let data: Vec<u8> = pkt.data.to_vec();
        let raw = RawPacket {
            data,
            ifidx: pkt.address.interface_index(),
            subifidx: pkt.address.subinterface_index(),
            outbound: pkt.address.outbound(),
            loopback: pkt.address.loopback(),
        };
        counters.captured.inc();
        match tx.try_send(raw.clone()) {
            Ok(()) => {}
            Err(TrySendError::Full(rejected)) => {
                // The pipeline is behind. We can't block the capture thread
                // (that would overflow the driver queue and start dropping
                // packets), and we can't drop the packet either (WinDivert is
                // diverting it). Re-inject it untouched so the application
                // still gets an answer from the real resolver.
                counters.dropped.inc();
                warn!("capture queue full; falling back to passthrough");
                let inj = Injector {
                    handle: Arc::clone(&handle),
                    counters: Arc::clone(&counters),
                    ifindex_override: 0,
                };
                if let Err(e) = inj.repass(&rejected) {
                    error!(error = %e, "re-pass on queue full failed");
                } else {
                    counters.passed_through.inc();
                }
            }
            Err(TrySendError::Closed(_)) => {
                debug!("capture channel closed; reader exiting");
                break;
            }
        }
    }
    debug!("capture reader thread exiting");
}

// ---------------------------------------------------------------------------
// Filter construction
// ---------------------------------------------------------------------------

/// Compile the user-facing capture config plus a few runtime facts (the local
/// port the upstream client is bound to, etc.) into a WinDivert filter string.
pub fn compile_filter(
    cfg: &Config,
    self_udp_port: u16,
    self_tcp_port: u16,
    is_forward: bool,
    upstream_port: u16,
) -> Result<String> {
    let v4 = cfg.capture.intercept_ipv4;
    let v6 = cfg.capture.intercept_ipv6;
    if !v4 && !v6 {
        bail!("at least one of capture.intercept_ipv4 or capture.intercept_ipv6 must be true");
    }
    let family = match (v4, v6) {
        (true, true) => "(ip or ipv6)".to_string(),
        (true, false) => "ip".to_string(),
        (false, true) => "ipv6".to_string(),
        (false, false) => unreachable!(),
    };

    // Outbound leg, split per transport.
    //
    // Each branch is guarded by its protocol keyword and expresses the
    // self-exclusion with the `!=` operator rather than `not (field == n)`.
    // WinDivert *rejects* `not (udp.SrcPort == n)` outright (INVALID_PARAMETER)
    // even when the branch is already guarded by `udp`: it cannot negate a
    // comparison on a field that may be absent from the packet. Verified
    // against WinDivert 2.2.2 with examples/filter_probe{,2}.rs.
    let udp_branch = if self_udp_port == 0 {
        "udp and udp.DstPort == 53".to_string()
    } else {
        format!("udp and udp.DstPort == 53 and udp.SrcPort != {self_udp_port}")
    };
    let tcp_branch = if cfg.capture.block_tcp_53 {
        if self_tcp_port == 0 {
            Some("tcp and tcp.DstPort == 53".to_string())
        } else {
            Some(format!("tcp and tcp.DstPort == 53 and tcp.SrcPort != {self_tcp_port}"))
        }
    } else {
        None
    };
    let port_sel = match tcp_branch {
        Some(tcp) => format!("({udp_branch} or {tcp})"),
        None => udp_branch,
    };

    let out = format!("(outbound and {family} and not loopback and {port_sel})");

    let mut parts = vec![out];
    if is_forward && upstream_port != 0 {
        // Forward mode also needs to see the upstream's reply, which comes
        // inbound on the upstream's source port.
        let in_clause = format!(
            "(inbound and {family} and not loopback and udp and udp.SrcPort == {upstream_port})"
        );
        parts.push(in_clause);
    }
    Ok(parts.join(" or "))
}

fn open_error(err: WinDivertError, filter: &str) -> anyhow::Error {
    use windivert::error::WinDivertError as E;
    match err {
        E::Open(open) => match open {
            windivert::error::WinDivertOpenError::AccessDenied => {
                anyhow!("WinDivert refused the handle: not running as Administrator")
            }
            windivert::error::WinDivertOpenError::MissingSYS => anyhow!(
                "WinDivert32.sys / WinDivert64.sys not found next to WinDivert.dll \
                 (re-run the `cargo build` or check the vendored files)"
            ),
            windivert::error::WinDivertOpenError::InvalidParameter => {
                anyhow!("WinDivert rejected the filter `{filter}` (InvalidParameter)")
            }
            other => anyhow!("WinDivertOpen failed: {other}"),
        },
        other => anyhow!("WinDivertOpen failed: {other}"),
    }
}

#[allow(dead_code)]
pub(crate) fn default_capture_buffer(max_packet_size: u64) -> usize {
    let v = if max_packet_size == 0 {
        65_535
    } else {
        max_packet_size
    };
    v.clamp(1280, 65_535) as usize
}

#[allow(dead_code)]
pub fn mode_is_forward(m: Mode) -> bool {
    matches!(m, Mode::Forward)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn default_filter_includes_udp_tcp_dns() {
        let cfg = Config::default();
        let f = compile_filter(&cfg, 0, 0, false, 0).unwrap();
        assert!(f.contains("udp.DstPort == 53"));
        assert!(f.contains("not loopback"));
    }

    #[test]
    fn filter_includes_tcp_when_block_enabled() {
        let mut cfg = Config::default();
        cfg.capture.block_tcp_53 = true;
        let f = compile_filter(&cfg, 0, 0, false, 0).unwrap();
        assert!(f.contains("tcp.DstPort == 53"));
    }

    #[test]
    fn filter_excludes_self_port() {
        let mut cfg = Config::default();
        cfg.capture.block_tcp_53 = true;
        let f = compile_filter(&cfg, 50000, 50001, false, 0).unwrap();
        // WinDivert 2.2.2 rejects `not (udp.SrcPort == n)`, so self-exclusion
        // must use the `!=` operator inside each protocol branch.
        assert!(f.contains("udp.SrcPort != 50000"));
        assert!(f.contains("tcp.SrcPort != 50001"));
        assert!(!f.contains("not (udp.SrcPort"));
    }

    #[test]
    fn forward_mode_appends_inbound_clause() {
        let cfg = Config::default();
        let f = compile_filter(&cfg, 0, 0, true, 1053).unwrap();
        assert!(f.contains("inbound"));
        assert!(f.contains("udp.SrcPort == 1053"));
    }

    #[test]
    fn v4_only_filter() {
        let mut cfg = Config::default();
        cfg.capture.intercept_ipv6 = false;
        let f = compile_filter(&cfg, 0, 0, false, 0).unwrap();
        assert!(f.contains("ip ") || f.contains("(ip and") || f.contains("ip and"));
        assert!(!f.contains("ipv6"));
    }
}
