//! Flow tracker: opens a `SNIFF|RECV_ONLY` flow handle and maps
//! `(protocol, local_port, is_v6)` → `process_id` for the local endpoints of
//! every TCP/UDP flow that has port 53 as its remote port.
//!
//! We need this when the configuration lists extra PIDs in `capture.exclude_pids`
//! (or our own PID): the application then never has its queries intercepted.
//! Note that we avoid using `local_address()` because the upstream wrapper has
//! a known bug for IPv6; port alone is unambiguous enough because two DNS
//! flows from the same process usually do not share an ephemeral port.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Result, anyhow};
use dashmap::DashMap;
use tracing::{debug, trace};
use windivert::prelude::*;

use crate::stats::Counters;

/// Identity of a flow endpoint. We deliberately omit the source address (v6
/// `local_address()` is broken in the upstream wrapper) and use the local
/// port + IPv6 flag instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Transport protocol (`IPPROTO_TCP = 6`, `IPPROTO_UDP = 17`).
    pub protocol: u8,
    /// Local port.
    pub local_port: u16,
    /// `true` when the flow is IPv6.
    pub is_v6: bool,
}

/// Outcome of a flow lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowVal {
    /// A single PID is associated with this flow.
    Known(u32),
    /// Two (or more) distinct PIDs share this key — we refuse to make a
    /// decision so we never wrongly drop traffic.
    Ambiguous,
}

impl FlowVal {
    fn absorb(self, pid: u32) -> FlowVal {
        match self {
            FlowVal::Known(p) if p == pid => FlowVal::Known(pid),
            FlowVal::Known(_) => FlowVal::Ambiguous,
            FlowVal::Ambiguous => FlowVal::Ambiguous,
        }
    }
}

/// The tracker plus the OS thread that drives the flow handle.
pub struct FlowTracker {
    map: DashMap<FlowKey, FlowVal>,
    handle: Arc<WinDivert<FlowLayer>>,
    counters: Arc<Counters>,
}

impl FlowTracker {
    /// Open the flow handle with the documented `SNIFF|RECV_ONLY` flags. The
    /// filter restricts to TCP/UDP flows destined for port 53 (outbound DNS).
    pub fn open(counters: Arc<Counters>) -> Result<Arc<Self>> {
        let filter = "outbound and (tcp or udp) and remotePort == 53";
        // WinDivert::flow() forces set_sniff() and set_recv_only(), which is
        // exactly the mandatory behaviour for FLOW.
        let handle = WinDivert::flow(filter, 0i16, WinDivertFlags::new())
            .map_err(|e| anyhow!("WinDivertFlow open failed: {e}"))?;
        Ok(Arc::new(FlowTracker {
            map: DashMap::new(),
            handle: Arc::new(handle),
            counters,
        }))
    }

    /// Spawn the blocking reader that drains the flow handle.
    pub fn spawn_reader(self: Arc<Self>, stop: Arc<std::sync::atomic::AtomicBool>) -> JoinHandle<()> {
        thread::Builder::new()
            .name("dnsflt-flow".into())
            .spawn(move || flow_reader(self, stop))
            .expect("spawn dnsflt-flow thread")
    }

    /// Returns `Some(pid)` only when the lookup is unambiguous; `None` for
    /// unknown/ambiguous flows.
    pub fn is_excluded(&self, key: FlowKey) -> Option<u32> {
        self.map.get(&key).and_then(|v| match *v {
                FlowVal::Known(pid) => Some(pid),
                FlowVal::Ambiguous => None,
            })
    }

    /// Number of flows currently tracked (used by tests).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Insertion helper (handy when restarting the tracker, also useful for
    /// unit tests).
    pub fn insert_for_test(&self, key: FlowKey, pid: u32) {
        self.map.insert(key, FlowVal::Known(pid));
    }
}

fn flow_reader(tracker: Arc<FlowTracker>, stop: Arc<std::sync::atomic::AtomicBool>) {
    let handle = Arc::clone(&tracker.handle);
    let buf_size = 2048usize;
    let mut buf = vec![0u8; buf_size];
    let backoff = Duration::from_millis(50);

    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        let pkt = match handle.recv(Some(&mut buf)) {
            Ok(p) => p,
            Err(e) => {
                trace!(error = %e, "flow recv error; backing off");
                std::thread::sleep(backoff);
                continue;
            }
        };
        let evt = pkt.address.event();
        let key = FlowKey {
            protocol: pkt.address.protocol(),
            local_port: pkt.address.local_port(),
            is_v6: pkt.address.ipv6(),
        };
        match evt {
            WinDivertEvent::FlowStablished => {
                let pid = pkt.address.process_id();
                tracker
                    .map
                    .entry(key)
                    .and_modify(|v| *v = v.absorb(pid))
                    .or_insert(FlowVal::Known(pid));
                tracker.counters.flow_added.inc();
                trace!(?key, pid, "flow established");
            }
            WinDivertEvent::FlowDeleted => {
                if tracker.map.remove(&key).is_some() {
                    tracker.counters.flow_removed.inc();
                    trace!(?key, "flow deleted");
                }
            }
            other => {
                // WinDivert generates Socket* events on the same handle even
                // when we asked for flow events. They're harmless here.
                trace!(event = ?other, "non-flow event (ignored)");
            }
        }
    }
    debug!("flow reader exiting");
}

/// Helper for the pipeline: build a `FlowKey` from an intercepted UDP or TCP
/// datagram using the local port (the application's source port).
pub fn key_for_udp(app_port: u16, is_v6: bool) -> FlowKey {
    FlowKey {
        protocol: crate::packet::IPPROTO_UDP,
        local_port: app_port,
        is_v6,
    }
}

pub fn key_for_tcp(app_port: u16, is_v6: bool) -> FlowKey {
    FlowKey {
        protocol: crate::packet::IPPROTO_TCP,
        local_port: app_port,
        is_v6,
    }
}

/// Compatibility shim: existing tests / callers sometimes hand us a `HashMap`
/// of PIDs (the `Config::exclude_pid_set()` output). This helper decides
/// whether a given key matches any of them.
pub fn pid_in_set(map: &HashMap<u32, ()>, pid: u32) -> bool {
    map.contains_key(&pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absorb_same_pid_is_idempotent() {
        let v = FlowVal::Known(1234);
        assert_eq!(v.absorb(1234), FlowVal::Known(1234));
    }

    #[test]
    fn absorb_different_pid_ambiguous() {
        let v = FlowVal::Known(1234);
        assert_eq!(v.absorb(5678), FlowVal::Ambiguous);
    }

    #[test]
    fn keys_are_distinct() {
        assert_ne!(key_for_udp(53, false), key_for_udp(53, true));
        assert_ne!(key_for_udp(53, false), key_for_tcp(53, false));
        assert_ne!(key_for_udp(1234, false), key_for_udp(1235, false));
    }

    #[test]
    fn lookup_unambiguous() {
        // Manually build a tracker (no handle — only the map is exercised).
        let map: DashMap<FlowKey, FlowVal> = DashMap::new();
        let k = key_for_udp(53123, false);
        map.insert(k, FlowVal::Known(4242));
        let v = map.get(&k).unwrap();
        assert!(matches!(*v, FlowVal::Known(4242)));
        assert_eq!(
            pid_in_set(&HashMap::from([(4242, ())]), 4242),
            true
        );
    }
}