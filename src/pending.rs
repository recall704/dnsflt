//! In-flight query bookkeeping.
//!
//! Two tables live here:
//!
//! * [`PendingTable`] — every query we have absorbed and not yet answered,
//!   keyed by the full 5-tuple plus the DNS transaction ID. It bounds memory
//!   and feeds the `pending_entries` counter.
//! * [`NatTable`] — the reverse index needed by `mode = "forward"`, mapping the
//!   application's socket back to the server it originally addressed so the
//!   upstream's reply can be rewritten on the way in.

use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::dns::Query;
use crate::packet::Family;

#[derive(Debug)]
struct TtlValue<V> {
    value: V,
    expires: Instant,
}

/// A `DashMap` with per-entry expiry, an entry cap and a cheap eviction policy.
#[derive(Debug)]
pub struct TtlMap<K: Eq + Hash, V> {
    map: DashMap<K, TtlValue<V>>,
    ttl: Duration,
    max: usize,
}

impl<K: Eq + Hash + Clone, V> TtlMap<K, V> {
    /// Create a map whose entries live at most `ttl` and which never holds more
    /// than `max` entries.
    pub fn new(ttl: Duration, max: usize) -> Self {
        TtlMap {
            map: DashMap::new(),
            ttl,
            max: max.max(16),
        }
    }

    /// Configured per-entry lifetime.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Entry cap.
    pub fn capacity(&self) -> usize {
        self.max
    }

    /// Number of entries, expired ones included.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `true` when the map holds nothing.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Look an entry up, reaping it first when it has expired.
    pub fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Eq + Hash + ?Sized,
        V: Clone,
    {
        let now = Instant::now();
        let entry = self.map.get(key)?;
        if entry.expires > now {
            return Some(entry.value.clone());
        }
        // Drop the read guard before taking the write lock: DashMap shards are
        // single-writer and removing while still holding the Ref deadlocks.
        drop(entry);
        self.map.remove(key);
        None
    }

    /// Insert an entry. Returns `false` when the map is at capacity and the
    /// caller should give up (and, for example, pass the packet through).
    pub fn insert(&self, key: K, value: V) -> bool {
        if self.map.len() >= self.max && !self.map.contains_key(&key) {
            self.gc();
            if self.map.len() >= self.max {
                return false;
            }
        }
        self.map.insert(
            key,
            TtlValue {
                value,
                expires: Instant::now() + self.ttl,
            },
        );
        true
    }

    /// Remove an entry.
    pub fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.map.remove(key).map(|(_, entry)| entry.value)
    }

    /// Drop every expired entry and return how many were removed.
    pub fn gc(&self) -> usize {
        let now = Instant::now();
        let stale: Vec<K> = self
            .map
            .iter()
            .filter(|entry| entry.expires <= now)
            .map(|entry| entry.key().clone())
            .collect();
        for key in &stale {
            self.map.remove(key);
        }
        stale.len()
    }

    /// Drop everything.
    pub fn clear(&self) {
        self.map.clear();
    }

    /// Snapshot every live value (used by tests and diagnostics).
    pub fn values(&self) -> Vec<V>
    where
        V: Clone,
    {
        let now = Instant::now();
        self.map
            .iter()
            .filter(|entry| entry.expires > now)
            .map(|entry| entry.value.clone())
            .collect()
    }
}

/// Identity of an in-flight query.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PendingKey {
    /// Address family.
    pub family: Family,
    /// IP protocol (`17` for UDP, `6` for TCP).
    pub protocol: u8,
    /// Application source port.
    pub sport: u16,
    /// Server destination port (always 53).
    pub dport: u16,
    /// Application source address.
    pub saddr: IpAddr,
    /// Server address the application meant to talk to.
    pub daddr: IpAddr,
    /// DNS transaction ID.
    pub dns_id: u16,
}

/// What we remember about an absorbed query.
#[derive(Debug, Clone)]
pub struct PendingQuery {
    /// The parsed question.
    pub query: Arc<Query>,
    /// Application source socket.
    pub src: SocketAddr,
    /// The server the application addressed.
    pub dst: SocketAddr,
}

/// Query table.
#[derive(Debug)]
pub struct PendingTable {
    inner: TtlMap<PendingKey, PendingQuery>,
}

impl PendingTable {
    /// Create a table with the given query TTL and entry cap.
    pub fn new(ttl: Duration, max: usize) -> Self {
        PendingTable {
            inner: TtlMap::new(ttl, max),
        }
    }

    /// Number of tracked queries.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` when nothing is in flight.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Record a query. `false` means the table is full.
    pub fn insert(&self, key: PendingKey, value: PendingQuery) -> bool {
        self.inner.insert(key, value)
    }

    /// Look a query up (currently only used by tests and diagnostics).
    pub fn get(&self, key: &PendingKey) -> Option<PendingQuery> {
        self.inner.get(key)
    }

    /// Forget a query.
    pub fn remove(&self, key: &PendingKey) -> Option<PendingQuery> {
        self.inner.remove(key)
    }

    /// Drop expired queries.
    pub fn gc(&self) -> usize {
        self.inner.gc()
    }

    /// Drop everything.
    pub fn clear(&self) {
        self.inner.clear()
    }
}

/// Reverse index for `mode = "forward"`.
///
/// Keyed by what the *inbound* reply will look like: the application address,
/// its port and the DNS transaction ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NatKey {
    /// Application address (the reply's destination).
    pub app_addr: IpAddr,
    /// Application port (the reply's destination port).
    pub app_port: u16,
    /// DNS transaction ID.
    pub dns_id: u16,
}

/// The mapping stored for a forwarded query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatEntry {
    /// The server the application originally addressed.
    pub server: SocketAddr,
    /// The application address.
    pub app: SocketAddr,
    /// The explicit upstream we re-sent the query to.
    pub upstream: SocketAddr,
    /// The original DNS payload that the application sent, used as a
    /// last-resort fallback if the upstream never replies.
    pub query: Vec<u8>,
}

/// NAT table.
#[derive(Debug)]
pub struct NatTable {
    inner: TtlMap<NatKey, NatEntry>,
}

impl NatTable {
    /// Create a table sized like the pending table.
    pub fn new(ttl: Duration, max: usize) -> Self {
        NatTable {
            inner: TtlMap::new(ttl, max),
        }
    }

    /// Number of tracked rewrites.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` when nothing is tracked.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Remember a rewrite. `false` means the table is full.
    pub fn insert(&self, key: NatKey, value: NatEntry) -> bool {
        self.inner.insert(key, value)
    }

    /// Look up a rewrite for an inbound reply.
    pub fn get(&self, key: &NatKey) -> Option<NatEntry> {
        self.inner.get(key)
    }

    /// Forget a rewrite.
    pub fn remove(&self, key: &NatKey) -> Option<NatEntry> {
        self.inner.remove(key)
    }

    /// Drop expired rewrites.
    pub fn gc(&self) -> usize {
        self.inner.gc()
    }

    /// Drop everything.
    pub fn clear(&self) {
        self.inner.clear()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns;

    fn query(name: &str, id: u16) -> Arc<Query> {
        Arc::new(dns::parse_query(&dns::build_query(name, 1, id, None)).unwrap())
    }

    fn key(id: u16) -> PendingKey {
        PendingKey {
            family: Family::V4,
            protocol: 17,
            sport: 50000,
            dport: 53,
            saddr: "10.0.0.2".parse().unwrap(),
            daddr: "8.8.8.8".parse().unwrap(),
            dns_id: id,
        }
    }

    #[test]
    fn insert_and_remove() {
        let table = PendingTable::new(Duration::from_secs(10), 4);
        let value = PendingQuery {
            query: query("example.com", 1),
            src: "10.0.0.2:50000".parse().unwrap(),
            dst: "8.8.8.8:53".parse().unwrap(),
        };
        assert!(table.insert(key(1), value.clone()));
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(&key(1)).unwrap().src, value.src);
        assert!(table.get(&key(2)).is_none());
        assert!(table.remove(&key(1)).is_some());
        assert!(table.is_empty());
    }

    #[test]
    fn full_table_rejects_new_keys_but_refreshes_known_ones() {
        let table = TtlMap::new(Duration::from_secs(10), 16);
        for i in 0..16u16 {
            assert!(table.insert(i, i), "insert {i}");
        }
        assert!(!table.insert(999, 999), "table should be full");
        assert!(table.insert(3, 3), "an existing key must still be refreshed");
        assert_eq!(table.len(), 16);
    }

    #[test]
    fn expiry() {
        let table = TtlMap::new(Duration::from_millis(1), 16);
        table.insert(1u16, "a");
        std::thread::sleep(Duration::from_millis(10));
        assert!(table.get(&1).is_none());
        table.insert(2u16, "b");
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(table.gc(), 1);
        assert!(table.is_empty());
    }

    #[test]
    fn nat_round_trip() {
        let nat = NatTable::new(Duration::from_secs(10), 16);
        let key = NatKey {
            app_addr: "10.0.0.2".parse().unwrap(),
            app_port: 50000,
            dns_id: 0x1234,
        };
        let entry = NatEntry {
            server: "8.8.8.8:53".parse().unwrap(),
            app: "10.0.0.2:50000".parse().unwrap(),
            upstream: "192.168.0.1:1053".parse().unwrap(),
            query: b"\x00\x01\x02\x03".to_vec(),
        };
        assert!(nat.insert(key.clone(), entry.clone()));
        assert_eq!(nat.get(&key), Some(entry.clone()));
        assert!(nat.remove(&key).is_some());
        assert!(nat.is_empty());
    }
}
