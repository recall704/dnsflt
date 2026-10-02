//! A small TTL cache for upstream answers.
//!
//! Entries are keyed by `(lowercased QNAME, QTYPE, QCLASS)` and hold the raw
//! response bytes exactly as the upstream produced them. On a hit the caller
//! only has to patch in the client's transaction ID — the wire ancestor name
//! is kept in its original case so nothing else needs rewriting.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::dns::Query;

/// Cache key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Lowercased QNAME in wire format.
    pub name: Vec<u8>,
    /// QTYPE.
    pub qtype: u16,
    /// QCLASS.
    pub qclass: u16,
}

impl CacheKey {
    /// Build a key from a parsed query.
    pub fn from_query(query: &Query) -> CacheKey {
        CacheKey {
            name: query.qname_lower.clone(),
            qtype: query.qtype,
            qclass: query.qclass,
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    response: Arc<Vec<u8>>,
    expires: Instant,
}

/// Bounded TTL cache.
#[derive(Debug)]
pub struct Cache {
    map: DashMap<CacheKey, Entry>,
    max_entries: usize,
    max_ttl: Duration,
}

impl Cache {
    /// Create a cache holding at most `max_entries` answers, clamping every TTL
    /// to `max_ttl`.
    pub fn new(max_entries: usize, max_ttl: Duration) -> Cache {
        Cache {
            map: DashMap::new(),
            max_entries: max_entries.max(16),
            max_ttl,
        }
    }

    /// Number of live entries (including ones that have just expired).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `true` when the cache holds nothing.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Look up an answer. Expired entries are removed on the way out.
    pub fn get(&self, key: &CacheKey) -> Option<Arc<Vec<u8>>> {
        let now = Instant::now();
        let entry = self.map.get(key)?;
        if entry.expires > now {
            return Some(Arc::clone(&entry.response));
        }
        // Drop the read guard before taking the write lock: DashMap shards are
        // single-writer and removing while still holding the Ref deadlocks.
        drop(entry);
        self.map.remove(key);
        None
    }

    /// Insert an answer with the given lifetime. A zero `ttl` is ignored so we
    /// never store something that is already stale.
    pub fn insert(&self, key: CacheKey, response: Arc<Vec<u8>>, ttl: Duration) {
        let ttl = ttl.min(self.max_ttl);
        if ttl.is_zero() {
            return;
        }
        if self.map.len() >= self.max_entries {
            self.evict();
        }
        self.map.insert(
            key,
            Entry {
                response,
                expires: Instant::now() + ttl,
            },
        );
    }

    /// Remove every expired entry and return how many were dropped.
    pub fn gc(&self) -> usize {
        let now = Instant::now();
        let stale: Vec<CacheKey> = self
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

    fn evict(&self) {
        self.gc();
        if self.map.len() < self.max_entries {
            return;
        }
        // Still full of live entries: drop the first quarter we run into. This
        // is deliberately crude — DNS answers are cheap to re-fetch and a
        // precise LRU would need bookkeeping on the hot path.
        let target = self.max_entries / 4;
        let victims: Vec<CacheKey> = self
            .map
            .iter()
            .take(target)
            .map(|entry| entry.key().clone())
            .collect();
        for key in &victims {
            self.map.remove(key);
        }
        tracing::debug!("cache evicted {} entries", victims.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns;

    fn key(name: &str, qtype: u16) -> CacheKey {
        let q = dns::parse_query(&dns::build_query(name, qtype, 1, None)).unwrap();
        CacheKey::from_query(&q)
    }

    #[test]
    fn hit_and_miss() {
        let cache = Cache::new(128, Duration::from_secs(300));
        let k = key("example.com", 1);
        assert!(cache.get(&k).is_none());
        cache.insert(k.clone(), Arc::new(vec![1, 2, 3]), Duration::from_secs(60));
        assert_eq!(cache.get(&k).as_deref(), Some(&vec![1, 2, 3]));
        assert!(cache.get(&key("example.com", 28)).is_none());
        assert!(cache.get(&key("other.com", 1)).is_none());
    }

    #[test]
    fn case_insensitive_lookup() {
        let cache = Cache::new(128, Duration::from_secs(300));
        let k = key("Example.COM", 1);
        cache.insert(k, Arc::new(vec![9]), Duration::from_secs(60));
        assert!(cache.get(&key("example.com", 1)).is_some());
    }

    #[test]
    fn zero_ttl_is_not_stored() {
        let cache = Cache::new(128, Duration::from_secs(300));
        let k = key("example.com", 1);
        cache.insert(k.clone(), Arc::new(vec![1]), Duration::ZERO);
        assert!(cache.get(&k).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn expiry_is_honoured() {
        let cache = Cache::new(128, Duration::from_secs(300));
        let k = key("example.com", 1);
        cache.insert(k.clone(), Arc::new(vec![1]), Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(15));
        assert!(cache.get(&k).is_none());
        assert_eq!(cache.gc(), 0, "the expired entry was already reaped on get");
    }

    #[test]
    fn max_ttl_clamps() {
        let cache = Cache::new(128, Duration::from_secs(5));
        let k = key("example.com", 1);
        cache.insert(k.clone(), Arc::new(vec![1]), Duration::from_secs(3600));
        let entry = cache.map.get(&k).unwrap();
        assert!(entry.expires <= Instant::now() + Duration::from_secs(5));
    }

    #[test]
    fn bounded_size() {
        let cache = Cache::new(16, Duration::from_secs(300));
        for i in 0..200u16 {
            cache.insert(key("example.com", i), Arc::new(vec![1]), Duration::from_secs(60));
        }
        assert!(cache.len() <= 16, "cache grew to {}", cache.len());
    }
}
