//! Hot path: turn every intercepted frame into either an injected reply, a
//! forwarded packet, or a pass-through.
//!
//! Concurrency model: the capture thread (`capture::spawn_reader`) feeds a
//! bounded `mpsc::Sender<RawPacket>`. A small tokio task drains the channel
//! and spawns a short-lived task per packet; the per-packet tasks share a
//! [`Ctx`] full of `Arc`s so they can be processed in parallel.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::Receiver;
use tracing::{debug, trace, warn};

use crate::cache::{Cache, CacheKey};
use crate::capture::{Injector, RawPacket};
use crate::config::{CompiledRule, Config, Mode, OnUpstreamFailure, RuleAction};
use crate::dns::{self, DnsError, Query};
use crate::flowtrack::{key_for_tcp, key_for_udp, FlowTracker};
use crate::packet::{self, Family, IpInfo, parse_ip, parse_tcp, parse_udp};
use crate::pending::{NatEntry, NatKey, PendingKey, PendingQuery, PendingTable, NatTable};
use crate::stats::Counters;
use crate::upstream::{UpstreamDriver, UpstreamRequest, UpstreamResult};

/// Shared state handed to every per-packet task.
pub struct Ctx {
    pub config: Arc<Config>,
    pub counters: Arc<Counters>,
    pub injector: Injector,
    pub cache: Option<Arc<Cache>>,
    pub pending: Arc<PendingTable>,
    pub nat: Arc<NatTable>,
    pub upstream: UpstreamDriver,
    pub exclude: Option<Arc<FlowTracker>>,
    /// PIDs that must never be intercepted (own PID + `capture.exclude_pids`).
    pub exclude_pids: HashSet<u32>,
    /// Local UDP port our upstream client is bound to (used for self-exclusion).
    pub self_udp_port: u16,
    /// Whether `block_tcp_53` is active.
    pub block_tcp_53: bool,
    pub rules: Vec<CompiledRule>,
    pub compiled: CompiledFlags,
}

/// Compiled boolean derived from the configuration once at start-up.
#[derive(Debug, Clone, Copy)]
pub struct CompiledFlags {
    pub mode: Mode,
    pub on_upstream_failure: OnUpstreamFailure,
    pub dump: bool,
}

/// Drain the capture channel and dispatch each one to [`handle_packet`].
pub async fn run_dispatcher(
    mut rx: Receiver<RawPacket>,
    ctx: Arc<Ctx>,
    pending_max: usize,
) {
    let gc_interval = tokio::time::interval(Duration::from_secs(1));
    tokio::pin!(gc_interval);
    gc_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = gc_interval.tick() => {
                ctx.pending.gc();
                ctx.nat.gc();
                let pending_len = ctx.pending.len();
                if pending_len > pending_max {
                    // The table is over its cap: new queries will be dropped
                    // rather than queued. Worth a warning so the operator can
                    // see it rather than just watching `dropped` climb.
                    warn!(pending_len, pending_max, "pending table over capacity");
                }
            }
            maybe = rx.recv() => {
                let Some(raw) = maybe else { break };
                let ctx2 = Arc::clone(&ctx);
                tokio::spawn(async move { handle_packet(ctx2, raw).await; });
            }
        }
    }
}

async fn handle_packet(ctx: Arc<Ctx>, raw: RawPacket) {
    if raw.data.is_empty() {
        return;
    }

    let info = match parse_ip(&raw.data) {
        Ok(i) => i,
        Err(_) => {
            ctx.counters.dropped.inc();
            re_pass(&ctx, &raw);
            return;
        }
    };

    if info.fragmented {
        // Reassembling fragments from the kernel is out of scope; just pass
        // them through so the application can put them back together.
        ctx.counters.dropped.inc();
        re_pass(&ctx, &raw);
        return;
    }

    let proto = info.protocol;
    let app_port = match proto {
        packet::IPPROTO_UDP => match parse_udp(&raw.data, &info) {
            Ok(u) => u.sport,
            Err(_) => {
                re_pass(&ctx, &raw);
                return;
            }
        },
        packet::IPPROTO_TCP => match parse_tcp(&raw.data, &info) {
            Ok(t) => t.sport,
            Err(_) => {
                re_pass(&ctx, &raw);
                return;
            }
        },
        _ => {
            re_pass(&ctx, &raw);
            return;
        }
    };

    // Self-exclusion: packets that originated from our own client port would
    // otherwise bounce forever. The capture filter already excludes UDP from
    // our local port, but it's belt-and-braces.
    if proto == packet::IPPROTO_UDP && app_port == ctx.self_udp_port {
        re_pass(&ctx, &raw);
        return;
    }

    // Mode passthrough: re-inject untouched, no rules.
    if ctx.compiled.mode == Mode::Passthrough {
        re_pass(&ctx, &raw);
        return;
    }

    // PID exclusion via the flow table (only for outbound).
    if raw.outbound {
        let key = if proto == packet::IPPROTO_UDP {
            key_for_udp(app_port, info.family.is_v6())
        } else {
            key_for_tcp(app_port, info.family.is_v6())
        };
        if let Some(tracker) = &ctx.exclude {
            if let Some(pid) = tracker.is_excluded(key) {
                if ctx.exclude_pids.contains(&pid) {
                    re_pass(&ctx, &raw);
                    return;
                }
            }
        }
    }

    if proto == packet::IPPROTO_UDP {
        handle_udp(ctx, raw, info, app_port).await;
    } else if proto == packet::IPPROTO_TCP {
        if ctx.block_tcp_53 && app_port == 53 {
            handle_tcp_53(ctx, &raw, &info, app_port).await;
        } else {
            re_pass(&ctx, &raw);
        }
    } else {
        re_pass(&ctx, &raw);
    }
}

async fn handle_tcp_53(ctx: Arc<Ctx>, raw: &RawPacket, info: &IpInfo, server_port: u16) {
    let seg = match parse_tcp(&raw.data, &info) {
        Ok(s) => s,
        Err(e) => {
            trace!(error = %e, "parse_tcp on block path");
            re_pass(&ctx, raw);
            return;
        }
    };
    let (src, dst, sport, dport) = if raw.outbound {
        (info.dst, info.src, server_port, seg.dport)
    } else {
        (info.src, info.dst, seg.sport, seg.dport)
    };
    let payload_len = seg.payload_len;
    match packet::build_tcp_reset(src, dst, sport, dport, &seg, payload_len) {
        Ok(bytes) => {
            if let Err(e) = ctx.injector.inject(bytes, !raw.outbound, raw.ifidx, raw.subifidx) {
                warn!(error = %e, "inject TCP RST failed");
            } else {
                ctx.counters.tcp_reset.inc();
            }
        }
        Err(e) => warn!(error = %e, "build_tcp_reset failed"),
    }
}

async fn handle_udp(
    ctx: Arc<Ctx>,
    raw: RawPacket,
    info: IpInfo,
    _app_port: u16,
) {
    let udp = match parse_udp(&raw.data, &info) {
        Ok(u) => u,
        Err(_) => {
            re_pass(&ctx, &raw);
            return;
        }
    };
    // Only packets *destined* for DNS are ours. This must be the destination
    // port: on an outbound query the source port is the application's
    // ephemeral port, which is essentially never 53.
    if udp.dport != 53 {
        re_pass(&ctx, &raw);
        return;
    }
    let payload = raw.data.get(udp.payload_off..udp.payload_off + udp.payload_len);
    let payload = match payload {
        Some(p) => p,
        None => {
            re_pass(&ctx, &raw);
            return;
        }
    };
    let query = match dns::parse_query(payload) {
        Ok(q) => q,
        Err(e) => {
            if !matches!(e, DnsError::TooShort) {
                trace!(error = %e, "parse_query failed");
            }
            re_pass(&ctx, &raw);
            return;
        }
    };

    if let Some(rule) = match_rule(&ctx.rules, &query.name_text) {
        match rule.action {
            RuleAction::Block => {
                let reply = dns::servfail_response(&query);
                forge_and_inject(&ctx, &raw, info.dst, SocketAddr::new(info.src, _app_port), reply);
                ctx.counters.blocked.inc();
                return;
            }
            RuleAction::Passthrough => {
                // `re_pass` already counts the pass-through itself.
                re_pass(&ctx, &raw);
                return;
            }
            RuleAction::Server => {
                ctx.counters.rule_routed.inc();
                trace!("rule.server fallback to global upstream (M5)");
            }
        }
    }

    if !query.qtype_allowed(&ctx.config.capture.qtype_whitelist) {
        ctx.counters.qtype_filtered.inc();
        re_pass(&ctx, &raw);
        return;
    }

    let family = info.family;
    let app_ip = info.src;
    let server_ip = info.dst;
    let payload_owned = payload.to_vec();

    if ctx.compiled.mode == Mode::Forward {
        forward_dns(ctx, raw, family, app_ip, server_ip, payload_owned);
    } else {
        hijack_dns(ctx, raw, app_ip, server_ip, query, payload_owned).await;
    }
}

async fn hijack_dns(
    ctx: Arc<Ctx>,
    raw: RawPacket,
    app_ip: IpAddr,
    server_ip: IpAddr,
    query: Query,
    query_payload: Vec<u8>,
) {
    let sport = match raw_outbound_sport(&raw) {
        Some(p) => p,
        None => {
            re_pass(&ctx, &raw);
            return;
        }
    };
    let family = if raw.data[0] >> 4 == 6 { Family::V6 } else { Family::V4 };
    let app = SocketAddr::new(app_ip, sport);
    let server = SocketAddr::new(server_ip, 53);

    // Cache lookup.
    if let Some(cache) = &ctx.cache {
        let ck = CacheKey::from_query(&query);
        if let Some(bytes) = cache.get(&ck) {
            ctx.counters.cache_hits.inc();
            let mut reply = bytes.as_ref().clone();
            dns::patch_id(&mut reply, query.id);
            if dns::response_matches_query(&query, &reply) {
                forge_and_inject(&ctx, &raw, server_ip, app, reply);
                return;
            }
            // Bad cache entry — fall through to live resolution and let it
            // expire naturally.
        } else {
            ctx.counters.cache_misses.inc();
        }
    }

    // Record pending entry so duplicate retransmits are recognised.
    let pkey = PendingKey {
        family,
        protocol: packet::IPPROTO_UDP,
        sport,
        dport: 53,
        saddr: app_ip,
        daddr: server_ip,
        dns_id: query.id,
    };
    let _ = ctx.pending.insert(
        pkey,
        PendingQuery {
            query: Arc::new(query.clone()),
            src: server,
            dst: app,
        },
    );

    // Send to upstream.
    let req = UpstreamRequest {
        query: query_payload.clone(),
        timeout: Duration::from_millis(ctx.config.timeout_ms),
    };
    let sent_at = Instant::now();
    let res = ctx.upstream.dispatch(req).await;

    let reply = match res {
        UpstreamResult::Ok(bytes) => {
            ctx.counters.upstream_ok.inc();
            ctx.counters
                .last_rtt_us
                .store(sent_at.elapsed().as_micros() as u64);
            if dns::is_truncated(&bytes) {
                ctx.counters.truncated.inc();
            }
            if !dns::response_matches_query(&query, &bytes) {
                ctx.counters.upstream_mismatched.inc();
                warn!("upstream response did not match the request; treating as failure");
                on_failure(&ctx, &raw, server_ip, app, &query_payload, family);
                return;
            }
            let mut reply = bytes;
            dns::patch_id(&mut reply, query.id);

            if let Some(cache) = &ctx.cache {
                if let Some(ttl) = dns::min_answer_ttl(&reply) {
                    let key = CacheKey {
                        name: query.qname_lower.clone(),
                        qtype: query.qtype,
                        qclass: query.qclass,
                    };
                    cache.insert(key, Arc::new(reply.clone()), Duration::from_secs(ttl as u64));
                }
            }
            reply
        }
        UpstreamResult::Timeout => {
            ctx.counters.upstream_timeouts.inc();
            on_failure(&ctx, &raw, server_ip, app, &query_payload, family);
            return;
        }
        UpstreamResult::Error(msg) => {
            ctx.counters.upstream_errors.inc();
            warn!(error = %msg, "upstream error");
            on_failure(&ctx, &raw, server_ip, app, &query_payload, family);
            return;
        }
    };

    forge_and_inject(&ctx, &raw, server_ip, app, reply);
    ctx.counters.hijacked.inc();
}

fn on_failure(
    ctx: &Ctx,
    raw: &RawPacket,
    server_ip: IpAddr,
    _app: SocketAddr,
    query_payload: &[u8],
    family: Family,
) {
    match ctx.compiled.on_upstream_failure {
        OnUpstreamFailure::Forward => {
            forward_dns_inline(
                ctx,
                raw.clone(),
                family,
                raw_src_ip(raw),
                server_ip,
                query_payload.to_vec(),
            );
        }
        OnUpstreamFailure::Drop => {
            ctx.counters.dropped.inc();
        }
    }
}

fn forward_dns(
    ctx: Arc<Ctx>,
    raw: RawPacket,
    family: Family,
    app_ip: IpAddr,
    server_ip: IpAddr,
    query_payload: Vec<u8>,
) {
    forward_dns_inline(&ctx, raw, family, app_ip, server_ip, query_payload);
}

fn forward_dns_inline(
    ctx: &Ctx,
    raw: RawPacket,
    family: Family,
    app_ip: IpAddr,
    server_ip: IpAddr,
    query_payload: Vec<u8>,
) {
    let upstream = match ctx.config.resolve_upstream() {
        Ok(u) => u.addr,
        Err(_) => {
            re_pass(ctx, &raw);
            return;
        }
    };
    if upstream.ip().is_loopback() {
        re_pass(ctx, &raw);
        return;
    }
    if family != Family::of(&upstream.ip()) {
        ctx.counters.dropped.inc();
        re_pass(ctx, &raw);
        return;
    }

    let app_port = match raw_outbound_sport(&raw) {
        Some(p) => p,
        None => {
            re_pass(ctx, &raw);
            return;
        }
    };
    let app = SocketAddr::new(app_ip, app_port);
    let bytes = match packet::build_udp(app_ip, upstream.ip(), app_port, 53, 64, &query_payload) {
        Ok(b) => b,
        Err(_) => {
            re_pass(ctx, &raw);
            return;
        }
    };
    let original = raw.clone();

    let nat_key = NatKey {
        app_addr: app_ip,
        app_port,
        dns_id: dns::peek_id(&query_payload).unwrap_or(0),
    };
    let entry = NatEntry {
        server: SocketAddr::new(server_ip, 53),
        app,
        upstream,
        query: query_payload.clone(),
    };
    let _ = ctx.nat.insert(nat_key.clone(), entry);

    if let Err(e) = ctx.injector.inject(bytes, true, raw.ifidx, raw.subifidx) {
        warn!(error = %e, "forward inject (outbound) failed");
        return;
    }
    ctx.counters.forwarded.inc();

    let counters = Arc::clone(&ctx.counters);
    let nat = Arc::clone(&ctx.nat);
    let injector = ctx.injector.clone();
    let timeout = ctx.config.upstream_deadline();
    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        if let Some(entry) = nat.get(&nat_key) {
            if entry.server == SocketAddr::new(server_ip, 53) {
                counters.fallback_forwarded.inc();
                let _ = nat.remove(&nat_key);
                let rebuilt = packet::build_udp(app_ip, server_ip, app_port, 53, 64, &entry.query);
                if let Ok(bytes) = rebuilt {
                    if let Err(e) = injector.inject(bytes, true, original.ifidx, original.subifidx) {
                        warn!(error = %e, "fallback inject failed");
                    }
                }
            }
        }
    });
}

fn forge_and_inject(
    ctx: &Ctx,
    raw: &RawPacket,
    server_ip: IpAddr,
    app: SocketAddr,
    reply: Vec<u8>,
) {
    let bytes = match Injector::forge_udp_dns(SocketAddr::new(server_ip, 53), app, reply.clone()) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "forge_udp_dns failed");
            return;
        }
    };
    if let Err(e) = ctx.injector.inject(bytes, false, raw.ifidx, raw.subifidx) {
        warn!(error = %e, "inject reply failed");
        ctx.counters.inject_errors.inc();
    } else {
        ctx.counters.injected.inc();
    }
    if ctx.compiled.dump {
        let summary = dns::describe_full(&reply);
        debug!(reply = %summary, "injected reply");
    }
}

fn match_rule<'a>(rules: &'a [CompiledRule], name: &str) -> Option<&'a CompiledRule> {
    let n = name.to_ascii_lowercase();
    rules.iter().find(|r| r.matches(&n))
}

fn re_pass(ctx: &Ctx, raw: &RawPacket) {
    if let Err(e) = ctx.injector.repass(raw) {
        warn!(error = %e, "repass failed");
        ctx.counters.inject_errors.inc();
    } else {
        ctx.counters.passed_through.inc();
    }
}

fn raw_outbound_sport(raw: &RawPacket) -> Option<u16> {
    let info = parse_ip(&raw.data).ok()?;
    let udp = parse_udp(&raw.data, &info).ok()?;
    Some(udp.sport)
}

fn raw_src_ip(raw: &RawPacket) -> IpAddr {
    parse_ip(&raw.data)
        .map(|i| i.src)
        .unwrap_or_else(|_| IpAddr::from([0, 0, 0, 0]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HostPattern, RuleAction};

    #[test]
    fn match_rule_wildcard() {
        let rule = CompiledRule {
            patterns: vec![HostPattern::Any],
            action: RuleAction::Passthrough,
            server: None,
        };
        let rules = vec![rule.clone()];
        assert!(match_rule(&rules, "example.com").is_some());

        let rule2 = CompiledRule {
            patterns: vec![HostPattern::Subdomain("corp.local".into())],
            action: RuleAction::Passthrough,
            server: None,
        };
        let rules = vec![rule2];
        assert!(match_rule(&rules, "host.corp.local").is_some());
        assert!(match_rule(&rules, "corp.local").is_none());
        assert!(match_rule(&rules, "example.com").is_none());
    }
}