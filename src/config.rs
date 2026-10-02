//! TOML configuration: schema, defaults, validation and rule compilation.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::packet::Family;

/// What to do with an intercepted DNS query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Absorb the query, resolve it ourselves, and forge the reply so the
    /// application believes it came from the original server.
    Hijack,
    /// Rewrite both directions (NAT): the query is re-sent to the upstream
    /// address and the upstream's reply is rewritten back to the original
    /// server address.
    Forward,
    /// Only log; packets are re-injected untouched.
    Passthrough,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Hijack
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Mode::Hijack => "hijack",
            Mode::Forward => "forward",
            Mode::Passthrough => "passthrough",
        })
    }
}

impl std::str::FromStr for Mode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "hijack" | "absorb" => Ok(Mode::Hijack),
            "forward" | "nat" | "redirect" => Ok(Mode::Forward),
            "passthrough" | "pass" | "sniff" => Ok(Mode::Passthrough),
            other => bail!("unknown mode `{other}` (expected hijack|forward|passthrough)"),
        }
    }
}

/// What to do when the upstream never answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnUpstreamFailure {
    /// Re-inject the original query so the real server still gets it.
    Forward,
    /// Drop it; the application resolves via its own retry/timeout policy.
    Drop,
}

impl Default for OnUpstreamFailure {
    fn default() -> Self {
        OnUpstreamFailure::Forward
    }
}

/// Rule action for a hostname match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// Send this name to a dedicated upstream server.
    Server,
    /// Answer the application with `NXDOMAIN`-style behaviour (actually a
    /// `SERVFAIL`, which is what applications handle cleanly) and drop it.
    Block,
    /// Let the packet travel to the original server untouched.
    Passthrough,
}

/// Transport used to reach the upstream resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpstreamScheme {
    /// Plain UDP.
    Udp,
    /// DNS over TCP with a 2-byte length prefix.
    Tcp,
}

impl std::fmt::Display for UpstreamScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            UpstreamScheme::Udp => "udp",
            UpstreamScheme::Tcp => "tcp",
        })
    }
}

/// A parsed upstream endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedUpstream {
    /// Transport scheme.
    pub scheme: UpstreamScheme,
    /// Resolved socket address.
    pub addr: SocketAddr,
    /// The text as written in the config.
    pub original: String,
}

impl std::fmt::Display for ResolvedUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}", self.scheme, self.addr)
    }
}

/// Parse an upstream string.
///
/// Accepted: `udp://host:port`, `tcp://host:port`, bare `host:port`
/// (defaults to UDP), bare `host` (defaults to port 53).
/// `https://` (DoH) and `tls://` / `http://` (DoT) are rejected with a clear
/// "not implemented" message — they are M5 work.
pub fn parse_upstream(raw: &str) -> Result<ResolvedUpstream> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("upstream address is empty");
    }
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((s, rest)) => {
            let scheme = match s.to_ascii_lowercase().as_str() {
                "udp" => UpstreamScheme::Udp,
                "tcp" => UpstreamScheme::Tcp,
                "https" | "doh" => bail!(
                    "upstream `{raw}`: DNS-over-HTTPS is not implemented yet (planned for M5); use udp:// or tcp://"
                ),
                "tls" | "dot" | "http" => bail!(
                    "upstream `{raw}`: DNS-over-TLS/HTTP is not implemented yet (planned for M5); use udp:// or tcp://"
                ),
                other => bail!("upstream `{raw}`: unknown scheme `{other}` (expected udp:// or tcp://)"),
            };
            (scheme, rest)
        }
        None => (UpstreamScheme::Udp, trimmed),
    };

    if rest.is_empty() {
        bail!("upstream `{raw}` has no host");
    }
    let hostport = if rest.contains(':') && !rest.ends_with(']') {
        // already host:port (including [v6]:port)
        rest.to_string()
    } else if rest.starts_with('[') {
        // [v6] without a port
        format!("{rest}:53")
    } else {
        format!("{rest}:53")
    };

    let addr = hostport
        .to_socket_addrs()
        .with_context(|| format!("upstream `{raw}`: cannot resolve `{hostport}`"))?
        .next()
        .with_context(|| format!("upstream `{raw}`: `{hostport}` resolved to no addresses"))?;

    Ok(ResolvedUpstream {
        scheme,
        addr,
        original: trimmed.to_string(),
    })
}

/// Interception settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaptureConfig {
    /// Capture `ip`-framed queries.
    pub intercept_ipv4: bool,
    /// Capture `ipv6`-framed queries.
    pub intercept_ipv6: bool,
    /// Answer TCP:53 with a RST and drop the connection.
    pub block_tcp_53: bool,
    /// QTYPEs to intercept; empty means "everything".
    pub qtype_whitelist: Vec<u16>,
    /// Extra process IDs to leave alone (our own PID is always excluded).
    pub exclude_pids: Vec<u32>,
    /// Pin outbound injection to a specific interface index (0 = automatic).
    pub upstream_ifindex: u32,
    /// WinDivert queue length.
    pub queue_length: u64,
    /// WinDivert queue time, in milliseconds.
    pub queue_time_ms: u64,
    /// Size of the receive buffer, in bytes (0 = 65535).
    pub max_packet_size: u64,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        CaptureConfig {
            intercept_ipv4: true,
            intercept_ipv6: true,
            block_tcp_53: false,
            qtype_whitelist: Vec::new(),
            exclude_pids: Vec::new(),
            upstream_ifindex: 0,
            queue_length: 4096,
            queue_time_ms: 2000,
            max_packet_size: 0,
        }
    }
}

/// Logging settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// Default verbosity (`error`..`trace`).
    pub level: String,
    /// Also write logs to this file.
    pub file: Option<PathBuf>,
    /// Print a decoded packet summary for every intercepted datagram.
    pub dump: bool,
    /// Roll the log file once a day instead of appending forever.
    pub rotate: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig {
            level: "info".into(),
            file: None,
            dump: false,
            rotate: true,
        }
    }
}

/// Control socket settings used by `dnsflt stats`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ControlConfig {
    /// Serve the counter endpoint.
    pub enabled: bool,
    /// `host:port` to listen on.
    pub addr: String,
}

impl Default for ControlConfig {
    fn default() -> Self {
        ControlConfig {
            enabled: true,
            addr: "127.0.0.1:53535".into(),
        }
    }
}

/// Pending-query-table limits.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PendingConfig {
    /// Maximum in-flight queries before we stop absorbing and pass through.
    pub max_entries: usize,
    /// Hard deadline for an in-flight query, in milliseconds.
    pub ttl_ms: u64,
}

impl Default for PendingConfig {
    fn default() -> Self {
        PendingConfig {
            max_entries: 10_000,
            ttl_ms: 10_000,
        }
    }
}

/// One hostname routing rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Hostnames or wildcard patterns (`*.corp.local`, `*corp.local`).
    pub hostnames: Vec<String>,
    /// What to do with matching queries. Omitted means: `server` if a
    /// `server` is given, otherwise `block`.
    #[serde(default)]
    pub action: Option<RuleAction>,
    /// Upstream for this rule. Implies `action = "server"` when `action` is
    /// omitted; required when `action = "server"` is spelled out.
    pub server: Option<String>,
}

impl Rule {
    /// Effective action: explicit `action`, else inferred from `server`.
    fn effective_action(&self) -> RuleAction {
        self.action.unwrap_or(if self.server.is_some() {
            RuleAction::Server
        } else {
            RuleAction::Block
        })
    }
}

/// One compiled hostname pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    /// Bare `*` — matches every name.
    Any,
    /// `*.corp.local` — subdomains of the suffix only; the apex itself is
    /// *not* matched.
    Subdomain(String),
    /// `*corp.local` — any name ending in the suffix, apex included.
    Suffix(String),
    /// Plain hostname — matches the name itself and its subdomains.
    Host(String),
}

/// A rule with its patterns and server already resolved.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Compiled hostname patterns.
    pub patterns: Vec<HostPattern>,
    /// Action to take.
    pub action: RuleAction,
    /// Pre-resolved dedicated upstream.
    pub server: Option<ResolvedUpstream>,
}

impl CompiledRule {
    /// Whether `name` (trailing dot optional, case-insensitive) matches.
    pub fn matches(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.');
        let name = name.to_ascii_lowercase();
        self.patterns.iter().any(|pattern| match pattern {
            HostPattern::Any => true,
            HostPattern::Subdomain(suffix) => {
                name.len() > suffix.len()
                    && name.ends_with(suffix)
                    && name.as_bytes()[name.len() - suffix.len() - 1] == b'.'
            }
            HostPattern::Suffix(suffix) => name.ends_with(suffix),
            HostPattern::Host(host) => {
                name == *host
                    || name.len() > host.len()
                        && name.ends_with(host)
                        && name.as_bytes()[name.len() - host.len() - 1] == b'.'
            }
        })
    }
}

/// The whole configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Upstream resolver (`udp://`, `tcp://`, or bare `host:port`).
    pub upstream: String,
    /// Per-attempt timeout, in milliseconds.
    pub timeout_ms: u64,
    /// Extra attempts after the first one.
    pub retries: u32,
    /// Interception mode.
    pub mode: Mode,
    /// Enable the TTL cache.
    pub cache: bool,
    /// Upper bound on cached TTLs, in seconds.
    pub cache_max_ttl: u64,
    /// Behaviour when the upstream does not answer.
    pub on_upstream_failure: OnUpstreamFailure,
    /// Capture settings.
    pub capture: CaptureConfig,
    /// Log settings.
    pub log: LogConfig,
    /// Control socket settings.
    pub control: ControlConfig,
    /// Hostname routing rules, evaluated in order.
    pub rules: Vec<Rule>,
    /// Pending table limits.
    pub pending: PendingConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            upstream: "192.168.0.1:1053".into(),
            timeout_ms: 3000,
            retries: 1,
            mode: Mode::default(),
            cache: false,
            cache_max_ttl: 300,
            on_upstream_failure: OnUpstreamFailure::default(),
            capture: CaptureConfig::default(),
            log: LogConfig::default(),
            control: ControlConfig::default(),
            rules: Vec::new(),
            pending: PendingConfig::default(),
        }
    }
}

impl Config {
    /// Read and validate a config file.
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config `{}`", path.display()))?;
        let cfg: Config = toml::from_str(&text)
            .with_context(|| format!("cannot parse config `{}`", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Same as [`Config::load`] but tolerates a missing file by returning the
    /// built-in defaults.
    pub fn load_or_default(path: &Path) -> Result<Config> {
        if path.exists() {
            Config::load(path)
        } else {
            Ok(Config::default())
        }
    }

    /// Check every field for consistency.
    pub fn validate(&self) -> Result<()> {
        if !(100..=60_000).contains(&self.timeout_ms) {
            bail!("timeout_ms must be within 100..60000 (got {})", self.timeout_ms);
        }
        if self.retries > 10 {
            bail!("retries must be within 0..10 (got {})", self.retries);
        }
        if self.cache_max_ttl > 86_400 {
            bail!(
                "cache_max_ttl must be within 0..86400 seconds (got {})",
                self.cache_max_ttl
            );
        }
        if self.pending.max_entries == 0 {
            bail!("pending.max_entries must be at least 1");
        }
        if !(100..=600_000).contains(&self.pending.ttl_ms) {
            bail!(
                "pending.ttl_ms must be within 100..600000 (got {})",
                self.pending.ttl_ms
            );
        }
        if self.pending.ttl_ms < self.timeout_ms {
            bail!(
                "pending.ttl_ms ({}) must be >= timeout_ms ({}), otherwise queries expire before the upstream answers",
                self.pending.ttl_ms,
                self.timeout_ms
            );
        }
        if !(32..=16_384).contains(&self.capture.queue_length) {
            bail!(
                "capture.queue_length must be within 32..16384 (got {})",
                self.capture.queue_length
            );
        }
        if !(100..=16_000).contains(&self.capture.queue_time_ms) {
            bail!(
                "capture.queue_time_ms must be within 100..16000 (got {})",
                self.capture.queue_time_ms
            );
        }
        if !self.capture.intercept_ipv4 && !self.capture.intercept_ipv6 {
            bail!("capture.intercept_ipv4 and capture.intercept_ipv6 cannot both be false");
        }
        // Resolve everything up front so that a typo fails at startup and not
        // on the first query.
        let upstream = parse_upstream(&self.upstream)
            .with_context(|| "invalid `upstream` (or `mode = \"hijack\"` needs a working upstream)")?;
        if self.mode == Mode::Forward {
            if upstream.scheme != UpstreamScheme::Udp {
                bail!("mode = \"forward\" only supports udp:// upstreams");
            }
            if upstream.addr.ip().is_loopback() {
                bail!(
                    "mode = \"forward\" cannot use a loopback upstream (`{}`): \
                     WinDivert does not capture loopback traffic, so the reply would never be seen",
                    upstream.addr
                );
            }
        }
        self.control_addr()?;
        for (index, rule) in self.rules.iter().enumerate() {
            if rule.hostnames.is_empty() {
                bail!("rules[{index}].hostnames must not be empty");
            }
            match rule.effective_action() {
                RuleAction::Server => {
                    let server = rule.server.as_deref().with_context(|| {
                        format!("rules[{index}] uses action = \"server\" but has no `server`")
                    })?;
                    parse_upstream(server)
                        .with_context(|| format!("rules[{index}].server is invalid"))?;
                }
                _ => {
                    if rule.server.is_some() {
                        tracing::warn!(
                            "rules[{index}].server is ignored because action is not \"server\""
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Resolve the configured upstream.
    pub fn resolve_upstream(&self) -> Result<ResolvedUpstream> {
        parse_upstream(&self.upstream)
    }

    /// Parse the configured control-socket address.
    pub fn control_addr(&self) -> Result<SocketAddr> {
        let raw = self.control.addr.trim();
        let candidate = if raw.contains(':') {
            raw.to_string()
        } else {
            format!("{raw}:53535")
        };
        candidate
            .to_socket_addrs()
            .with_context(|| format!("control.addr `{}` is not a valid address", self.control.addr))?
            .next()
            .with_context(|| format!("control.addr `{}` resolved to no addresses", self.control.addr))
    }

    /// Compile the hostname rules into matchable form.
    pub fn compile_rules(&self) -> Result<Vec<CompiledRule>> {
        let mut out = Vec::with_capacity(self.rules.len());
        for (index, rule) in self.rules.iter().enumerate() {
            let mut patterns = Vec::with_capacity(rule.hostnames.len());
            for pattern in &rule.hostnames {
                let p = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
                let compiled = if p == "*" || p == "*." {
                    HostPattern::Any
                } else if let Some(rest) = p.strip_prefix("*.") {
                    HostPattern::Subdomain(rest.to_string())
                } else if let Some(rest) = p.strip_prefix('*') {
                    HostPattern::Suffix(rest.to_string())
                } else if p.contains('*') {
                    bail!(
                        "rules[{index}]: wildcard is only supported as a leading `*`, `*.` or `*suffix` (got `{pattern}`)"
                    );
                } else {
                    HostPattern::Host(p)
                };
                patterns.push(compiled);
            }
            let action = rule.effective_action();
            let server = match action {
                RuleAction::Server => {
                    let raw = rule.server.as_deref().context("missing server")?;
                    Some(parse_upstream(raw).with_context(|| format!("rules[{index}].server"))?)
                }
                _ => None,
            };
            out.push(CompiledRule {
                patterns,
                action,
                server,
            });
        }
        Ok(out)
    }

    /// Total deadline for one upstream query including retries.
    pub fn upstream_deadline(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.timeout_ms * (self.retries as u64 + 1))
    }

    /// True when both families are captured (used for filter construction).
    pub fn captures(&self, family: Family) -> bool {
        match family {
            Family::V4 => self.capture.intercept_ipv4,
            Family::V6 => self.capture.intercept_ipv6,
        }
    }

    /// Lookup helper for the `exclude_pids` list, combined with our own PID.
    pub fn exclude_pid_set(&self) -> HashMap<u32, ()> {
        let mut set = HashMap::with_capacity(self.capture.exclude_pids.len() + 1);
        set.insert(std::process::id(), ());
        for pid in &self.capture.exclude_pids {
            set.insert(*pid, ());
        }
        set
    }

    /// Addresses we must never intercept because they are our own upstream.
    pub fn upstream_endpoints(&self) -> Vec<(IpAddr, SocketAddr)> {
        let mut out = Vec::new();
        if let Ok(up) = self.resolve_upstream() {
            out.push((up.addr.ip(), up.addr));
        }
        for rule in &self.rules {
            if let Some(server) = rule.server.as_deref() {
                if let Ok(up) = parse_upstream(server) {
                    out.push((up.addr.ip(), up.addr));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_parsing() {
        let up = parse_upstream("192.168.0.1:1053").unwrap();
        assert_eq!(up.scheme, UpstreamScheme::Udp);
        assert_eq!(up.addr.port(), 1053);

        let up = parse_upstream("tcp://1.1.1.1:53").unwrap();
        assert_eq!(up.scheme, UpstreamScheme::Tcp);
        assert_eq!(up.addr.port(), 53);

        let up = parse_upstream("8.8.8.8").unwrap();
        assert_eq!(up.addr.port(), 53);

        assert!(parse_upstream("https://dns.google/dns-query").is_err());
        assert!(parse_upstream("tls://1.1.1.1").is_err());
        assert!(parse_upstream("").is_err());
        assert!(parse_upstream("udp://").is_err());
        assert!(parse_upstream("bogus://1.1.1.1").is_err());
    }

    #[test]
    fn defaults_are_valid() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = toml::from_str::<Config>("nope = 1").unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn parses_the_documented_example() {
        let text = r#"
upstream = "192.168.0.1:1053"
timeout_ms = 3000
retries = 1
mode = "hijack"
cache = false
cache_max_ttl = 300
on_upstream_failure = "forward"

[capture]
intercept_ipv4 = true
intercept_ipv6 = true
block_tcp_53 = true
qtype_whitelist = []
exclude_pids = []
upstream_ifindex = 0

[log]
level = "info"
dump = false

[control]
enabled = true
addr = "127.0.0.1:53535"

[[rules]]
hostnames = ["*.corp.local"]
action = "server"
server = "10.0.0.1:53"
"#;
        let cfg: Config = toml::from_str(text).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.mode, Mode::Hijack);
        assert!(cfg.capture.block_tcp_53);
        let rules = cfg.compile_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].matches("host.corp.local"));
        assert!(!rules[0].matches("CORP.local"));
        assert!(!rules[0].matches("corp.local.evil.com"));
        assert!(!rules[0].matches("example.com"));
    }

    /// `*suffix` matches the apex as well; `*.suffix` does not.
    #[test]
    fn star_without_dot_matches_apex() {
        let cfg = Config {
            rules: vec![Rule {
                hostnames: vec!["*corp.local".into()],
                action: Some(RuleAction::Block),
                server: None,
            }],
            ..Config::default()
        };
        let rules = cfg.compile_rules().unwrap();
        assert!(rules[0].matches("CORP.local"));
        assert!(rules[0].matches("host.corp.local"));
        assert!(rules[0].matches("xcorp.local"));
        assert!(!rules[0].matches("corp.local.evil.com"));
        assert!(!rules[0].matches("example.com"));
    }

    #[test]
    fn validation_bounds() {
        let mut cfg = Config::default();
        cfg.timeout_ms = 10;
        assert!(cfg.validate().is_err());
        cfg.timeout_ms = 3000;

        cfg.retries = 42;
        assert!(cfg.validate().is_err());
        cfg.retries = 1;

        cfg.cache_max_ttl = 999_999;
        assert!(cfg.validate().is_err());
        cfg.cache_max_ttl = 300;

        cfg.capture.intercept_ipv4 = false;
        cfg.capture.intercept_ipv6 = false;
        assert!(cfg.validate().is_err());
        cfg.capture.intercept_ipv4 = true;
        cfg.capture.intercept_ipv6 = true;

        cfg.pending.ttl_ms = 100;
        assert!(cfg.validate().is_err());
        cfg.pending.ttl_ms = 10_000;

        cfg.upstream = "not a host".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rule_without_server_is_rejected() {
        let cfg = Config {
            rules: vec![Rule {
                hostnames: vec!["x".into()],
                action: Some(RuleAction::Server),
                server: None,
            }],
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
    }

    /// A rule carrying a `server` but no explicit `action` must still be
    /// accepted (the action is inferred as `server`).
    #[test]
    fn rule_action_is_inferred_from_server() {
        let cfg = Config {
            rules: vec![Rule {
                hostnames: vec!["x".into()],
                action: None,
                server: Some("10.0.0.53:53".into()),
            }],
            ..Config::default()
        };
        assert!(cfg.validate().is_ok());
        let compiled = cfg.compile_rules().expect("compile");
        assert_eq!(compiled[0].action, RuleAction::Server);
        assert!(compiled[0].server.is_some());
    }

    /// A rule with neither `action` nor `server` defaults to blocking.
    #[test]
    fn rule_action_defaults_to_block() {
        let cfg = Config {
            rules: vec![Rule {
                hostnames: vec!["x".into()],
                action: None,
                server: None,
            }],
            ..Config::default()
        };
        assert!(cfg.validate().is_ok());
        let compiled = cfg.compile_rules().expect("compile");
        assert_eq!(compiled[0].action, RuleAction::Block);
    }

    #[test]
    fn wildcard_must_be_leading() {
        let cfg = Config {
            rules: vec![Rule {
                hostnames: vec!["a.*.b".into()],
                action: Some(RuleAction::Block),
                server: None,
            }],
            ..Config::default()
        };
        assert!(cfg.compile_rules().is_err());
    }
}
