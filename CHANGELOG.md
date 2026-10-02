# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-02

### Added

- Transparent DNS interception on Windows via WinDivert: capture outbound
  UDP/53 queries, resolve through a configurable upstream, inject the answers
  back with the original server as source.
- Three modes: `hijack` (default), `forward` (source NAT) and `passthrough`.
- Routing rules with hostname wildcard matching (`block`, `passthrough`,
  `server` actions).
- Anti-spoofing validation of upstream answers (transaction ID, QR bit,
  OPCODE, Question section matching).
- DNS response cache and automatic TCP retry on truncated (TC=1) answers.
- `on_upstream_failure = "forward" | "drop"` with a deadline-based safety net
  that re-injects the original query to the original server.
- Config validation (`dnsflt check`) that rejects unknown keys.
- Windows service management (`install-service` / `uninstall-service`).
- Runtime statistics over a loopback TCP control socket (`dnsflt stats`,
  `--json`, `--watch`).
- Vendored WinDivert 2.2.2 runtime (dynamically linked, LGPL-3.0).
