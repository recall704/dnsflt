# dnsflt

**English** | [简体中文](README.zh-CN.md)

A single-process Windows CLI DNS interceptor. `dnsflt` uses WinDivert to capture
all local DNS queries sent to port 53, forwards them to an upstream resolver of
your choice, and injects the answers back into the network stack — applications
never notice that the replies did not come from the server they originally
addressed.

Behavior-wise it is equivalent to [YogaDNS](https://inlhec.io/): applications
keep talking to `8.8.8.8:53` without any per-application configuration and
without ever knowing that a different resolver actually answered.

```
app ──sendto(8.8.8.8:53)──▶ WinDivert (intercept)
                              │
                              ├─ UDP ─▶ 192.168.0.1:1053
                              │           │
                              │◀── reply ─┘
                              │
app ◀──injected reply (src=8.8.8.8:53)──┘
```

## How it works

1. **Capture.** A WinDivert handle is opened at the `Network` layer with the
   filter `outbound and (ip or ipv6) and udp.DstPort == 53 and not loopback`.
   Loopback traffic is invisible to the driver and therefore excluded; the
   filter also excludes the source port of our own upstream socket so we never
   capture our own queries.
   Note: WinDivert 2.2.2 refuses to compile `not (udp.SrcPort == N)` (even with
   an `udp` guard in front); the filter must be written using the `!=`
   operator inside each protocol branch instead.
2. **Parsing.** IP/UDP headers and DNS queries are parsed by hand on the hot
   path. `hickory-proto` is only used for the human-readable `--dump` output
   and never touches the interception path.
3. **Forwarding.** The query payload is sent to the upstream over a regular
   UDP socket; an in-flight table keyed by DNS ID matches the answers.
   Truncated responses (TC=1) automatically trigger one TCP retry.
   The upstream socket must be `set_nonblocking(true)` *before* being handed
   to `from_std` — on Windows, a blocking socket freezes the worker thread in
   a synchronous `recv` and the driver stops consuming commands entirely.
4. **Validation.** An answer's ID must match and it must be a response. When
   the answer carries a Question section, its QNAME/QTYPE/QCLASS must equal the
   question we sent — spoofed or late answers cannot be injected.
5. **Injection.** A full IP + UDP + DNS packet is built with the *original*
   server as the source address, injected as **inbound**, with `IfIdx`/
   `SubIfIdx` copied from the captured query packet. The driver recomputes
   checksums; the TTL is not decremented when the impostor flag is zero, so
   the answer the application sees is indistinguishable from a real one.

### Anti-spoofing

By design the upstream answers are validated rather than blindly trusted: the
ID is rewritten to what the application expects, but the Question section in
the answer must correspond to the question we sent. Transaction ID, QR bit and
OPCODE are all checked; answers with `QDCOUNT > 1` are rejected outright and
answers with `QDCOUNT == 0` are accepted on the ID alone.

### Modes

| Mode | Behavior |
| ---- | -------- |
| `hijack` | Intercept queries, resolve upstream, inject the forged answer. Default. |
| `forward` | Rewrite the destination address and hand the packet back to the kernel for delivery (source NAT). Requires an `udp://` upstream of the same address family; loopback upstreams are rejected because the driver cannot see loopback traffic. |
| `passthrough` | Captured packets are re-injected unchanged. Useful to verify the capture path. |

### Failure behavior

When the upstream does not answer, `on_upstream_failure` decides:

- `forward` (default) — hand the original query back to the real server so the
  application degrades to plain DNS instead of waiting until timeout.
- `drop` — drop the query and let the application time out on its own.

`forward` mode has a matching safety net: if an upstream answer has not
arrived within the deadline, the original query is re-injected to the server
the application originally addressed.

## Requirements

- Windows 10 or later, x64.
- **Administrator privileges.** Opening a WinDivert handle requires elevation.
  The check is skipped when running as a service, because SCM already runs as
  LocalSystem.
- MSVC toolchain (`x86_64-pc-windows-msvc`) for building from source.

## Install

### Download a release

Grab the latest zip from the
[Releases](https://github.com/recall704/dnsflt/releases) page and extract it.
The zip contains everything that must travel together:

```
dnsflt.exe
WinDivert.dll
WinDivert64.sys
```

`WinDivert.dll` and the kernel driver must sit next to the executable, because
the Windows loader resolves the implicitly-linked import library relative to
the directory of the running executable.

### Build from source

```sh
cargo build --release
```

The WinDivert SDK is vendored under `vendor/windivert/` (configured via
`.cargo/config.toml`), so the build works offline. `build.rs` copies
`WinDivert.dll` and the kernel driver next to the produced executable, i.e.
the same three files as above appear in `target/release/`.

## Usage

```sh
dnsflt -c dnsflt.toml run          # start intercepting (default subcommand)
dnsflt -c dnsflt.toml check        # validate config, show the generated filter
dnsflt -c dnsflt.toml stats        # query a running instance
dnsflt install-service             # register as a Windows service
dnsflt uninstall-service
```

Global options: `-c/--config <PATH>`, `-v/--verbose` (repeatable),
`--log-level <LEVEL>`.

### Configuration

A fully commented example lives in [`dnsflt.toml`](dnsflt.toml). Unknown keys
are rejected — a misspelled option errors out immediately instead of being
silently ignored. TOML syntax note: top-level keys must appear *before* any
`[table]` header.

```toml
upstream = "192.168.0.1:1053"
mode = "hijack"
cache = true

[capture]
block_tcp_53 = false

[[rules]]
hostnames = ["*.ads.com"]
action = "block"
```

### Routing rules

Rules are evaluated in order; the first match wins. Pattern semantics:

| Pattern | Behavior |
| ------- | -------- |
| `corp.local` | matches `corp.local` itself and all of its subdomains |
| `*.corp.local` | subdomains only; the apex `corp.local` is **not** matched |
| `*corp.local` | any name ending in `corp.local` (apex included) |
| `*` | matches everything (catch-all, must come last) |

Matching is case-insensitive.

```toml
[[rules]]
hostnames = ["ads.example.com", "*.tracker.net"]
action = "block"          # block | passthrough | server

[[rules]]
hostnames = ["*.corp.local"]
server = "10.0.0.53:53"   # implies action = "server"
```

### Excluding processes

Our own PID is always excluded — the interceptor never captures its own
upstream queries. To exempt a third-party process, list its PID in
`capture.exclude_pids`. This requires knowing the PID in advance, which is
unrealistic for short-lived processes; prefer a set of stable PIDs rather than
relying on dynamic discovery.

### Running as a service

```sh
dnsflt -c C:\dnsflt\dnsflt.toml install-service --start auto --start-now
dnsflt stats
```

The service runs as LocalSystem by default and the registered command line
carries the config path. `--start` accepts `auto`, `demand` (default) or
`disabled`; `--account` / `--password` override the run account; `--name` and
`--display-name` override the SCM identity; `--service-config` pins a config
path that differs from the installation-time one. Uninstall with
`dnsflt uninstall-service --stop`.

## Stats

`dnsflt stats` talks to a running instance over a zero-dependency TCP control
socket (bound to loopback `127.0.0.1:53535` by default). The socket has no
authentication and must stay on loopback. Common options:

| Option | Effect |
| ------ | ------ |
| `--json` | machine-readable output |
| `--watch <MS>` | refresh every N milliseconds until interrupted |
| `--control <ADDR>` | connect to a non-default endpoint |

Key counters: `captured`, `hijacked`, `injected`,
`upstream_sent`/`upstream_recv`/`upstream_ok`, `upstream_timeouts`,
`passed_through`, `last_rtt_us` (last upstream round-trip, microseconds).
`upstream_ok` should grow together with `captured`; if only `captured` grows
while `upstream_sent` stalls, the upstream driver is stuck — the classic
symptom of the blocking-socket problem.

## Testing

`testdata/` ships a fake upstream and end-to-end configs, see
[`testdata/README.md`](testdata/README.md). `tests/e2e_pipeline.rs` covers
everything that does not need the kernel driver — real UDP upstream traffic,
anti-spoofing rejections, forged packet construction. The capture and
injection syscalls only execute when elevated.

## License

`dnsflt` is licensed under the [LGPL-3.0](LICENSE). It is **dynamically**
linked against `WinDivert.dll` (LGPL-3.0) — no static linking, no embedded
driver sources. The binaries in `vendor/windivert/` are the unmodified
upstream distribution, kept solely to satisfy the DLL + `.sys` runtime
requirement; `vendor/windivert/LICENSE` contains the full LGPLv3, GPLv3 and
GPLv2 texts. Distributing `dnsflt.exe` implies shipping those three files
alongside it.
