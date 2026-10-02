# dnsflt end-to-end test rig

Two pieces, both optional:

## 1. Fake upstream (`fake_upstream.py`)

Answers every A query with `203.0.113.7` (RFC 5737 TEST-NET-3 — deliberately
not a real address) and logs the QNAME/ID it actually received, so a passing
test proves dnsflt really forwarded the client's question rather than answering
locally.

```sh
python testdata/fake_upstream.py 1053
```

Verified working on `127.0.0.1`. A LAN address such as `192.168.0.100` does
**not** work unless Windows Defender Firewall permits inbound UDP — the default
blocks it. Loopback is the right choice for `hijack` mode, since only
`forward` mode needs to see the upstream reply come back through the driver.

## 2. Config (`e2e.toml`)

```toml
upstream = "127.0.0.1:1053"
mode = "hijack"
```

`block_tcp_53 = true` so the compiled filter covers both transports. Note that
in TOML a top-level key must appear *before* any `[table]` header — `rules` and
friends placed after `[control]` silently become fields of that table and are
then rejected by `deny_unknown_fields`.

## What is covered without elevation

`tests/e2e_pipeline.rs` drives everything that does not need the WinDivert
kernel handle: query construction, the real `UpstreamDriver` over UDP,
anti-spoof validation, ID patching, and forged packet construction.

```sh
python testdata/fake_upstream.py 1053 &
cargo test --test e2e_pipeline -- --nocapture --test-threads=1
```

## What needs Administrator

The capture and injection syscalls. `dnsflt run` refuses to start unelevated
(exit 1, "needs to run as Administrator"). To finish the loop, run from an
elevated shell, then resolve anything through the original server:

```sh
dnsflt -c testdata/e2e.toml run
nslookup example.com 8.8.8.8      # must come back as 203.0.113.7
dnsflt stats                      # captured/hijacked/injected must all advance
```