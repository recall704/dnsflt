//! Runtime wiring: open the upstream socket, open the divert handle(s),
//! spawn the pipeline, then wait for the user (or the SCM) to ask us to stop.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::admin;
use crate::cache::Cache;
use crate::capture::{self, Divert, DivertSpec, RawPacket};
use crate::config::{Config, Mode};
use crate::flowtrack::FlowTracker;
use crate::pending::{NatTable, PendingTable};
use crate::pipeline::{self, Ctx, CompiledFlags};
use crate::stats::{self, Counters};
use crate::upstream::UpstreamDriver;

/// Result of [`run`].
///
/// This is normally used to feed the process exit code:
/// `Ok(()) => ExitCode::SUCCESS`, `Err(_) => ExitCode::FAILURE`.
pub type RunResult = Result<()>;

/// Top-level entry point used by `main.rs` and the service dispatcher.
pub async fn run(config: Config, mut stop_rx: watch::Receiver<bool>) -> RunResult {
    let config = Arc::new(config);
    let counters = Arc::new(Counters::new());

    // 1. Sanity check elevation (skip if we got here as a Windows service —
    //    SCM-started processes run as `LocalSystem`).
    if !admin::is_elevated() && !is_service_invocation() {
        bail!("dnsflt needs to run as Administrator (or as a service); re-run elevated");
    }

    // 2. Resolve the upstream.
    let upstream = config.resolve_upstream().context("resolve upstream")?;

    // 3. Start the upstream client so we can learn its local port (used for
    //    self-exclusion in the capture filter).
    let (upstream_driver, self_udp_port) =
        UpstreamDriver::start(&upstream, config.retries, Arc::clone(&counters))
            .context("start upstream")?;

    // 4. Optional flow tracker for PID exclusion.
    let exclude_tracker = if config_has_exclude_pids(&config) {
        match FlowTracker::open(Arc::clone(&counters)) {
            Ok(t) => {
                let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let _reader = Arc::clone(&t).spawn_reader(Arc::clone(&stop));
                stop_signal_for_reader(&stop, &mut stop_rx);
                Some(t)
            }
            Err(e) => {
                warn!(error = %e, "flow tracker unavailable; PID exclusion disabled");
                None
            }
        }
    } else {
        None
    };

    // 5. Build the WinDivert filter using the upstream's known port.
    let upstream_port = upstream.addr.port();
    let is_forward = config.mode == Mode::Forward;
    let filter = capture::compile_filter(
        &config,
        self_udp_port,
        0,
        is_forward,
        upstream_port,
    )?;

    // 6. Open the divert handle.
    let buffer_size = capture::default_capture_buffer(config.capture.max_packet_size);
    let divert = Divert::open(&DivertSpec {
        filter: &filter,
        queue_length: config.capture.queue_length,
        queue_time_ms: config.capture.queue_time_ms,
        buffer_size,
    })
    .with_context(|| format!("open WinDivert handle with filter `{filter}`"))?;
    info!(
        filter = %filter,
        self_udp_port,
        upstream_port,
        buffer_size,
        "WinDivert handle open"
    );

    // 7. Build shared pipeline context.
    let cache = if config.cache {
        let c = Arc::new(Cache::new(
            4_096,
            Duration::from_secs(config.cache_max_ttl),
        ));
        Some(c)
    } else {
        None
    };
    let pending = Arc::new(PendingTable::new(
        Duration::from_millis(config.pending.ttl_ms),
        config.pending.max_entries.max(1),
    ));
    let nat = Arc::new(NatTable::new(
        Duration::from_millis(config.pending.ttl_ms),
        config.pending.max_entries.max(1),
    ));
    let injector = divert.injector(Arc::clone(&counters), config.capture.upstream_ifindex);

    let compiled = CompiledFlags {
        mode: config.mode,
        on_upstream_failure: config.on_upstream_failure,
        dump: config.log.dump,
    };

    let ctx = Arc::new(Ctx {
        config: Arc::clone(&config),
        counters: Arc::clone(&counters),
        injector,
        cache,
        pending,
        nat,
        upstream: upstream_driver,
        exclude: exclude_tracker,
        exclude_pids: config.exclude_pid_set().keys().copied().collect(),
        self_udp_port,
        block_tcp_53: config.capture.block_tcp_53,
        rules: config.compile_rules().context("compile rules")?,
        compiled,
    });

    // 8. Create the capture→pipeline channel.
    let queue_capacity = (config.capture.queue_length as usize).clamp(64, 16_384);
    let (raw_tx, raw_rx) = mpsc::channel::<RawPacket>(queue_capacity);

    // 9. Spawn the reader thread.
    let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader_handle = {
        let handle = divert.handle();
        let counters = Arc::clone(&counters);
        let stop = Arc::clone(&stop_flag);
        capture::spawn_reader(
            handle,
            capture::ReaderOpts {
                buffer_size,
                queue_capacity,
                counters,
                stop: Arc::clone(&stop),
            },
            raw_tx,
        )
    };
    stop_signal_for_reader(&stop_flag, &mut stop_rx);

    // 10. Spawn the pipeline dispatcher.
    let pending_max = config.pending.max_entries;
    let pipeline_handle = {
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move { pipeline::run_dispatcher(raw_rx, ctx, pending_max).await })
    };

    // 11. Optional control socket.
    let control_handle = if config.control.enabled {
        match config.control_addr() {
            Ok(addr) => {
                let counters = Arc::clone(&counters);
                let rx = stop_rx.clone();
                Some(tokio::spawn(async move {
                    if let Err(e) = stats::serve(addr, counters, rx).await {
                        warn!(error = %e, "control socket stopped");
                    }
                }))
            }
            Err(e) => {
                warn!(error = %e, "control address invalid; skipping");
                None
            }
        }
    } else {
        None
    };

    info!("dnsflt is intercepting DNS traffic");
    info!(
        "current counters: captured={} dropped={} injected={} inject_errors={} passed_through={}",
        counters.captured.get(),
        counters.dropped.get(),
        counters.injected.get(),
        counters.inject_errors.get(),
        counters.passed_through.get(),
    );

    // 12. Wait for shutdown.
    let _ = stop_rx.changed().await;
    info!("shutdown requested; stopping threads");
    stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);

    // 13. Give the threads a moment, then exit (the WinDivert driver has no
    //     graceful drop, so we cannot close it while still being used by the
    //     pipeline; `process::exit` is the only safe option for fast cleanup).
    let _ = timeout(Duration::from_secs(2), async {
        // Drop pipeline first so the channel closes.
        drop(ctx);
        let _ = pipeline_handle.await;
    })
    .await;
    if let Some(h) = control_handle {
        h.abort();
    }
    let _ = reader_handle.join();
    log_final(&counters);
    Ok(())
}

fn log_final(counters: &Counters) {
    let snap = counters.snapshot();
    info!(
        captured = snap.captured,
        dropped = snap.dropped,
        injected = snap.injected,
        inject_errors = snap.inject_errors,
        passed_through = snap.passed_through,
        hijacked = snap.hijacked,
        forwarded = snap.forwarded,
        upstream_ok = snap.upstream_ok,
        upstream_timeouts = snap.upstream_timeouts,
        upstream_errors = snap.upstream_errors,
        cache_hits = snap.cache_hits,
        cache_misses = snap.cache_misses,
        fallback_forwarded = snap.fallback_forwarded,
        uptime_ms = snap.uptime_ms,
        "final counter snapshot"
    );
}

fn stop_signal_for_reader(
    flag: &Arc<std::sync::atomic::AtomicBool>,
    stop_rx: &mut watch::Receiver<bool>,
) {
    let flag = Arc::clone(flag);
    let mut rx = stop_rx.clone();
    tokio::spawn(async move {
        let _ = rx.changed().await;
        flag.store(true, std::sync::atomic::Ordering::Relaxed);
    });
}

fn config_has_exclude_pids(cfg: &Config) -> bool {
    !cfg.capture.exclude_pids.is_empty()
}

/// Returns true when the current process was started by the Windows service
/// dispatcher (`service-run` sub-command).
pub fn is_service_invocation() -> bool {
    std::env::args().any(|a| a == "service-run")
}