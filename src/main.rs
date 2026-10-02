//! `dnsflt` CLI entry point.
//!
//! Parses the command line, loads + validates the configuration, then
//! dispatches to one of the run / check / stats / install-service /
//! uninstall-service / service-run code paths.

use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use tokio::sync::watch;
use tracing::{Level, info};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

use dnsflt::capture;
use dnsflt::cli::{Cli, Command, InstallArgs, RunArgs, StartKind, StatsArgs, UninstallArgs};
use dnsflt::config::Config;
use dnsflt::engine;
use dnsflt::service;
use dnsflt::stats;

/// Resolved log configuration.
struct LogPlan {
    level: Level,
    to_file: Option<std::path::PathBuf>,
    dump: bool,
}

impl LogPlan {
    fn resolve(cli: &Cli, cfg: Option<&Config>) -> LogPlan {
        let level = cli
            .verbosity_level()
            .map(|s| parse_level(s))
            .or_else(|| cfg.map(|c| parse_level(&c.log.level)))
            .unwrap_or(Level::INFO);
        let to_file = cfg.and_then(|c| c.log.file.clone());
        let dump = matches!(cli.command, Some(Command::Run(RunArgs { dump: true, .. })))
            || cfg.map(|c| c.log.dump).unwrap_or(false);
        LogPlan { level, to_file, dump }
    }
}

fn parse_level(s: &str) -> Level {
    match s.to_ascii_lowercase().as_str() {
        "error" => Level::ERROR,
        "warn" | "warning" => Level::WARN,
        "info" => Level::INFO,
        "debug" => Level::DEBUG,
        "trace" => Level::TRACE,
        _ => Level::INFO,
    }
}

fn init_logging(plan: &LogPlan) -> Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(plan.level.into())
        .from_env_lossy();
    let use_color = std::io::stderr().is_terminal();
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_ansi(use_color);
    if let Some(path) = &plan.to_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open log file {}", path.display()))?;
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(file)
            .with_target(false)
            .with_ansi(false);
        tracing_subscriber::registry()
            .with(filter)
            .with(stderr_layer)
            .with(file_layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(stderr_layer)
            .init();
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut config: Option<Config> = None;
    if !matches!(cli.command, Some(Command::ServiceRun(_))) {
        match Config::load_or_default(&cli.config) {
            Ok(c) => config = Some(c),
            Err(e) => {
                eprintln!("dnsflt: failed to load config {}: {e:#}", cli.config.display());
                return ExitCode::from(2);
            }
        }
    }
    let plan = LogPlan::resolve(&cli, config.as_ref());
    if let Err(e) = init_logging(&plan) {
        eprintln!("dnsflt: failed to initialize logging: {e:#}");
        return ExitCode::from(2);
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("dnsflt: failed to build tokio runtime: {e:#}");
            return ExitCode::from(2);
        }
    };
    let result = runtime.block_on(run_app(&cli, config, plan.dump));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dnsflt: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn run_app(cli: &Cli, mut config: Option<Config>, dump: bool) -> Result<()> {
    match &cli.command {
        None | Some(Command::Run(_)) => {
            let mut cfg = config.take().context("config is required for `run`")?;
            apply_run_overrides(&mut cfg, cli, dump)?;
            cfg.validate().context("config validation")?;
            let (stop_tx, stop_rx) = watch::channel(false);
            spawn_ctrl_c(stop_tx.clone());
            engine::run(cfg, stop_rx).await
        }
        Some(Command::Check(args)) => {
            let cfg = config.take().context("config is required for `check`")?;
            cfg.validate().context("config validation")?;
            do_check(cfg, args).await
        }
        Some(Command::Stats(args)) => do_stats(cli, args).await,
        Some(Command::InstallService(args)) => do_install_service(&cli.config, args),
        Some(Command::UninstallService(args)) => do_uninstall_service(args),
        Some(Command::ServiceRun(_)) => do_service_run(),
    }
}

fn apply_run_overrides(cfg: &mut Config, cli: &Cli, dump: bool) -> Result<()> {
    if let Some(mode) = cli.parse_mode_override()? {
        cfg.mode = mode;
    }
    if let Some(Command::Run(args)) = &cli.command {
        if let Some(raw) = &args.upstream {
            cfg.upstream = raw.clone();
        }
        if args.cache {
            cfg.cache = true;
        } else if args.no_cache {
            cfg.cache = false;
        }
        if args.dump {
            cfg.log.dump = true;
        }
    }
    let _ = dump; // already applied above
    if let Some(Command::Run(args)) = &cli.command {
        if args.force {
            // No flag in Config yet; reserved for testing.
        }
    }
    Ok(())
}

async fn do_check(cfg: Config, args: &dnsflt::cli::CheckArgs) -> Result<()> {
    use dnsflt::config::Mode;
    info!("loaded configuration OK");
    info!("upstream = {}", cfg.upstream);
    info!("mode = {:?}", cfg.mode);
    if cfg.mode == Mode::Forward && cfg.upstream.contains("127.0.0.1") {
        bail!("forward mode is incompatible with a loopback upstream");
    }
    if !args.skip_upstream {
        let upstream = cfg.resolve_upstream()?;
        info!("upstream resolved to {}", upstream.addr);
    }
    if !args.skip_divert {
        let filter = capture::compile_filter(&cfg, 0, 0, cfg.mode == Mode::Forward, cfg.resolve_upstream()?.addr.port())?;
        info!("would open WinDivert with filter: {filter}");
    }
    if args.json {
        println!("{{\"ok\":true,\"mode\":\"{:?}\",\"upstream\":\"{}\",\"cache\":{}}}",
            cfg.mode, cfg.upstream, cfg.cache);
    } else {
        println!("config OK");
    }
    Ok(())
}

async fn do_stats(_cli: &Cli, args: &StatsArgs) -> Result<()> {
    let addr = match &args.control {
        Some(s) => s.parse()?,
        None => "127.0.0.1:53535".parse()?,
    };
    let timeout = Duration::from_millis(args.watch.map(|_| 200).unwrap_or(2000));
    let command = if args.json { "json" } else { "table" };
    loop {
        match stats::fetch(addr, command, timeout) {
            Ok(line) => {
                if let Some(ms) = args.watch {
                    print!("\x1b[2J\x1b[H{line}\n");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                } else {
                    print!("{line}");
                    return Ok(());
                }
            }
            Err(e) => {
                if args.watch.is_some() {
                    eprintln!("stats: {e}");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                } else {
                    return Err(e);
                }
            }
        }
    }
}

fn do_install_service(config_path: &Path, args: &InstallArgs) -> Result<()> {
    use windows_service::service::ServiceStartType;

    let start_type = match args.start {
        StartKind::Auto => ServiceStartType::AutoStart,
        StartKind::Demand => ServiceStartType::OnDemand,
        StartKind::Disabled => ServiceStartType::Disabled,
    };
    // `--service-config` wins over the global `--config`, so that the config
    // baked into the service can differ from the one used to install it.
    let baked = args.service_config.as_deref().unwrap_or(config_path);
    let opts = service::InstallOpts {
        name: &args.name,
        display_name: args.display_name.as_deref(),
        config_path: Some(baked),
        start_type,
        account: args.account.as_deref(),
        password: args.password.as_deref(),
        start_now: args.start_now,
    };
    service::install(opts)
}

fn do_uninstall_service(args: &UninstallArgs) -> Result<()> {
    service::uninstall(&args.name, args.stop)
}

fn do_service_run() -> Result<()> {
    service::run_service_main()
}

fn spawn_ctrl_c(stop_tx: watch::Sender<bool>) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        let _ = stop_tx.send(true);
    });
}