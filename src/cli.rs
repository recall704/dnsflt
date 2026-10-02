//! Command-line surface, implemented with `clap` derive.

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

use crate::config::Mode;

/// `dnsflt` — a single-process DNS interceptor.
#[derive(Debug, Parser)]
#[command(
    name = "dnsflt",
    version,
    about = "Intercept local DNS traffic and resolve it through a custom upstream",
    long_about = "dnsflt captures outbound DNS queries (UDP/TCP port 53) with WinDivert, \
resolves them through an upstream resolver and injects the reply back so that \
applications believe it came from the server they originally addressed.",
    disable_help_subcommand = true,
    propagate_version = true,
    subcommand_negates_reqs = true
)]
pub struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short = 'c', long, global = true, default_value = "dnsflt.toml", value_name = "PATH")]
    pub config: PathBuf,

    /// Increase log verbosity (-v = debug, -vv = trace).
    #[arg(short = 'v', long, global = true, action = ArgAction::Count)]
    pub verbose: u8,

    /// Override the configured log level (error|warn|info|debug|trace).
    #[arg(long, global = true, value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Sub-command to run; defaults to `run`.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Available sub-commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start intercepting DNS traffic (default).
    Run(RunArgs),

    /// Validate the configuration and probe the environment.
    Check(CheckArgs),

    /// Query a running instance for its counters.
    Stats(StatsArgs),

    /// Register dnsflt as a Windows service.
    InstallService(InstallArgs),

    /// Remove the dnsflt Windows service.
    UninstallService(UninstallArgs),

    /// Internal entry point used by the Windows service dispatcher.
    #[command(hide = true)]
    ServiceRun(ServiceRunArgs),
}

/// How the service should be started by the SCM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum StartKind {
    /// Start automatically at boot.
    Auto,
    /// Start only when asked (default).
    Demand,
    /// Let the SCM enable/disable the service (kept for completeness).
    Disabled,
}

/// Arguments for `dnsflt run`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Override the interception mode.
    #[arg(long, value_name = "MODE")]
    pub mode: Option<String>,

    /// Override the upstream resolver (`udp://`, `tcp://`, or `host:port`).
    #[arg(long, value_name = "ADDR")]
    pub upstream: Option<String>,

    /// Enable the response cache.
    #[arg(long, conflicts_with = "no_cache")]
    pub cache: bool,

    /// Disable the response cache.
    #[arg(long, conflicts_with = "cache")]
    pub no_cache: bool,

    /// Log a decoded dump of every intercepted datagram.
    #[arg(long)]
    pub dump: bool,

    /// Open WinDivert even if the process does not look elevated (for tests).
    #[arg(long, hide = true)]
    pub force: bool,
}

/// Arguments for `dnsflt check`.
#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,

    /// Name used for the upstream probe.
    #[arg(long, default_value = "example.com", value_name = "NAME")]
    pub name: String,

    /// QTYPE used for the upstream probe.
    #[arg(long, default_value_t = 1, value_name = "TYPE")]
    pub qtype: u16,

    /// Do not send a probe query to the upstream.
    #[arg(long)]
    pub skip_upstream: bool,

    /// Do not try to open a WinDivert handle.
    #[arg(long)]
    pub skip_divert: bool,

    /// Probe timeout in milliseconds.
    #[arg(long, default_value_t = 3000, value_name = "MS")]
    pub timeout_ms: u64,
}

/// Arguments for `dnsflt stats`.
#[derive(Debug, Args)]
pub struct StatsArgs {
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,

    /// Control endpoint of the running instance.
    #[arg(long, value_name = "ADDR")]
    pub control: Option<String>,

    /// Repeat every N milliseconds until interrupted.
    #[arg(long, value_name = "MS")]
    pub watch: Option<u64>,
}

/// Arguments for `dnsflt install-service`.
#[derive(Debug, Args)]
pub struct InstallArgs {
    /// Service name.
    #[arg(long, default_value = "dnsflt", value_name = "NAME")]
    pub name: String,

    /// Human-readable service name.
    #[arg(long, value_name = "TEXT")]
    pub display_name: Option<String>,

    /// SCM start type.
    #[arg(long, value_enum, default_value = "demand")]
    pub start: StartKind,

    /// Account the service runs as (defaults to LocalSystem).
    #[arg(long, value_name = "ACCOUNT")]
    pub account: Option<String>,

    /// Password for `--account`.
    #[arg(long, value_name = "PASSWORD")]
    pub password: Option<String>,

    /// Configuration path baked into the service command line (defaults to the
    /// resolved `--config`).
    #[arg(long, value_name = "PATH")]
    pub service_config: Option<PathBuf>,

    /// Start the service right after installing it.
    #[arg(long)]
    pub start_now: bool,
}

/// Arguments for `dnsflt uninstall-service`.
#[derive(Debug, Args)]
pub struct UninstallArgs {
    /// Service name.
    #[arg(long, default_value = "dnsflt", value_name = "NAME")]
    pub name: String,

    /// Stop the service first if it is running.
    #[arg(long)]
    pub stop: bool,
}

/// Arguments for the hidden `service-run` entry point.
#[derive(Debug, Args)]
pub struct ServiceRunArgs {
    /// Print to the console instead of only using the event log.
    #[arg(long)]
    pub console: bool,
}

impl Cli {
    /// Mode override requested on the command line, if any.
    pub fn mode_override(&self) -> Option<&str> {
        match &self.command {
            Some(Command::Run(args)) => args.mode.as_deref(),
            _ => None,
        }
    }

    /// Parse the `--mode` value.
    pub fn parse_mode_override(&self) -> anyhow::Result<Option<Mode>> {
        match self.mode_override() {
            Some(raw) => Ok(Some(raw.parse::<Mode>()?)),
            None => Ok(None),
        }
    }

    /// Effective log level, honouring `-v`/`-vv` before the config value.
    pub fn verbosity_level(&self) -> Option<&'static str> {
        match self.verbose {
            0 => None,
            1 => Some("debug"),
            _ => Some("trace"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_command_is_run() {
        let cli = Cli::try_parse_from(["dnsflt"]).unwrap();
        assert!(cli.command.is_none());
        assert_eq!(cli.config, PathBuf::from("dnsflt.toml"));
        assert_eq!(cli.verbosity_level(), None);
    }

    #[test]
    fn parses_run_overrides() {
        let cli = Cli::try_parse_from([
            "dnsflt",
            "-c",
            "other.toml",
            "-vv",
            "run",
            "--mode",
            "forward",
            "--upstream",
            "tcp://1.1.1.1:53",
            "--no-cache",
            "--dump",
        ])
        .unwrap();
        assert_eq!(cli.config, PathBuf::from("other.toml"));
        assert_eq!(cli.verbosity_level(), Some("trace"));
        assert_eq!(cli.parse_mode_override().unwrap(), Some(Mode::Forward));
        match cli.command.unwrap() {
            Command::Run(args) => {
                assert!(args.no_cache);
                assert!(args.dump);
                assert_eq!(args.upstream.as_deref(), Some("tcp://1.1.1.1:53"));
            }
            other => panic!("unexpected command {other:?}"),
        }
    }

    #[test]
    fn cache_flags_conflict() {
        assert!(Cli::try_parse_from(["dnsflt", "run", "--cache", "--no-cache"]).is_err());
    }

    #[test]
    fn parses_check_and_stats() {
        let cli = Cli::try_parse_from(["dnsflt", "check", "--json", "--name", "a.example"]).unwrap();
        match cli.command.unwrap() {
            Command::Check(args) => {
                assert!(args.json);
                assert_eq!(args.name, "a.example");
                assert_eq!(args.qtype, 1);
            }
            other => panic!("unexpected command {other:?}"),
        }

        let cli = Cli::try_parse_from(["dnsflt", "stats", "--control", "127.0.0.1:1"]).unwrap();
        match cli.command.unwrap() {
            Command::Stats(args) => assert_eq!(args.control.as_deref(), Some("127.0.0.1:1")),
            other => panic!("unexpected command {other:?}"),
        }
    }

    #[test]
    fn parses_install_service() {
        let cli = Cli::try_parse_from([
            "dnsflt",
            "install-service",
            "--name",
            "dnsflt-test",
            "--start",
            "auto",
            "--start-now",
        ])
        .unwrap();
        match cli.command.unwrap() {
            Command::InstallService(args) => {
                assert_eq!(args.name, "dnsflt-test");
                assert_eq!(args.start, StartKind::Auto);
                assert!(args.start_now);
            }
            other => panic!("unexpected command {other:?}"),
        }
    }
}
