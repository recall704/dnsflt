//! Windows service wrapper.
//!
//! `dnsflt install-service` and `dnsflt uninstall-service` register / remove
//! a service entry that runs `dnsflt service-run` under the LocalSystem
//! account. The dispatcher below is invoked when the SCM sends a "start"
//! control code; it loads the configured TOML, wires the engine, and blocks
//! until the SCM tells us to stop.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::sync::watch;
use tracing::{error, info};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
    ServiceStartType, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{ServiceControlHandlerResult, register};
use windows_service::service_dispatcher;

use crate::config::Config;
use crate::engine;

/// Service name registered with the SCM.
pub const SERVICE_NAME: &str = "dnsflt";
/// Display name shown in `sc query`.
pub const DISPLAY_NAME: &str = "dnsflt DNS filter";
/// Friendly description.
pub const DESCRIPTION: &str = "Intercepts and rewrites local DNS traffic via WinDivert.";

/// Install the service.
///
/// `opts` carries everything `dnsflt install-service` was asked for. The
/// resolved config path is baked into the registered command line so the
/// service finds its config without needing a working directory.
pub fn install(opts: InstallOpts<'_>) -> Result<()> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("open SCM")?;

    let exe = std::env::current_exe().context("locate own exe")?;
    let mut launch_arguments: Vec<OsString> = vec![OsString::from("service-run")];
    if let Some(p) = opts.config_path {
        launch_arguments.push(OsString::from("-c"));
        launch_arguments.push(OsString::from(p));
    }
    let info = ServiceInfo {
        name: OsString::from(opts.name),
        display_name: OsString::from(opts.display_name.unwrap_or(DISPLAY_NAME)),
        service_type: ServiceType::OWN_PROCESS,
        start_type: opts.start_type,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments,
        dependencies: vec![],
        account_name: opts.account.map(OsString::from),
        account_password: opts.password.map(OsString::from),
    };
    let service = manager
        .create_service(&info, ServiceAccess::QUERY_STATUS | ServiceAccess::START)
        .context("create service")?;
    info!(name = %opts.name, start_type = ?opts.start_type, "service installed");
    if opts.start_now {
        let _ = service.start::<OsString>(&[]);
    }
    drop(service);
    Ok(())
}

/// Everything `install` needs, borrowed so no allocation is required.
#[derive(Debug, Clone, Copy)]
pub struct InstallOpts<'a> {
    /// SCM service name.
    pub name: &'a str,
    /// Display name; falls back to [`DISPLAY_NAME`].
    pub display_name: Option<&'a str>,
    /// Config path baked into the command line.
    pub config_path: Option<&'a Path>,
    /// SCM start type.
    pub start_type: ServiceStartType,
    /// Service account (`None` = LocalSystem).
    pub account: Option<&'a str>,
    /// Password for `account`.
    pub password: Option<&'a str>,
    /// Start the service immediately after registering it.
    pub start_now: bool,
}

/// Remove the service from the SCM. Stops it first when `stop_first` is set.
pub fn uninstall(name: &str, stop_first: bool) -> Result<()> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    )
    .context("open SCM")?;
    let svc = manager
        .open_service(name, ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)
        .context("open service")?;

    // Try to stop it (ignore failures).
    if stop_first {
        match svc.query_status() {
            Ok(status) if status.current_state != windows_service::service::ServiceState::Stopped => {
                let _ = svc.stop();
            }
            _ => {}
        }
    }
    svc.delete().context("delete service")?;
    info!(name, "service removed");
    Ok(())
}

/// Windows service entry point. Invoked by the SCM when the service is
/// started. Returns when the SCM tells us to stop.
pub fn run_service_main() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

windows_service::define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service_main_inner() {
        error!(error = ?e, "service_main exited with error");
    }
}

fn run_service_main_inner() -> Result<()> {
    let (stop_tx, stop_rx) = watch::channel(false);

    // The SCM handler accepts stop/shutdown.
    let stop_tx_clone = stop_tx.clone();
    let event_handler = register(
        SERVICE_NAME,
        move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_tx_clone.send(true);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        },
    )?;
    let pending_status_handle = Some(event_handler);
    set_status(&pending_status_handle, ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: windows_service::service::ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    })?;

    // Read --config from our command line (the SCM argv we registered).
    let config_path = parse_config_arg();
    let config = match config_path {
        Some(p) => Config::load(&p).with_context(|| format!("load config from {}", p.display()))?,
        None => Config::load_or_default(&std::path::Path::new("dnsflt.toml"))
            .context("load config")?,
    };
    if let Err(e) = config.validate() {
        return Err(anyhow!("config validation failed: {e:?}"));
    }

    // Switch the status to Running before we start the engine.
    set_status(&pending_status_handle, ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: windows_service::service::ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(1),
        process_id: None,
    })?;

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => return Err(anyhow!("build tokio runtime: {e}")),
    };
    let result = runtime.block_on(engine::run(config, stop_rx));

    set_status(&pending_status_handle, ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: windows_service::service::ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: if result.is_ok() {
            ServiceExitCode::Win32(0)
        } else {
            ServiceExitCode::ServiceSpecific(1)
        },
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    })?;
    result
}

fn set_status(
    handle: &Option<windows_service::service_control_handler::ServiceStatusHandle>,
    status: ServiceStatus,
) -> Result<()> {
    match handle {
        Some(h) => h.set_service_status(status).context("set service status"),
        None => Ok(()),
    }
}

fn parse_config_arg() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "-c" || a == "--config" {
            return args.next().map(PathBuf::from);
        }
        if let Some(rest) = a.strip_prefix("--config=") {
            return Some(PathBuf::from(rest));
        }
    }
    None
}