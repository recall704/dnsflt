//! Administrator-privilege detection.
//!
//! WinDivert needs an elevated token to load `WinDivert64.sys` and to open a
//! divert handle, so `run`, `check`, `install-service` and
//! `uninstall-service` all report elevation. When the process is launched by
//! the Service Control Manager it already runs as `LocalSystem`, which is why
//! the check is informational rather than fatal for the service entry point.

/// `true` when the current process token reports `TokenElevation`.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Non-Windows stub (the whole tool is Windows-only, but this keeps `check`
/// buildable for tooling on other hosts).
#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

/// Human-readable elevation state for log lines.
pub fn describe() -> &'static str {
    if is_elevated() {
        "elevated (Administrator)"
    } else {
        "NOT elevated — WinDivert will refuse to open; re-run from an elevated shell"
    }
}

/// Whether WinDivert is expected to be usable.
pub fn divert_usable() -> bool {
    is_elevated()
}

/// Error text shared by every entry point that needs WinDivert.
pub const ELEVATION_HINT: &str = "dnsflt needs Administrator rights: right-click the terminal \
(or the executable) and choose \"Run as administrator\", or install it as a Windows service \
(`dnsflt install-service --start-now`).";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_panic() {
        let _ = is_elevated();
        let _ = describe();
        let _ = divert_usable();
    }
}
