//! Build glue for the vendored WinDivert runtime.
//!
//! `windivert-sys` links `WinDivert.dll` dynamically and copies `WinDivert.dll`
//! together with the kernel driver (`WinDivert64.sys` / `WinDivert32.sys`) into
//! its own `OUT_DIR`. That is *not* enough: the Windows loader resolves the
//! implicitly-linked import library relative to the directory of the running
//! executable, so the files must sit next to `dnsflt.exe` (and next to the test
//! binaries in `deps/`).
//!
//! This script copies them there and is a best-effort operation: if `vendor/`
//! is missing we emit a warning instead of failing the build, so that
//! `cargo test` for the pure-Rust modules still works on a machine without the
//! vendored binaries.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Files that must sit beside the executable at runtime.
const RUNTIME_FILES: [&str; 3] = ["WinDivert.dll", "WinDivert64.sys", "WinDivert32.sys"];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let vendor = manifest_dir.join("vendor").join("windivert");
    println!("cargo:rerun-if-changed={}", vendor.display());

    // `OUT_DIR` is `<target>/[<triple>/]<profile>/build/<pkg>-<hash>/out`.
    // Two ancestors up from `build/`'s parent is the profile directory.
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let profile_dir = out_dir
        .ancestors()
        .nth(3)
        .map(Path::to_path_buf)
        .or_else(|| {
            // Fallback for exotic layouts: <target>/<profile>
            let profile = env::var("PROFILE").ok()?;
            let target = env::var_os("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| manifest_dir.join("target"));
            Some(target.join(profile))
        });

    let Some(profile_dir) = profile_dir else {
        println!("cargo:warning=dnsflt: could not determine target profile dir; WinDivert files not copied");
        return;
    };

    if !vendor.is_dir() {
        println!(
            "cargo:warning=dnsflt: vendor/windivert not found — copy WinDivert.dll / WinDivert64.sys there before running dnsflt"
        );
        return;
    }

    let destinations = [profile_dir.clone(), profile_dir.join("deps")];
    let mut copied = Vec::new();
    for dest in &destinations {
        if let Err(err) = std::fs::create_dir_all(dest) {
            println!(
                "cargo:warning=dnsflt: cannot create {}: {err}",
                dest.display()
            );
            continue;
        }
        for name in RUNTIME_FILES {
            let src = vendor.join(name);
            if !src.is_file() {
                continue;
            }
            let dst = dest.join(name);
            if needs_copy(&src, &dst) {
                if let Err(err) = std::fs::copy(&src, &dst) {
                    println!(
                        "cargo:warning=dnsflt: cannot copy {} -> {}: {err}",
                        src.display(),
                        dst.display()
                    );
                } else {
                    copied.push(dst);
                }
            }
        }
    }

    if copied.is_empty() {
        // Nothing to report: files were already up to date.
    } else {
        for path in &copied {
            println!("cargo:warning=dnsflt: staged {}", path.display());
        }
    }

    // The driver is a kernel-mode binary and cannot be produced by the C
    // toolchain in this crate; make sure the .sys that we ship is the one
    // matching the .dll version we vendored, otherwise WinDivert refuses to
    // open a handle.
    let version_file = vendor.join("VERSION");
    if version_file.is_file() {
        if let Ok(version) = std::fs::read_to_string(&version_file) {
            println!("cargo:rustc-env=DNSFLT_WINDIVERT_VERSION={}", version.trim());
        }
    }

    emit_git_hash(&manifest_dir);
}

fn needs_copy(src: &Path, dst: &Path) -> bool {
    match (src.metadata(), dst.metadata()) {
        (Ok(a), Ok(b)) => a.len() != b.len() || is_newer(src, dst),
        (Ok(_), Err(_)) => true,
        _ => false,
    }
}

fn is_newer(src: &Path, dst: &Path) -> bool {
    match (src.metadata(), dst.metadata()) {
        (Ok(a), Ok(b)) => match (a.modified(), b.modified()) {
            (Ok(am), Ok(bm)) => am > bm,
            _ => true,
        },
        _ => false,
    }
}

fn emit_git_hash(manifest_dir: &Path) {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(manifest_dir)
        .output();
    if let Ok(output) = output {
        if output.status.success() {
            if let Ok(hash) = String::from_utf8(output.stdout) {
                println!("cargo:rustc-env=DNSFLT_GIT_HASH={}", hash.trim());
            }
        }
    }
}
