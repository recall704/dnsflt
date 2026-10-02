//! Library surface of `dnsflt`.
//!
//! The binary in `main.rs` is a thin CLI over these modules. Exposing them as
//! a library lets integration tests drive the real pipeline (query building,
//! the upstream driver, anti-spoof validation, forged packet construction)
//! without going through the CLI or the WinDivert kernel handle.

pub mod admin;
pub mod cache;
pub mod capture;
pub mod cli;
pub mod config;
pub mod dns;
pub mod engine;
pub mod flowtrack;
pub mod packet;
pub mod pending;
pub mod pipeline;
pub mod service;
pub mod stats;
pub mod upstream;