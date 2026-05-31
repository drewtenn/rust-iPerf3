//! Public API for the `rPerf3` crate.
//!
//! The crate is primarily a CLI (`src/main.rs`), but exposing the
//! runtime entry points here lets integration tests in `tests/` drive
//! a full client/server handshake in-process without shelling out.

pub mod cli;
pub mod client;
pub mod common;
pub mod server;

pub use client::run_client;
pub use common::test::Config;
pub use common::Direction;
pub use common::TransportKind;
pub use server::{run_server, run_server_loop, run_server_on, run_server_on_timeout, DEFAULT_HANDSHAKE_TIMEOUT};
