//! NexusFlow client capabilities embedded in the RustDesk service process.

// Native RustDesk Tunnel uses these stable DTO/protocol primitives directly.
// Keeping the source here avoids linking the retired tunnel-client/core crates
// into the production feature graph.
mod domain;
mod protocol;
extern crate self as nexus_tunnel_core;
pub use domain::*;
pub use protocol::*;

mod native_application;
mod native_presence;
pub use native_application::{TunnelMetrics, TunnelRuntime, TunnelRuntimeConfigError};
pub use native_presence::{PresenceClient, PresenceClientError};

pub mod agent;
pub mod control;
pub mod desired_state;
pub mod identity;
pub mod ipc;
pub mod local_proxy;
pub mod runtime;
pub mod status;
pub mod tunnel;

pub use runtime::{NexusRuntime, RuntimeConfig};
