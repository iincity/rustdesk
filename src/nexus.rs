//! Stable Nexus facade for RustDesk integration points.
//!
//! Runtime orchestration and native transport hooks live behind this boundary
//! so RustDesk call sites remain unchanged while Nexus behavior stays isolated.

#[cfg(feature = "nexus-agent")]
mod agent_host;
#[path = "nexus_impl.rs"]
mod implementation;
mod ipc_bridge;
mod lifecycle;
#[path = "nexus/native_transport.rs"]
mod native_transport;
mod tunnel_gateway;
mod tunnel_host;

pub use implementation::*;
pub use ipc_bridge::handle_request;
pub use lifecycle::TunnelApplicationReporter;
pub(crate) use native_transport::*;
