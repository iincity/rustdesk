//! NexusFlow client capabilities embedded in the RustDesk service process.

// Native RustDesk Tunnel uses these stable DTO/protocol primitives directly.
// Keeping the source here avoids linking the retired tunnel-client/core crates
// into the production feature graph.
mod domain;
mod protocol;
pub use domain::*;
pub use protocol::*;

// These modules own orchestration and external I/O separately.  Public
// re-exports preserve the host-facing API while the native implementation is
// gradually isolated from the retired Tunnel compatibility layout.
pub(crate) mod application;
pub mod infrastructure;
mod transport;
pub use transport::authi_socket::{
    agent_socket_endpoint, encode_socket_io_ack, encode_socket_io_event, parse_socket_io_event,
    AgentCancellation, AgentDispatch, AgentExecutionFinish, AgentExecutionStart,
    AgentRpcRequest, AgentRuntimeMetrics,
};
pub use application::{TunnelMetrics, TunnelRuntime, TunnelRuntimeConfigError};
pub use transport::{PresenceClient, PresenceClientError};

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
