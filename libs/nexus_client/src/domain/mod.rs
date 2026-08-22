//! Pure Tunnel business and identity models.

mod assignment;
mod desired_state;
mod identity;
mod lifecycle;
mod local_access;
mod visitor;

pub use assignment::{
    CompiledTunnelConfig, CompiledTunnelProxy, ConfigCompileError, ConfigRenderError,
    OidcRelayCredentials, RelayAssignment, TunnelDataPlaneAssignment,
};
pub use desired_state::{
    is_valid_dns_name, ConfigError, ForwardProxyPlugin, ForwardProxyProtocol, Http2UpstreamPlugin,
    Http2UpstreamProtocol, HttpsUpstreamPlugin, ProtectedAccess, StaticFilePlugin,
    TransportProtocol, TunnelDesiredState, TunnelMode, TunnelPolicy, TunnelRoute, TunnelService,
    UnixSocketPlugin,
};
pub use identity::derive_presence_device_id;
pub use lifecycle::{
    ApplyError, ConfigGeneration, Transition, TunnelMachine, TunnelState, TunnelStatus,
};
pub use local_access::{LocalAccessError, LocalAccessListener, LocalAccessProtocol};
pub use visitor::{TunnelVisitor, VisitorError, VisitorProtocol, XtcpNatProtocol};
