//! Application use cases: compose verified Desired State with host lifecycle.

mod notice;
mod tunnel_runtime;

pub use notice::should_refresh_from_notice;
pub use tunnel_runtime::{TunnelMetrics, TunnelRuntime, TunnelRuntimeConfigError};
