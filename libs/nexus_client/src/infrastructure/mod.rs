//! Host-bound adapters kept outside domain and application policy.
//!
//! Process and loopback implementations remain behind their stable public
//! modules until their callers migrate; this module is the inward-facing
//! ownership boundary for that migration.

pub use crate::agent::AgentProcess;
pub use crate::local_proxy::{LocalProxyCapabilities, LoopbackProxy};
