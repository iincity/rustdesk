//! Thin adapter between RustDesk's native lifecycle and NexusFlow.

use std::path::PathBuf;

pub use nexus_client::{NexusRuntime, RuntimeConfig};

/// Builds NexusFlow runtime input from the native RustDesk identity.
///
/// The caller remains responsible for obtaining the ID through RustDesk's
/// existing identity path; NexusFlow never generates a replacement ID.
pub fn runtime_config(
    rustdesk_id: impl Into<String>,
    config_dir: impl Into<PathBuf>,
) -> RuntimeConfig {
    RuntimeConfig::new(rustdesk_id, config_dir)
}
