//! Thin adapter between RustDesk's native lifecycle and NexusFlow.

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

pub use nexus_client::{
    ipc::{ErrorResponse, GetStatusRequest, Request, Response, StatusResponse, IPC_VERSION},
    status::{ClientStatus, HealthState},
    tunnel::TunnelState,
    NexusRuntime, RuntimeConfig,
};

fn runtime_slot() -> &'static Mutex<Option<NexusRuntime>> {
    static RUNTIME: OnceLock<Mutex<Option<NexusRuntime>>> = OnceLock::new();
    RUNTIME.get_or_init(|| Mutex::new(None))
}

pub struct RuntimeGuard;

impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        stop_runtime();
    }
}

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

pub fn start_runtime(
    rustdesk_id: impl Into<String>,
    config_dir: impl Into<PathBuf>,
) -> RuntimeGuard {
    let mut runtime = NexusRuntime::new(runtime_config(rustdesk_id, config_dir));
    runtime.start();
    *runtime_slot().lock().unwrap() = Some(runtime);
    RuntimeGuard
}

pub fn stop_runtime() {
    let mut slot = runtime_slot().lock().unwrap();
    if let Some(runtime) = slot.as_mut() {
        runtime.stop();
    }
    *slot = None;
}

pub fn status_snapshot() -> Option<ClientStatus> {
    runtime_slot()
        .lock()
        .unwrap()
        .as_ref()
        .map(|runtime| runtime.status().clone())
}

pub fn handle_request(request: Request) -> Response {
    match request {
        Request::GetStatus(GetStatusRequest { version }) if version == IPC_VERSION => {
            Response::Status(StatusResponse {
                version,
                status: status_snapshot(),
            })
        }
        Request::GetStatus(GetStatusRequest { version }) => Response::Error(ErrorResponse {
            version: IPC_VERSION,
            message: format!("unsupported nexus ipc version {version}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        handle_request, start_runtime, status_snapshot, GetStatusRequest, HealthState, Request,
        Response, TunnelState,
    };

    #[test]
    fn lifecycle_runtime_is_visible_through_snapshot() {
        let _guard = start_runtime("123456789", "config");

        let status = status_snapshot().unwrap();

        assert_eq!(status.health, HealthState::Running);
        assert_eq!(status.tunnel.state, TunnelState::Disabled);
    }

    #[test]
    fn ipc_handler_rejects_unknown_versions() {
        let response = handle_request(Request::GetStatus(GetStatusRequest { version: 99 }));

        match response {
            Response::Error(error) => {
                assert!(error.message.contains("unsupported nexus ipc version"));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
}
