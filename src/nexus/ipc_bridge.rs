//! Versioned Nexus requests carried over RustDesk's existing authorized IPC.
//!
//! This bridge deliberately exposes only a status snapshot and schedules
//! refresh work against the Host-owned control-plane URL. It never accepts
//! routes, grants, credentials, or arbitrary endpoints from IPC callers.

use super::implementation::{
    host_control_plane_url, refresh_tunnel_desired_state, status_snapshot, ErrorResponse,
    GetStatusRequest, RefreshDesiredStateRequest, RefreshPortForwardCredentialRequest,
    RefreshScheduledResponse, Request, Response, StatusResponse, IPC_VERSION,
};

#[cfg(feature = "nexus-native-tunnel")]
use super::implementation::refresh_port_forward_credential;

/// Handles the small, versioned request set allowed through the existing IPC.
pub fn handle_request(request: Request) -> Response {
    match request {
        Request::GetStatus(GetStatusRequest { version }) if version == IPC_VERSION => {
            Response::Status(StatusResponse {
                version,
                status: status_snapshot(),
            })
        }
        Request::RefreshDesiredState(RefreshDesiredStateRequest { version })
            if version == IPC_VERSION =>
        {
            let Some(url) = host_control_plane_url().lock().unwrap().clone() else {
                return host_service_not_running();
            };
            let Ok(handle) = hbb_common::tokio::runtime::Handle::try_current() else {
                return runtime_required();
            };
            handle.spawn(async move {
                if let Err(error) = refresh_tunnel_desired_state(&url).await {
                    hbb_common::log::warn!("Nexus IPC Desired State refresh failed: {error}");
                }
            });
            Response::RefreshScheduled(RefreshScheduledResponse { version })
        }
        #[cfg(feature = "nexus-native-tunnel")]
        Request::RefreshPortForwardCredential(RefreshPortForwardCredentialRequest {
            version,
            grant_id,
        }) if version == IPC_VERSION => {
            let Some(url) = host_control_plane_url().lock().unwrap().clone() else {
                return host_service_not_running();
            };
            let Some(path) = std::env::var_os("NEXUS_TUNNEL_CREDENTIAL_FILE") else {
                return Response::Error(ErrorResponse {
                    version: IPC_VERSION,
                    message: "Nexus PortForward credential path is not configured".into(),
                });
            };
            let handle = hbb_common::tokio::runtime::Handle::current();
            handle.spawn(async move {
                if let Err(error) =
                    refresh_port_forward_credential(&url, &grant_id, path.as_ref()).await
                {
                    hbb_common::log::warn!(
                        "Nexus IPC PortForward credential refresh failed: {error}"
                    );
                }
            });
            Response::PortForwardCredentialRefreshScheduled(RefreshScheduledResponse { version })
        }
        Request::GetStatus(GetStatusRequest { version })
        | Request::RefreshDesiredState(RefreshDesiredStateRequest { version })
        | Request::RefreshPortForwardCredential(RefreshPortForwardCredentialRequest {
            version,
            ..
        }) => unsupported_version(version),
    }
}

fn host_service_not_running() -> Response {
    Response::Error(ErrorResponse {
        version: IPC_VERSION,
        message: "Nexus host service is not running".into(),
    })
}

fn runtime_required() -> Response {
    Response::Error(ErrorResponse {
        version: IPC_VERSION,
        message: "Nexus IPC refresh requires the RustDesk Tokio runtime".into(),
    })
}

fn unsupported_version(version: u16) -> Response {
    Response::Error(ErrorResponse {
        version: IPC_VERSION,
        message: format!("unsupported nexus ipc version {version}"),
    })
}
