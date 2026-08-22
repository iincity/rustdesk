use crate::status::ClientStatus;

pub const IPC_NAMESPACE: &str = "_nexus";
pub const IPC_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    GetStatus(GetStatusRequest),
    /// Ask the already-running host loop to fetch the next signed Desired State.
    /// No URL, config, token, or credential crosses the authorized IPC boundary.
    RefreshDesiredState(RefreshDesiredStateRequest),
    /// Ask the running host to fetch one execution-scoped PortForward
    /// credential. URL and destination path remain host configuration.
    RefreshPortForwardCredential(RefreshPortForwardCredentialRequest),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetStatusRequest {
    pub version: u16,
}

impl Default for GetStatusRequest {
    fn default() -> Self {
        Self {
            version: IPC_VERSION,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefreshDesiredStateRequest {
    pub version: u16,
}

impl Default for RefreshDesiredStateRequest {
    fn default() -> Self {
        Self {
            version: IPC_VERSION,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshPortForwardCredentialRequest {
    pub version: u16,
    pub grant_id: String,
}

impl RefreshPortForwardCredentialRequest {
    pub fn new(grant_id: impl Into<String>) -> Self {
        Self {
            version: IPC_VERSION,
            grant_id: grant_id.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Response {
    Status(StatusResponse),
    RefreshScheduled(RefreshScheduledResponse),
    PortForwardCredentialRefreshScheduled(RefreshScheduledResponse),
    Error(ErrorResponse),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusResponse {
    pub version: u16,
    pub status: Option<ClientStatus>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefreshScheduledResponse {
    pub version: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErrorResponse {
    pub version: u16,
    pub message: String,
}
