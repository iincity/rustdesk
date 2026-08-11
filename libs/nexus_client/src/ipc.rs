use crate::status::ClientStatus;

pub const IPC_NAMESPACE: &str = "_nexus";
pub const IPC_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    GetStatus(GetStatusRequest),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Response {
    Status(StatusResponse),
    Error(ErrorResponse),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusResponse {
    pub version: u16,
    pub status: Option<ClientStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErrorResponse {
    pub version: u16,
    pub message: String,
}
