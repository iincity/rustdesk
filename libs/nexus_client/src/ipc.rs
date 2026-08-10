pub const IPC_NAMESPACE: &str = "_nexus";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    GetStatus,
}
