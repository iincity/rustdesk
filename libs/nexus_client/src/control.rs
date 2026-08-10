#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneStatus {
    pub desired_state_version: Option<u64>,
    pub connected: bool,
}
