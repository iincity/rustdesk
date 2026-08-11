use crate::tunnel::ConfigVersion;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneStatus {
    pub desired_state_version: Option<ConfigVersion>,
    pub connected: bool,
}
