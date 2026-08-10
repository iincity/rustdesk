use crate::tunnel::TunnelState;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HealthState {
    #[default]
    Stopped,
    Running,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientStatus {
    pub health: HealthState,
    pub tunnel: TunnelState,
}
