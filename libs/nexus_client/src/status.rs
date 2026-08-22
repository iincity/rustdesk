use crate::tunnel::TunnelStatus;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HealthState {
    #[default]
    Stopped,
    Running,
}

/// Read-only lifecycle of the optional machine-bound Agent channel.
/// It is deliberately separate from the RustDesk host health so a Socket
/// outage cannot make Remote or native Tunnel appear unavailable.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AgentHealthState {
    #[default]
    Disabled,
    Connecting,
    Ready,
    Degraded,
    Stopping,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientStatus {
    pub health: HealthState,
    pub tunnel: TunnelStatus,
    pub agent_health: AgentHealthState,
    /// Waiting Agent work only; the active execution is intentionally excluded.
    pub agent_queue_depth: usize,
}
