#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TunnelState {
    #[default]
    Disabled,
    PresenceOnly,
    Activating,
    Active,
    Draining,
    Backoff,
}
