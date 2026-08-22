//! Pure Desired State lifecycle state machine.

use crate::{ConfigDigest, ConfigError, ConfigVersion, TunnelDesiredState, TunnelMode};

/// Lifecycle failures are deterministic and contain no control-plane secrets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplyError {
    InvalidConfig(ConfigError),
    MissingDesiredState,
    StaleVersion {
        current: ConfigVersion,
        received: ConfigVersion,
    },
    ConflictingVersion {
        version: ConfigVersion,
        current: ConfigDigest,
        received: ConfigDigest,
    },
    InvalidTransition {
        from: TunnelState,
        event: &'static str,
    },
    StaleGeneration {
        current: ConfigGeneration,
        received: ConfigGeneration,
    },
    RetryNotReady {
        retry_not_before_secs: u64,
        observed_at_secs: u64,
    },
}

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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TunnelStatus {
    pub state: TunnelState,
    pub desired_version: Option<ConfigVersion>,
    pub desired_digest: Option<ConfigDigest>,
    pub applied_version: Option<ConfigVersion>,
    pub applied_digest: Option<ConfigDigest>,
    pub backoff_attempts: u32,
    /// Earliest monotonic/UTC second supplied by the host at which this generation may retry.
    pub retry_not_before_secs: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transition {
    pub from: TunnelState,
    pub to: TunnelState,
}

/// Identifies one verified Desired State generation for asynchronous runtime callbacks.
///
/// It contains only the signed version and digest, never configuration payload or credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigGeneration {
    pub version: ConfigVersion,
    pub digest: ConfigDigest,
}
impl Transition {
    pub fn changed(self) -> bool {
        self.from != self.to
    }
}

/// Applies verified Desired State generations without performing I/O.
#[derive(Clone, Debug, Default)]
pub struct TunnelMachine {
    desired: Option<TunnelDesiredState>,
    status: TunnelStatus,
}

impl TunnelMachine {
    pub fn status(&self) -> &TunnelStatus {
        &self.status
    }
    pub fn desired_state(&self) -> Option<&TunnelDesiredState> {
        self.desired.as_ref()
    }
    /// Returns the generation that runtime completion callbacks must acknowledge.
    pub fn generation(&self) -> Option<ConfigGeneration> {
        Some(ConfigGeneration {
            version: self.status.desired_version?,
            digest: self.status.desired_digest?,
        })
    }
    pub fn apply_desired_state(
        &mut self,
        desired: TunnelDesiredState,
    ) -> Result<Transition, ApplyError> {
        desired.validate().map_err(ApplyError::InvalidConfig)?;
        let digest = desired.digest();
        if let Some(current_version) = self.status.desired_version {
            if desired.version < current_version {
                return Err(ApplyError::StaleVersion {
                    current: current_version,
                    received: desired.version,
                });
            }
            if desired.version == current_version {
                let current = self
                    .status
                    .desired_digest
                    .expect("desired digest must exist when desired version exists");
                if digest != current {
                    return Err(ApplyError::ConflictingVersion {
                        version: desired.version,
                        current,
                        received: digest,
                    });
                }
                self.desired = Some(desired);
                return Ok(Transition {
                    from: self.status.state,
                    to: self.status.state,
                });
            }
        }
        self.status.desired_version = Some(desired.version);
        self.status.desired_digest = Some(digest);
        self.desired = Some(desired);
        self.status.backoff_attempts = 0;
        self.status.retry_not_before_secs = None;
        let next = match self.desired.as_ref().expect("just set desired").mode {
            TunnelMode::Disabled => self.passive_target(TunnelState::Disabled),
            TunnelMode::PresenceOnly => self.passive_target(TunnelState::PresenceOnly),
            TunnelMode::Active => TunnelState::Activating,
        };
        if matches!(next, TunnelState::Disabled | TunnelState::PresenceOnly) {
            self.mark_applied();
        }
        Ok(self.transition(next))
    }
    pub fn on_activation_succeeded(
        &mut self,
        generation: ConfigGeneration,
    ) -> Result<Transition, ApplyError> {
        self.ensure_desired()?;
        self.require_generation(generation)?;
        self.require_state(TunnelState::Activating, "activation_succeeded")?;
        self.mark_applied();
        self.status.backoff_attempts = 0;
        self.status.retry_not_before_secs = None;
        Ok(self.transition(TunnelState::Active))
    }
    pub fn on_activation_failed(
        &mut self,
        generation: ConfigGeneration,
        observed_at_secs: u64,
    ) -> Result<Transition, ApplyError> {
        self.ensure_desired()?;
        self.require_generation(generation)?;
        self.require_state(TunnelState::Activating, "activation_failed")?;
        self.status.backoff_attempts = self.status.backoff_attempts.saturating_add(1);
        self.status.retry_not_before_secs =
            Some(observed_at_secs.saturating_add(self.current_backoff_secs().into()));
        Ok(self.transition(TunnelState::Backoff))
    }
    pub fn on_drain_complete(
        &mut self,
        generation: ConfigGeneration,
    ) -> Result<Transition, ApplyError> {
        self.require_generation(generation)?;
        self.require_state(TunnelState::Draining, "drain_complete")?;
        self.complete_passive_transition()
    }
    pub fn on_retry_ready(
        &mut self,
        generation: ConfigGeneration,
        observed_at_secs: u64,
    ) -> Result<Transition, ApplyError> {
        self.require_generation(generation)?;
        self.require_state(TunnelState::Backoff, "retry_ready")?;
        let retry_not_before_secs = self
            .status
            .retry_not_before_secs
            .expect("Backoff state must have a retry window");
        if observed_at_secs < retry_not_before_secs {
            return Err(ApplyError::RetryNotReady {
                retry_not_before_secs,
                observed_at_secs,
            });
        }
        self.status.retry_not_before_secs = None;
        self.complete_passive_transition()
    }
    fn passive_target(&self, passive: TunnelState) -> TunnelState {
        match self.status.state {
            // Backoff owns no successful data-plane generation, so a revoked request
            // can return directly to the requested passive state without waiting for
            // a drain callback that will never arrive.
            TunnelState::Active | TunnelState::Activating => TunnelState::Draining,
            _ => passive,
        }
    }
    fn complete_passive_transition(&mut self) -> Result<Transition, ApplyError> {
        let mode = self.ensure_desired()?.mode;
        let next = match mode {
            TunnelMode::Disabled => TunnelState::Disabled,
            TunnelMode::PresenceOnly => TunnelState::PresenceOnly,
            TunnelMode::Active => TunnelState::Activating,
        };
        if matches!(next, TunnelState::Disabled | TunnelState::PresenceOnly) {
            self.mark_applied();
            self.status.backoff_attempts = 0;
            self.status.retry_not_before_secs = None;
        }
        Ok(self.transition(next))
    }
    fn ensure_desired(&self) -> Result<&TunnelDesiredState, ApplyError> {
        self.desired.as_ref().ok_or(ApplyError::MissingDesiredState)
    }
    /// Rejects stale runtime callbacks so they cannot skip lifecycle states.
    fn require_state(&self, state: TunnelState, event: &'static str) -> Result<(), ApplyError> {
        if self.status.state == state {
            Ok(())
        } else {
            Err(ApplyError::InvalidTransition {
                from: self.status.state,
                event,
            })
        }
    }
    fn require_generation(&self, received: ConfigGeneration) -> Result<(), ApplyError> {
        let current = self.generation().ok_or(ApplyError::MissingDesiredState)?;
        if current == received {
            Ok(())
        } else {
            Err(ApplyError::StaleGeneration { current, received })
        }
    }
    fn current_backoff_secs(&self) -> u16 {
        let policy = &self
            .ensure_desired()
            .expect("desired state was validated")
            .policy;
        let mut delay = policy.initial_backoff_secs;
        for _ in 1..self.status.backoff_attempts {
            delay = delay.saturating_mul(2).min(policy.max_backoff_secs);
        }
        delay
    }
    fn mark_applied(&mut self) {
        self.status.applied_version = self.status.desired_version;
        self.status.applied_digest = self.status.desired_digest;
    }
    fn transition(&mut self, next: TunnelState) -> Transition {
        let from = self.status.state;
        self.status.state = next;
        Transition { from, to: next }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::desired_state::tests::active_state;

    #[test]
    fn rejects_stale_versions() {
        let mut machine = TunnelMachine::default();
        machine
            .apply_desired_state(TunnelDesiredState::presence_only(2))
            .unwrap();
        assert_eq!(
            machine.apply_desired_state(TunnelDesiredState::presence_only(1)),
            Err(ApplyError::StaleVersion {
                current: ConfigVersion(2),
                received: ConfigVersion(1)
            })
        );
    }

    #[test]
    fn rejects_same_version_conflicts() {
        let mut machine = TunnelMachine::default();
        machine
            .apply_desired_state(TunnelDesiredState::presence_only(3))
            .unwrap();
        match machine.apply_desired_state(active_state(3)).unwrap_err() {
            ApplyError::ConflictingVersion {
                version,
                current,
                received,
            } => {
                assert_eq!(version, ConfigVersion(3));
                assert_ne!(current, received);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn transitions_to_active_after_activation_success() {
        let mut machine = TunnelMachine::default();
        let first = machine.apply_desired_state(active_state(1)).unwrap();
        let second = machine
            .on_activation_succeeded(machine.generation().unwrap())
            .unwrap();
        assert_eq!(
            (first, second),
            (
                Transition {
                    from: TunnelState::Disabled,
                    to: TunnelState::Activating
                },
                Transition {
                    from: TunnelState::Activating,
                    to: TunnelState::Active
                }
            )
        );
        assert_eq!(machine.status().state, TunnelState::Active);
        assert_eq!(machine.status().applied_version, Some(ConfigVersion(1)));
    }

    #[test]
    fn drains_before_presence_only() {
        let mut machine = TunnelMachine::default();
        machine.apply_desired_state(active_state(4)).unwrap();
        machine
            .on_activation_succeeded(machine.generation().unwrap())
            .unwrap();
        let first = machine
            .apply_desired_state(TunnelDesiredState::presence_only(5))
            .unwrap();
        let second = machine
            .on_drain_complete(machine.generation().unwrap())
            .unwrap();
        assert_eq!(first.to, TunnelState::Draining);
        assert_eq!(second.to, TunnelState::PresenceOnly);
        assert_eq!(machine.status().applied_version, Some(ConfigVersion(5)));
    }

    #[test]
    fn retries_after_backoff() {
        let mut machine = TunnelMachine::default();
        machine.apply_desired_state(active_state(6)).unwrap();
        assert_eq!(
            machine
                .on_activation_failed(machine.generation().unwrap(), 100)
                .unwrap()
                .to,
            TunnelState::Backoff
        );
        assert_eq!(
            machine
                .on_retry_ready(machine.generation().unwrap(), 101)
                .unwrap()
                .to,
            TunnelState::Activating
        );
        assert_eq!(machine.status().backoff_attempts, 1);
        assert_eq!(machine.status().retry_not_before_secs, None);
    }

    #[test]
    fn stale_callbacks_cannot_skip_lifecycle_states() {
        let mut machine = TunnelMachine::default();
        machine
            .apply_desired_state(TunnelDesiredState::presence_only(1))
            .unwrap();
        assert_eq!(
            machine.on_activation_succeeded(machine.generation().unwrap()),
            Err(ApplyError::InvalidTransition {
                from: TunnelState::PresenceOnly,
                event: "activation_succeeded",
            })
        );
        assert_eq!(
            machine.on_drain_complete(machine.generation().unwrap()),
            Err(ApplyError::InvalidTransition {
                from: TunnelState::PresenceOnly,
                event: "drain_complete",
            })
        );
    }

    #[test]
    fn old_generation_callback_cannot_complete_a_new_generation() {
        let mut machine = TunnelMachine::default();
        machine.apply_desired_state(active_state(1)).unwrap();
        let old = machine.generation().unwrap();
        machine.apply_desired_state(active_state(2)).unwrap();
        let current = machine.generation().unwrap();
        assert_eq!(
            machine.on_activation_succeeded(old),
            Err(ApplyError::StaleGeneration {
                current,
                received: old,
            })
        );
        assert_eq!(machine.status().state, TunnelState::Activating);
        assert_eq!(machine.status().applied_version, None);
    }

    #[test]
    fn retry_waits_for_a_bounded_exponential_backoff_window() {
        let mut machine = TunnelMachine::default();
        let mut desired = active_state(1);
        desired.policy.initial_backoff_secs = 2;
        desired.policy.max_backoff_secs = 5;
        machine.apply_desired_state(desired).unwrap();
        let generation = machine.generation().unwrap();
        machine.on_activation_failed(generation, 10).unwrap();
        assert_eq!(machine.status().retry_not_before_secs, Some(12));
        assert_eq!(
            machine.on_retry_ready(generation, 11),
            Err(ApplyError::RetryNotReady {
                retry_not_before_secs: 12,
                observed_at_secs: 11,
            })
        );
        machine.on_retry_ready(generation, 12).unwrap();
        machine.on_activation_failed(generation, 20).unwrap();
        assert_eq!(machine.status().retry_not_before_secs, Some(24));
        machine.on_retry_ready(generation, 24).unwrap();
        machine.on_activation_failed(generation, 30).unwrap();
        assert_eq!(machine.status().retry_not_before_secs, Some(35));
    }

    #[test]
    fn revoked_backoff_returns_to_presence_without_a_drain_callback() {
        let mut machine = TunnelMachine::default();
        machine.apply_desired_state(active_state(1)).unwrap();
        machine
            .on_activation_failed(machine.generation().unwrap(), 10)
            .unwrap();
        let transition = machine
            .apply_desired_state(TunnelDesiredState::presence_only(2))
            .unwrap();
        assert_eq!(transition.to, TunnelState::PresenceOnly);
        assert_eq!(machine.status().state, TunnelState::PresenceOnly);
        assert_eq!(machine.status().retry_not_before_secs, None);
        assert_eq!(machine.status().applied_version, Some(ConfigVersion(2)));
    }
}
