use std::path::PathBuf;

use crate::{
    identity::DeviceIdentity,
    status::{ClientStatus, HealthState},
    tunnel::{ApplyError, Transition, TunnelDesiredState, TunnelRuntime},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    pub identity: DeviceIdentity,
    pub config_dir: PathBuf,
}

impl RuntimeConfig {
    pub fn new(rustdesk_id: impl Into<String>, config_dir: impl Into<PathBuf>) -> Self {
        Self {
            identity: DeviceIdentity::from_rustdesk_id(rustdesk_id),
            config_dir: config_dir.into(),
        }
    }
}

/// Lifecycle owner embedded by the RustDesk service process.
#[derive(Debug)]
pub struct NexusRuntime {
    config: RuntimeConfig,
    status: ClientStatus,
    tunnel: TunnelRuntime,
}

impl NexusRuntime {
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            config,
            status: ClientStatus::default(),
            tunnel: TunnelRuntime::new(),
        }
    }

    pub fn start(&mut self) {
        self.status.health = HealthState::Running;
    }

    pub fn stop(&mut self) {
        self.status.health = HealthState::Stopped;
    }

    pub fn apply_tunnel_desired_state(
        &mut self,
        desired: TunnelDesiredState,
    ) -> Result<Transition, ApplyError> {
        let transition = self.tunnel.apply_desired_state(desired)?;
        self.status.tunnel = self.tunnel.status().clone();
        Ok(transition)
    }

    pub fn tunnel(&self) -> &TunnelRuntime {
        &self.tunnel
    }

    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    pub fn status(&self) -> &ClientStatus {
        &self.status
    }
}

#[cfg(test)]
mod tests {
    use super::{NexusRuntime, RuntimeConfig};
    use crate::{
        status::HealthState,
        tunnel::{TunnelDesiredState, TunnelState},
    };

    #[test]
    fn runtime_uses_the_native_rustdesk_id() {
        let mut runtime = NexusRuntime::new(RuntimeConfig::new("123456789", "config"));

        runtime.start();

        assert_eq!(runtime.config().identity.rustdesk_id, "123456789");
        assert_eq!(runtime.status().health, HealthState::Running);
    }

    #[test]
    fn runtime_tracks_tunnel_status_from_shared_runtime() {
        let mut runtime = NexusRuntime::new(RuntimeConfig::new("123456789", "config"));

        runtime
            .apply_tunnel_desired_state(TunnelDesiredState::presence_only(7))
            .unwrap();

        assert_eq!(runtime.status().tunnel.state, TunnelState::PresenceOnly);
        assert_eq!(
            runtime.status().tunnel.desired_version.map(|version| version.0),
            Some(7)
        );
    }
}
