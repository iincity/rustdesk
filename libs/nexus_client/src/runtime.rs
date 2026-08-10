use std::path::PathBuf;

use crate::{
    identity::DeviceIdentity,
    status::{ClientStatus, HealthState},
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
}

impl NexusRuntime {
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            config,
            status: ClientStatus::default(),
        }
    }

    pub fn start(&mut self) {
        self.status.health = HealthState::Running;
    }

    pub fn stop(&mut self) {
        self.status.health = HealthState::Stopped;
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
    use crate::status::HealthState;

    #[test]
    fn runtime_uses_the_native_rustdesk_id() {
        let mut runtime = NexusRuntime::new(RuntimeConfig::new("123456789", "config"));

        runtime.start();

        assert_eq!(runtime.config().identity.rustdesk_id, "123456789");
        assert_eq!(runtime.status().health, HealthState::Running);
    }
}
