use std::path::PathBuf;

use crate::{
    agent::{AgentError, AgentJob, AgentLocalProxy, AgentProcess},
    identity::DeviceIdentity,
    status::{AgentHealthState, ClientStatus, HealthState},
    tunnel::{ApplyError, ConfigGeneration, Transition, TunnelDesiredState, TunnelRuntime},
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
        let version = self
            .tunnel
            .status()
            .desired_version
            .map(|version| version.0.saturating_add(1))
            .unwrap_or(1);
        let _ = self
            .tunnel
            .apply_desired_state(TunnelDesiredState::presence_only(version));
        self.status.tunnel = self.tunnel.status().clone();
        self.status.health = HealthState::Running;
    }

    pub fn stop(&mut self) {
        let _ = self.tunnel.shutdown();
        self.status.tunnel = self.tunnel.status().clone();
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

    /// Records completion from the exact data-plane generation that was started.
    pub fn on_tunnel_activation_succeeded(
        &mut self,
        generation: ConfigGeneration,
    ) -> Result<Transition, ApplyError> {
        let transition = self.tunnel.on_activation_succeeded(generation)?;
        self.status.tunnel = self.tunnel.status().clone();
        Ok(transition)
    }

    /// Records an activation failure for the generation the native host owns.
    /// Deliberate cancellation is handled by `on_tunnel_drain_complete` instead.
    pub fn on_tunnel_activation_failed(
        &mut self,
        generation: ConfigGeneration,
    ) -> Result<Transition, ApplyError> {
        let transition = self.tunnel.on_activation_failed(generation)?;
        self.status.tunnel = self.tunnel.status().clone();
        Ok(transition)
    }

    /// Records draining completion from the exact generation that began draining.
    pub fn on_tunnel_drain_complete(
        &mut self,
        generation: ConfigGeneration,
    ) -> Result<Transition, ApplyError> {
        let transition = self.tunnel.on_drain_complete(generation)?;
        self.status.tunnel = self.tunnel.status().clone();
        Ok(transition)
    }

    /// Re-enters activation after the host waited for the core-calculated
    /// retry deadline for this exact asynchronous generation.
    pub fn on_tunnel_retry_ready(
        &mut self,
        generation: ConfigGeneration,
    ) -> Result<Transition, ApplyError> {
        let transition = self.tunnel.on_retry_ready(generation)?;
        self.status.tunnel = self.tunnel.status().clone();
        Ok(transition)
    }

    pub fn bind_device_uid(&mut self, device_uid: impl Into<String>) {
        self.config.identity.bind_device_uid(device_uid);
    }

    pub fn presence_device_id(&self) -> Option<u64> {
        self.config
            .identity
            .device_uid
            .as_deref()
            .map(crate::tunnel::derive_presence_device_id)
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

    /// The Host owns Agent connectivity; this only projects its finite state
    /// through the existing runtime status snapshot.
    pub fn set_agent_health(&mut self, health: AgentHealthState) {
        self.status.agent_health = health;
    }

    /// Projects the Host-owned bounded Agent queue through the existing IPC status.
    pub fn set_agent_queue_depth(&mut self, depth: usize) {
        self.status.agent_queue_depth = depth;
    }

    /// Validates a machine-bound Agent envelope before any process spawn.
    /// Socket/Realtime callers pass the authenticated machine identity here;
    /// the runtime never accepts a browser bearer or an arbitrary target.
    pub fn spawn_agent_job(
        &self,
        job: &AgentJob,
        machine_id: &str,
    ) -> Result<AgentProcess, AgentError> {
        self.spawn_agent_job_with_local_proxy(job, machine_id, None)
    }

    /// Starts a device-bound Agent with the only optional data-plane input the
    /// Agent is allowed to see: a Host-owned loopback endpoint and capability.
    pub fn spawn_agent_job_with_local_proxy(
        &self,
        job: &AgentJob,
        machine_id: &str,
        local_proxy: Option<&AgentLocalProxy>,
    ) -> Result<AgentProcess, AgentError> {
        if job.job_id.trim().is_empty()
            || job.tenant_id.trim().is_empty()
            || job.machine_id != machine_id
            || self.config.identity.device_uid.as_deref() != Some(job.device_uid.as_str())
            || job.timeout_ms == 0
        {
            return Err(AgentError::InvalidArgument);
        }
        let (provider, command) = job.command().ok_or(AgentError::InvalidArgument)?;
        command.spawn_with_local_proxy(
            provider,
            Some(&self.config.config_dir),
            Some(std::time::Duration::from_millis(job.timeout_ms)),
            local_proxy,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{NexusRuntime, RuntimeConfig};
    use crate::{
        agent::AgentJob,
        status::{AgentHealthState, HealthState},
        tunnel::{
            TransportProtocol, TunnelDesiredState, TunnelPolicy, TunnelRoute, TunnelService,
            TunnelState,
        },
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
            runtime
                .status()
                .tunnel
                .desired_version
                .map(|version| version.0),
            Some(7)
        );
    }

    #[test]
    fn runtime_projects_agent_health_without_changing_host_health() {
        let mut runtime = NexusRuntime::new(RuntimeConfig::new("123456789", "config"));
        runtime.start();
        runtime.set_agent_health(AgentHealthState::Ready);
        runtime.set_agent_queue_depth(3);

        assert_eq!(runtime.status().health, HealthState::Running);
        assert_eq!(runtime.status().agent_health, AgentHealthState::Ready);
        assert_eq!(runtime.status().agent_queue_depth, 3);
    }

    #[test]
    fn runtime_keeps_presence_only_while_idle_and_drains_active_data_plane() {
        let mut runtime = NexusRuntime::new(RuntimeConfig::new("123456789", "config"));
        runtime.start();
        assert_eq!(runtime.status().tunnel.state, TunnelState::PresenceOnly);

        runtime
            .apply_tunnel_desired_state(TunnelDesiredState::active(
                2,
                vec![TunnelService {
                    service_id: "service-ssh".into(),
                    name: "ssh".into(),
                    local_addr: "127.0.0.1:22".into(),
                    protocol: TransportProtocol::Tcp,
                    virtual_host: None,
                    protected_access: None,
                }],
                vec![TunnelRoute {
                    route_id: "route-ssh".into(),
                    service: "ssh".into(),
                    remote_addr: "edge://ssh".into(),
                }],
                TunnelPolicy::default(),
            ))
            .unwrap();
        let generation = runtime.tunnel().generation().unwrap();
        runtime.on_tunnel_activation_succeeded(generation).unwrap();
        assert_eq!(runtime.status().tunnel.state, TunnelState::Active);

        runtime
            .apply_tunnel_desired_state(TunnelDesiredState::presence_only(3))
            .unwrap();
        assert_eq!(runtime.status().tunnel.state, TunnelState::Draining);
        let generation = runtime.tunnel().generation().unwrap();
        runtime.on_tunnel_drain_complete(generation).unwrap();
        assert_eq!(runtime.status().tunnel.state, TunnelState::PresenceOnly);
    }

    #[test]
    fn agent_job_is_bound_to_the_active_device_and_machine_before_spawn() {
        let mut runtime = NexusRuntime::new(RuntimeConfig::new("123456789", "config"));
        runtime.bind_device_uid("device-a");
        let job = AgentJob {
            job_id: "job-1".into(),
            tenant_id: "tenant-a".into(),
            device_uid: "device-a".into(),
            machine_id: "machine-a".into(),
            provider: "codex".into(),
            program: "codex".into(),
            args: vec!["--version".into()],
            timeout_ms: 1_000,
        };
        assert!(runtime.spawn_agent_job(&job, "machine-b").is_err());
    }

    #[test]
    fn runtime_derives_the_control_plane_presence_identity_from_device_uid() {
        let mut runtime = NexusRuntime::new(RuntimeConfig::new("123456789", "config"));
        assert_eq!(runtime.presence_device_id(), None);
        runtime.bind_device_uid("device-1");
        assert_eq!(
            runtime.presence_device_id(),
            Some(crate::tunnel::derive_presence_device_id("device-1"))
        );
    }

    #[test]
    fn stop_disables_tunnel_before_marking_runtime_stopped() {
        let mut runtime = NexusRuntime::new(RuntimeConfig::new("123456789", "config"));
        runtime
            .apply_tunnel_desired_state(TunnelDesiredState::presence_only(7))
            .unwrap();

        runtime.stop();

        assert_eq!(runtime.status().health, HealthState::Stopped);
        assert_eq!(runtime.status().tunnel.state, TunnelState::Disabled);
        assert_eq!(
            runtime.status().tunnel.desired_version.map(|v| v.0),
            Some(8)
        );
    }
}
