//! Desired State lifecycle orchestration and local metrics.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    ApplyError, CompiledTunnelConfig, ConfigCompileError, ConfigNotice, Transition,
    TunnelDataPlaneAssignment, TunnelDesiredState, TunnelMachine, TunnelState, TunnelStatus,
};

use super::should_refresh_from_notice;

/// Applies already-verified Desired State; it never fetches control-plane data or starts I/O.
#[derive(Debug, Default)]
pub struct TunnelRuntime {
    machine: TunnelMachine,
    metrics: TunnelMetrics,
}

impl TunnelRuntime {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn status(&self) -> &TunnelStatus {
        self.machine.status()
    }
    pub fn desired_state(&self) -> Option<&TunnelDesiredState> {
        self.machine.desired_state()
    }
    /// Returns the generation token required when an asynchronous data-plane task completes.
    pub fn generation(&self) -> Option<crate::ConfigGeneration> {
        self.machine.generation()
    }
    pub fn metrics(&self) -> &TunnelMetrics {
        &self.metrics
    }

    /// Returns whether this unauthenticated notice requires a signed-state refresh.
    pub fn should_refresh_from_notice(&self, notice: ConfigNotice) -> bool {
        should_refresh_from_notice(self.status(), notice)
    }

    pub fn compile_active_config(
        &self,
        assignment: &TunnelDataPlaneAssignment,
    ) -> Result<CompiledTunnelConfig, TunnelRuntimeConfigError> {
        assignment
            .compile(
                self.desired_state()
                    .ok_or(TunnelRuntimeConfigError::MissingDesiredState)?,
            )
            .map_err(TunnelRuntimeConfigError::Compile)
    }

    pub fn apply_desired_state(
        &mut self,
        desired: TunnelDesiredState,
    ) -> Result<Transition, ApplyError> {
        let result = self.machine.apply_desired_state(desired);
        match &result {
            Ok(transition) => {
                self.metrics.desired_state_applied += 1;
                if transition.to == TunnelState::Activating {
                    self.metrics.activation_started_at = Some(now_secs());
                }
            }
            Err(_) => self.metrics.desired_state_rejected += 1,
        }
        result
    }

    /// Requests the next Disabled generation as part of host shutdown.
    pub fn shutdown(&mut self) -> Result<Option<Transition>, ApplyError> {
        let Some(current) = self.desired_state().cloned() else {
            return Ok(None);
        };
        self.apply_desired_state(TunnelDesiredState::disabled(
            current.version.0.saturating_add(1),
        ))
        .map(Some)
    }
    pub fn on_activation_succeeded(
        &mut self,
        generation: crate::ConfigGeneration,
    ) -> Result<Transition, ApplyError> {
        let result = self.machine.on_activation_succeeded(generation);
        if result.is_ok() {
            self.metrics.activation_count += 1;
            self.metrics.activation_time_secs_total += self
                .metrics
                .activation_started_at
                .take()
                .map(|started| now_secs().saturating_sub(started))
                .unwrap_or_default();
        } else {
            self.metrics.errors += 1;
        }
        result
    }
    pub fn on_activation_failed(
        &mut self,
        generation: crate::ConfigGeneration,
    ) -> Result<Transition, ApplyError> {
        self.metrics.activation_started_at = None;
        self.metrics.errors += 1;
        self.machine.on_activation_failed(generation, now_secs())
    }
    pub fn on_drain_complete(
        &mut self,
        generation: crate::ConfigGeneration,
    ) -> Result<Transition, ApplyError> {
        self.machine.on_drain_complete(generation)
    }
    pub fn on_retry_ready(
        &mut self,
        generation: crate::ConfigGeneration,
    ) -> Result<Transition, ApplyError> {
        self.machine.on_retry_ready(generation, now_secs())
    }
    pub fn record_presence_heartbeat(&mut self, succeeded: bool) {
        self.metrics.presence_heartbeats += 1;
        if succeeded {
            self.metrics.presence_heartbeats_succeeded += 1;
        }
    }
    pub fn record_transport_reconnect(&mut self) {
        self.metrics.transport_reconnects += 1;
    }
    pub fn record_connection_opened(&mut self) {
        self.metrics.active_connections += 1;
    }
    pub fn record_connection_closed(&mut self) {
        self.metrics.active_connections = self.metrics.active_connections.saturating_sub(1);
    }
    pub fn record_bytes(&mut self, sent: u64, received: u64) {
        self.metrics.bytes_sent = self.metrics.bytes_sent.saturating_add(sent);
        self.metrics.bytes_received = self.metrics.bytes_received.saturating_add(received);
    }
    pub fn record_error(&mut self) {
        self.metrics.errors += 1;
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(u64::MAX)
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TunnelMetrics {
    pub presence_heartbeats: u64,
    pub presence_heartbeats_succeeded: u64,
    pub desired_state_applied: u64,
    pub desired_state_rejected: u64,
    pub activation_count: u64,
    pub activation_time_secs_total: u64,
    pub transport_reconnects: u64,
    pub active_connections: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub errors: u64,
    #[doc(hidden)]
    pub activation_started_at: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TunnelRuntimeConfigError {
    MissingDesiredState,
    Compile(ConfigCompileError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RelayAssignment, TransportProtocol, TunnelPolicy, TunnelRoute, TunnelService};

    fn active() -> TunnelDesiredState {
        TunnelDesiredState::active(
            1,
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
                remote_addr: "edge://tenant-a/ssh".into(),
            }],
            TunnelPolicy::default(),
        )
    }
    fn assignment() -> TunnelDataPlaneAssignment {
        TunnelDataPlaneAssignment {
            relay: RelayAssignment {
                address: "relay.example.test".into(),
                port: 7000,
                client_id: "device-1".into(),
                token: "short-lived-token".into(),
                oidc: None,
                expires_at: u64::MAX,
            },
            remote_ports: vec![("edge://tenant-a/ssh".into(), 10_022)],
        }
    }
    #[test]
    fn runtime_reuses_core_state_machine() {
        let mut runtime = TunnelRuntime::new();
        runtime
            .apply_desired_state(TunnelDesiredState::presence_only(1))
            .unwrap();
        assert_eq!(runtime.status().state, TunnelState::PresenceOnly);
        assert_eq!(runtime.status().desired_version.map(|v| v.0), Some(1));
    }
    #[test]
    fn runtime_compiles_only_the_current_desired_state() {
        let mut runtime = TunnelRuntime::new();
        runtime.apply_desired_state(active()).unwrap();
        assert_eq!(
            runtime
                .compile_active_config(&assignment())
                .unwrap()
                .proxies[0]
                .remote_port,
            10_022
        );
    }
    #[test]
    fn shutdown_requests_disabled_generation() {
        let mut runtime = TunnelRuntime::new();
        runtime
            .apply_desired_state(TunnelDesiredState::presence_only(7))
            .unwrap();
        assert_eq!(
            runtime.shutdown().unwrap().unwrap().to,
            TunnelState::Disabled
        );
        assert_eq!(
            runtime.status().desired_version,
            Some(crate::ConfigVersion(8))
        );
    }
    #[test]
    fn runtime_metrics_track_presence_activation_connections_bytes_and_errors() {
        let mut runtime = TunnelRuntime::new();
        runtime.record_presence_heartbeat(true);
        runtime.record_presence_heartbeat(false);
        runtime.record_connection_opened();
        runtime.record_bytes(12, 34);
        runtime.record_connection_closed();
        runtime.record_transport_reconnect();
        runtime.record_error();
        assert_eq!(runtime.metrics().presence_heartbeats, 2);
        assert_eq!(runtime.metrics().presence_heartbeats_succeeded, 1);
        assert_eq!(runtime.metrics().active_connections, 0);
        assert_eq!(runtime.metrics().bytes_sent, 12);
        assert_eq!(runtime.metrics().bytes_received, 34);
        assert_eq!(runtime.metrics().transport_reconnects, 1);
        assert_eq!(runtime.metrics().errors, 1);
    }
}
