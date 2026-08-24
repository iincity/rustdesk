//! Relay assignment validation and compilation into bounded Tunnel targets.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::{
    ForwardProxyPlugin, Http2UpstreamPlugin, HttpsUpstreamPlugin, ProtectedAccess,
    StaticFilePlugin, UnixSocketPlugin,
};
use crate::{ConfigError, TransportProtocol, TunnelDesiredState, TunnelMode};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayAssignment {
    pub address: String,
    pub port: u16,
    pub client_id: String,
    /// Short-lived token authentication supplied by the control plane.
    /// It must be empty when `oidc` is present so a generation has exactly one
    /// authentication mechanism.
    pub token: String,
    /// Optional short-lived OIDC client credential issued by the control plane.
    /// This deliberately has no file, exec, CA-file, proxy, or TLS-bypass field.
    pub oidc: Option<OidcRelayCredentials>,
    /// Unix timestamp after which this assignment cannot create a new generation.
    pub expires_at: u64,
}

/// Narrow OIDC client-credentials grant usable by a Relay generation.
///
/// The host keeps it in memory only. It is not an end-user login and cannot
/// carry arbitrary upstream authentication settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcRelayCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub token_endpoint_url: String,
    pub audience: Option<String>,
    pub scope: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunnelDataPlaneAssignment {
    pub relay: RelayAssignment,
    /// Maps a control-plane route address to its assigned Relay port.
    pub remote_ports: Vec<(String, u16)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledTunnelConfig {
    pub relay: RelayAssignment,
    pub proxies: Vec<CompiledTunnelProxy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledTunnelProxy {
    pub name: String,
    pub local_addr: String,
    pub protocol: TransportProtocol,
    pub remote_port: u16,
    pub virtual_host: Option<String>,
    pub protected_access: Option<ProtectedAccess>,
    pub static_file_plugin: Option<StaticFilePlugin>,
    pub unix_socket_plugin: Option<UnixSocketPlugin>,
    pub forward_proxy_plugin: Option<ForwardProxyPlugin>,
    pub http2_upstream_plugin: Option<Http2UpstreamPlugin>,
    /// The Rustls bridge replaces this proxy's local address before data-plane activation.
    pub https_upstream_plugin: Option<HttpsUpstreamPlugin>,
}

impl CompiledTunnelConfig {
    /// Replaces one signed service's backend with a host-owned loopback bridge.
    ///
    /// The bridge address is ephemeral runtime state, never a control-plane field.
    pub fn override_local_addr(
        &mut self,
        service_id: &str,
        local_addr: String,
    ) -> Result<(), ConfigRenderError> {
        let Some(proxy) = self
            .proxies
            .iter_mut()
            .find(|proxy| proxy.name == service_id)
        else {
            return Err(ConfigRenderError::UnauthorizedLocalOverride);
        };
        if proxy.https_upstream_plugin.is_none() {
            return Err(ConfigRenderError::UnauthorizedLocalOverride);
        }
        split_local_addr(&local_addr)?;
        proxy.local_addr = local_addr;
        Ok(())
    }
}

impl TunnelDataPlaneAssignment {
    pub fn compile(
        &self,
        desired: &TunnelDesiredState,
    ) -> Result<CompiledTunnelConfig, ConfigCompileError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(u64::MAX);
        self.compile_at(desired, now)
    }

    /// Validates assignment and Desired State before creating any data-plane generation.
    pub fn compile_at(
        &self,
        desired: &TunnelDesiredState,
        now: u64,
    ) -> Result<CompiledTunnelConfig, ConfigCompileError> {
        desired
            .validate()
            .map_err(ConfigCompileError::InvalidDesiredState)?;
        if desired.mode != TunnelMode::Active {
            return Err(ConfigCompileError::InactiveDesiredState);
        }
        if self.relay.address.trim().is_empty() {
            return Err(ConfigCompileError::EmptyRelayAddress);
        }
        if self.relay.port == 0 {
            return Err(ConfigCompileError::ZeroRelayPort);
        }
        if self.relay.client_id.trim().is_empty() {
            return Err(ConfigCompileError::EmptyClientId);
        }
        if let Some(oidc) = &self.relay.oidc {
            validate_oidc(oidc)?;
            if !self.relay.token.is_empty() {
                return Err(ConfigCompileError::ConflictingRelayAuth);
            }
        } else if self.relay.token.trim().is_empty() {
            return Err(ConfigCompileError::EmptyToken);
        }
        if self.relay.expires_at <= now {
            return Err(ConfigCompileError::ExpiredRelayToken);
        }
        let mut proxies = Vec::with_capacity(desired.routes.len());
        for route in &desired.routes {
            let service = desired
                .services
                .iter()
                .find(|service| service.name == route.service)
                .ok_or_else(|| {
                    ConfigCompileError::InvalidDesiredState(ConfigError::UnknownRouteService(
                        route.service.clone(),
                    ))
                })?;
            let remote_port = if matches!(
                service.protocol,
                TransportProtocol::Tcp | TransportProtocol::Udp
            ) {
                let port = self
                    .remote_ports
                    .iter()
                    .find_map(|(address, port)| (address == &route.remote_addr).then_some(*port))
                    .ok_or_else(|| {
                        ConfigCompileError::MissingRoutePort(route.remote_addr.clone())
                    })?;
                if port == 0 {
                    return Err(ConfigCompileError::ZeroRoutePort(route.remote_addr.clone()));
                }
                port
            } else {
                0
            };
            proxies.push(CompiledTunnelProxy {
                // `service_id` is signed and unique, unlike display names or
                // route ordering. Visitors use it as their upstream serverName.
                name: service.service_id.clone(),
                local_addr: service.local_addr.clone(),
                protocol: service.protocol,
                remote_port,
                virtual_host: service.virtual_host.clone(),
                protected_access: service.protected_access.clone(),
                static_file_plugin: desired
                    .static_file_plugins
                    .iter()
                    .find(|plugin| plugin.service_id == service.service_id)
                    .cloned(),
                unix_socket_plugin: desired
                    .unix_socket_plugins
                    .iter()
                    .find(|plugin| plugin.service_id == service.service_id)
                    .cloned(),
                forward_proxy_plugin: desired
                    .forward_proxy_plugins
                    .iter()
                    .find(|plugin| plugin.service_id == service.service_id)
                    .cloned(),
                http2_upstream_plugin: desired
                    .http2_upstream_plugins
                    .iter()
                    .find(|plugin| plugin.service_id == service.service_id)
                    .cloned(),
                https_upstream_plugin: desired
                    .https_upstream_plugins
                    .iter()
                    .find(|plugin| plugin.service_id == service.service_id)
                    .cloned(),
            });
        }
        Ok(CompiledTunnelConfig {
            relay: self.relay.clone(),
            proxies,
        })
    }
}

fn split_local_addr(local_addr: &str) -> Result<(&str, u16), ConfigRenderError> {
    let (host, port) = local_addr
        .rsplit_once(':')
        .ok_or_else(|| ConfigRenderError::InvalidLocalAddress(local_addr.into()))?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| ConfigRenderError::InvalidLocalAddress(local_addr.into()))?;
    let host = host.trim().trim_matches(['[', ']']);
    if host.is_empty() {
        return Err(ConfigRenderError::InvalidLocalAddress(local_addr.into()));
    }
    Ok((host, port))
}
fn validate_oidc(oidc: &OidcRelayCredentials) -> Result<(), ConfigCompileError> {
    if oidc.client_id.trim().is_empty() || oidc.client_secret.trim().is_empty() {
        return Err(ConfigCompileError::InvalidOidcCredentials);
    }
    // The fixed upstream permits plaintext HTTP and custom CA/bypass settings.
    // Nexus only accepts a short-lived credential over a normal HTTPS endpoint.
    let endpoint_host = oidc
        .token_endpoint_url
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or_default();
    if endpoint_host.is_empty()
        || endpoint_host.starts_with(['.', ':'])
        || !oidc.token_endpoint_url.starts_with("https://")
        || oidc.token_endpoint_url.len() > 2048
        || oidc.token_endpoint_url.chars().any(char::is_control)
    {
        return Err(ConfigCompileError::InvalidOidcEndpoint);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigRenderError {
    InvalidLocalAddress(String),
    UnauthorizedLocalOverride,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigCompileError {
    InvalidDesiredState(ConfigError),
    InactiveDesiredState,
    EmptyRelayAddress,
    ZeroRelayPort,
    EmptyClientId,
    EmptyToken,
    ConflictingRelayAuth,
    InvalidOidcCredentials,
    InvalidOidcEndpoint,
    ExpiredRelayToken,
    MissingRoutePort(String),
    ZeroRoutePort(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::desired_state::tests::active_state;

    fn assignment(expires_at: u64, ports: Vec<(String, u16)>) -> TunnelDataPlaneAssignment {
        TunnelDataPlaneAssignment {
            relay: RelayAssignment {
                address: "relay.example.test".into(),
                port: 7000,
                client_id: "device-1".into(),
                token: "short-lived-token".into(),
                oidc: None,
                expires_at,
            },
            remote_ports: ports,
        }
    }

    #[test]
    fn compiles_control_plane_services_and_routes_into_tunnel_targets() {
        let compiled = assignment(u64::MAX, vec![("edge://tenant-a/rdp".into(), 10_001)])
            .compile(&active_state(1))
            .unwrap();
        assert_eq!(
            compiled.proxies,
            vec![CompiledTunnelProxy {
                name: "service-rdp".into(),
                local_addr: "127.0.0.1:3389".into(),
                protocol: TransportProtocol::Tcp,
                remote_port: 10_001,
                virtual_host: None,
                protected_access: None,
                static_file_plugin: None,
                unix_socket_plugin: None,
                forward_proxy_plugin: None,
                http2_upstream_plugin: None,
                https_upstream_plugin: None,
            }]
        );
    }

    #[test]
    fn only_a_signed_https_upstream_can_replace_its_ephemeral_loopback_backend() {
        let mut desired = active_state(1);
        desired.https_upstream_plugins.push(HttpsUpstreamPlugin {
            service_id: "service-rdp".into(),
            server_name: "backend.example.test".into(),
        });
        let mut compiled = assignment(u64::MAX, vec![("edge://tenant-a/rdp".into(), 10_001)])
            .compile(&desired)
            .unwrap();
        compiled
            .override_local_addr("service-rdp", "127.0.0.1:45678".into())
            .unwrap();
        assert_eq!(compiled.proxies[0].local_addr, "127.0.0.1:45678");

        let mut plain = assignment(u64::MAX, vec![("edge://tenant-a/rdp".into(), 10_001)])
            .compile(&active_state(1))
            .unwrap();
        assert_eq!(
            plain.override_local_addr("service-rdp", "127.0.0.1:45678".into()),
            Err(ConfigRenderError::UnauthorizedLocalOverride)
        );
    }

    #[test]
    fn compiler_refuses_routes_without_control_plane_port_assignments() {
        assert_eq!(
            assignment(u64::MAX, Vec::new())
                .compile(&active_state(1))
                .unwrap_err(),
            ConfigCompileError::MissingRoutePort("edge://tenant-a/rdp".into())
        );
    }

    #[test]
    fn compiler_rejects_expired_relay_assignments_before_activation() {
        assert_eq!(
            assignment(100, vec![("edge://tenant-a/rdp".into(), 10_001)])
                .compile_at(&active_state(1), 100),
            Err(ConfigCompileError::ExpiredRelayToken)
        );
    }

    #[test]
    fn rejects_plaintext_or_conflicting_oidc_relay_authentication() {
        let mut assignment = assignment(u64::MAX, vec![("edge://tenant-a/rdp".into(), 10_001)]);
        assignment.relay.oidc = Some(OidcRelayCredentials {
            client_id: "relay-client".into(),
            client_secret: "short-secret".into(),
            token_endpoint_url: "http://issuer.example/token".into(),
            audience: None,
            scope: None,
        });
        assert_eq!(
            assignment.compile(&active_state(1)).unwrap_err(),
            ConfigCompileError::InvalidOidcEndpoint
        );
        assignment.relay.oidc.as_mut().unwrap().token_endpoint_url = "https://".into();
        assignment.relay.token.clear();
        assert_eq!(
            assignment.compile(&active_state(1)).unwrap_err(),
            ConfigCompileError::InvalidOidcEndpoint
        );
        assignment.relay.token = "also-present".into();
        assignment.relay.oidc.as_mut().unwrap().token_endpoint_url =
            "https://issuer.example/token".into();
        assert_eq!(
            assignment.compile(&active_state(1)).unwrap_err(),
            ConfigCompileError::ConflictingRelayAuth
        );
    }
}
