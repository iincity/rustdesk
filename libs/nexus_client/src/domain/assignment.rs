//! Relay assignment validation and compilation into the fixed FRP target model.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::{
    ForwardProxyPlugin, ForwardProxyProtocol, Http2UpstreamPlugin, Http2UpstreamProtocol,
    HttpsUpstreamPlugin, ProtectedAccess, StaticFilePlugin, UnixSocketPlugin,
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
    /// Maps a control-plane route address to the assigned FRP remote port.
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
    /// The Rustls bridge replaces this proxy's local address before FRP starts.
    pub https_upstream_plugin: Option<HttpsUpstreamPlugin>,
}

impl CompiledTunnelConfig {
    /// Renders the one signed Relay authentication mode accepted by Nexus.
    pub fn relay_auth_toml(relay: &RelayAssignment) -> String {
        if let Some(oidc) = &relay.oidc {
            let mut auth = format!(
                "method = \"oidc\"\n[auth.oidc]\nclientID = \"{}\"\nclientSecret = \"{}\"\ntokenEndpointURL = \"{}\"\n",
                toml_string(&oidc.client_id),
                toml_string(&oidc.client_secret),
                toml_string(&oidc.token_endpoint_url),
            );
            if let Some(audience) = &oidc.audience {
                auth.push_str(&format!("audience = \"{}\"\n", toml_string(audience)));
            }
            if let Some(scope) = &oidc.scope {
                auth.push_str(&format!("scope = \"{}\"\n", toml_string(scope)));
            }
            auth
        } else {
            format!(
                "method = \"token\"\ntoken = \"{}\"\n",
                toml_string(&relay.token)
            )
        }
    }

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

    /// Renders only the TOML subset supported by the fixed upstream frp-rs revision.
    pub fn to_frp_toml(&self) -> Result<String, ConfigRenderError> {
        let mut toml =
            format!(
            "serverAddr = \"{}\"\nserverPort = {}\nuser = \"{}\"\nclientID = \"{}\"\n\n[auth]\n",
            toml_string(&self.relay.address), self.relay.port,
            toml_string(&self.relay.client_id), toml_string(&self.relay.client_id),
        );
        toml.push_str(&Self::relay_auth_toml(&self.relay));
        for proxy in &self.proxies {
            let (local_ip, local_port) = split_local_addr(&proxy.local_addr)?;
            let protocol = match proxy.protocol {
                TransportProtocol::Tcp => "tcp",
                TransportProtocol::Udp => "udp",
                TransportProtocol::Stcp => "stcp",
                TransportProtocol::Sudp => "sudp",
                TransportProtocol::Xtcp => "xtcp",
                TransportProtocol::Http => "http",
                TransportProtocol::Https => "https",
                TransportProtocol::TcpMux => "tcpmux",
            };
            toml.push_str(&format!(
                "\n[[proxies]]\nname = \"{}\"\ntype = \"{}\"\nlocalIP = \"{}\"\nlocalPort = {}\n",
                toml_string(&proxy.name),
                protocol,
                toml_string(local_ip),
                local_port,
            ));
            if matches!(
                proxy.protocol,
                TransportProtocol::Tcp | TransportProtocol::Udp
            ) {
                toml.push_str(&format!("remotePort = {}\n", proxy.remote_port));
            }
            if let Some(host) = &proxy.virtual_host {
                toml.push_str(&format!("customDomains = [\"{}\"]\n", toml_string(host)));
            }
            if proxy.protocol == TransportProtocol::TcpMux {
                // Fixed frp-rs accepts only the HTTP CONNECT muxer; omitting it
                // makes the otherwise valid proxy fail upstream validation.
                toml.push_str("multiplexer = \"httpconnect\"\n");
            }
            if let Some(access) = &proxy.protected_access {
                toml.push_str(&format!(
                    "secretKey = \"{}\"\nallowUsers = [{}]\n",
                    toml_string(&access.secret),
                    access
                        .allowed_device_uids
                        .iter()
                        .map(|device_uid| format!("\"{}\"", toml_string(device_uid)))
                        .collect::<Vec<_>>()
                        .join(", "),
                ));
            }
            if let Some(plugin) = &proxy.static_file_plugin {
                toml.push_str(&format!(
                    "[proxies.plugin]\ntype = \"static_file\"\nlocalPath = \"{}\"\n",
                    toml_string(&plugin.local_path),
                ));
                if let Some(strip_prefix) = &plugin.strip_prefix {
                    toml.push_str(&format!(
                        "stripPrefix = \"{}\"\n",
                        toml_string(strip_prefix)
                    ));
                }
            }
            if let Some(plugin) = &proxy.unix_socket_plugin {
                toml.push_str(&format!(
                    "[proxies.plugin]\ntype = \"unix_domain_socket\"\nunixPath = \"{}\"\n",
                    toml_string(&plugin.unix_path)
                ));
            }
            if let Some(plugin) = &proxy.forward_proxy_plugin {
                let (kind, user, password) = match plugin.protocol {
                    ForwardProxyProtocol::Http => ("http_proxy", "httpUser", "httpPassword"),
                    ForwardProxyProtocol::Socks5 => ("socks5", "username", "password"),
                };
                toml.push_str(&format!("[proxies.plugin]\ntype = \"{kind}\"\n"));
                if let (Some(username), Some(secret)) = (&plugin.username, &plugin.password) {
                    toml.push_str(&format!(
                        "{user} = \"{}\"\n{password} = \"{}\"\n",
                        toml_string(username),
                        toml_string(secret)
                    ));
                }
            }
            if let Some(plugin) = &proxy.http2_upstream_plugin {
                let kind = match plugin.protocol {
                    Http2UpstreamProtocol::Http => "http2http",
                };
                toml.push_str(&format!(
                    "[proxies.plugin]\ntype = \"{kind}\"\nlocalAddr = \"{}\"\n",
                    toml_string(&proxy.local_addr)
                ));
            }
        }
        Ok(toml)
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
fn toml_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
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
    use crate::{TunnelPolicy, TunnelRoute, TunnelService};

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
    fn compiles_control_plane_services_and_routes_into_frp_proxy_targets() {
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
    fn renders_only_the_signed_static_file_plugin() {
        let mut desired = active_state(1);
        desired.static_file_plugins.push(StaticFilePlugin {
            service_id: "service-rdp".into(),
            local_path: "C:/nexus-static".into(),
            strip_prefix: Some("support".into()),
        });
        let rendered = assignment(u64::MAX, vec![("edge://tenant-a/rdp".into(), 10_001)])
            .compile(&desired)
            .unwrap()
            .to_frp_toml()
            .unwrap();
        assert!(rendered.contains("type = \"static_file\""));
        assert!(rendered.contains("localPath = \"C:/nexus-static\""));
        assert!(rendered.contains("stripPrefix = \"support\""));
        assert!(!rendered.contains("httpPassword"));
    }

    #[test]
    fn renders_only_the_signed_unix_socket_plugin() {
        let mut desired = active_state(1);
        desired.unix_socket_plugins.push(UnixSocketPlugin {
            service_id: "service-rdp".into(),
            unix_path: "/run/nexus/backend.sock".into(),
        });
        let rendered = assignment(u64::MAX, vec![("edge://tenant-a/rdp".into(), 10_001)])
            .compile(&desired)
            .unwrap()
            .to_frp_toml()
            .unwrap();
        assert!(rendered.contains("type = \"unix_domain_socket\""));
        assert!(rendered.contains("unixPath = \"/run/nexus/backend.sock\""));
        assert!(!rendered.contains("plugin = \"socks5\""));
    }

    #[test]
    fn renders_signed_http_forward_proxy_plugin_without_raw_options() {
        let mut desired = active_state(1);
        desired.forward_proxy_plugins.push(ForwardProxyPlugin {
            service_id: "service-rdp".into(),
            protocol: ForwardProxyProtocol::Http,
            username: Some("proxy-user".into()),
            password: Some("proxy-pass".into()),
        });
        let rendered = assignment(u64::MAX, vec![("edge://tenant-a/rdp".into(), 10_001)])
            .compile(&desired)
            .unwrap()
            .to_frp_toml()
            .unwrap();
        assert!(rendered.contains("type = \"http_proxy\""));
        assert!(rendered.contains("httpUser = \"proxy-user\""));
        assert!(!rendered.contains("socks5"));
    }

    #[test]
    fn renders_signed_http_upstream_without_raw_tls_options() {
        let mut desired = active_state(1);
        desired.http2_upstream_plugins.push(Http2UpstreamPlugin {
            service_id: "service-rdp".into(),
            protocol: Http2UpstreamProtocol::Http,
        });
        let rendered = assignment(u64::MAX, vec![("edge://tenant-a/rdp".into(), 10_001)])
            .compile(&desired)
            .unwrap()
            .to_frp_toml()
            .unwrap();
        assert!(rendered.contains("type = \"http2http\""));
        assert!(rendered.contains("localAddr = \"127.0.0.1:3389\""));
        assert!(!rendered.contains("crtPath"));
        assert!(!rendered.contains("requestHeaders"));
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
        assert!(compiled
            .to_frp_toml()
            .unwrap()
            .contains("localPort = 45678"));

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
    fn compiler_rejects_expired_relay_assignments_before_rendering() {
        assert_eq!(
            assignment(100, vec![("edge://tenant-a/rdp".into(), 10_001)])
                .compile_at(&active_state(1), 100),
            Err(ConfigCompileError::ExpiredRelayToken)
        );
    }

    #[test]
    fn rendered_toml_matches_the_frp_client_config_surface() {
        let toml = assignment(u64::MAX, vec![("edge://tenant-a/rdp".into(), 10_001)])
            .compile(&active_state(1))
            .unwrap()
            .to_frp_toml()
            .unwrap();
        assert!(toml.contains("serverAddr = \"relay.example.test\""));
        assert!(toml.contains("[[proxies]]\nname = \"service-rdp\"\ntype = \"tcp\""));
        assert!(toml.contains("localIP = \"127.0.0.1\"\nlocalPort = 3389\nremotePort = 10001"));
    }

    #[test]
    fn renders_udp_routes_with_the_upstream_proxy_type() {
        let desired = TunnelDesiredState::active(
            1,
            vec![TunnelService {
                service_id: "service-dns".into(),
                name: "dns".into(),
                local_addr: "127.0.0.1:5353".into(),
                protocol: TransportProtocol::Udp,
                virtual_host: None,
                protected_access: None,
            }],
            vec![TunnelRoute {
                route_id: "route-dns".into(),
                service: "dns".into(),
                remote_addr: "edge://tenant-a/dns".into(),
            }],
            TunnelPolicy::default(),
        );
        let toml = assignment(u64::MAX, vec![("edge://tenant-a/dns".into(), 10_053)])
            .compile(&desired)
            .unwrap()
            .to_frp_toml()
            .unwrap();
        assert!(toml.contains("name = \"service-dns\"\ntype = \"udp\""));
        assert!(toml.contains("remotePort = 10053"));
    }

    #[test]
    fn renders_control_plane_virtual_hosts_as_http_and_https_proxies() {
        for (protocol, proxy_type) in [
            (TransportProtocol::Http, "http"),
            (TransportProtocol::Https, "https"),
        ] {
            let desired = TunnelDesiredState::active(
                1,
                vec![TunnelService {
                    service_id: "service-web".into(),
                    name: "web".into(),
                    local_addr: "127.0.0.1:8080".into(),
                    protocol,
                    virtual_host: Some("app.tenant.example".into()),
                    protected_access: None,
                }],
                vec![TunnelRoute {
                    route_id: "route-web".into(),
                    service: "web".into(),
                    remote_addr: "app.tenant.example".into(),
                }],
                TunnelPolicy::default(),
            );
            let toml = assignment(u64::MAX, Vec::new())
                .compile(&desired)
                .unwrap()
                .to_frp_toml()
                .unwrap();
            assert!(toml.contains(&format!("type = \"{proxy_type}\"")));
            assert!(toml.contains("customDomains = [\"app.tenant.example\"]"));
            assert!(!toml.contains("remotePort = 443"));
        }
    }

    #[test]
    fn renders_tcp_mux_with_controlled_host_without_remote_port() {
        let desired = TunnelDesiredState::active(
            1,
            vec![TunnelService {
                service_id: "service-mux".into(),
                name: "mux".into(),
                local_addr: "127.0.0.1:8080".into(),
                protocol: TransportProtocol::TcpMux,
                virtual_host: Some("mux.example.test".into()),
                protected_access: None,
            }],
            vec![TunnelRoute {
                route_id: "route-mux".into(),
                service: "mux".into(),
                remote_addr: "mux.example.test".into(),
            }],
            TunnelPolicy::default(),
        );
        let toml = assignment(u64::MAX, Vec::new())
            .compile(&desired)
            .unwrap()
            .to_frp_toml()
            .unwrap();
        assert!(toml.contains("type = \"tcpmux\""));
        assert!(toml.contains("customDomains = [\"mux.example.test\"]"));
        assert!(toml.contains("multiplexer = \"httpconnect\""));
        assert!(!toml.contains("remotePort ="));
    }

    #[test]
    fn renders_signed_protected_access_without_raw_upstream_options() {
        let desired = TunnelDesiredState::active(
            1,
            vec![TunnelService {
                service_id: "service-stcp".into(),
                name: "support".into(),
                local_addr: "127.0.0.1:3389".into(),
                protocol: TransportProtocol::Stcp,
                virtual_host: None,
                protected_access: Some(crate::ProtectedAccess {
                    secret: "0123456789abcdef".into(),
                    allowed_device_uids: vec!["visitor-device".into()],
                    route_id: "route-support".into(),
                }),
            }],
            vec![TunnelRoute {
                route_id: "route-support".into(),
                service: "support".into(),
                remote_addr: "edge://support".into(),
            }],
            TunnelPolicy::default(),
        );
        let rendered = assignment(u64::MAX, Vec::new())
            .compile(&desired)
            .unwrap()
            .to_frp_toml()
            .unwrap();
        assert!(rendered.contains("type = \"stcp\""));
        assert!(rendered.contains("secretKey = \"0123456789abcdef\""));
        assert!(rendered.contains("allowUsers = [\"visitor-device\"]"));
        assert!(!rendered.contains("remotePort"));
    }

    #[test]
    fn renders_only_control_plane_signed_https_oidc_credentials() {
        let mut assignment = assignment(u64::MAX, vec![("edge://tenant-a/rdp".into(), 10_001)]);
        assignment.relay.token.clear();
        assignment.relay.oidc = Some(OidcRelayCredentials {
            client_id: "relay-client".into(),
            client_secret: "short-secret".into(),
            token_endpoint_url: "https://issuer.example/token".into(),
            audience: Some("nexus-relay".into()),
            scope: Some("frp".into()),
        });
        let rendered = assignment
            .compile(&active_state(1))
            .unwrap()
            .to_frp_toml()
            .unwrap();
        assert!(rendered.contains("method = \"oidc\""));
        assert!(rendered.contains("tokenEndpointURL = \"https://issuer.example/token\""));
        assert!(!rendered.contains("trustedCaFile"));
        assert!(!rendered.contains("insecureSkipVerify"));
        assert!(!rendered.contains("token = \""));
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

    #[test]
    fn renders_xtcp_with_signed_access_and_no_remote_port() {
        let mut desired = active_state(1);
        desired.services[0].protocol = TransportProtocol::Xtcp;
        desired.services[0].protected_access = Some(ProtectedAccess {
            secret: "0123456789abcdef".into(),
            allowed_device_uids: vec!["visitor-device".into()],
            route_id: "route-rdp".into(),
        });
        let toml = assignment(u64::MAX, Vec::new())
            .compile(&desired)
            .unwrap()
            .to_frp_toml()
            .unwrap();
        assert!(toml.contains("type = \"xtcp\""));
        assert!(toml.contains("secretKey = \"0123456789abcdef\""));
        assert!(!toml.contains("remotePort ="));
    }
}
