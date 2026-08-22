//! Versioned Desired State model, validation, and deterministic digest.

use std::{
    collections::BTreeSet,
    path::{Component, Path},
};

use sha2::{Digest, Sha256};

use super::{LocalAccessListener, TunnelVisitor};
use crate::{ConfigDigest, ConfigVersion};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TunnelMode {
    #[default]
    Disabled,
    PresenceOnly,
    Active,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    /// Secret-key protected TCP service; access is limited by signed device IDs.
    Stcp,
    /// Secret-key protected UDP service; access is limited by signed device IDs.
    Sudp,
    /// NAT-traversed protected proxy; requires signed `ProtectedAccess`.
    Xtcp,
    /// HTTP virtual-host proxy; the route's remote address is the assigned
    /// control-plane host name and is never treated as raw FRP configuration.
    Http,
    /// HTTPS virtual-host proxy with the same controlled host mapping.
    Https,
    /// TCP mux virtual-host proxy; requires an explicit signed host.
    TcpMux,
}

/// Control-plane-authorized access material for protected FRP services.
///
/// This value is signed with the Desired State and is deliberately narrower
/// than upstream configuration: callers cannot inject listeners or plugins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedAccess {
    pub secret: String,
    pub allowed_device_uids: Vec<String>,
    pub route_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunnelService {
    /// Stable control-plane identity used by telemetry and audit records.
    pub service_id: String,
    pub name: String,
    pub local_addr: String,
    pub protocol: TransportProtocol,
    /// Explicit HTTP(S) host supplied by the signed control-plane model.
    pub virtual_host: Option<String>,
    /// Required only by protected STCP/SUDP services.
    pub protected_access: Option<ProtectedAccess>,
}

/// A signed, deliberately narrow static-file backend for one TCP service.
///
/// It is not raw FRP plugin TOML: paths must be absolute, cannot traverse a
/// parent directory, and the plugin is bound to an existing signed service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticFilePlugin {
    pub service_id: String,
    pub local_path: String,
    pub strip_prefix: Option<String>,
}

/// Signed Unix-domain-socket backend for one plain TCP service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnixSocketPlugin {
    pub service_id: String,
    pub unix_path: String,
}

/// Signed HTTP or SOCKS5 forward-proxy backend for one plain TCP service.
/// Credentials are optional as a pair and are never accepted as raw plugin TOML.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForwardProxyPlugin {
    pub service_id: String,
    pub protocol: ForwardProxyProtocol,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardProxyProtocol {
    Http,
    Socks5,
}

/// Signed HTTP upstream protocol for a TCP service.
///
/// The backend address is the service's already-signed `local_addr`. This
/// intentionally excludes raw header rewrites and TLS/certificate options.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http2UpstreamPlugin {
    pub service_id: String,
    pub protocol: Http2UpstreamProtocol,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http2UpstreamProtocol {
    Http,
}

/// Signed HTTPS backend for one TCP service, terminated locally by Rustls.
///
/// `local_addr` remains the signed backend endpoint; `server_name` is the
/// required DNS identity verified against the fixed public-root trust store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsUpstreamPlugin {
    pub service_id: String,
    pub server_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunnelRoute {
    /// Stable control-plane identity used by telemetry and access grants.
    pub route_id: String,
    pub service: String,
    pub remote_addr: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TunnelPolicy {
    pub presence_interval_secs: u16,
    pub initial_backoff_secs: u16,
    pub max_backoff_secs: u16,
}
impl Default for TunnelPolicy {
    fn default() -> Self {
        Self {
            presence_interval_secs: 30,
            initial_backoff_secs: 1,
            max_backoff_secs: 30,
        }
    }
}

/// The signed control-plane configuration accepted by the local lifecycle.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TunnelDesiredState {
    pub version: ConfigVersion,
    pub mode: TunnelMode,
    pub services: Vec<TunnelService>,
    pub routes: Vec<TunnelRoute>,
    pub policy: TunnelPolicy,
    /// Signed protected-service access listeners, separate from publishing services.
    pub visitors: Vec<TunnelVisitor>,
    /// Signed loopback-only support listeners, never raw FRP plugins.
    pub local_access_listeners: Vec<LocalAccessListener>,
    /// Signed whitelist of the only upstream plugin currently admitted.
    pub static_file_plugins: Vec<StaticFilePlugin>,
    /// Signed whitelist of Unix-domain-socket upstreams.
    pub unix_socket_plugins: Vec<UnixSocketPlugin>,
    pub forward_proxy_plugins: Vec<ForwardProxyPlugin>,
    /// Signed HTTP upstream adapters with no raw TLS/plugin options.
    pub http2_upstream_plugins: Vec<Http2UpstreamPlugin>,
    /// Signed HTTPS upstream adapters with fixed Rustls trust semantics.
    pub https_upstream_plugins: Vec<HttpsUpstreamPlugin>,
}

impl TunnelDesiredState {
    pub fn disabled(version: u64) -> Self {
        Self {
            version: ConfigVersion(version),
            ..Self::default()
        }
    }
    pub fn presence_only(version: u64) -> Self {
        Self {
            version: ConfigVersion(version),
            mode: TunnelMode::PresenceOnly,
            ..Self::default()
        }
    }
    pub fn active(
        version: u64,
        services: Vec<TunnelService>,
        routes: Vec<TunnelRoute>,
        policy: TunnelPolicy,
    ) -> Self {
        Self {
            version: ConfigVersion(version),
            mode: TunnelMode::Active,
            services,
            routes,
            policy,
            visitors: Vec::new(),
            local_access_listeners: Vec::new(),
            static_file_plugins: Vec::new(),
            unix_socket_plugins: Vec::new(),
            forward_proxy_plugins: Vec::new(),
            http2_upstream_plugins: Vec::new(),
            https_upstream_plugins: Vec::new(),
        }
    }
    pub fn digest(&self) -> ConfigDigest {
        match self.digest_algorithm() {
            "sha256-v2" => self.v2_digest(),
            algorithm => ConfigDigest(self.canonical_digest_bytes(
                match algorithm {
                    "sha256-v3" => b"nexusflow-tunnel-desired-state-sha256-v3\0",
                    "sha256-v4" => b"nexusflow-tunnel-desired-state-sha256-v4\0",
                    "sha256-v5" => b"nexusflow-tunnel-desired-state-sha256-v5\0",
                    "sha256-v6" => b"nexusflow-tunnel-desired-state-sha256-v6\0",
                    "sha256-v7" => b"nexusflow-tunnel-desired-state-sha256-v7\0",
                    "sha256-v8" => b"nexusflow-tunnel-desired-state-sha256-v8\0",
                    "sha256-v9" => b"nexusflow-tunnel-desired-state-sha256-v9\0",
                    "sha256-v10" => b"nexusflow-tunnel-desired-state-sha256-v10\0",
                    "sha256-v11" => b"nexusflow-tunnel-desired-state-sha256-v11\0",
                    _ => unreachable!("TunnelDesiredState only emits known digest selectors"),
                },
                true,
            )),
        }
    }

    /// Canonical selector for the digest and signed envelope of this state.
    /// New issuers must use this instead of duplicating capability checks.
    pub fn digest_algorithm(&self) -> &'static str {
        if !self.https_upstream_plugins.is_empty() {
            "sha256-v11"
        } else if !self.http2_upstream_plugins.is_empty() {
            "sha256-v10"
        } else if !self.forward_proxy_plugins.is_empty()
            && (!self.static_file_plugins.is_empty() || !self.unix_socket_plugins.is_empty())
        {
            "sha256-v9"
        } else if !self.forward_proxy_plugins.is_empty() {
            "sha256-v8"
        } else if !self.static_file_plugins.is_empty() && !self.unix_socket_plugins.is_empty() {
            "sha256-v7"
        } else if !self.unix_socket_plugins.is_empty() {
            "sha256-v6"
        } else if !self.static_file_plugins.is_empty() {
            "sha256-v4"
        } else if self.has_xtcp_visitor() {
            "sha256-v5"
        } else if !self.visitors.is_empty() || !self.local_access_listeners.is_empty() {
            "sha256-v3"
        } else {
            "sha256-v2"
        }
    }

    fn has_xtcp_visitor(&self) -> bool {
        self.visitors
            .iter()
            .any(|visitor| matches!(visitor.protocol, super::VisitorProtocol::Xtcp))
    }

    /// The previous SHA-256 envelope digest, retained solely for V2 payload verification.
    pub fn v2_digest(&self) -> ConfigDigest {
        ConfigDigest(
            self.canonical_digest_bytes(b"nexusflow-tunnel-desired-state-sha256-v2\0", false),
        )
    }

    /// Compatibility digest for explicitly versioned V1 control-plane envelopes.
    /// New envelopes must use [`Self::digest`], never this collision-prone value.
    pub fn legacy_v1_digest(&self) -> u64 {
        let mut value = 0xcbf29ce484222325_u64;
        for byte in self.canonical_bytes(false) {
            value ^= u64::from(byte);
            value = value.wrapping_mul(0x100000001b3);
        }
        value
    }

    fn canonical_digest_bytes(&self, domain: &[u8], include_access: bool) -> [u8; 32] {
        Sha256::digest([domain, &self.canonical_bytes(include_access)].concat()).into()
    }

    fn canonical_bytes(&self, include_access: bool) -> Vec<u8> {
        let mut builder = CanonicalBuilder::default();
        builder.push_u64(self.version.0);
        builder.push_u8(self.mode as u8);
        builder.push_u16(self.policy.presence_interval_secs);
        builder.push_u16(self.policy.initial_backoff_secs);
        builder.push_u16(self.policy.max_backoff_secs);
        builder.push_u64(self.services.len() as u64);
        for service in &self.services {
            builder.push_str(&service.service_id);
            builder.push_str(&service.name);
            builder.push_str(&service.local_addr);
            builder.push_u8(service.protocol as u8);
            builder.push_str(service.virtual_host.as_deref().unwrap_or(""));
            match &service.protected_access {
                Some(access) => {
                    builder.push_u8(1);
                    builder.push_str(&access.secret);
                    builder.push_u64(access.allowed_device_uids.len() as u64);
                    for device_uid in &access.allowed_device_uids {
                        builder.push_str(device_uid);
                    }
                    builder.push_str(&access.route_id);
                }
                None => builder.push_u8(0),
            }
        }
        builder.push_u64(self.routes.len() as u64);
        for route in &self.routes {
            builder.push_str(&route.route_id);
            builder.push_str(&route.service);
            builder.push_str(&route.remote_addr);
        }
        if include_access {
            builder.push_u64(self.visitors.len() as u64);
            for visitor in &self.visitors {
                builder.push_str(&visitor.visitor_id);
                builder.push_u8(visitor.protocol as u8);
                builder.push_str(&visitor.service_id);
                builder.push_str(&visitor.server_device_uid);
                builder.push_str(&visitor.visitor_device_uid);
                builder.push_str(&visitor.secret);
                builder.push_str(&visitor.bind.to_string());
                builder.push_u16(visitor.max_connections);
                builder.push_str(visitor.grant_id.as_deref().unwrap_or(""));
            }
            builder.push_u64(self.local_access_listeners.len() as u64);
            for listener in &self.local_access_listeners {
                builder.push_str(&listener.listener_id);
                builder.push_u8(listener.protocol as u8);
                builder.push_str(&listener.bind.to_string());
                builder.push_u64(listener.allowed_targets.len() as u64);
                for target in &listener.allowed_targets {
                    builder.push_str(&target.to_string());
                }
                builder.push_u16(listener.max_connections);
            }
            if !self.static_file_plugins.is_empty() {
                builder.push_u64(self.static_file_plugins.len() as u64);
                for plugin in &self.static_file_plugins {
                    builder.push_str(&plugin.service_id);
                    builder.push_str(&plugin.local_path);
                    builder.push_str(plugin.strip_prefix.as_deref().unwrap_or(""));
                }
            }
            if !self.unix_socket_plugins.is_empty() {
                builder.push_u64(self.unix_socket_plugins.len() as u64);
                for plugin in &self.unix_socket_plugins {
                    builder.push_str(&plugin.service_id);
                    builder.push_str(&plugin.unix_path);
                }
            }
            if !self.forward_proxy_plugins.is_empty() {
                builder.push_u64(self.forward_proxy_plugins.len() as u64);
                for plugin in &self.forward_proxy_plugins {
                    builder.push_str(&plugin.service_id);
                    builder.push_u8(match plugin.protocol {
                        ForwardProxyProtocol::Http => 0,
                        ForwardProxyProtocol::Socks5 => 1,
                    });
                    builder.push_str(plugin.username.as_deref().unwrap_or(""));
                    builder.push_str(plugin.password.as_deref().unwrap_or(""));
                }
            }
            if !self.http2_upstream_plugins.is_empty() {
                builder.push_u64(self.http2_upstream_plugins.len() as u64);
                for plugin in &self.http2_upstream_plugins {
                    builder.push_str(&plugin.service_id);
                    builder.push_u8(match plugin.protocol {
                        Http2UpstreamProtocol::Http => 0,
                    });
                }
            }
            if !self.https_upstream_plugins.is_empty() {
                builder.push_u64(self.https_upstream_plugins.len() as u64);
                for plugin in &self.https_upstream_plugins {
                    builder.push_str(&plugin.service_id);
                    builder.push_str(&plugin.server_name);
                }
            }
        }
        builder.0
    }
    /// Rejects malformed and ambiguous business identities before lifecycle state changes.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.policy.presence_interval_secs == 0 {
            return Err(ConfigError::InvalidPolicy(
                "presence interval must be positive",
            ));
        }
        if self.policy.initial_backoff_secs == 0 {
            return Err(ConfigError::InvalidPolicy(
                "initial backoff must be positive",
            ));
        }
        if self.policy.initial_backoff_secs > self.policy.max_backoff_secs {
            return Err(ConfigError::InvalidPolicy(
                "initial backoff must not exceed max backoff",
            ));
        }
        let mut names = BTreeSet::new();
        let mut service_ids = BTreeSet::new();
        for service in &self.services {
            if service.service_id.trim().is_empty() {
                return Err(ConfigError::EmptyServiceId);
            }
            if !service_ids.insert(service.service_id.as_str()) {
                return Err(ConfigError::DuplicateServiceId(service.service_id.clone()));
            }
            if service.name.trim().is_empty() {
                return Err(ConfigError::EmptyServiceName);
            }
            if service.local_addr.trim().is_empty() {
                return Err(ConfigError::EmptyLocalAddress(service.name.clone()));
            }
            match service.protocol {
                TransportProtocol::Http | TransportProtocol::Https | TransportProtocol::TcpMux
                    if !is_valid_dns_name(service.virtual_host.as_deref().unwrap_or("")) =>
                {
                    return Err(ConfigError::InvalidVirtualHost(service.name.clone()));
                }
                TransportProtocol::Tcp | TransportProtocol::Udp
                    if service.virtual_host.is_some() =>
                {
                    return Err(ConfigError::UnexpectedVirtualHost(service.name.clone()));
                }
                _ => {}
            }
            match service.protocol {
                TransportProtocol::Stcp | TransportProtocol::Sudp | TransportProtocol::Xtcp => {
                    let access = service
                        .protected_access
                        .as_ref()
                        .ok_or_else(|| ConfigError::MissingProtectedAccess(service.name.clone()))?;
                    if access.secret.len() < 16 || access.allowed_device_uids.is_empty() {
                        return Err(ConfigError::InvalidProtectedAccess(service.name.clone()));
                    }
                    if access.route_id.trim().is_empty() {
                        return Err(ConfigError::InvalidProtectedAccess(service.name.clone()));
                    }
                    let mut devices = BTreeSet::new();
                    if access.allowed_device_uids.iter().any(|device_uid| {
                        device_uid.trim().is_empty() || !devices.insert(device_uid.as_str())
                    }) {
                        return Err(ConfigError::InvalidProtectedAccess(service.name.clone()));
                    }
                }
                _ if service.protected_access.is_some() => {
                    return Err(ConfigError::UnexpectedProtectedAccess(service.name.clone()));
                }
                _ => {}
            }
            if !names.insert(service.name.as_str()) {
                return Err(ConfigError::DuplicateServiceName(service.name.clone()));
            }
        }
        let mut route_ids = BTreeSet::new();
        for route in &self.routes {
            if route.route_id.trim().is_empty() {
                return Err(ConfigError::EmptyRouteId);
            }
            if !route_ids.insert(route.route_id.as_str()) {
                return Err(ConfigError::DuplicateRouteId(route.route_id.clone()));
            }
            if route.remote_addr.trim().is_empty() {
                return Err(ConfigError::EmptyRemoteAddress(route.service.clone()));
            }
            if !names.contains(route.service.as_str()) {
                return Err(ConfigError::UnknownRouteService(route.service.clone()));
            }
        }
        for service in &self.services {
            if let Some(access) = &service.protected_access {
                if !self
                    .routes
                    .iter()
                    .any(|route| route.route_id == access.route_id && route.service == service.name)
                {
                    return Err(ConfigError::InvalidProtectedAccess(service.name.clone()));
                }
            }
        }
        let mut visitor_ids = BTreeSet::new();
        for visitor in &self.visitors {
            visitor
                .validate()
                .map_err(|_| ConfigError::InvalidVisitor(visitor.visitor_id.clone()))?;
            if !visitor_ids.insert(visitor.visitor_id.as_str()) {
                return Err(ConfigError::DuplicateVisitorId(visitor.visitor_id.clone()));
            }
            let service = self
                .services
                .iter()
                .find(|service| service.service_id == visitor.service_id)
                .ok_or_else(|| ConfigError::InvalidVisitor(visitor.visitor_id.clone()))?;
            let access = service
                .protected_access
                .as_ref()
                .filter(|_| {
                    matches!(
                        service.protocol,
                        TransportProtocol::Stcp | TransportProtocol::Sudp | TransportProtocol::Xtcp
                    )
                })
                .ok_or_else(|| ConfigError::InvalidVisitor(visitor.visitor_id.clone()))?;
            let protocol_matches = matches!(
                (service.protocol, visitor.protocol),
                (TransportProtocol::Stcp, super::VisitorProtocol::Stcp)
                    | (TransportProtocol::Sudp, super::VisitorProtocol::Sudp)
                    | (TransportProtocol::Xtcp, super::VisitorProtocol::Xtcp)
            );
            if !access
                .allowed_device_uids
                .iter()
                .any(|device| device == &visitor.visitor_device_uid)
                || visitor.secret != access.secret
                || !protocol_matches
            {
                return Err(ConfigError::InvalidVisitor(visitor.visitor_id.clone()));
            }
        }
        let mut listener_ids = BTreeSet::new();
        for listener in &self.local_access_listeners {
            listener
                .validate()
                .map_err(|_| ConfigError::InvalidLocalAccess(listener.listener_id.clone()))?;
            if !listener_ids.insert(listener.listener_id.as_str()) {
                return Err(ConfigError::DuplicateLocalAccessId(
                    listener.listener_id.clone(),
                ));
            }
        }
        let mut plugin_services = BTreeSet::new();
        for plugin in &self.static_file_plugins {
            let path = Path::new(&plugin.local_path);
            let windows_absolute = plugin.local_path.as_bytes().get(1) == Some(&b':')
                && plugin
                    .local_path
                    .as_bytes()
                    .get(2)
                    .is_some_and(|separator| *separator == b'/' || *separator == b'\\');
            if plugin.service_id.trim().is_empty()
                || !plugin_services.insert(plugin.service_id.as_str())
                || (!path.is_absolute() && !windows_absolute)
                || path
                    .components()
                    .any(|component| matches!(component, Component::ParentDir))
                || plugin.strip_prefix.as_deref().is_some_and(|prefix| {
                    prefix.is_empty()
                        || prefix.starts_with('/')
                        || prefix.contains(['\\', '?', '#'])
                        || prefix
                            .split('/')
                            .any(|part| part.is_empty() || part == "." || part == "..")
                })
                || !self.services.iter().any(|service| {
                    service.service_id == plugin.service_id
                        && service.protocol == TransportProtocol::Tcp
                        && service.protected_access.is_none()
                })
            {
                return Err(ConfigError::InvalidStaticFilePlugin(
                    plugin.service_id.clone(),
                ));
            }
        }
        for plugin in &self.unix_socket_plugins {
            if plugin.service_id.trim().is_empty()
                || !plugin_services.insert(plugin.service_id.as_str())
                // Unix paths must keep Unix semantics even when a signed state
                // is validated on a Windows control-plane development host.
                || !plugin.unix_path.starts_with('/')
                || plugin.unix_path.split('/').any(|part| part == "..")
                || plugin.unix_path.contains(['\\', '\r', '\n', '"'])
                || !self.services.iter().any(|service| {
                    service.service_id == plugin.service_id
                        && service.protocol == TransportProtocol::Tcp
                        && service.protected_access.is_none()
                })
            {
                return Err(ConfigError::InvalidUnixSocketPlugin(
                    plugin.service_id.clone(),
                ));
            }
        }
        for plugin in &self.forward_proxy_plugins {
            let credentials_valid = match (&plugin.username, &plugin.password) {
                (None, None) => true,
                (Some(username), Some(password)) => {
                    !username.trim().is_empty()
                        && !password.is_empty()
                        && !username.contains(['\r', '\n', '"', '\\'])
                        && !password.contains(['\r', '\n', '"', '\\'])
                }
                _ => false,
            };
            if plugin.service_id.trim().is_empty()
                || !plugin_services.insert(plugin.service_id.as_str())
                || !credentials_valid
                || !self.services.iter().any(|service| {
                    service.service_id == plugin.service_id
                        && service.protocol == TransportProtocol::Tcp
                        && service.protected_access.is_none()
                })
            {
                return Err(ConfigError::InvalidForwardProxyPlugin(
                    plugin.service_id.clone(),
                ));
            }
        }
        for plugin in &self.http2_upstream_plugins {
            if plugin.service_id.trim().is_empty()
                || !plugin_services.insert(plugin.service_id.as_str())
                || !self.services.iter().any(|service| {
                    service.service_id == plugin.service_id
                        && service.protocol == TransportProtocol::Tcp
                        && service.protected_access.is_none()
                })
            {
                return Err(ConfigError::InvalidHttp2UpstreamPlugin(
                    plugin.service_id.clone(),
                ));
            }
        }
        for plugin in &self.https_upstream_plugins {
            if plugin.service_id.trim().is_empty()
                || !plugin_services.insert(plugin.service_id.as_str())
                || !is_valid_dns_name(&plugin.server_name)
                || !self.services.iter().any(|service| {
                    service.service_id == plugin.service_id
                        && service.protocol == TransportProtocol::Tcp
                        && service.protected_access.is_none()
                })
            {
                return Err(ConfigError::InvalidHttpsUpstreamPlugin(
                    plugin.service_id.clone(),
                ));
            }
        }
        match self.mode {
            TunnelMode::Disabled | TunnelMode::PresenceOnly
                if !self.services.is_empty()
                    || !self.routes.is_empty()
                    || !self.visitors.is_empty()
                    || !self.local_access_listeners.is_empty()
                    || !self.static_file_plugins.is_empty()
                    || !self.unix_socket_plugins.is_empty()
                    || !self.forward_proxy_plugins.is_empty()
                    || !self.http2_upstream_plugins.is_empty()
                    || !self.https_upstream_plugins.is_empty() =>
            {
                Err(ConfigError::UnexpectedRoutesForPassiveMode)
            }
            TunnelMode::Active if self.services.is_empty() => Err(ConfigError::MissingServices),
            TunnelMode::Active if self.routes.is_empty() => Err(ConfigError::MissingRoutes),
            _ => Ok(()),
        }
    }
}

/// Validates a signed DNS name used by virtual hosts and TLS SNI.
pub fn is_valid_dns_name(host: &str) -> bool {
    let host = host.trim();
    !host.is_empty()
        && host.len() <= 253
        && host.is_ascii()
        && !host.contains(['/', ':', ' ', '\\'])
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigError {
    EmptyServiceId,
    DuplicateServiceId(String),
    EmptyServiceName,
    EmptyLocalAddress(String),
    EmptyRemoteAddress(String),
    EmptyRouteId,
    DuplicateRouteId(String),
    DuplicateServiceName(String),
    UnknownRouteService(String),
    MissingServices,
    MissingRoutes,
    UnexpectedRoutesForPassiveMode,
    InvalidPolicy(&'static str),
    InvalidVirtualHost(String),
    UnexpectedVirtualHost(String),
    MissingProtectedAccess(String),
    InvalidProtectedAccess(String),
    UnexpectedProtectedAccess(String),
    InvalidVisitor(String),
    DuplicateVisitorId(String),
    InvalidLocalAccess(String),
    DuplicateLocalAccessId(String),
    InvalidStaticFilePlugin(String),
    InvalidUnixSocketPlugin(String),
    InvalidForwardProxyPlugin(String),
    InvalidHttp2UpstreamPlugin(String),
    InvalidHttpsUpstreamPlugin(String),
}

#[derive(Default)]
struct CanonicalBuilder(Vec<u8>);
impl CanonicalBuilder {
    fn push_u8(&mut self, value: u8) {
        self.push_bytes(&[value]);
    }
    fn push_u16(&mut self, value: u16) {
        self.push_bytes(&value.to_le_bytes());
    }
    fn push_u64(&mut self, value: u64) {
        self.push_bytes(&value.to_le_bytes());
    }
    fn push_str(&mut self, value: &str) {
        self.push_u64(value.len() as u64);
        self.push_bytes(value.as_bytes());
    }
    fn push_bytes(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::{LocalAccessProtocol, VisitorProtocol, XtcpNatProtocol};

    pub(crate) fn active_state(version: u64) -> TunnelDesiredState {
        TunnelDesiredState::active(
            version,
            vec![TunnelService {
                service_id: "service-rdp".into(),
                name: "rdp".into(),
                local_addr: "127.0.0.1:3389".into(),
                protocol: TransportProtocol::Tcp,
                virtual_host: None,
                protected_access: None,
            }],
            vec![TunnelRoute {
                route_id: "route-rdp".into(),
                service: "rdp".into(),
                remote_addr: "edge://tenant-a/rdp".into(),
            }],
            TunnelPolicy::default(),
        )
    }

    #[test]
    fn validates_route_references() {
        let error = TunnelDesiredState::active(
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
                service: "rdp".into(),
                remote_addr: "edge://tenant-a/ssh".into(),
            }],
            TunnelPolicy::default(),
        )
        .validate()
        .unwrap_err();
        assert_eq!(error, ConfigError::UnknownRouteService("rdp".into()));
    }

    #[test]
    fn digest_is_stable_for_equal_configs() {
        let left = active_state(8).digest();
        let right = active_state(8).digest();
        assert_eq!(left, right);
        assert_ne!(left, ConfigDigest::default());
    }

    #[test]
    fn digest_selector_covers_each_published_capability_version() {
        let mut state = active_state(1);
        assert_eq!(state.digest_algorithm(), "sha256-v2");

        state.local_access_listeners.push(LocalAccessListener {
            listener_id: "local".into(),
            protocol: LocalAccessProtocol::Socks5,
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_targets: vec!["127.0.0.1:3389".parse().unwrap()],
            max_connections: 1,
        });
        assert_eq!(state.digest_algorithm(), "sha256-v3");

        state.static_file_plugins.push(StaticFilePlugin {
            service_id: "service-rdp".into(),
            local_path: if cfg!(windows) {
                "C:/nexus-static".into()
            } else {
                "/var/lib/nexus-static".into()
            },
            strip_prefix: None,
        });
        assert_eq!(state.digest_algorithm(), "sha256-v4");

        state.static_file_plugins.clear();
        state.visitors.push(TunnelVisitor {
            visitor_id: "visitor".into(),
            protocol: VisitorProtocol::Xtcp,
            xtcp_nat_protocol: Some(XtcpNatProtocol::Quic),
            service_id: "service-rdp".into(),
            server_device_uid: "server".into(),
            visitor_device_uid: "visitor".into(),
            secret: "0123456789abcdef".into(),
            bind: "127.0.0.1:0".parse().unwrap(),
            max_connections: 1,
            grant_id: None,
        });
        assert_eq!(state.digest_algorithm(), "sha256-v5");

        state.visitors.clear();
        state.unix_socket_plugins.push(UnixSocketPlugin {
            service_id: "service-rdp".into(),
            unix_path: "/run/nexus.sock".into(),
        });
        assert_eq!(state.digest_algorithm(), "sha256-v6");

        state.static_file_plugins.push(StaticFilePlugin {
            service_id: "service-rdp".into(),
            local_path: "/var/lib/nexus-static".into(),
            strip_prefix: None,
        });
        assert_eq!(state.digest_algorithm(), "sha256-v7");

        state.static_file_plugins.clear();
        state.unix_socket_plugins.clear();
        state.forward_proxy_plugins.push(ForwardProxyPlugin {
            service_id: "service-rdp".into(),
            protocol: ForwardProxyProtocol::Http,
            username: None,
            password: None,
        });
        assert_eq!(state.digest_algorithm(), "sha256-v8");

        state.static_file_plugins.push(StaticFilePlugin {
            service_id: "service-rdp".into(),
            local_path: "/var/lib/nexus-static".into(),
            strip_prefix: None,
        });
        assert_eq!(state.digest_algorithm(), "sha256-v9");

        state.http2_upstream_plugins.push(Http2UpstreamPlugin {
            service_id: "service-rdp".into(),
            protocol: Http2UpstreamProtocol::Http,
        });
        assert_eq!(state.digest_algorithm(), "sha256-v10");

        state.https_upstream_plugins.push(HttpsUpstreamPlugin {
            service_id: "service-rdp".into(),
            server_name: "backend.example.test".into(),
        });
        assert_eq!(state.digest_algorithm(), "sha256-v11");
    }

    #[test]
    fn stable_service_and_route_ids_are_required_and_signed_into_the_digest() {
        let mut state = active_state(1);
        let digest = state.digest();
        state.services[0].service_id.clear();
        assert_eq!(state.validate(), Err(ConfigError::EmptyServiceId));
        state.services[0].service_id = "service-other".into();
        assert_ne!(state.digest(), digest);
        state.routes[0].route_id.clear();
        assert_eq!(state.validate(), Err(ConfigError::EmptyRouteId));
    }

    #[test]
    fn virtual_hosts_are_signed_and_reserved_for_http_proxies() {
        let mut desired = active_state(1);
        desired.services[0].protocol = TransportProtocol::Http;
        assert_eq!(
            desired.validate(),
            Err(ConfigError::InvalidVirtualHost("rdp".into()))
        );
        desired.services[0].virtual_host = Some("rdp.example.test".into());
        let digest = desired.digest();
        desired.services[0].virtual_host = Some("other.example.test".into());
        assert_ne!(digest, desired.digest());

        let mut tcp = active_state(1);
        tcp.services[0].virtual_host = Some("rdp.example.test".into());
        assert_eq!(
            tcp.validate(),
            Err(ConfigError::UnexpectedVirtualHost("rdp".into()))
        );
    }

    #[test]
    fn protected_access_is_required_signed_and_rejected_for_plain_protocols() {
        let mut state = active_state(1);
        state.services[0].protocol = TransportProtocol::Stcp;
        assert_eq!(
            state.validate(),
            Err(ConfigError::MissingProtectedAccess("rdp".into()))
        );
        state.services[0].protected_access = Some(ProtectedAccess {
            secret: "0123456789abcdef".into(),
            allowed_device_uids: vec!["visitor-device".into()],
            route_id: "route-rdp".into(),
        });
        assert!(state.validate().is_ok());
        let digest = state.digest();
        state.services[0]
            .protected_access
            .as_mut()
            .unwrap()
            .secret
            .push('x');
        assert_ne!(digest, state.digest());
        state.services[0].protocol = TransportProtocol::Tcp;
        assert_eq!(
            state.validate(),
            Err(ConfigError::UnexpectedProtectedAccess("rdp".into()))
        );
    }

    #[test]
    fn access_listeners_are_signed_and_bound_to_the_protected_service_grant() {
        let mut state = active_state(1);
        state.services[0].protocol = TransportProtocol::Stcp;
        state.services[0].protected_access = Some(ProtectedAccess {
            secret: "0123456789abcdef".into(),
            allowed_device_uids: vec!["visitor-device".into()],
            route_id: "route-rdp".into(),
        });
        state.visitors.push(TunnelVisitor {
            visitor_id: "visitor-rdp".into(),
            protocol: VisitorProtocol::Stcp,
            xtcp_nat_protocol: None,
            service_id: "service-rdp".into(),
            server_device_uid: "device-publisher".into(),
            visitor_device_uid: "visitor-device".into(),
            secret: "0123456789abcdef".into(),
            bind: "127.0.0.1:19000".parse().unwrap(),
            max_connections: 1,
            grant_id: None,
        });
        state.local_access_listeners.push(LocalAccessListener {
            listener_id: "support".into(),
            protocol: LocalAccessProtocol::Socks5,
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_targets: vec!["127.0.0.1:3389".parse().unwrap()],
            max_connections: 1,
        });
        assert!(state.validate().is_ok());
        let digest = state.digest();
        state.local_access_listeners[0].allowed_targets[0] = "127.0.0.1:3390".parse().unwrap();
        assert_ne!(digest, state.digest());
        state.visitors[0].visitor_device_uid = "ungranted-device".into();
        assert_eq!(
            state.validate(),
            Err(ConfigError::InvalidVisitor("visitor-rdp".into()))
        );
        state.visitors[0].visitor_device_uid = "visitor-device".into();
        state.visitors[0].secret.push('x');
        assert_eq!(
            state.validate(),
            Err(ConfigError::InvalidVisitor("visitor-rdp".into()))
        );
    }

    #[test]
    fn static_file_plugins_are_signed_and_cannot_escape_the_service_boundary() {
        let mut state = active_state(1);
        state.static_file_plugins.push(StaticFilePlugin {
            service_id: "service-rdp".into(),
            local_path: "C:/nexus-static".into(),
            strip_prefix: Some("support".into()),
        });
        assert!(state.validate().is_ok());
        let digest = state.digest();
        state.static_file_plugins[0].local_path = "C:/nexus-other".into();
        assert_ne!(digest, state.digest());
        state.static_file_plugins[0].local_path = "../escape".into();
        assert!(matches!(
            state.validate(),
            Err(ConfigError::InvalidStaticFilePlugin(_))
        ));
    }

    #[test]
    fn unix_socket_plugins_are_signed_and_reject_traversal_or_wrong_services() {
        let mut state = active_state(1);
        state.unix_socket_plugins.push(UnixSocketPlugin {
            service_id: "service-rdp".into(),
            unix_path: "/run/nexus/backend.sock".into(),
        });
        assert!(state.validate().is_ok());
        let digest = state.digest();
        state.unix_socket_plugins[0].unix_path = "/run/../secret.sock".into();
        assert_eq!(
            state.validate(),
            Err(ConfigError::InvalidUnixSocketPlugin("service-rdp".into()))
        );
        state.unix_socket_plugins[0].unix_path = "/run/nexus/other.sock".into();
        assert_ne!(digest, state.digest());
        state.static_file_plugins.push(StaticFilePlugin {
            service_id: "service-rdp".into(),
            local_path: "C:/nexus-static".into(),
            strip_prefix: None,
        });
        assert!(matches!(
            state.validate(),
            Err(ConfigError::InvalidStaticFilePlugin(_))
                | Err(ConfigError::InvalidUnixSocketPlugin(_))
        ));
    }

    #[test]
    fn http2_upstream_plugins_are_signed_and_bound_to_plain_tcp_services() {
        let mut state = active_state(1);
        state.http2_upstream_plugins.push(Http2UpstreamPlugin {
            service_id: "service-rdp".into(),
            protocol: Http2UpstreamProtocol::Http,
        });
        assert!(state.validate().is_ok());
        let digest = state.digest();
        state.http2_upstream_plugins[0].service_id = "service-rdp-copy".into();
        assert_ne!(digest, state.digest());
        state.http2_upstream_plugins[0].service_id = "missing-service".into();
        assert_eq!(
            state.validate(),
            Err(ConfigError::InvalidHttp2UpstreamPlugin(
                "missing-service".into()
            ))
        );
    }

    #[test]
    fn https_upstream_plugins_bind_a_plain_tcp_service_and_server_name() {
        let mut state = active_state(1);
        state.https_upstream_plugins.push(HttpsUpstreamPlugin {
            service_id: "service-rdp".into(),
            server_name: "backend.example.test".into(),
        });
        assert!(state.validate().is_ok());
        let digest = state.digest();
        state.https_upstream_plugins[0].server_name = "other.example.test".into();
        assert_ne!(digest, state.digest());
        state.https_upstream_plugins[0].server_name = "bad_name".into();
        assert_eq!(
            state.validate(),
            Err(ConfigError::InvalidHttpsUpstreamPlugin(
                "service-rdp".into()
            ))
        );
    }

    #[test]
    fn stable_telemetry_ids_cannot_be_reused_within_a_state() {
        let mut state = active_state(1);
        state.services.push(state.services[0].clone());
        state.services[1].name = "rdp-copy".into();
        assert_eq!(
            state.validate(),
            Err(ConfigError::DuplicateServiceId("service-rdp".into()))
        );
        let mut state = active_state(1);
        state.routes.push(state.routes[0].clone());
        assert_eq!(
            state.validate(),
            Err(ConfigError::DuplicateRouteId("route-rdp".into()))
        );
    }

    #[test]
    fn passive_modes_reject_service_payloads() {
        let error = TunnelDesiredState {
            version: ConfigVersion(9),
            mode: TunnelMode::PresenceOnly,
            services: vec![TunnelService {
                service_id: "service-ssh".into(),
                name: "ssh".into(),
                local_addr: "127.0.0.1:22".into(),
                protocol: TransportProtocol::Tcp,
                virtual_host: None,
                protected_access: None,
            }],
            routes: Vec::new(),
            policy: TunnelPolicy::default(),
            visitors: Vec::new(),
            local_access_listeners: Vec::new(),
            static_file_plugins: Vec::new(),
            unix_socket_plugins: Vec::new(),
            forward_proxy_plugins: Vec::new(),
            http2_upstream_plugins: Vec::new(),
            https_upstream_plugins: Vec::new(),
        }
        .validate()
        .unwrap_err();
        assert_eq!(error, ConfigError::UnexpectedRoutesForPassiveMode);
    }
}
