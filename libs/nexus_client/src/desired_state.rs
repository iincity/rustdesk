//! Untrusted control-plane Desired State parsing and signature-envelope checks.
//!
//! This crate owns no device private key. The RustDesk adapter supplies the
//! public-key verification operation after it has fetched the named key.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::tunnel::{
    ConfigVersion, ForwardProxyPlugin, ForwardProxyProtocol, Http2UpstreamPlugin,
    Http2UpstreamProtocol, HttpsUpstreamPlugin, LocalAccessListener, LocalAccessProtocol,
    OidcRelayCredentials, ProtectedAccess, RelayAssignment, StaticFilePlugin, TransportProtocol,
    TunnelDataPlaneAssignment, TunnelDesiredState, TunnelMode, TunnelPolicy, TunnelRoute,
    TunnelService, TunnelVisitor, UnixSocketPlugin, VisitorProtocol, XtcpNatProtocol,
};

/// A Desired State accepted at the network boundary, together with its signed
/// relay assignment. The assignment stays outside the core business model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDesiredState {
    pub desired_state: TunnelDesiredState,
    pub data_plane_assignment: Option<TunnelDataPlaneAssignment>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DesiredStateError {
    InvalidPayload,
    DeviceMismatch,
    OutsideValidityWindow,
    InvalidState,
    DigestMismatch,
    InvalidSignature,
}

impl std::fmt::Display for DesiredStateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPayload => "invalid payload",
            Self::DeviceMismatch => "device binding mismatch",
            Self::OutsideValidityWindow => "outside validity window",
            Self::InvalidState => "invalid state",
            Self::DigestMismatch => "digest mismatch",
            Self::InvalidSignature => "invalid signature",
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DesiredStateWire {
    owner_account_id: String,
    device_uid: String,
    key_id: String,
    version: u64,
    #[serde(default)]
    digest_algorithm: Option<String>,
    digest_hex: String,
    not_before: i64,
    expires_at: i64,
    #[serde(default)]
    rollback_of_version: Option<u64>,
    signature_hex: String,
    /// Issuance metadata emitted alongside the signed envelope. Validity is
    /// governed by `not_before`/`expires_at`, so the host does not apply it.
    #[serde(default, rename = "issuedAt")]
    _issued_at: i64,
    mode: DesiredStateModeWire,
    services: Vec<TunnelServiceWire>,
    routes: Vec<TunnelRouteWire>,
    policy: TunnelPolicyWire,
    #[serde(default)]
    data_plane_assignment: Option<TunnelAssignmentWire>,
    #[serde(default)]
    visitors: Vec<TunnelVisitorWire>,
    #[serde(default)]
    local_access_listeners: Vec<LocalAccessListenerWire>,
    /// The only admitted upstream plugin model. Raw FRP plugin options remain
    /// rejected at this network boundary.
    #[serde(default)]
    static_file_plugins: Vec<StaticFilePluginWire>,
    #[serde(default)]
    unix_socket_plugins: Vec<UnixSocketPluginWire>,
    #[serde(default)]
    forward_proxy_plugins: Vec<ForwardProxyPluginWire>,
    #[serde(default)]
    http2_upstream_plugins: Vec<Http2UpstreamPluginWire>,
    #[serde(default)]
    https_upstream_plugins: Vec<HttpsUpstreamPluginWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigningKeyIdWire {
    key_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TunnelServiceWire {
    service_id: String,
    name: String,
    local_addr: String,
    protocol: ProtocolWire,
    #[serde(default)]
    virtual_host: Option<String>,
    #[serde(default)]
    protected_access: Option<ProtectedAccessWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProtectedAccessWire {
    secret: String,
    allowed_device_uids: Vec<String>,
    route_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TunnelVisitorWire {
    visitor_id: String,
    protocol: VisitorProtocolWire,
    #[serde(default)]
    xtcp_nat_protocol: Option<XtcpNatProtocolWire>,
    service_id: String,
    server_device_uid: String,
    visitor_device_uid: String,
    secret: String,
    bind: std::net::SocketAddr,
    max_connections: u16,
    /// Opaque control-plane capability; never serialized into FRP options.
    #[serde(default)]
    grant_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum VisitorProtocolWire {
    Stcp,
    Sudp,
    Xtcp,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum XtcpNatProtocolWire {
    Kcp,
    Quic,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalAccessListenerWire {
    listener_id: String,
    protocol: LocalAccessProtocolWire,
    bind: std::net::SocketAddr,
    allowed_targets: Vec<std::net::SocketAddr>,
    max_connections: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StaticFilePluginWire {
    service_id: String,
    local_path: String,
    #[serde(default)]
    strip_prefix: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnixSocketPluginWire {
    service_id: String,
    unix_path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ForwardProxyPluginWire {
    service_id: String,
    protocol: ForwardProxyProtocolWire,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ForwardProxyProtocolWire {
    Http,
    Socks5,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Http2UpstreamPluginWire {
    service_id: String,
    protocol: Http2UpstreamProtocolWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Http2UpstreamProtocolWire {
    Http,
}

/// Wire form intentionally has no certificate, root, or TLS-option escape hatch.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HttpsUpstreamPluginWire {
    service_id: String,
    server_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum LocalAccessProtocolWire {
    Socks5,
    HttpConnect,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TunnelRouteWire {
    route_id: String,
    service: String,
    remote_addr: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TunnelPolicyWire {
    presence_interval_secs: u16,
    initial_backoff_secs: u16,
    max_backoff_secs: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum DesiredStateModeWire {
    Disabled,
    #[serde(alias = "presenceonly")]
    PresenceOnly,
    Active,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ProtocolWire {
    Tcp,
    Udp,
    Stcp,
    Sudp,
    Http,
    Https,
    TcpMux,
    Xtcp,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TunnelAssignmentWire {
    relay: RelayWire,
    remote_ports: Vec<RemotePortWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RelayWire {
    address: String,
    port: u16,
    client_id: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    oidc: Option<OidcRelayWire>,
    expires_at: u64,
}

/// The wire form intentionally omits upstream CA, proxy, token-source, and
/// TLS-bypass switches. The control plane signs short-lived credentials only.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OidcRelayWire {
    client_id: String,
    client_secret: String,
    token_endpoint_url: String,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RemotePortWire {
    remote_addr: String,
    port: u16,
}

/// Reads only the key selector needed to retrieve the corresponding trusted
/// public key. It deliberately does not validate or apply the state.
pub fn signing_key_id(payload: &str) -> Result<String, DesiredStateError> {
    let wire: SigningKeyIdWire =
        serde_json::from_str(payload).map_err(|_| DesiredStateError::InvalidPayload)?;
    (!wire.key_id.trim().is_empty())
        .then_some(wire.key_id)
        .ok_or(DesiredStateError::InvalidPayload)
}

/// Parses a complete Desired State only after the caller has selected the
/// public key by `key_id`. `verify` receives canonical bytes and prevents this
/// library from receiving RustDesk private-key material.
pub fn parse_and_verify_desired_state(
    payload: &str,
    expected_device_uid: &str,
    now: i64,
    verify: impl FnOnce(&str, &[u8], &[u8; 64]) -> bool,
) -> Result<VerifiedDesiredState, DesiredStateError> {
    let wire: DesiredStateWire =
        serde_json::from_str(payload).map_err(|_| DesiredStateError::InvalidPayload)?;
    if wire.device_uid != expected_device_uid {
        return Err(DesiredStateError::DeviceMismatch);
    }
    if wire.not_before > now || wire.expires_at <= now {
        return Err(DesiredStateError::OutsideValidityWindow);
    }
    let signature: [u8; 64] = hex::decode(&wire.signature_hex)
        .map_err(|_| DesiredStateError::InvalidSignature)?
        .try_into()
        .map_err(|_| DesiredStateError::InvalidSignature)?;
    if !verify(&wire.key_id, &wire.canonical_payload(), &signature) {
        return Err(DesiredStateError::InvalidSignature);
    }
    let desired_state = wire.to_desired_state()?;
    let data_plane_assignment = wire.to_assignment();
    // An Active state without its signed Relay assignment could only leave the
    // host in Activating indefinitely. Reject it before it reaches the
    // lifecycle runtime rather than guessing a Relay or accepting raw FRP.
    if desired_state.mode == TunnelMode::Active && data_plane_assignment.is_none() {
        return Err(DesiredStateError::InvalidState);
    }
    Ok(VerifiedDesiredState {
        desired_state,
        data_plane_assignment,
    })
}

impl DesiredStateWire {
    fn to_desired_state(&self) -> Result<TunnelDesiredState, DesiredStateError> {
        let desired_state = TunnelDesiredState {
            version: ConfigVersion(self.version),
            mode: match self.mode {
                DesiredStateModeWire::Disabled => TunnelMode::Disabled,
                DesiredStateModeWire::PresenceOnly => TunnelMode::PresenceOnly,
                DesiredStateModeWire::Active => TunnelMode::Active,
            },
            services: self
                .services
                .iter()
                .map(|service| TunnelService {
                    service_id: service.service_id.clone(),
                    name: service.name.clone(),
                    local_addr: service.local_addr.clone(),
                    protocol: match service.protocol {
                        ProtocolWire::Tcp => TransportProtocol::Tcp,
                        ProtocolWire::Udp => TransportProtocol::Udp,
                        ProtocolWire::Stcp => TransportProtocol::Stcp,
                        ProtocolWire::Sudp => TransportProtocol::Sudp,
                        ProtocolWire::Http => TransportProtocol::Http,
                        ProtocolWire::Https => TransportProtocol::Https,
                        ProtocolWire::TcpMux => TransportProtocol::TcpMux,
                        ProtocolWire::Xtcp => TransportProtocol::Xtcp,
                    },
                    virtual_host: service.virtual_host.clone(),
                    protected_access: service.protected_access.as_ref().map(|access| {
                        ProtectedAccess {
                            secret: access.secret.clone(),
                            allowed_device_uids: access.allowed_device_uids.clone(),
                            route_id: access.route_id.clone(),
                        }
                    }),
                })
                .collect(),
            routes: self
                .routes
                .iter()
                .map(|route| TunnelRoute {
                    route_id: route.route_id.clone(),
                    service: route.service.clone(),
                    remote_addr: route.remote_addr.clone(),
                })
                .collect(),
            policy: TunnelPolicy {
                presence_interval_secs: self.policy.presence_interval_secs,
                initial_backoff_secs: self.policy.initial_backoff_secs,
                max_backoff_secs: self.policy.max_backoff_secs,
            },
            visitors: self
                .visitors
                .iter()
                .map(|visitor| TunnelVisitor {
                    visitor_id: visitor.visitor_id.clone(),
                    protocol: match visitor.protocol {
                        VisitorProtocolWire::Stcp => VisitorProtocol::Stcp,
                        VisitorProtocolWire::Sudp => VisitorProtocol::Sudp,
                        VisitorProtocolWire::Xtcp => VisitorProtocol::Xtcp,
                    },
                    xtcp_nat_protocol: visitor.xtcp_nat_protocol.as_ref().map(|protocol| {
                        match protocol {
                            XtcpNatProtocolWire::Kcp => XtcpNatProtocol::Kcp,
                            XtcpNatProtocolWire::Quic => XtcpNatProtocol::Quic,
                        }
                    }),
                    service_id: visitor.service_id.clone(),
                    server_device_uid: visitor.server_device_uid.clone(),
                    visitor_device_uid: visitor.visitor_device_uid.clone(),
                    secret: visitor.secret.clone(),
                    bind: visitor.bind,
                    max_connections: visitor.max_connections,
                    grant_id: visitor.grant_id.clone(),
                })
                .collect(),
            local_access_listeners: self
                .local_access_listeners
                .iter()
                .map(|listener| LocalAccessListener {
                    listener_id: listener.listener_id.clone(),
                    protocol: match listener.protocol {
                        LocalAccessProtocolWire::Socks5 => LocalAccessProtocol::Socks5,
                        LocalAccessProtocolWire::HttpConnect => LocalAccessProtocol::HttpConnect,
                    },
                    bind: listener.bind,
                    allowed_targets: listener.allowed_targets.clone(),
                    max_connections: listener.max_connections,
                })
                .collect(),
            static_file_plugins: self
                .static_file_plugins
                .iter()
                .map(|plugin| StaticFilePlugin {
                    service_id: plugin.service_id.clone(),
                    local_path: plugin.local_path.clone(),
                    strip_prefix: plugin.strip_prefix.clone(),
                })
                .collect(),
            unix_socket_plugins: self
                .unix_socket_plugins
                .iter()
                .map(|plugin| UnixSocketPlugin {
                    service_id: plugin.service_id.clone(),
                    unix_path: plugin.unix_path.clone(),
                })
                .collect(),
            forward_proxy_plugins: self
                .forward_proxy_plugins
                .iter()
                .map(|plugin| ForwardProxyPlugin {
                    service_id: plugin.service_id.clone(),
                    protocol: match plugin.protocol {
                        ForwardProxyProtocolWire::Http => ForwardProxyProtocol::Http,
                        ForwardProxyProtocolWire::Socks5 => ForwardProxyProtocol::Socks5,
                    },
                    username: plugin.username.clone(),
                    password: plugin.password.clone(),
                })
                .collect(),
            http2_upstream_plugins: self
                .http2_upstream_plugins
                .iter()
                .map(|plugin| Http2UpstreamPlugin {
                    service_id: plugin.service_id.clone(),
                    protocol: match plugin.protocol {
                        Http2UpstreamProtocolWire::Http => Http2UpstreamProtocol::Http,
                    },
                })
                .collect(),
            https_upstream_plugins: self
                .https_upstream_plugins
                .iter()
                .map(|plugin| HttpsUpstreamPlugin {
                    service_id: plugin.service_id.clone(),
                    server_name: plugin.server_name.clone(),
                })
                .collect(),
        };
        desired_state
            .validate()
            .map_err(|_| DesiredStateError::InvalidState)?;
        match self.digest_algorithm.as_deref() {
            // V1 is accepted only when the envelope explicitly omits the new
            // selector. Every selector added since then is defined by tunnel-core.
            None if self.digest_hex.len() == 16
                && self.digest_hex == format!("{:016x}", desired_state.legacy_v1_digest()) =>
            {
                Ok(desired_state)
            }
            Some(algorithm)
                if algorithm == desired_state.digest_algorithm()
                    && self.digest_hex.len() == 64
                    && self.digest_hex == desired_state.digest().to_hex() =>
            {
                Ok(desired_state)
            }
            _ => Err(DesiredStateError::DigestMismatch),
        }
    }

    fn to_assignment(&self) -> Option<TunnelDataPlaneAssignment> {
        self.data_plane_assignment
            .as_ref()
            .map(|assignment| TunnelDataPlaneAssignment {
                relay: RelayAssignment {
                    address: assignment.relay.address.clone(),
                    port: assignment.relay.port,
                    client_id: assignment.relay.client_id.clone(),
                    token: assignment.relay.token.clone(),
                    oidc: assignment
                        .relay
                        .oidc
                        .as_ref()
                        .map(|oidc| OidcRelayCredentials {
                            client_id: oidc.client_id.clone(),
                            client_secret: oidc.client_secret.clone(),
                            token_endpoint_url: oidc.token_endpoint_url.clone(),
                            audience: oidc.audience.clone(),
                            scope: oidc.scope.clone(),
                        }),
                    expires_at: assignment.relay.expires_at,
                },
                remote_ports: assignment
                    .remote_ports
                    .iter()
                    .map(|route| (route.remote_addr.clone(), route.port))
                    .collect(),
            })
    }

    fn canonical_payload(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"nexusflow-tunnel-desired-state-v1\0");
        for part in [
            self.owner_account_id.as_bytes(),
            self.device_uid.as_bytes(),
            self.key_id.as_bytes(),
            self.digest_hex.as_bytes(),
        ] {
            hasher.update((part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        // V1 signatures predate the selector, so their canonical payload is
        // byte-for-byte unchanged. V2 signatures bind the selector explicitly.
        if let Some(algorithm) = &self.digest_algorithm {
            hasher.update([1]);
            hash_string(&mut hasher, algorithm);
        }
        hasher.update(self.version.to_le_bytes());
        hasher.update(self.not_before.to_le_bytes());
        hasher.update(self.expires_at.to_le_bytes());
        if let Some(version) = self.rollback_of_version {
            hasher.update([1]);
            hasher.update(version.to_le_bytes());
        }
        match &self.data_plane_assignment {
            None => hasher.update([0]),
            Some(assignment) => {
                hasher.update([1]);
                hash_string(&mut hasher, &assignment.relay.address);
                hasher.update(assignment.relay.port.to_le_bytes());
                hash_string(&mut hasher, &assignment.relay.client_id);
                hash_string(&mut hasher, &assignment.relay.token);
                if let Some(oidc) = &assignment.relay.oidc {
                    // Keep legacy token assignment signatures byte-compatible;
                    // the marker is present only for the new OIDC variant.
                    hasher.update([1]);
                    hash_string(&mut hasher, &oidc.client_id);
                    hash_string(&mut hasher, &oidc.client_secret);
                    hash_string(&mut hasher, &oidc.token_endpoint_url);
                    hash_option_string(&mut hasher, oidc.audience.as_deref());
                    hash_option_string(&mut hasher, oidc.scope.as_deref());
                }
                hasher.update(assignment.relay.expires_at.to_le_bytes());
                hasher.update((assignment.remote_ports.len() as u64).to_le_bytes());
                for route in &assignment.remote_ports {
                    hash_string(&mut hasher, &route.remote_addr);
                    hasher.update(route.port.to_le_bytes());
                }
            }
        }
        hasher.finalize().to_vec()
    }
}

fn hash_string(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn hash_option_string(hasher: &mut Sha256, value: Option<&str>) {
    if let Some(value) = value {
        hasher.update([1]);
        hash_string(hasher, value);
    } else {
        hasher.update([0]);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_and_verify_desired_state, signing_key_id, DesiredStateError, ForwardProxyPluginWire,
        ForwardProxyProtocolWire, Http2UpstreamPluginWire, Http2UpstreamProtocolWire,
        HttpsUpstreamPluginWire, TunnelVisitorWire, UnixSocketPluginWire, VerifiedDesiredState,
        VisitorProtocolWire, XtcpNatProtocolWire,
    };

    fn payload() -> String {
        let digest = format!(
            "{:016x}",
            crate::tunnel::TunnelDesiredState::presence_only(1).legacy_v1_digest()
        );
        format!(
            r#"{{"ownerAccountId":"account-1","deviceUid":"device-1","keyId":"key-1","version":1,"digestHex":"{digest}","notBefore":1,"expiresAt":3,"signatureHex":"{}","mode":"presenceonly","services":[],"routes":[],"policy":{{"presenceIntervalSecs":30,"initialBackoffSecs":1,"maxBackoffSecs":30}}}}"#,
            "00".repeat(64)
        )
    }

    #[test]
    fn verifies_device_window_digest_and_signature_before_exposing_state() {
        let state = parse_and_verify_desired_state(
            &payload(),
            "device-1",
            2,
            |key_id, bytes, signature| {
                key_id == "key-1" && !bytes.is_empty() && signature == &[0; 64]
            },
        )
        .unwrap();
        assert_eq!(state.desired_state.version.0, 1);
        assert_eq!(signing_key_id(&payload()).unwrap(), "key-1");
    }

    #[test]
    fn accepts_control_plane_camel_case_presence_mode() {
        let payload = payload().replace("\"mode\":\"presenceonly\"", "\"mode\":\"presenceOnly\"");
        assert!(parse_and_verify_desired_state(&payload, "device-1", 2, |_, _, _| true).is_ok());
    }

    #[test]
    fn rejects_a_tampered_digest_even_if_the_signature_callback_accepts_it() {
        assert_eq!(
            parse_and_verify_desired_state(
                &payload().replacen("digestHex\":\"", "digestHex\":\"0000000000000000", 1),
                "device-1",
                2,
                |_, _, _| true
            ),
            Err(DesiredStateError::DigestMismatch)
        );
    }

    #[test]
    fn rejects_digest_algorithm_downgrade_and_v2_length_mismatch() {
        let desired = crate::tunnel::TunnelDesiredState::presence_only(1);
        let legacy = format!("{:016x}", desired.legacy_v1_digest());
        let v2 = payload().replacen(
            &format!("\"digestHex\":\"{legacy}"),
            &format!(
                "\"digestAlgorithm\":\"sha256-v2\",\"digestHex\":\"{}",
                desired.digest().to_hex()
            ),
            1,
        );
        assert_eq!(
            parse_and_verify_desired_state(&v2, "device-1", 2, |_, _, _| true),
            Ok(VerifiedDesiredState {
                desired_state: desired.clone(),
                data_plane_assignment: None,
            })
        );
        assert_eq!(
            parse_and_verify_desired_state(
                &v2.replacen("sha256-v2", "fnv1a64", 1),
                "device-1",
                2,
                |_, _, _| true
            ),
            Err(DesiredStateError::DigestMismatch)
        );
    }

    #[test]
    fn rejects_protected_protocols_without_a_signed_access_grant() {
        let payload = payload().replace(
            "\"services\":[]",
            "\"services\":[{\"serviceId\":\"x\",\"name\":\"x\",\"localAddr\":\"127.0.0.1:1\",\"protocol\":\"stcp\"}]",
        );
        assert_eq!(
            parse_and_verify_desired_state(&payload, "device-1", 2, |_, _, _| true),
            Err(DesiredStateError::InvalidState)
        );
    }

    #[test]
    fn rejects_unknown_plugins_and_transports_instead_of_ignoring_them() {
        let plugin = payload().replace(
            "\"services\":[]",
            "\"services\":[{\"serviceId\":\"x\",\"name\":\"x\",\"localAddr\":\"127.0.0.1:1\",\"protocol\":\"tcp\",\"plugin\":{\"type\":\"socks5\"}}]",
        );
        assert_eq!(
            parse_and_verify_desired_state(&plugin, "device-1", 2, |_, _, _| true),
            Err(DesiredStateError::InvalidPayload)
        );
        for transport in ["kcp", "quic", "websocket", "wss"] {
            let payload = payload().replace(
                "\"services\":[]",
                &format!(
                    "\"services\":[{{\"serviceId\":\"x\",\"name\":\"x\",\"localAddr\":\"127.0.0.1:1\",\"protocol\":\"{transport}\"}}]"
                ),
            );
            assert_eq!(
                parse_and_verify_desired_state(&payload, "device-1", 2, |_, _, _| true),
                Err(DesiredStateError::InvalidPayload)
            );
        }
        for capability in [
            "\"oidc\":{\"issuer\":\"https://issuer.example\"}",
            "\"admin\":{\"address\":\"127.0.0.1:7400\"}",
            "\"virtualNetwork\":{\"name\":\"private\"}",
        ] {
            let payload = payload().replacen(
                "\"mode\":\"presenceonly\"",
                &format!("\"mode\":\"presenceonly\",{capability}"),
                1,
            );
            assert_eq!(
                parse_and_verify_desired_state(&payload, "device-1", 2, |_, _, _| true),
                Err(DesiredStateError::InvalidPayload)
            );
        }
    }

    #[test]
    fn xtcp_wire_accepts_only_the_bounded_nat_protocol_selector() {
        let wire: TunnelVisitorWire = serde_json::from_str(
            r#"{"visitorId":"v","protocol":"xtcp","xtcpNatProtocol":"quic","serviceId":"s","serverDeviceUid":"publisher","visitorDeviceUid":"visitor","secret":"0123456789abcdef","bind":"127.0.0.1:19000","maxConnections":1}"#,
        )
        .unwrap();
        assert!(matches!(wire.protocol, VisitorProtocolWire::Xtcp));
        assert!(matches!(
            wire.xtcp_nat_protocol,
            Some(XtcpNatProtocolWire::Quic)
        ));
        assert!(serde_json::from_str::<TunnelVisitorWire>(
            r#"{"visitorId":"v","protocol":"xtcp","xtcpNatProtocol":"stun","serviceId":"s","serverDeviceUid":"publisher","visitorDeviceUid":"visitor","secret":"0123456789abcdef","bind":"127.0.0.1:19000","maxConnections":1}"#
        )
        .is_err());
    }

    #[test]
    fn unix_socket_plugin_wire_rejects_raw_plugin_options() {
        assert!(serde_json::from_str::<UnixSocketPluginWire>(
            r#"{"serviceId":"svc","unixPath":"/run/nexus/backend.sock"}"#
        )
        .is_ok());
        assert!(serde_json::from_str::<UnixSocketPluginWire>(
            r#"{"serviceId":"svc","unixPath":"/run/nexus/backend.sock","plugin":{"type":"socks5"}}"#
        )
        .is_err());
    }

    #[test]
    fn forward_proxy_plugin_wire_is_bounded_and_rejects_raw_options() {
        let wire: ForwardProxyPluginWire = serde_json::from_str(
            r#"{"serviceId":"svc","protocol":"http","username":"u","password":"p"}"#,
        )
        .unwrap();
        assert!(matches!(wire.protocol, ForwardProxyProtocolWire::Http));
        assert_eq!(wire.username.as_deref(), Some("u"));
        assert!(serde_json::from_str::<ForwardProxyPluginWire>(
            r#"{"serviceId":"svc","protocol":"socks5","plugin":{"type":"virtual_net"}}"#
        )
        .is_err());
    }

    #[test]
    fn http2_upstream_plugin_wire_rejects_tls_and_header_escape_hatches() {
        let wire: Http2UpstreamPluginWire =
            serde_json::from_str(r#"{"serviceId":"svc","protocol":"http"}"#).unwrap();
        assert!(matches!(wire.protocol, Http2UpstreamProtocolWire::Http));
        assert!(serde_json::from_str::<Http2UpstreamPluginWire>(
            r#"{"serviceId":"svc","protocol":"https"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Http2UpstreamPluginWire>(
            r#"{"serviceId":"svc","protocol":"http","crtPath":"cert.pem"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Http2UpstreamPluginWire>(
            r#"{"serviceId":"svc","protocol":"http","requestHeaders":{"set":{"Host":"x"}}}"#
        )
        .is_err());
    }

    #[test]
    fn https_upstream_wire_allows_only_the_signed_service_and_dns_name() {
        let wire: HttpsUpstreamPluginWire =
            serde_json::from_str(r#"{"serviceId":"svc","serverName":"backend.example.test"}"#)
                .unwrap();
        assert_eq!(wire.server_name, "backend.example.test");
        assert!(serde_json::from_str::<HttpsUpstreamPluginWire>(
            r#"{"serviceId":"svc","serverName":"backend.example.test","caPath":"root.pem"}"#
        )
        .is_err());
    }

    #[test]
    fn parses_signed_stcp_access_without_exposing_raw_upstream_options() {
        let desired = crate::tunnel::TunnelDesiredState::active(
            1,
            vec![crate::tunnel::TunnelService {
                service_id: "support".into(),
                name: "support".into(),
                local_addr: "127.0.0.1:3389".into(),
                protocol: crate::tunnel::TransportProtocol::Stcp,
                virtual_host: None,
                protected_access: Some(crate::tunnel::ProtectedAccess {
                    secret: "0123456789abcdef".into(),
                    allowed_device_uids: vec!["visitor-device".into()],
                    route_id: "route-support".into(),
                }),
            }],
            vec![crate::tunnel::TunnelRoute {
                route_id: "route-support".into(),
                service: "support".into(),
                remote_addr: "edge://support".into(),
            }],
            crate::tunnel::TunnelPolicy::default(),
        );
        let payload = format!(
            r#"{{"ownerAccountId":"account-1","deviceUid":"device-1","keyId":"key-1","version":1,"digestHex":"{:016x}","notBefore":1,"expiresAt":3,"signatureHex":"{}","mode":"active","services":[{{"serviceId":"support","name":"support","localAddr":"127.0.0.1:3389","protocol":"stcp","protectedAccess":{{"secret":"0123456789abcdef","allowedDeviceUids":["visitor-device"],"routeId":"route-support"}}}}],"routes":[{{"routeId":"route-support","service":"support","remoteAddr":"edge://support"}}],"policy":{{"presenceIntervalSecs":30,"initialBackoffSecs":1,"maxBackoffSecs":30}},"dataPlaneAssignment":{{"relay":{{"address":"relay.example","port":7000,"clientId":"device-1","token":"token","expiresAt":999}},"remotePorts":[]}}}}"#,
            desired.legacy_v1_digest(),
            "00".repeat(64),
        );
        let verified = parse_and_verify_desired_state(&payload, "device-1", 2, |_, _, _| true)
            .unwrap_or_else(|error| panic!("{error:?}: {payload}"));
        assert_eq!(verified.desired_state, desired);
    }

    #[test]
    fn parses_v3_signed_visitor_and_local_access_without_raw_proxy_options() {
        let mut desired = crate::tunnel::TunnelDesiredState::active(
            1,
            vec![crate::tunnel::TunnelService {
                service_id: "support".into(),
                name: "support".into(),
                local_addr: "127.0.0.1:3389".into(),
                protocol: crate::tunnel::TransportProtocol::Stcp,
                virtual_host: None,
                protected_access: Some(crate::tunnel::ProtectedAccess {
                    secret: "0123456789abcdef".into(),
                    allowed_device_uids: vec!["visitor-device".into()],
                    route_id: "route-support".into(),
                }),
            }],
            vec![crate::tunnel::TunnelRoute {
                route_id: "route-support".into(),
                service: "support".into(),
                remote_addr: "edge://support".into(),
            }],
            crate::tunnel::TunnelPolicy::default(),
        );
        desired.visitors.push(crate::tunnel::TunnelVisitor {
            visitor_id: "visitor-support".into(),
            protocol: crate::tunnel::VisitorProtocol::Stcp,
            xtcp_nat_protocol: None,
            service_id: "support".into(),
            server_device_uid: "device-publisher".into(),
            visitor_device_uid: "visitor-device".into(),
            secret: "0123456789abcdef".into(),
            bind: "127.0.0.1:19000".parse().unwrap(),
            max_connections: 1,
            grant_id: Some("grant-support".into()),
        });
        desired
            .local_access_listeners
            .push(crate::tunnel::LocalAccessListener {
                listener_id: "support-local".into(),
                protocol: crate::tunnel::LocalAccessProtocol::Socks5,
                bind: "127.0.0.1:0".parse().unwrap(),
                allowed_targets: vec!["127.0.0.1:3389".parse().unwrap()],
                max_connections: 1,
            });
        let payload = format!(
            r#"{{"ownerAccountId":"account-1","deviceUid":"device-1","keyId":"key-1","version":1,"digestAlgorithm":"sha256-v3","digestHex":"{}","notBefore":1,"expiresAt":3,"signatureHex":"{}","mode":"active","services":[{{"serviceId":"support","name":"support","localAddr":"127.0.0.1:3389","protocol":"stcp","protectedAccess":{{"secret":"0123456789abcdef","allowedDeviceUids":["visitor-device"],"routeId":"route-support"}}}}],"routes":[{{"routeId":"route-support","service":"support","remoteAddr":"edge://support"}}],"policy":{{"presenceIntervalSecs":30,"initialBackoffSecs":1,"maxBackoffSecs":30}},"visitors":[{{"visitorId":"visitor-support","protocol":"stcp","serviceId":"support","serverDeviceUid":"device-publisher","visitorDeviceUid":"visitor-device","secret":"0123456789abcdef","bind":"127.0.0.1:19000","maxConnections":1,"grantId":"grant-support"}}],"localAccessListeners":[{{"listenerId":"support-local","protocol":"socks5","bind":"127.0.0.1:0","allowedTargets":["127.0.0.1:3389"],"maxConnections":1}}],"dataPlaneAssignment":{{"relay":{{"address":"relay.example","port":7000,"clientId":"device-1","token":"token","expiresAt":999}},"remotePorts":[]}}}}"#,
            desired.digest().to_hex(),
            "00".repeat(64),
        );
        assert_eq!(
            parse_and_verify_desired_state(&payload, "device-1", 2, |_, _, _| true)
                .unwrap()
                .desired_state,
            desired
        );
        assert_eq!(
            parse_and_verify_desired_state(&payload, "device-1", 2, |_, _, _| true)
                .unwrap()
                .desired_state
                .visitors[0]
                .grant_id
                .as_deref(),
            Some("grant-support")
        );
        assert!(!desired.visitors[0]
            .to_frp_toml()
            .unwrap()
            .contains("grant-support"));
    }

    #[test]
    fn parses_v4_signed_static_file_plugin_without_raw_proxy_options() {
        let mut desired = crate::tunnel::TunnelDesiredState::active(
            1,
            vec![crate::tunnel::TunnelService {
                service_id: "docs".into(),
                name: "docs".into(),
                local_addr: "127.0.0.1:8080".into(),
                protocol: crate::tunnel::TransportProtocol::Tcp,
                virtual_host: None,
                protected_access: None,
            }],
            vec![crate::tunnel::TunnelRoute {
                route_id: "docs-route".into(),
                service: "docs".into(),
                remote_addr: "edge://docs".into(),
            }],
            crate::tunnel::TunnelPolicy::default(),
        );
        desired
            .static_file_plugins
            .push(crate::tunnel::StaticFilePlugin {
                service_id: "docs".into(),
                local_path: if cfg!(windows) {
                    "C:/nexus-docs".into()
                } else {
                    "/var/lib/nexus-docs".into()
                },
                strip_prefix: Some("assets".into()),
            });
        let local_path = &desired.static_file_plugins[0].local_path;
        let payload = format!(
            r#"{{"ownerAccountId":"account-1","deviceUid":"device-1","keyId":"key-1","version":1,"digestAlgorithm":"sha256-v4","digestHex":"{}","notBefore":1,"expiresAt":3,"signatureHex":"{}","mode":"active","services":[{{"serviceId":"docs","name":"docs","localAddr":"127.0.0.1:8080","protocol":"tcp"}}],"routes":[{{"routeId":"docs-route","service":"docs","remoteAddr":"edge://docs"}}],"policy":{{"presenceIntervalSecs":30,"initialBackoffSecs":1,"maxBackoffSecs":30}},"staticFilePlugins":[{{"serviceId":"docs","localPath":"{local_path}","stripPrefix":"assets"}}],"dataPlaneAssignment":{{"relay":{{"address":"relay.example","port":7000,"clientId":"device-1","token":"token","expiresAt":999}},"remotePorts":[{{"remoteAddr":"edge://docs","port":17000}}]}}}}"#,
            desired.digest().to_hex(),
            "00".repeat(64),
        );
        assert_eq!(
            parse_and_verify_desired_state(&payload, "device-1", 2, |_, _, _| true)
                .unwrap()
                .desired_state,
            desired
        );
        assert_eq!(
            parse_and_verify_desired_state(
                &payload.replacen(local_path, &format!("{local_path}-tampered"), 1),
                "device-1",
                2,
                |_, _, _| true,
            ),
            Err(DesiredStateError::DigestMismatch)
        );
    }

    #[test]
    fn rejects_unsafe_grant_capability_before_it_reaches_the_runtime() {
        let wire = r#"{"visitorId":"v","protocol":"stcp","serviceId":"s","serverDeviceUid":"publisher","visitorDeviceUid":"visitor","secret":"0123456789abcdef","bind":"127.0.0.1:19000","maxConnections":1,"grantId":"grant\n-injected"}"#;
        let visitor: TunnelVisitorWire = serde_json::from_str(wire).unwrap();
        assert!(visitor
            .grant_id
            .as_deref()
            .is_some_and(|grant| grant.contains('\n')));
        let mut invalid = crate::tunnel::TunnelVisitor {
            visitor_id: visitor.visitor_id,
            protocol: crate::tunnel::VisitorProtocol::Stcp,
            xtcp_nat_protocol: None,
            service_id: visitor.service_id,
            server_device_uid: visitor.server_device_uid,
            visitor_device_uid: visitor.visitor_device_uid,
            secret: visitor.secret,
            bind: visitor.bind,
            max_connections: visitor.max_connections,
            grant_id: visitor.grant_id,
        };
        assert!(matches!(
            invalid.validate(),
            Err(crate::tunnel::VisitorError::InvalidVisitor)
        ));
        invalid.grant_id = Some("grant-ok".into());
        assert!(invalid.validate().is_ok());
    }

    #[test]
    fn rejects_active_state_without_a_signed_relay_assignment() {
        let desired_state = crate::tunnel::TunnelDesiredState::active(
            1,
            vec![crate::tunnel::TunnelService {
                service_id: "ssh".into(),
                name: "ssh".into(),
                local_addr: "127.0.0.1:22".into(),
                protocol: crate::tunnel::TransportProtocol::Tcp,
                virtual_host: None,
                protected_access: None,
            }],
            vec![crate::tunnel::TunnelRoute {
                route_id: "ssh-route".into(),
                service: "ssh".into(),
                remote_addr: "edge://ssh".into(),
            }],
            crate::tunnel::TunnelPolicy::default(),
        );
        let payload = format!(
            r#"{{"ownerAccountId":"account-1","deviceUid":"device-1","keyId":"key-1","version":1,"digestHex":"{:016x}","notBefore":1,"expiresAt":3,"signatureHex":"{}","mode":"active","services":[{{"serviceId":"ssh","name":"ssh","localAddr":"127.0.0.1:22","protocol":"tcp"}}],"routes":[{{"routeId":"ssh-route","service":"ssh","remoteAddr":"edge://ssh"}}],"policy":{{"presenceIntervalSecs":30,"initialBackoffSecs":1,"maxBackoffSecs":30}}}}"#,
            desired_state.legacy_v1_digest(),
            "00".repeat(64)
        );
        assert_eq!(
            parse_and_verify_desired_state(&payload, "device-1", 2, |_, _, _| true),
            Err(DesiredStateError::InvalidState)
        );
    }
}
