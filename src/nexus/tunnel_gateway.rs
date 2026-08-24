//! Headless adapter for RustDesk's existing PortForward client.
//!
//! It owns no GUI state. UI-only notifications are projected to logs while
//! RustDesk continues to own its native hash and Login protocol handlers.

#[cfg(feature = "nexus-native-tunnel")]
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
};

#[cfg(feature = "nexus-native-tunnel")]
#[derive(Debug)]
pub(super) struct GatewayConfig {
    pub(super) credential_path: PathBuf,
    pub(super) peer_id: String,
    pub(super) bind_addr: SocketAddr,
    pub(super) token: String,
    pub(super) device_uid: String,
    pub(super) control_plane_url: String,
    pub(super) grant_id: String,
}

/// Parses explicit Gateway deployment values without consulting environment or
/// global RustDesk configuration. This keeps invalid input fail-closed and
/// directly testable before the native client is constructed.
#[cfg(feature = "nexus-native-tunnel")]
pub(super) fn gateway_config_from_values(
    credential_path: Option<PathBuf>,
    peer_id: Option<String>,
    bind: Option<String>,
    token: Option<String>,
    device_uid: Option<String>,
    control_plane_url: Option<String>,
    grant_id: Option<String>,
) -> Result<GatewayConfig, String> {
    let credential_path = credential_path.ok_or("NEXUS_TUNNEL_CREDENTIAL_FILE is required")?;
    let peer_id = peer_id
        .filter(|value| !value.trim().is_empty())
        .ok_or("NEXUS_GATEWAY_PEER_ID is required")?;
    let bind_addr: SocketAddr = bind
        .unwrap_or_else(|| "127.0.0.1:21119".into())
        .parse()
        .map_err(|_| "NEXUS_GATEWAY_BIND must be an IPv4 socket address".to_string())?;
    if !bind_addr.is_ipv4() {
        return Err("NEXUS_GATEWAY_BIND must be an IPv4 socket address".into());
    }
    if bind_addr.port() == 0 {
        return Err("NEXUS_GATEWAY_BIND must use a non-zero port".into());
    }
    let device_uid = device_uid
        .filter(|value| !value.trim().is_empty())
        .ok_or("NEXUS_GATEWAY_DEVICE_UID is required")?;
    let control_plane_url = control_plane_url
        .filter(|value| !value.trim().is_empty())
        .ok_or("NEXUS_GATEWAY_CONTROL_PLANE_URL is required")?;
    let grant_id = grant_id
        .filter(|value| !value.is_empty())
        .filter(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        .ok_or("NEXUS_GATEWAY_GRANT_ID is invalid")?;
    Ok(GatewayConfig {
        credential_path,
        peer_id,
        bind_addr,
        token: token.unwrap_or_default(),
        device_uid,
        control_plane_url,
        grant_id,
    })
}

#[cfg(feature = "nexus-native-tunnel")]
#[derive(Clone)]
pub(super) struct HeadlessPortForwardInterface {
    lch: Arc<RwLock<crate::client::LoginConfigHandler>>,
}

#[cfg(feature = "nexus-native-tunnel")]
impl HeadlessPortForwardInterface {
    pub(super) fn new(id: String, force_relay: bool) -> Self {
        Self::with_conn_type(
            id,
            force_relay,
            hbb_common::rendezvous_proto::ConnType::PORT_FORWARD,
        )
    }

    pub(super) fn with_conn_type(
        id: String,
        force_relay: bool,
        conn_type: hbb_common::rendezvous_proto::ConnType,
    ) -> Self {
        let mut handler = crate::client::LoginConfigHandler::default();
        handler.initialize(id, conn_type, None, force_relay, None, None, None);
        Self {
            lch: Arc::new(RwLock::new(handler)),
        }
    }
}

#[cfg(feature = "nexus-native-tunnel")]
#[async_trait::async_trait]
impl crate::client::Interface for HeadlessPortForwardInterface {
    fn send(&self, _data: crate::client::Data) {}

    fn msgbox(&self, msgtype: &str, title: &str, text: &str, _link: &str) {
        hbb_common::log::warn!("Nexus headless PortForward {msgtype}: {title}: {text}");
    }

    fn handle_login_error(&self, error: &str) -> bool {
        hbb_common::log::warn!("Nexus headless PortForward login rejected: {error}");
        false
    }

    fn handle_peer_info(&self, peer_info: hbb_common::message_proto::PeerInfo) {
        self.lch.write().unwrap().handle_peer_info(&peer_info);
    }

    fn set_multiple_windows_session(
        &self,
        _sessions: Vec<hbb_common::message_proto::WindowsSession>,
    ) {
    }

    async fn handle_hash(
        &self,
        password: &str,
        hash: hbb_common::message_proto::Hash,
        peer: &mut hbb_common::Stream,
    ) {
        crate::client::handle_hash(self.lch.clone(), password, hash, self, peer).await;
    }

    async fn handle_login_from_ui(
        &self,
        os_username: String,
        os_password: String,
        password: String,
        remember: bool,
        peer: &mut hbb_common::Stream,
    ) {
        crate::client::handle_login_from_ui(
            self.lch.clone(),
            os_username,
            os_password,
            password,
            remember,
            peer,
        )
        .await;
    }

    async fn handle_test_delay(
        &self,
        delay: hbb_common::message_proto::TestDelay,
        peer: &mut hbb_common::Stream,
    ) {
        crate::client::handle_test_delay(delay, peer).await;
    }

    fn get_lch(&self) -> Arc<RwLock<crate::client::LoginConfigHandler>> {
        self.lch.clone()
    }
}
