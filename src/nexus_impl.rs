//! Thin adapter between RustDesk's native lifecycle and NexusFlow.

#[cfg(feature = "nexus-native-tunnel")]
use std::fs;
#[cfg(any(feature = "nexus-frp-compat-smoke", feature = "nexus-native-tunnel"))]
use std::sync::Arc;
use std::{
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::{Mutex, OnceLock},
    time::Duration,
};

#[cfg(feature = "nexus-agent")]
use hbb_common::websocket::WsFramedStream;
use hbb_common::{config::Config, sodiumoxide::crypto::sign};
pub use nexus_client::{
    control::{PresenceSessionKeyLease, SignedControlPlaneRequest},
    desired_state::VerifiedDesiredState,
    ipc::{
        ErrorResponse, GetStatusRequest, RefreshDesiredStateRequest,
        RefreshPortForwardCredentialRequest, RefreshScheduledResponse, Request, Response,
        StatusResponse, IPC_VERSION,
    },
    status::{AgentHealthState, ClientStatus, HealthState},
    tunnel::{ConfigDigest, ConfigVersion, PresenceClient, PresenceHeartbeat, TunnelState},
    NexusRuntime, RuntimeConfig,
};
#[cfg(feature = "nexus-agent")]
use std::collections::{HashMap, VecDeque};
#[cfg(feature = "nexus-native-tunnel")]
use std::sync::RwLock;

/// Application-layer boundary for reporting a verified Desired State outcome.
/// Production uses the signed HTTPS adapter below; tests can inject a local
/// recorder without weakening the production transport policy.
pub trait TunnelApplicationReporter: Send + Sync {
    fn report<'a>(
        &'a self,
        control_plane_url: &'a str,
        version: u64,
        digest_hex: &'a str,
        outcome: &'a str,
        detail: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

struct HttpsTunnelApplicationReporter;

impl TunnelApplicationReporter for HttpsTunnelApplicationReporter {
    fn report<'a>(
        &'a self,
        control_plane_url: &'a str,
        version: u64,
        digest_hex: &'a str,
        outcome: &'a str,
        detail: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(record_tunnel_desired_state_application_http(
            control_plane_url,
            version,
            digest_hex,
            outcome,
            detail,
            false,
        ))
    }
}

#[cfg(test)]
struct LoopbackTunnelApplicationReporter;

#[cfg(test)]
impl TunnelApplicationReporter for LoopbackTunnelApplicationReporter {
    fn report<'a>(
        &'a self,
        control_plane_url: &'a str,
        version: u64,
        digest_hex: &'a str,
        outcome: &'a str,
        detail: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(record_tunnel_desired_state_application_loopback(
            control_plane_url,
            version,
            digest_hex,
            outcome,
            detail,
        ))
    }
}

#[cfg(feature = "nexus-frp-compat-smoke")]
use nexus_client::tunnel::{
    ConfigGeneration, FrpCancellationToken, FrpRuntime, FrpVisitorRuntime, HttpConnectRuntime,
    HttpsUpstreamRuntime, LocalAccessProtocol, Socks5Runtime, TunnelMode,
};

fn runtime_slot() -> &'static Mutex<Option<NexusRuntime>> {
    static RUNTIME: OnceLock<Mutex<Option<NexusRuntime>>> = OnceLock::new();
    RUNTIME.get_or_init(|| Mutex::new(None))
}

fn host_control_plane_url() -> &'static Mutex<Option<String>> {
    static URL: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    URL.get_or_init(|| Mutex::new(None))
}

#[cfg(feature = "nexus-agent")]
fn active_agent_cancellations(
) -> &'static Mutex<HashMap<String, hbb_common::tokio_util::sync::CancellationToken>> {
    static CANCELLATIONS: OnceLock<
        Mutex<HashMap<String, hbb_common::tokio_util::sync::CancellationToken>>,
    > = OnceLock::new();
    CANCELLATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(feature = "nexus-agent")]
fn register_agent_cancellation(
    execution_id: &str,
) -> Option<hbb_common::tokio_util::sync::CancellationToken> {
    let mut active = active_agent_cancellations().lock().ok()?;
    // One Host runs one Agent execution at a time. The Socket ACK rejects
    // additional work instead of building an unbounded in-memory queue.
    if !active.is_empty() {
        return None;
    }
    let cancellation = hbb_common::tokio_util::sync::CancellationToken::new();
    active.insert(execution_id.to_string(), cancellation.clone());
    Some(cancellation)
}

#[cfg(feature = "nexus-agent")]
fn cancel_active_agent(execution_id: &str) -> bool {
    let cancellation = active_agent_cancellations()
        .lock()
        .ok()
        .and_then(|active| active.get(execution_id).cloned());
    cancellation.is_some_and(|cancellation| {
        cancellation.cancel();
        true
    })
}

#[cfg(feature = "nexus-agent")]
struct ActiveAgentCancellationGuard(String);

#[cfg(feature = "nexus-agent")]
impl Drop for ActiveAgentCancellationGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = active_agent_cancellations().lock() {
            active.remove(&self.0);
        }
    }
}

/// Headless adapter for the already-existing RustDesk PortForward client.
/// It owns no GUI state and turns UI-only notifications into logs while
/// retaining RustDesk's native hash and Login protocol handlers.
#[cfg(feature = "nexus-native-tunnel")]
#[derive(Clone)]
struct HeadlessPortForwardInterface {
    lch: Arc<RwLock<crate::client::LoginConfigHandler>>,
}

#[cfg(feature = "nexus-native-tunnel")]
impl HeadlessPortForwardInterface {
    fn new(id: String, force_relay: bool) -> Self {
        Self::with_conn_type(
            id,
            force_relay,
            hbb_common::rendezvous_proto::ConnType::PORT_FORWARD,
        )
    }

    fn with_conn_type(
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

/// Deployment-owned inputs required to attach Tunnel to the native service.
///
/// None of these endpoints is inferred from another URL: guessing a Gateway
/// from a control-plane address could send authenticated UDP traffic to the
/// wrong trust boundary. Missing input leaves Tunnel networking disabled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunnelHostConfig {
    pub device_uid: String,
    pub control_plane_url: String,
    pub presence_gateway: SocketAddr,
    pub presence_bind: SocketAddr,
}

/// Runs the headless public-side Gateway using the existing native
/// `PORT_FORWARD` session owner. All target fields come from the verified
/// credential file; only the explicit bind address is deployment-owned.
#[cfg(feature = "nexus-native-tunnel")]
pub async fn run_headless_gateway_from_env() -> Result<(), String> {
    run_headless_gateway_from_env_with_loopback_http(false).await
}

/// Test-harness-only Gateway entrypoint. It accepts plain HTTP exclusively on
/// loopback, so the multi-process WSL test can use the in-memory Control Plane
/// without weakening the production HTTPS boundary.
#[cfg(feature = "nexus-e2e-gateway")]
pub async fn run_headless_gateway_from_env_for_e2e() -> Result<(), String> {
    run_headless_gateway_from_env_with_loopback_http(true).await
}

/// E2E-only legacy PortForward fixture. It deliberately skips all Nexus
/// credential variables so the existing no-context branch remains covered
/// beside a Nexus Gateway; production has no entrypoint for this helper.
#[cfg(feature = "nexus-e2e-gateway")]
pub async fn run_legacy_port_forward_from_env_for_e2e() -> Result<(), String> {
    let peer_id = e2e_peer_id()?;
    let bind_addr = e2e_bind_addr()?;
    let target = std::env::var("NEXUS_E2E_LEGACY_TARGET")
        .ok()
        .and_then(|value| {
            value
                .rsplit_once(':')
                .map(|(host, port)| (host.to_owned(), port.to_owned()))
        })
        .and_then(|(host, port)| port.parse().ok().map(|port| (host, port)))
        .filter(|(host, port)| !host.is_empty() && *port > 0)
        .ok_or("NEXUS_E2E_LEGACY_TARGET must be host:port")?;
    configure_e2e_rendezvous()?;
    let key = crate::common::get_key(false).await;
    let password = std::env::var("NEXUS_E2E_LEGACY_PASSWORD")
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or("NEXUS_E2E_LEGACY_PASSWORD is required")?;
    let interface = HeadlessPortForwardInterface::new(peer_id, e2e_force_relay());
    let listener_config = crate::client::Interface::get_lch(&interface);
    let (_close_sender, receiver) = hbb_common::tokio::sync::mpsc::unbounded_channel();
    crate::port_forward::listen_with_bind_ready(
        &bind_addr.ip().to_string(),
        crate::client::Interface::get_id(&interface),
        password,
        i32::from(bind_addr.port()),
        interface,
        receiver,
        &key,
        "",
        listener_config,
        target.0,
        target.1,
        None,
    )
    .await
    .map_err(|error| error.to_string())
}

/// E2E-only `DEFAULT_CONN` transport smoke. The stream is retained briefly,
/// which proves it can coexist with the separately owned PortForward sessions
/// without adding a second Remote implementation or production hook.
#[cfg(feature = "nexus-e2e-gateway")]
pub async fn run_remote_smoke_from_env_for_e2e() -> Result<(), String> {
    let peer_id = e2e_peer_id()?;
    configure_e2e_rendezvous()?;
    let key = crate::common::get_key(false).await;
    let interface = HeadlessPortForwardInterface::with_conn_type(
        peer_id.clone(),
        e2e_force_relay(),
        hbb_common::rendezvous_proto::ConnType::DEFAULT_CONN,
    );
    let ((stream, _direct, _pk, _kcp, _stream_type), _) = crate::client::Client::start(
        &peer_id,
        &key,
        "",
        hbb_common::rendezvous_proto::ConnType::DEFAULT_CONN,
        interface,
    )
    .await
    .map_err(|error| error.to_string())?;
    println!("NEXUS_E2E_REMOTE_CONNECTED");
    hbb_common::tokio::time::sleep(std::time::Duration::from_secs(12)).await;
    drop(stream);
    Ok(())
}

#[cfg(feature = "nexus-e2e-gateway")]
fn e2e_peer_id() -> Result<String, String> {
    std::env::var("NEXUS_E2E_PEER_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or("NEXUS_E2E_PEER_ID is required".into())
}

#[cfg(feature = "nexus-e2e-gateway")]
fn e2e_bind_addr() -> Result<SocketAddr, String> {
    let bind_addr = std::env::var("NEXUS_E2E_BIND")
        .unwrap_or_else(|_| "127.0.0.1:21119".into())
        .parse::<SocketAddr>()
        .map_err(|_| "NEXUS_E2E_BIND must be an IPv4 socket address".to_string())?;
    if !bind_addr.is_ipv4() || bind_addr.port() == 0 {
        return Err("NEXUS_E2E_BIND must use a non-zero IPv4 port".into());
    }
    Ok(bind_addr)
}

#[cfg(feature = "nexus-e2e-gateway")]
fn e2e_force_relay() -> bool {
    std::env::var("NEXUS_E2E_FORCE_RELAY").ok().as_deref() == Some("Y")
}

#[cfg(feature = "nexus-e2e-gateway")]
fn configure_e2e_rendezvous() -> Result<(), String> {
    let rendezvous = std::env::var("NEXUS_E2E_RENDEZVOUS_SERVER")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or("NEXUS_E2E_RENDEZVOUS_SERVER is required")?;
    Config::set_option("custom-rendezvous-server".into(), rendezvous);
    if let Ok(key) = std::env::var("NEXUS_E2E_RENDEZVOUS_KEY") {
        Config::set_option("key".into(), key);
    }
    Config::set_option(
        "force-always-relay".into(),
        if e2e_force_relay() { "Y" } else { "N" }.into(),
    );
    Ok(())
}

#[cfg(feature = "nexus-native-tunnel")]
async fn run_headless_gateway_from_env_with_loopback_http(
    allow_loopback_http: bool,
) -> Result<(), String> {
    let config = gateway_config_from_values(
        std::env::var_os("NEXUS_TUNNEL_CREDENTIAL_FILE").map(PathBuf::from),
        std::env::var("NEXUS_GATEWAY_PEER_ID").ok(),
        std::env::var("NEXUS_GATEWAY_BIND").ok(),
        std::env::var("NEXUS_GATEWAY_RUSTDESK_TOKEN").ok(),
        std::env::var("NEXUS_GATEWAY_DEVICE_UID").ok(),
        std::env::var("NEXUS_GATEWAY_CONTROL_PLANE_URL").ok(),
        std::env::var("NEXUS_GATEWAY_GRANT_ID").ok(),
    )?;
    if let Some(rendezvous) = std::env::var("NEXUS_GATEWAY_RENDEZVOUS_SERVER")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        // This is the existing RustDesk endpoint setting, not a Nexus
        // connection path. It keeps an isolated Gateway process on the same
        // native rendezvous/relay fabric as its Publishing Host.
        Config::set_option("custom-rendezvous-server".into(), rendezvous);
    }
    let _runtime = start_runtime(
        Config::get_id(),
        config
            .credential_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new(".")),
    );
    bind_device_uid(&config.device_uid).map_err(str::to_string)?;
    if allow_loopback_http {
        refresh_port_forward_credential_path_http(
            &config.control_plane_url,
            &gateway_port_forward_context_path(&config.grant_id)?,
            &config.credential_path,
            true,
        )
        .await?;
    } else {
        refresh_gateway_port_forward_credential(
            &config.control_plane_url,
            &config.grant_id,
            &config.credential_path,
        )
        .await?;
    }
    let target = crate::nexus::native_port_forward_credential_target(&config.credential_path)
        .ok_or("Nexus Gateway credential is invalid, expired, or revoked")?;
    let key = crate::common::get_key(false).await;
    // Only the test-only binary can request RustDesk's existing relay mode;
    // production Gateway transport choice remains the native default.
    let force_relay = cfg!(feature = "nexus-e2e-gateway")
        && std::env::var("NEXUS_E2E_FORCE_RELAY").ok().as_deref() == Some("Y");
    // The loopback harness reuses a HOME across transport cases. Clear the
    // persisted RustDesk relay preference so `--transport kcp` cannot inherit
    // a previous relay run; this branch only exists in the test binary.
    if cfg!(feature = "nexus-e2e-gateway") {
        Config::set_option(
            "force-always-relay".into(),
            if force_relay { "Y" } else { "N" }.into(),
        );
    }
    let interface = HeadlessPortForwardInterface::new(config.peer_id, force_relay);
    let listener_config = crate::client::Interface::get_lch(&interface);
    let (_close_sender, receiver) = hbb_common::tokio::sync::mpsc::unbounded_channel();
    crate::port_forward::listen_with_bind_ready(
        &config.bind_addr.ip().to_string(),
        crate::client::Interface::get_id(&interface),
        String::new(),
        i32::from(config.bind_addr.port()),
        interface,
        receiver,
        &key,
        &config.token,
        listener_config,
        target.0,
        target.1,
        None,
    )
    .await
    .map_err(|error| error.to_string())
}

#[cfg(feature = "nexus-native-tunnel")]
#[derive(Debug)]
struct GatewayConfig {
    credential_path: PathBuf,
    peer_id: String,
    bind_addr: SocketAddr,
    token: String,
    device_uid: String,
    control_plane_url: String,
    grant_id: String,
}

#[cfg(feature = "nexus-native-tunnel")]
fn gateway_config_from_values(
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

fn require_https_control_plane(control_plane_url: &str) -> Result<(), String> {
    reqwest::Url::parse(control_plane_url)
        .ok()
        .filter(|url| url.scheme() == "https")
        .map(|_| ())
        .ok_or_else(|| "Nexus control-plane URL must use HTTPS".into())
}

fn is_loopback_http(control_plane_url: &str) -> bool {
    reqwest::Url::parse(control_plane_url).is_ok_and(|url| {
        url.scheme() == "http"
            && url.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            })
    })
}

#[cfg(feature = "nexus-agent")]
fn agent_loopback_http_allowed(control_plane_url: &str) -> bool {
    // Test-only process harness escape hatch. Production builds never enable
    // `nexus-e2e-host`; deployed Agent callbacks remain HTTPS-only.
    cfg!(feature = "nexus-e2e-host")
        && std::env::var("NEXUS_E2E_ALLOW_LOOPBACK_HTTP").as_deref() == Ok("1")
        && is_loopback_http(control_plane_url)
}

impl TunnelHostConfig {
    const DEVICE_UID_OPTION: &'static str = "nexus-device-uid";
    const CONTROL_PLANE_URL_OPTION: &'static str = "nexus-control-plane-url";
    const PRESENCE_GATEWAY_OPTION: &'static str = "nexus-presence-gateway";
    const PRESENCE_BIND_OPTION: &'static str = "nexus-presence-bind";

    /// Reads the explicit Nexus deployment options from the existing RustDesk
    /// configuration store. This is intentionally separate from parsing so
    /// callers can test their deployment input without mutating global config.
    pub fn from_rustdesk_config() -> Result<Self, &'static str> {
        Self::parse(
            &Config::get_option(Self::DEVICE_UID_OPTION),
            &Config::get_option(Self::CONTROL_PLANE_URL_OPTION),
            &Config::get_option(Self::PRESENCE_GATEWAY_OPTION),
            &Config::get_option(Self::PRESENCE_BIND_OPTION),
        )
    }

    pub fn parse(
        device_uid: &str,
        control_plane_url: &str,
        presence_gateway: &str,
        presence_bind: &str,
    ) -> Result<Self, &'static str> {
        if device_uid.trim().is_empty() {
            return Err("Nexus device UID is not configured");
        }
        if control_plane_url.trim().is_empty() {
            return Err("Nexus control-plane URL is not configured");
        }
        let presence_gateway = presence_gateway
            .parse()
            .map_err(|_| "Nexus Presence Gateway address is invalid")?;
        let presence_bind = if presence_bind.trim().is_empty() {
            "0.0.0.0:0".parse().expect("static socket address is valid")
        } else {
            presence_bind
                .parse()
                .map_err(|_| "Nexus Presence bind address is invalid")?
        };
        Ok(Self {
            device_uid: device_uid.trim().into(),
            control_plane_url: control_plane_url.trim().trim_end_matches('/').into(),
            presence_gateway,
            presence_bind,
        })
    }
}

struct HostServiceTask {
    cancellation: hbb_common::tokio_util::sync::CancellationToken,
    task: hbb_common::tokio::task::JoinHandle<()>,
}

fn host_service_slot() -> &'static Mutex<Option<HostServiceTask>> {
    static HOST_SERVICE: OnceLock<Mutex<Option<HostServiceTask>>> = OnceLock::new();
    HOST_SERVICE.get_or_init(|| Mutex::new(None))
}

#[cfg(feature = "nexus-frp-compat-smoke")]
/// Keeps FRP task ownership at the RustDesk host boundary; the shared runtime
/// itself remains a synchronous, testable Desired State lifecycle owner.
struct DataPlaneSlot {
    generation: ConfigGeneration,
    /// The upstream reload retains one task; this reference gives its callbacks
    /// the currently committed generation instead of the spawn-time one.
    task_generation: Arc<Mutex<ConfigGeneration>>,
    cancellation: FrpCancellationToken,
    frp: FrpRuntime,
    /// Last committed signed inputs, retained so a failed reload can restore
    /// the previously serving upstream configuration before reporting failure.
    desired_state: nexus_client::tunnel::TunnelDesiredState,
    assignment: nexus_client::tunnel::TunnelDataPlaneAssignment,
    local_addr_overrides: Vec<(String, String)>,
    application: Option<GenerationApplication>,
}

#[cfg(feature = "nexus-frp-compat-smoke")]
fn data_plane_slot() -> &'static Mutex<Option<DataPlaneSlot>> {
    static DATA_PLANE: OnceLock<Mutex<Option<DataPlaneSlot>>> = OnceLock::new();
    DATA_PLANE.get_or_init(|| Mutex::new(None))
}

#[cfg(feature = "nexus-frp-compat-smoke")]
struct AuxiliarySlot {
    cancellation: FrpCancellationToken,
    tasks: Vec<hbb_common::tokio::task::JoinHandle<()>>,
    /// Ephemeral bridges bound before their FRP generation is committed.
    local_addr_overrides: Vec<(String, String)>,
}

#[cfg(feature = "nexus-frp-compat-smoke")]
/// Identifies the signed generation that owns a running FRP task's outcome.
/// The task reports only while this exact generation remains current, so an
/// old connection failure cannot overwrite a replacement's application state.
#[derive(Clone)]
struct GenerationApplication {
    control_plane_url: String,
    version: u64,
    digest_hex: String,
}

#[cfg(feature = "nexus-frp-compat-smoke")]
/// Returns the reporting context only when the completed task still owns the
/// current signed generation. This prevents a replaced FRP task from writing a
/// stale outcome after an atomic reload.
fn application_for_generation(
    current_generation: ConfigGeneration,
    application: Option<GenerationApplication>,
    completed_generation: ConfigGeneration,
) -> Option<GenerationApplication> {
    (current_generation == completed_generation)
        .then_some(application)
        .flatten()
}

#[cfg(feature = "nexus-frp-compat-smoke")]
fn auxiliary_slot() -> &'static Mutex<Option<AuxiliarySlot>> {
    static AUXILIARY: OnceLock<Mutex<Option<AuxiliarySlot>>> = OnceLock::new();
    AUXILIARY.get_or_init(|| Mutex::new(None))
}

pub struct RuntimeGuard {
    // The production guard has no synchronization responsibility. Tests share
    // one process-global runtime slot, so its owner must remain exclusive.
    #[cfg(test)]
    _test_runtime_lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
fn test_runtime_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        stop_runtime();
    }
}

/// Builds NexusFlow runtime input from the native RustDesk identity.
///
/// The caller remains responsible for obtaining the ID through RustDesk's
/// existing identity path; NexusFlow never generates a replacement ID.
pub fn runtime_config(
    rustdesk_id: impl Into<String>,
    config_dir: impl Into<PathBuf>,
) -> RuntimeConfig {
    RuntimeConfig::new(rustdesk_id, config_dir)
}

pub fn start_runtime(
    rustdesk_id: impl Into<String>,
    config_dir: impl Into<PathBuf>,
) -> RuntimeGuard {
    #[cfg(test)]
    let test_runtime_lock = test_runtime_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut runtime = NexusRuntime::new(runtime_config(rustdesk_id, config_dir));
    runtime.start();
    *runtime_slot().lock().unwrap() = Some(runtime);
    RuntimeGuard {
        #[cfg(test)]
        _test_runtime_lock: test_runtime_lock,
    }
}

pub fn stop_runtime() {
    if let Some(task) = host_service_slot().lock().unwrap().take() {
        task.cancellation.cancel();
        task.task.abort();
    }
    #[cfg(feature = "nexus-frp-compat-smoke")]
    cancel_data_plane();
    #[cfg(feature = "nexus-frp-compat-smoke")]
    cancel_auxiliary();
    let mut slot = runtime_slot().lock().unwrap();
    if let Some(runtime) = slot.as_mut() {
        runtime.stop();
    }
    *slot = None;
    *host_control_plane_url().lock().unwrap() = None;
}

#[cfg(feature = "nexus-frp-compat-smoke")]
fn cancel_auxiliary() {
    if let Some(slot) = auxiliary_slot().lock().unwrap().take() {
        slot.cancellation.cancel();
        for task in slot.tasks {
            task.abort();
        }
    }
}

#[cfg(feature = "nexus-frp-compat-smoke")]
async fn prepare_auxiliary(
    desired: &nexus_client::tunnel::TunnelDesiredState,
    assignment: Option<&nexus_client::tunnel::TunnelDataPlaneAssignment>,
) -> Result<Option<AuxiliarySlot>, String> {
    if desired.visitors.is_empty()
        && desired.local_access_listeners.is_empty()
        && desired.https_upstream_plugins.is_empty()
    {
        return Ok(None);
    }
    let cancellation = FrpCancellationToken::new();
    // Bind and validate the whole replacement before spawning it: a later
    // rejected listener must not leave an earlier visitor running.
    let mut runners: Vec<Pin<Box<dyn Future<Output = ()> + Send>>> = Vec::new();
    let mut local_addr_overrides = Vec::new();
    for plugin in &desired.https_upstream_plugins {
        let service = desired
            .services
            .iter()
            .find(|service| service.service_id == plugin.service_id)
            .ok_or_else(|| "HTTPS upstream service is unavailable".to_string())?;
        let runtime =
            HttpsUpstreamRuntime::bind(service.local_addr.clone(), plugin.server_name.clone())
                .await
                .map_err(|_| "HTTPS upstream bridge bind failed".to_string())?;
        let local_addr = runtime
            .local_addr()
            .map_err(|_| "HTTPS upstream bridge address failed".to_string())?;
        local_addr_overrides.push((plugin.service_id.clone(), local_addr.to_string()));
        let cancellation = cancellation.clone();
        runners.push(Box::pin(async move {
            let _ = runtime.run(cancellation).await;
        }));
    }
    for visitor in &desired.visitors {
        let relay = assignment
            .map(|value| &value.relay)
            .ok_or_else(|| "Tunnel visitor requires a Relay assignment".to_string())?;
        let runtime = FrpVisitorRuntime::new(visitor, relay)
            .map_err(|_| "Tunnel visitor configuration was rejected".to_string())?;
        let cancellation = cancellation.clone();
        runners.push(Box::pin(async move {
            let _ = runtime.run(cancellation).await;
        }));
    }
    for listener in &desired.local_access_listeners {
        match listener.protocol {
            LocalAccessProtocol::HttpConnect => {
                let runtime = HttpConnectRuntime::bind(listener)
                    .await
                    .map_err(|_| "HTTP CONNECT listener bind failed".to_string())?;
                let cancellation = cancellation.clone();
                runners.push(Box::pin(async move {
                    let _ = runtime.run(cancellation).await;
                }));
            }
            LocalAccessProtocol::Socks5 => {
                let runtime = Socks5Runtime::bind(listener)
                    .await
                    .map_err(|_| "SOCKS5 listener bind failed".to_string())?;
                let cancellation = cancellation.clone();
                runners.push(Box::pin(async move {
                    let _ = runtime.run(cancellation).await;
                }));
            }
        }
    }
    let tasks = runners.into_iter().map(hbb_common::tokio::spawn).collect();
    Ok(Some(AuxiliarySlot {
        cancellation,
        tasks,
        local_addr_overrides,
    }))
}

#[cfg(feature = "nexus-frp-compat-smoke")]
fn install_auxiliary(next: Option<AuxiliarySlot>) {
    cancel_auxiliary();
    *auxiliary_slot().lock().unwrap() = next;
}

#[cfg(feature = "nexus-frp-compat-smoke")]
/// Stops a pre-bound replacement that never became the committed generation.
fn cancel_prepared_auxiliary(slot: &Option<AuxiliarySlot>) {
    if let Some(slot) = slot {
        slot.cancellation.cancel();
    }
}

/// Starts the production-owned Tunnel loop after the RustDesk runtime exists.
///
/// The loop owns only network sessions. The native service retains the runtime
/// guard and stops this loop before destroying the lifecycle state machine.
/// A malformed or absent deployment configuration fails closed without
/// changing RustDesk remote-desktop startup.
pub fn start_host_service(config: TunnelHostConfig) -> Result<(), &'static str> {
    bind_device_uid(config.device_uid.clone())?;
    let handle = hbb_common::tokio::runtime::Handle::try_current()
        .map_err(|_| "Nexus host service requires the RustDesk Tokio runtime")?;
    let control_plane_url = config.control_plane_url.clone();
    // IPC refresh requests use this operator-supplied, HTTPS-validated URL;
    // callers cannot replace it with an arbitrary endpoint or payload.
    *host_control_plane_url().lock().unwrap() = Some(control_plane_url);
    let cancellation = hbb_common::tokio_util::sync::CancellationToken::new();
    let task = handle.spawn(run_host_service(config, cancellation.clone()));
    let mut slot = host_service_slot().lock().unwrap();
    if let Some(previous) = slot.replace(HostServiceTask { cancellation, task }) {
        previous.cancellation.cancel();
        previous.task.abort();
    }
    Ok(())
}

const PRESENCE_RETRY_MAX_SECS: u64 = 30;

fn new_presence_boot_uuid() -> uuid::Uuid {
    // UUID v4 draws from the operating-system CSPRNG. A new client starts its
    // packet sequence at zero, so every registration needs a fresh nonce domain.
    uuid::Uuid::new_v4()
}

fn next_presence_boot_id() -> u32 {
    new_presence_boot_uuid().as_u128() as u32
}

fn next_presence_retry_secs(current: u64) -> u64 {
    current.clamp(1, PRESENCE_RETRY_MAX_SECS)
}

type PresenceFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

struct PresenceHostOps<S> {
    refresh: Box<dyn FnMut() -> PresenceFuture<()> + Send>,
    establish: Box<dyn FnMut(u32) -> PresenceFuture<Result<S, String>> + Send>,
    heartbeat: Box<
        dyn for<'a> FnMut(
                &'a mut S,
            )
                -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>
            + Send,
    >,
    heartbeat_interval_secs: Box<dyn Fn() -> u64 + Send>,
    lease_needs_refresh: Box<dyn Fn(&S) -> bool + Send>,
    sleep: Box<dyn FnMut(u64) -> PresenceFuture<()> + Send>,
    next_boot_id: Box<dyn FnMut() -> u32 + Send>,
}

async fn run_presence_loop<S>(
    mut ops: PresenceHostOps<S>,
    cancellation: hbb_common::tokio_util::sync::CancellationToken,
) {
    let mut retry_secs = 1;
    loop {
        hbb_common::tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = (ops.refresh)() => {},
        }
        let boot_id = (ops.next_boot_id)();
        let mut session = match hbb_common::tokio::select! {
            _ = cancellation.cancelled() => return,
            result = (ops.establish)(boot_id) => result,
        } {
            Ok(session) => {
                retry_secs = 1;
                session
            }
            Err(error) => {
                hbb_common::log::warn!("Nexus Tunnel Presence registration failed: {error}");
                hbb_common::tokio::select! {
                    _ = cancellation.cancelled() => return,
                    _ = (ops.sleep)(retry_secs) => {},
                }
                retry_secs = next_presence_retry_secs(retry_secs.saturating_mul(2));
                continue;
            }
        };

        loop {
            if let Err(error) = hbb_common::tokio::select! {
                _ = cancellation.cancelled() => return,
                result = (ops.heartbeat)(&mut session) => result,
            } {
                hbb_common::log::warn!("Nexus Tunnel Presence heartbeat failed: {error}");
                break;
            }
            hbb_common::tokio::select! {
                _ = cancellation.cancelled() => return,
                _ = (ops.sleep)((ops.heartbeat_interval_secs)()) => {},
            }
            if (ops.lease_needs_refresh)(&session) {
                // A configured fixed bind cannot host two UDP sessions. Release
                // the old lease before creating its fresh boot-ID replacement.
                drop(session);
                match hbb_common::tokio::select! {
                    _ = cancellation.cancelled() => return,
                    result = (ops.establish)((ops.next_boot_id)()) => result,
                } {
                    Ok(replacement) => session = replacement,
                    Err(error) => {
                        hbb_common::log::warn!(
                            "Nexus Tunnel Presence lease refresh failed: {error}"
                        );
                        break;
                    }
                }
            }
            hbb_common::tokio::select! {
                _ = cancellation.cancelled() => return,
                _ = (ops.refresh)() => {},
            }
        }
        hbb_common::tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = (ops.sleep)(retry_secs) => {},
        }
        retry_secs = next_presence_retry_secs(retry_secs.saturating_mul(2));
    }
}

async fn run_host_service(
    config: TunnelHostConfig,
    cancellation: hbb_common::tokio_util::sync::CancellationToken,
) {
    let control_plane_url = config.control_plane_url;
    let refresh_url = control_plane_url.clone();
    let establish_url = control_plane_url.clone();
    let presence_bind = config.presence_bind;
    let presence_gateway = config.presence_gateway;
    #[cfg(feature = "nexus-agent")]
    let agent_task = hbb_common::tokio::spawn(run_agent_socket_loop(
        control_plane_url.clone(),
        cancellation.clone(),
    ));
    run_presence_loop(
        PresenceHostOps {
            refresh: Box::new(move || {
                let control_plane_url = refresh_url.clone();
                Box::pin(async move {
                    if let Err(error) = refresh_tunnel_desired_state(&control_plane_url).await {
                        hbb_common::log::warn!(
                            "Nexus Tunnel Desired State refresh failed: {error}"
                        );
                    }
                })
            }),
            establish: Box::new(move |boot_id| {
                let control_plane_url = establish_url.clone();
                Box::pin(async move {
                    establish_presence_session(
                        &control_plane_url,
                        presence_bind,
                        presence_gateway,
                        boot_id,
                    )
                    .await
                })
            }),
            heartbeat: Box::new(|session| {
                Box::pin(async move {
                    let (config_version, config_digest) = status_snapshot()
                        .map(|status| {
                            (
                                status.tunnel.desired_version.unwrap_or_default(),
                                status.tunnel.desired_digest.unwrap_or_default(),
                            )
                        })
                        .unwrap_or_default();
                    session
                        .send_heartbeat(PresenceHeartbeat {
                            config_version,
                            config_digest,
                            capability_digest: 0,
                        })
                        .await
                })
            }),
            heartbeat_interval_secs: Box::new(|| {
                status_snapshot()
                    .and_then(|_| {
                        runtime_slot()
                            .lock()
                            .unwrap()
                            .as_ref()
                            .and_then(|runtime| runtime.tunnel().desired_state())
                            .map(|desired| desired.policy.presence_interval_secs.into())
                    })
                    .unwrap_or(30)
            }),
            lease_needs_refresh: Box::new(|session| {
                let interval_secs = status_snapshot()
                    .and_then(|_| {
                        runtime_slot()
                            .lock()
                            .unwrap()
                            .as_ref()
                            .and_then(|runtime| runtime.tunnel().desired_state())
                            .map(|desired| desired.policy.presence_interval_secs)
                    })
                    .unwrap_or(30);
                session.lease().expires_at
                    <= hbb_common::get_time().saturating_add(interval_secs.into())
            }),
            sleep: Box::new(|secs| {
                Box::pin(hbb_common::tokio::time::sleep(Duration::from_secs(secs)))
            }),
            next_boot_id: Box::new(next_presence_boot_id),
        },
        cancellation,
    )
    .await;
    #[cfg(feature = "nexus-agent")]
    agent_task.abort();
}

#[cfg(feature = "nexus-agent")]
const AGENT_SOCKET_CONNECT_TIMEOUT_MS: u64 = 10_000;
#[cfg(feature = "nexus-agent")]
const AGENT_SOCKET_RETRY_MAX_SECS: u64 = 30;
#[cfg(feature = "nexus-agent")]
const AGENT_SOCKET_REFRESH_SKEW_MS: i64 = 5_000;
#[cfg(feature = "nexus-agent")]
const AGENT_MAX_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1_000;
#[cfg(feature = "nexus-agent")]
const AGENT_MAX_PROMPT_BYTES: usize = 64 * 1_024;
#[cfg(feature = "nexus-agent")]
const AGENT_QUEUE_CAPACITY: usize = 32;
#[cfg(feature = "nexus-agent")]
const AGENT_FINISH_RETRY_DELAYS_SECS: [u64; 5] = [1, 2, 5, 10, 30];

/// Keeps the machine-bound Agent channel independent from Presence. A broken
/// task connection is retried with a fresh short-lived credential; it never
/// stops RustDesk's remote-desktop or Tunnel host loop.
#[cfg(feature = "nexus-agent")]
async fn run_agent_socket_loop(
    control_plane_url: String,
    cancellation: hbb_common::tokio_util::sync::CancellationToken,
) {
    let mut retry_secs = 1;
    loop {
        set_agent_health(AgentHealthState::Connecting);
        let result = match request_machine_socket_lease(&control_plane_url).await {
            Ok(lease) => {
                run_agent_socket_session(&control_plane_url, lease, cancellation.clone()).await
            }
            Err(error) => Err(error),
        };
        if cancellation.is_cancelled() {
            set_agent_health(AgentHealthState::Stopping);
            return;
        }
        if let Err(error) = result {
            set_agent_health(AgentHealthState::Degraded);
            hbb_common::log::warn!("Nexus Agent Socket disconnected: {error}");
        }
        hbb_common::tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = hbb_common::tokio::time::sleep(Duration::from_secs(retry_secs)) => {}
        }
        retry_secs = retry_secs
            .saturating_mul(2)
            .clamp(1, AGENT_SOCKET_RETRY_MAX_SECS);
    }
}

#[cfg(feature = "nexus-agent")]
fn set_agent_health(health: AgentHealthState) {
    if let Ok(mut runtime) = runtime_slot().lock() {
        if let Some(runtime) = runtime.as_mut() {
            runtime.set_agent_health(health);
        }
    }
}

#[cfg(feature = "nexus-agent")]
fn set_agent_queue_depth(depth: usize) {
    if let Ok(mut runtime) = runtime_slot().lock() {
        if let Some(runtime) = runtime.as_mut() {
            runtime.set_agent_queue_depth(depth);
        }
    }
}

#[cfg(feature = "nexus-agent")]
fn agent_socket_endpoint(control_plane_url: &str) -> Result<String, String> {
    let mut url = reqwest::Url::parse(control_plane_url)
        .map_err(|_| "Nexus control-plane URL is invalid".to_string())?;
    if url.scheme() != "https" {
        return Err("Nexus control-plane URL must use HTTPS".into());
    }
    url.set_scheme("wss")
        .map_err(|_| "Nexus control-plane URL is invalid".to_string())?;
    url.set_path("/v1/updates/");
    url.set_query(Some("EIO=4&transport=websocket"));
    Ok(url.into())
}

#[cfg(feature = "nexus-agent")]
async fn run_agent_socket_session(
    control_plane_url: &str,
    lease: MachineSocketLease,
    cancellation: hbb_common::tokio_util::sync::CancellationToken,
) -> Result<(), String> {
    let endpoint = agent_socket_endpoint(control_plane_url)?;
    #[cfg(feature = "nexus-e2e-host")]
    let allow_e2e_self_signed_cert =
        std::env::var("NEXUS_E2E_ALLOW_INVALID_AGENT_TLS").as_deref() == Ok("1");
    #[cfg(not(feature = "nexus-e2e-host"))]
    let allow_e2e_self_signed_cert = false;
    // The process harness owns a one-day loopback TLS terminator. Production
    // builds have no escape hatch and always retain strict certificate checks.
    let mut socket = if allow_e2e_self_signed_cert {
        WsFramedStream::new(endpoint, None, None, AGENT_SOCKET_CONNECT_TIMEOUT_MS).await
    } else {
        WsFramedStream::new_strict(endpoint, None, None, AGENT_SOCKET_CONNECT_TIMEOUT_MS).await
    }
    .map_err(|_| "Nexus Agent Socket connection failed".to_string())?;
    let refresh_after = lease
        .expires_at
        .saturating_sub(hbb_common::get_time())
        .saturating_sub(AGENT_SOCKET_REFRESH_SKEW_MS);
    hbb_common::tokio::select! {
        result = run_agent_socket_frames(&mut socket, control_plane_url, lease, cancellation) => result,
        _ = hbb_common::tokio::time::sleep(Duration::from_millis(refresh_after as u64)) => Err("Nexus Agent Socket credential needs refresh".into()),
    }
}

#[cfg(feature = "nexus-agent")]
async fn run_agent_socket_frames(
    socket: &mut WsFramedStream,
    control_plane_url: &str,
    lease: MachineSocketLease,
    cancellation: hbb_common::tokio_util::sync::CancellationToken,
) -> Result<(), String> {
    let opening = next_agent_socket_frame(socket, &cancellation).await?;
    if !opening.starts_with('0') {
        return Err("Nexus Agent Socket did not send an Engine.IO handshake".into());
    }
    socket
        .send_text(format!(
            "40{}",
            serde_json::json!({
                "token": lease.token,
                "clientType": "machine-scoped",
                "machineId": lease.machine_id,
            })
        ))
        .await
        .map_err(|_| "Nexus Agent Socket authentication failed".to_string())?;

    loop {
        let frame = next_agent_socket_frame(socket, &cancellation).await?;
        if frame == "2" {
            socket
                .send_text("3")
                .await
                .map_err(|_| "Nexus Agent Socket heartbeat failed".to_string())?;
            continue;
        }
        if frame.starts_with("44") {
            return Err("Nexus Agent Socket authentication rejected".into());
        }
        if frame.starts_with("40") {
            break;
        }
    }

    send_agent_socket_event(
        socket,
        "rpc-register",
        &serde_json::json!({
            "method": format!("{}:orchestrator-dispatch", lease.machine_id),
        }),
    )
    .await?;
    send_agent_socket_event(
        socket,
        "rpc-register",
        &serde_json::json!({
            "method": format!("{}:orchestrator-cancel", lease.machine_id),
        }),
    )
    .await?;

    let mut ready = false;
    let mut pending_registrations = 2_u8;
    let (completed_sender, mut completed_receiver) =
        hbb_common::tokio::sync::mpsc::unbounded_channel::<()>();
    let mut queued: VecDeque<AgentDispatch> = VecDeque::with_capacity(AGENT_QUEUE_CAPACITY);
    set_agent_queue_depth(0);
    loop {
        let frame = hbb_common::tokio::select! {
            _ = cancellation.cancelled() => return Err("Nexus Agent Socket cancelled".into()),
            Some(()) = completed_receiver.recv() => {
                if let Some(dispatch) = queued.pop_front() {
                    if !launch_dispatched_agent(
                        control_plane_url,
                        &lease.machine_id,
                        dispatch.clone(),
                        cancellation.clone(),
                        completed_sender.clone(),
                    ) {
                        // A poisoned admission lock is recoverable; keep the
                        // FIFO item instead of silently losing an execution.
                        // ponytail: retry on the next Socket event; no second
                        // supervisor is needed for this process-local lock.
                        retain_queued_agent(&mut queued, dispatch);
                    }
                }
                set_agent_queue_depth(queued.len());
                continue;
            }
            frame = socket.next() => frame,
        }
        .ok_or_else(|| "Nexus Agent Socket closed".to_string())?
        .map_err(|_| "Nexus Agent Socket read failed".to_string())?;
        let frame = String::from_utf8(frame.to_vec())
            .map_err(|_| "Nexus Agent Socket sent invalid UTF-8".to_string())?;
        if frame == "2" {
            socket
                .send_text("3")
                .await
                .map_err(|_| "Nexus Agent Socket heartbeat failed".to_string())?;
            continue;
        }
        let Some((ack_id, event, payload)) = parse_agent_socket_event(&frame) else {
            continue;
        };
        if event == "rpc-registered" {
            pending_registrations = pending_registrations.saturating_sub(1);
            if pending_registrations == 0 {
                ready = true;
                set_agent_health(AgentHealthState::Ready);
            }
            continue;
        }
        if event != "rpc-request" {
            continue;
        }
        let expected_method = format!("{}:orchestrator-dispatch", lease.machine_id);
        let cancel_method = format!("{}:orchestrator-cancel", lease.machine_id);
        let accepted = ready
            && match serde_json::from_value::<AgentRpcRequest>(payload) {
                Ok(request) if request.method == expected_method => {
                    match serde_json::from_value::<AgentDispatch>(request.params) {
                        Ok(dispatch) => queue_or_launch_agent(
                            control_plane_url,
                            &lease.machine_id,
                            dispatch,
                            cancellation.clone(),
                            completed_sender.clone(),
                            &mut queued,
                        ),
                        Err(_) => false,
                    }
                }
                Ok(request) if request.method == cancel_method => {
                    serde_json::from_value::<AgentCancellation>(request.params)
                        .map(|request| {
                            remove_queued_agent(&mut queued, &request.execution_id)
                                || cancel_active_agent(&request.execution_id)
                        })
                        .unwrap_or(false)
                }
                _ => false,
            };
        set_agent_queue_depth(queued.len());
        if let Some(ack_id) = ack_id {
            socket
                .send_text(format!(
                    "43{ack_id}{}",
                    serde_json::json!([{ "accepted": accepted }])
                ))
                .await
                .map_err(|_| "Nexus Agent Socket acknowledgment failed".to_string())?;
        }
    }
}

#[cfg(feature = "nexus-agent")]
fn queue_or_launch_agent(
    control_plane_url: &str,
    machine_id: &str,
    dispatch: AgentDispatch,
    cancellation: hbb_common::tokio_util::sync::CancellationToken,
    completed_sender: hbb_common::tokio::sync::mpsc::UnboundedSender<()>,
    queued: &mut VecDeque<AgentDispatch>,
) -> bool {
    if active_agent_cancellations()
        .lock()
        .ok()
        .is_some_and(|active| active.contains_key(&dispatch.execution_id))
        || queued
            .iter()
            .any(|queued| queued.execution_id == dispatch.execution_id)
    {
        return false;
    }
    if launch_dispatched_agent(
        control_plane_url,
        machine_id,
        dispatch.clone(),
        cancellation.clone(),
        completed_sender.clone(),
    ) {
        return true;
    }
    enqueue_agent_dispatch(queued, dispatch)
}

#[cfg(feature = "nexus-agent")]
fn enqueue_agent_dispatch(queued: &mut VecDeque<AgentDispatch>, dispatch: AgentDispatch) -> bool {
    if queued.len() >= AGENT_QUEUE_CAPACITY
        || queued
            .iter()
            .any(|queued| queued.execution_id == dispatch.execution_id)
    {
        return false;
    }
    queued.push_back(dispatch);
    true
}

#[cfg(feature = "nexus-agent")]
fn remove_queued_agent(queued: &mut VecDeque<AgentDispatch>, execution_id: &str) -> bool {
    queued
        .iter()
        .position(|queued| queued.execution_id == execution_id)
        .map(|index| queued.remove(index))
        .is_some()
}

#[cfg(feature = "nexus-agent")]
fn retain_queued_agent(queued: &mut VecDeque<AgentDispatch>, dispatch: AgentDispatch) {
    queued.push_front(dispatch);
}

#[cfg(feature = "nexus-agent")]
fn launch_dispatched_agent(
    control_plane_url: &str,
    machine_id: &str,
    dispatch: AgentDispatch,
    cancellation: hbb_common::tokio_util::sync::CancellationToken,
    completed_sender: hbb_common::tokio::sync::mpsc::UnboundedSender<()>,
) -> bool {
    let Some(job_cancellation) = register_agent_cancellation(&dispatch.execution_id) else {
        return false;
    };
    let control_plane_url = control_plane_url.to_string();
    let machine_id = machine_id.to_string();
    hbb_common::tokio::spawn(async move {
        run_dispatched_agent(
            control_plane_url,
            machine_id,
            dispatch,
            cancellation,
            job_cancellation,
        )
        .await;
        let _ = completed_sender.send(());
    });
    true
}

#[cfg(feature = "nexus-agent")]
async fn next_agent_socket_frame(
    socket: &mut WsFramedStream,
    cancellation: &hbb_common::tokio_util::sync::CancellationToken,
) -> Result<String, String> {
    let frame = hbb_common::tokio::select! {
        _ = cancellation.cancelled() => return Err("Nexus Agent Socket cancelled".into()),
        frame = socket.next() => frame,
    }
    .ok_or_else(|| "Nexus Agent Socket closed".to_string())?
    .map_err(|_| "Nexus Agent Socket read failed".to_string())?;
    String::from_utf8(frame.to_vec()).map_err(|_| "Nexus Agent Socket sent invalid UTF-8".into())
}

#[cfg(feature = "nexus-agent")]
async fn send_agent_socket_event(
    socket: &mut WsFramedStream,
    event: &str,
    payload: &serde_json::Value,
) -> Result<(), String> {
    socket
        .send_text(format!("42{}", serde_json::json!([event, payload])))
        .await
        .map_err(|_| "Nexus Agent Socket write failed".to_string())
}

#[cfg(feature = "nexus-agent")]
fn parse_agent_socket_event(frame: &str) -> Option<(Option<&str>, String, serde_json::Value)> {
    let body = frame.strip_prefix("42")?;
    let array_at = body.find('[')?;
    let ack_id = (!body[..array_at].is_empty()).then_some(&body[..array_at]);
    let values: Vec<serde_json::Value> = serde_json::from_str(&body[array_at..]).ok()?;
    let event = values.first()?.as_str()?.to_string();
    Some((
        ack_id,
        event,
        values.get(1).cloned().unwrap_or(serde_json::Value::Null),
    ))
}

#[cfg(feature = "nexus-agent")]
fn agent_job_from_dispatch(
    dispatch: &AgentDispatch,
    machine_id: &str,
) -> Result<nexus_client::agent::AgentJob, &'static str> {
    let provider = dispatch.provider.trim();
    if !matches!(provider, "codex" | "claude" | "gemini" | "openclaw")
        || dispatch.execution_id.trim().is_empty()
        || !dispatch
            .execution_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        || dispatch.dispatch_token.trim().is_empty()
        || dispatch.tenant_id.trim().is_empty()
        || dispatch.prompt.len() > AGENT_MAX_PROMPT_BYTES
        || dispatch.timeout_ms == 0
        || dispatch.timeout_ms > AGENT_MAX_TIMEOUT_MS
    {
        return Err("invalid Agent dispatch");
    }
    let mut args: Vec<String> = (provider == "codex")
        .then(|| "exec".to_string())
        .into_iter()
        .collect();
    if let Some(model) = dispatch.model.as_deref().filter(|model| !model.is_empty()) {
        if model.len() > 128
            || !model
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        {
            return Err("invalid Agent model");
        }
        args.extend(["--model".to_string(), model.to_string()]);
    }
    // `--` prevents the untrusted prompt from becoming a process option. The
    // child itself receives no shell, stdin, inherited RustDesk credentials,
    // or control-plane bearer.
    args.extend(["--".to_string(), dispatch.prompt.clone()]);
    let device_uid = runtime_slot()
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|runtime| runtime.config().identity.device_uid.clone())
        .ok_or("Nexus device is not enrolled")?;
    Ok(nexus_client::agent::AgentJob {
        job_id: dispatch.execution_id.clone(),
        tenant_id: dispatch.tenant_id.clone(),
        device_uid,
        machine_id: machine_id.to_string(),
        provider: provider.to_string(),
        program: std::path::PathBuf::from(provider),
        args,
        timeout_ms: dispatch.timeout_ms,
    })
}

#[cfg(feature = "nexus-agent")]
async fn run_dispatched_agent(
    control_plane_url: String,
    machine_id: String,
    dispatch: AgentDispatch,
    cancellation: hbb_common::tokio_util::sync::CancellationToken,
    job_cancellation: hbb_common::tokio_util::sync::CancellationToken,
) {
    let _active = ActiveAgentCancellationGuard(dispatch.execution_id.clone());
    let Ok(job) = agent_job_from_dispatch(&dispatch, &machine_id) else {
        let _ = report_agent_execution_finish(
            &control_plane_url,
            &dispatch,
            "failed",
            None,
            Some("invalid_dispatch"),
        )
        .await;
        return;
    };
    #[cfg(all(feature = "nexus-agent", feature = "nexus-native-tunnel"))]
    let (local_proxy, tunnel) = if dispatch.tunnel_access {
        match prepare_agent_execution_tunnel(&control_plane_url, &dispatch.execution_id).await {
            Ok(prepared) => (Some(prepared.0), Some(prepared.1)),
            Err(_) => {
                let _ = report_agent_execution_finish(
                    &control_plane_url,
                    &dispatch,
                    "failed",
                    None,
                    Some("agent_tunnel_unavailable"),
                )
                .await;
                return;
            }
        }
    } else {
        (None, None)
    };
    #[cfg(not(feature = "nexus-native-tunnel"))]
    if dispatch.tunnel_access {
        let _ = report_agent_execution_finish(
            &control_plane_url,
            &dispatch,
            "failed",
            None,
            Some("agent_tunnel_unavailable"),
        )
        .await;
        return;
    }
    #[cfg(not(feature = "nexus-native-tunnel"))]
    let local_proxy: Option<nexus_client::agent::AgentLocalProxy> = None;
    let process = runtime_slot()
        .lock()
        .unwrap()
        .as_ref()
        .ok_or(())
        .and_then(|runtime| {
            runtime
                .spawn_agent_job_with_local_proxy(&job, &machine_id, local_proxy.as_ref())
                .map_err(|_| ())
        });
    let Ok(mut process) = process else {
        let _ = report_agent_execution_finish(
            &control_plane_url,
            &dispatch,
            "failed",
            None,
            Some("agent_spawn_failed"),
        )
        .await;
        return;
    };
    if report_agent_execution_start(&control_plane_url, &dispatch)
        .await
        .is_err()
    {
        let _ = process.cancel();
        return;
    }
    let (status, exit_code, error_code) = loop {
        match process.poll() {
            Ok(Some(exit)) => break agent_exit_status(&exit),
            Ok(None) => {}
            Err(_) => break ("failed", None, Some("agent_wait_failed")),
        }
        hbb_common::tokio::select! {
            _ = cancellation.cancelled() => {
                let exit = process.cancel().ok();
                break ("cancelled", exit.and_then(|exit| exit.exit_code), Some("host_stopped"));
            }
            _ = job_cancellation.cancelled() => {
                let exit = process.cancel().ok();
                break ("cancelled", exit.and_then(|exit| exit.exit_code), Some("remote_cancelled"));
            }
            _ = hbb_common::tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    };
    #[cfg(feature = "nexus-native-tunnel")]
    drop(tunnel);
    // Release the per-Host admission before finish triggers an in-memory
    // retry scheduler tick. A retry receives a fresh execution/grant and
    // must not be rejected while this completed child still holds the guard.
    drop(_active);
    let _ =
        report_agent_execution_finish(&control_plane_url, &dispatch, status, exit_code, error_code)
            .await;
}

#[cfg(all(feature = "nexus-agent", feature = "nexus-native-tunnel"))]
struct AgentExecutionTunnel {
    execution_id: String,
    target: (String, i32),
    capabilities: Arc<nexus_client::local_proxy::LocalProxyCapabilities>,
    proxy: nexus_client::local_proxy::LoopbackProxy,
    listener_close: hbb_common::tokio::sync::mpsc::UnboundedSender<crate::client::Data>,
    listener: hbb_common::tokio::task::JoinHandle<()>,
}

#[cfg(all(feature = "nexus-agent", feature = "nexus-native-tunnel"))]
impl Drop for AgentExecutionTunnel {
    fn drop(&mut self) {
        self.capabilities.revoke(&self.execution_id);
        crate::nexus::remove_execution_port_forward_context(&self.target);
        let _ = self.listener_close.send(crate::client::Data::Close);
        self.listener.abort();
        let _ = &self.proxy;
    }
}

#[cfg(all(feature = "nexus-agent", feature = "nexus-native-tunnel"))]
async fn prepare_agent_execution_tunnel(
    control_plane_url: &str,
    execution_id: &str,
) -> Result<(nexus_client::agent::AgentLocalProxy, AgentExecutionTunnel), String> {
    let credential_path = execution_credential_path(execution_id)?;
    let credential = refresh_execution_port_forward_credential(
        control_plane_url,
        execution_id,
        &credential_path,
    )
    .await;
    let _ = fs::remove_file(&credential_path);
    let credential = credential?;
    let interface = HeadlessPortForwardInterface::new(credential.publishing_rustdesk_id, false);
    let listener_config = crate::client::Interface::get_lch(&interface);
    let (listener_close, listener_receiver) = hbb_common::tokio::sync::mpsc::unbounded_channel();
    let (ready_sender, ready_receiver) = hbb_common::tokio::sync::oneshot::channel();
    let target = credential.target.clone();
    let key = crate::common::get_key(false).await;
    let listener_id = crate::client::Interface::get_id(&interface);
    let listener_target = target.clone();
    let listener = hbb_common::tokio::spawn(async move {
        let _ = crate::port_forward::listen_with_ready(
            listener_id,
            String::new(),
            0,
            interface,
            listener_receiver,
            &key,
            "",
            listener_config,
            listener_target.0,
            listener_target.1,
            Some(ready_sender),
        )
        .await;
    });
    let native_endpoint =
        match hbb_common::tokio::time::timeout(Duration::from_secs(10), ready_receiver).await {
            Ok(Ok(endpoint)) => endpoint,
            _ => {
                let _ = listener_close.send(crate::client::Data::Close);
                listener.abort();
                crate::nexus::remove_execution_port_forward_context(&target);
                return Err("native Agent PortForward listener unavailable".into());
            }
        };
    let capabilities = Arc::new(nexus_client::local_proxy::LocalProxyCapabilities::default());
    let capability = capabilities.issue(execution_id)?;
    let proxy = match nexus_client::local_proxy::LoopbackProxy::start(
        Arc::clone(&capabilities),
        capability.clone(),
        native_endpoint,
    ) {
        Ok(proxy) => proxy,
        Err(error) => {
            capabilities.revoke(execution_id);
            let _ = listener_close.send(crate::client::Data::Close);
            listener.abort();
            crate::nexus::remove_execution_port_forward_context(&target);
            return Err(error);
        }
    };
    #[cfg(feature = "nexus-e2e-host")]
    println!("NEXUS_E2E_AGENT_NATIVE_TUNNEL_READY");
    Ok((
        nexus_client::agent::AgentLocalProxy {
            endpoint: proxy.endpoint().to_string(),
            capability: capability.value,
        },
        AgentExecutionTunnel {
            execution_id: execution_id.to_string(),
            target,
            capabilities,
            proxy,
            listener_close,
            listener,
        },
    ))
}

#[cfg(all(feature = "nexus-agent", feature = "nexus-native-tunnel"))]
fn execution_credential_path(execution_id: &str) -> Result<PathBuf, String> {
    let path = std::env::temp_dir().join(format!(
        "nexus-agent-{execution_id}-{}.json",
        hex::encode(hbb_common::sodiumoxide::randombytes::randombytes(16))
    ));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|_| "unable to reserve Agent PortForward credential path".to_string())?;
    Ok(path)
}

#[cfg(feature = "nexus-agent")]
fn agent_exit_status(
    exit: &nexus_client::agent::AgentExit,
) -> (&'static str, Option<i32>, Option<&'static str>) {
    match exit.state {
        nexus_client::agent::AgentProcessState::Completed if exit.exit_code == Some(0) => {
            ("completed", exit.exit_code, None)
        }
        nexus_client::agent::AgentProcessState::Completed => {
            ("failed", exit.exit_code, Some("agent_exit_nonzero"))
        }
        nexus_client::agent::AgentProcessState::TimedOut => {
            ("timeout", exit.exit_code, Some("agent_timeout"))
        }
        nexus_client::agent::AgentProcessState::Cancelled => {
            ("cancelled", exit.exit_code, Some("agent_cancelled"))
        }
        nexus_client::agent::AgentProcessState::Running => {
            ("failed", exit.exit_code, Some("agent_invalid_exit"))
        }
    }
}

#[cfg(feature = "nexus-agent")]
async fn report_agent_execution_start(
    control_plane_url: &str,
    dispatch: &AgentDispatch,
) -> Result<(), String> {
    post_agent_execution(
        control_plane_url,
        &format!(
            "/v1/device/agent/executions/{}/start",
            dispatch.execution_id
        ),
        &AgentExecutionStart {
            dispatch_token: &dispatch.dispatch_token,
        },
    )
    .await
}

#[cfg(feature = "nexus-agent")]
async fn report_agent_execution_finish(
    control_plane_url: &str,
    dispatch: &AgentDispatch,
    status: &str,
    exit_code: Option<i32>,
    error_code: Option<&str>,
) -> Result<(), String> {
    let path = format!(
        "/v1/device/agent/executions/{}/finish",
        dispatch.execution_id
    );
    let payload = AgentExecutionFinish {
        dispatch_token: &dispatch.dispatch_token,
        status,
        exit_code,
        error_code,
    };
    let mut last_error = None;
    for attempt in 0..=AGENT_FINISH_RETRY_DELAYS_SECS.len() {
        match post_agent_execution(control_plane_url, &path, &payload).await {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
        if let Some(delay_secs) = AGENT_FINISH_RETRY_DELAYS_SECS.get(attempt) {
            hbb_common::tokio::time::sleep(Duration::from_secs(*delay_secs)).await;
        }
    }
    Err(last_error.unwrap_or_else(|| "Agent finish report failed".into()))
}

#[cfg(feature = "nexus-agent")]
async fn post_agent_execution(
    control_plane_url: &str,
    path: &str,
    payload: &impl serde::Serialize,
) -> Result<(), String> {
    let body = serde_json::to_vec(payload).map_err(|_| "invalid Agent status".to_string())?;
    let signed = sign_control_plane_request("POST", path, &body).map_err(str::to_string)?;
    #[cfg(test)]
    if control_plane_url == TEST_AGENT_CONTROL_PLANE_URL {
        test_agent_execution_reports()
            .lock()
            .map_err(|_| "Agent test report store unavailable".to_string())?
            .push((path.to_string(), body));
        return Ok(());
    }
    require_https_control_plane(control_plane_url)?;
    let response = reqwest::Client::new()
        .post(format!(
            "{}{}",
            control_plane_url.trim_end_matches('/'),
            path
        ))
        .header("content-type", "application/json")
        .header("x-nexus-device-uid", signed.device_uid)
        .header("x-nexus-timestamp", signed.timestamp)
        .header("x-nexus-nonce", signed.nonce_hex)
        .header("x-nexus-signature", signed.signature_hex)
        .body(body)
        .send()
        .await
        .map_err(|_| "Agent status request failed".to_string())?;
    response
        .status()
        .is_success()
        .then_some(())
        .ok_or_else(|| "Agent status request rejected".into())
}

#[cfg(test)]
const TEST_AGENT_CONTROL_PLANE_URL: &str = "https://agent-loopback.test";

#[cfg(test)]
fn test_agent_execution_reports() -> &'static Mutex<Vec<(String, Vec<u8>)>> {
    static REPORTS: OnceLock<Mutex<Vec<(String, Vec<u8>)>>> = OnceLock::new();
    REPORTS.get_or_init(|| Mutex::new(Vec::new()))
}

#[cfg(feature = "nexus-frp-compat-smoke")]
fn cancel_data_plane() {
    if let Some(slot) = data_plane_slot().lock().unwrap().take() {
        slot.cancellation.cancel();
    }
}

#[cfg(feature = "nexus-frp-compat-smoke")]
fn clear_data_plane(generation: ConfigGeneration) {
    let mut slot = data_plane_slot().lock().unwrap();
    if slot
        .as_ref()
        .is_some_and(|slot| slot.generation == generation)
    {
        *slot = None;
    }
}

pub fn status_snapshot() -> Option<ClientStatus> {
    runtime_slot()
        .lock()
        .unwrap()
        .as_ref()
        .map(|runtime| runtime.status().clone())
}

/// Converts the in-process runtime snapshot into the deliberately small,
/// read-only payload allowed over RustDesk's existing authorized IPC channel.
pub fn ipc_status() -> crate::ipc::NexusStatus {
    let status = status_snapshot();
    crate::ipc::NexusStatus {
        version: IPC_VERSION,
        health: match status.as_ref().map(|status| status.health) {
            Some(HealthState::Running) => "running",
            Some(HealthState::Stopped) | None => "stopped",
        }
        .into(),
        tunnel_state: match status.as_ref().map(|status| status.tunnel.state) {
            Some(TunnelState::Disabled) => "disabled",
            Some(TunnelState::PresenceOnly) => "presence-only",
            Some(TunnelState::Activating) => "activating",
            Some(TunnelState::Active) => "active",
            Some(TunnelState::Draining) => "draining",
            Some(TunnelState::Backoff) => "backoff",
            None => "disabled",
        }
        .into(),
        desired_version: status
            .as_ref()
            .and_then(|status| status.tunnel.desired_version.map(|version| version.0)),
        applied_version: status
            .as_ref()
            .and_then(|status| status.tunnel.applied_version.map(|version| version.0)),
    }
}

pub fn bind_device_uid(device_uid: impl Into<String>) -> Result<(), &'static str> {
    let mut slot = runtime_slot().lock().unwrap();
    let runtime = slot.as_mut().ok_or("Nexus runtime is not running")?;
    runtime.bind_device_uid(device_uid);
    Ok(())
}

/// Signs a control-plane request with RustDesk's existing Ed25519 device key.
/// The raw private key remains in RustDesk configuration and is never passed to
/// the Nexus client crate or persisted separately.
pub fn sign_control_plane_request(
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<SignedControlPlaneRequest, &'static str> {
    let device_uid = runtime_slot()
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|runtime| runtime.config().identity.device_uid.clone())
        .ok_or("Nexus device is not enrolled")?;
    let key_pair = Config::get_key_pair();
    let secret_key =
        sign::SecretKey::from_slice(&key_pair.0).ok_or("RustDesk device key unavailable")?;
    let nonce: [u8; 16] = hbb_common::sodiumoxide::randombytes::randombytes(16)
        .try_into()
        .map_err(|_| "failed to generate request nonce")?;
    nexus_client::control::sign_control_plane_request(
        &device_uid,
        method,
        path,
        hbb_common::get_time(),
        nonce,
        body,
        |message| sign::sign_detached(message, &secret_key).to_bytes(),
    )
    .map_err(|_| "invalid control-plane request")
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PresenceSessionKeyResponse {
    key_id: u8,
    key_hex: String,
    expires_at: i64,
}

#[cfg(feature = "nexus-agent")]
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MachineSocketLease {
    pub token: String,
    pub machine_id: String,
    pub expires_at: i64,
}

#[cfg(feature = "nexus-agent")]
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentDispatch {
    execution_id: String,
    dispatch_token: String,
    tenant_id: String,
    provider: String,
    model: Option<String>,
    prompt: String,
    timeout_ms: u64,
    #[serde(default)]
    tunnel_access: bool,
}

#[cfg(feature = "nexus-agent")]
#[derive(Debug, serde::Deserialize)]
struct AgentRpcRequest {
    method: String,
    params: serde_json::Value,
}

#[cfg(feature = "nexus-agent")]
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentCancellation {
    execution_id: String,
}

#[cfg(feature = "nexus-agent")]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentExecutionStart<'a> {
    dispatch_token: &'a str,
}

#[cfg(feature = "nexus-agent")]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentExecutionFinish<'a> {
    dispatch_token: &'a str,
    status: &'a str,
    exit_code: Option<i32>,
    error_code: Option<&'a str>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DesiredStateSigningKeyResponse {
    public_key_hex: String,
}

#[cfg(feature = "nexus-native-tunnel")]
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PortForwardCredentialResponse {
    grant_id: String,
    session_id: String,
    admission_proof_hex: String,
    target_digest: String,
    protocol_version: u32,
    expires_at: i64,
    nonce_hex: String,
    key_id: String,
    source_device_uid: String,
    publishing_device_uid: String,
    relay_node_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    publishing_rustdesk_id: String,
    target_host: String,
    target_port: i32,
}

#[cfg(all(feature = "nexus-agent", feature = "nexus-native-tunnel"))]
struct ExecutionPortForwardCredential {
    publishing_rustdesk_id: String,
    target: (String, i32),
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct DesiredStateApplicationRequest<'a> {
    version: u64,
    digest_hex: &'a str,
    outcome: &'a str,
    detail: Option<&'a str>,
}

/// Obtains a short-lived Presence AEAD key through the device-signed control
/// plane endpoint. The caller owns the returned key's in-memory lifetime.
pub async fn request_presence_session_key(
    control_plane_url: &str,
) -> Result<PresenceSessionKeyLease, String> {
    let signed = sign_control_plane_request("POST", "/v1/device/presence/session-key", &[])
        .map_err(str::to_string)?;
    require_https_control_plane(control_plane_url)?;
    let base_url = control_plane_url.trim_end_matches('/');
    let response = reqwest::Client::new()
        .post(format!("{base_url}/v1/device/presence/session-key"))
        .header("x-nexus-device-uid", signed.device_uid)
        .header("x-nexus-timestamp", signed.timestamp)
        .header("x-nexus-nonce", signed.nonce_hex)
        .header("x-nexus-signature", signed.signature_hex)
        .send()
        .await
        .map_err(|_| "control plane request failed".to_string())?;
    if !response.status().is_success() {
        return Err("control plane rejected Presence session key request".into());
    }
    let response: PresenceSessionKeyResponse = response
        .json()
        .await
        .map_err(|_| "invalid Presence session key response".to_string())?;
    if response.key_id == 0 || response.expires_at <= hbb_common::get_time() {
        return Err("invalid Presence session key lease".into());
    }
    let key = hex::decode(response.key_hex)
        .map_err(|_| "invalid Presence session key".to_string())?
        .try_into()
        .map_err(|_| "Presence session key must be 32 bytes".to_string())?;
    Ok(PresenceSessionKeyLease {
        key_id: response.key_id,
        key,
        expires_at: response.expires_at,
    })
}

/// Exchanges the native device signature for a short-lived, machine-bound
/// Socket.IO credential. This does not open a socket: the deployment-owned
/// service loop supplies the endpoint, TLS policy, and connection lifecycle.
#[cfg(feature = "nexus-agent")]
pub async fn request_machine_socket_lease(
    control_plane_url: &str,
) -> Result<MachineSocketLease, String> {
    const PATH: &str = "/v1/device/agent/socket-token";
    let signed = sign_control_plane_request("POST", PATH, &[]).map_err(str::to_string)?;
    if !agent_loopback_http_allowed(control_plane_url) {
        require_https_control_plane(control_plane_url)?;
    }
    let response = reqwest::Client::new()
        .post(format!(
            "{}{}",
            control_plane_url.trim_end_matches('/'),
            PATH
        ))
        .header("x-nexus-device-uid", signed.device_uid)
        .header("x-nexus-timestamp", signed.timestamp)
        .header("x-nexus-nonce", signed.nonce_hex)
        .header("x-nexus-signature", signed.signature_hex)
        .send()
        .await
        .map_err(|_| "control plane request failed".to_string())?;
    if !response.status().is_success() {
        return Err("control plane rejected Machine Socket token request".into());
    }
    let response: MachineSocketLease = response
        .json()
        .await
        .map_err(|_| "invalid Machine Socket token response".to_string())?;
    (!response.token.trim().is_empty()
        && !response.machine_id.trim().is_empty()
        && response.expires_at > hbb_common::get_time())
    .then_some(response)
    .ok_or_else(|| "invalid Machine Socket token response".into())
}

/// Compatibility wrapper for callers that only need the credential.
#[cfg(feature = "nexus-agent")]
pub async fn request_machine_socket_token(control_plane_url: &str) -> Result<String, String> {
    Ok(request_machine_socket_lease(control_plane_url).await?.token)
}

/// Downloads a Desired State through device-authenticated control-plane routes,
/// then verifies its signature, device binding, validity window, and digest
/// before returning it. Untrusted network JSON never reaches the state machine.
pub async fn fetch_tunnel_desired_state(
    control_plane_url: &str,
) -> Result<VerifiedDesiredState, String> {
    fetch_tunnel_desired_state_http(control_plane_url, false).await
}

async fn fetch_tunnel_desired_state_http(
    control_plane_url: &str,
    allow_loopback_http: bool,
) -> Result<VerifiedDesiredState, String> {
    let signed = sign_control_plane_request("GET", "/v1/device/tunnel/desired-state", &[])
        .map_err(str::to_string)?;
    if !allow_loopback_http {
        require_https_control_plane(control_plane_url)?;
    } else if !is_loopback_http(control_plane_url) {
        return Err("Nexus control-plane URL must use HTTPS".into());
    }
    let device_uid = signed.device_uid.clone();
    let base_url = control_plane_url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{base_url}/v1/device/tunnel/desired-state"))
        .header("x-nexus-device-uid", signed.device_uid)
        .header("x-nexus-timestamp", signed.timestamp)
        .header("x-nexus-nonce", signed.nonce_hex)
        .header("x-nexus-signature", signed.signature_hex)
        .send()
        .await
        .map_err(|_| "control plane request failed".to_string())?;
    if !response.status().is_success() {
        return Err("control plane rejected Tunnel Desired State request".into());
    }
    let payload = response
        .text()
        .await
        .map_err(|_| "invalid Tunnel Desired State response".to_string())?;
    let key_id = nexus_client::desired_state::signing_key_id(&payload)
        .map_err(|_| "invalid Tunnel Desired State response".to_string())?;
    if !key_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("invalid Tunnel signing key identifier".into());
    }
    let key_path = format!("/v1/device/tunnel/signing-keys/{key_id}");
    let signed = sign_control_plane_request("GET", &key_path, &[]).map_err(str::to_string)?;
    let response = client
        .get(format!("{base_url}{key_path}"))
        .header("x-nexus-device-uid", signed.device_uid)
        .header("x-nexus-timestamp", signed.timestamp)
        .header("x-nexus-nonce", signed.nonce_hex)
        .header("x-nexus-signature", signed.signature_hex)
        .send()
        .await
        .map_err(|_| "control plane request failed".to_string())?;
    if !response.status().is_success() {
        return Err("control plane rejected Tunnel signing key request".into());
    }
    let signing_key: DesiredStateSigningKeyResponse = response
        .json()
        .await
        .map_err(|_| "invalid Tunnel signing key response".to_string())?;
    let public_key: [u8; 32] = hex::decode(signing_key.public_key_hex)
        .map_err(|_| "invalid Tunnel signing key".to_string())?
        .try_into()
        .map_err(|_| "invalid Tunnel signing key".to_string())?;
    let public_key =
        sign::PublicKey::from_slice(&public_key).ok_or("invalid Tunnel signing key")?;
    nexus_client::desired_state::parse_and_verify_desired_state(
        &payload,
        &device_uid,
        hbb_common::get_time(),
        |received_key_id, bytes, signature| {
            received_key_id == key_id
                && sign::Signature::from_bytes(signature)
                    .map(|signature| sign::verify_detached(&signature, bytes, &public_key))
                    .unwrap_or(false)
        },
    )
    .map_err(|error| format!("Tunnel Desired State verification failed: {error}"))
}

/// Fetches one execution-bound PortForward credential through the existing
/// machine-bound request signer, verifies the Control Plane proof locally,
/// then atomically installs the JSON consumed by the native login hook.
#[cfg(feature = "nexus-native-tunnel")]
pub async fn refresh_port_forward_credential(
    control_plane_url: &str,
    grant_id: &str,
    credential_path: &std::path::Path,
) -> Result<(), String> {
    refresh_port_forward_credential_http(control_plane_url, grant_id, credential_path, false).await
}

/// Refreshes one Gateway-only grant through the same signed-device contract
/// used by the Host. The route itself enforces the gateway capability.
#[cfg(feature = "nexus-native-tunnel")]
pub async fn refresh_gateway_port_forward_credential(
    control_plane_url: &str,
    grant_id: &str,
    credential_path: &std::path::Path,
) -> Result<(), String> {
    refresh_port_forward_credential_path_http(
        control_plane_url,
        &gateway_port_forward_context_path(grant_id)?,
        credential_path,
        false,
    )
    .await
}

#[cfg(feature = "nexus-native-tunnel")]
fn gateway_port_forward_context_path(grant_id: &str) -> Result<String, String> {
    if !grant_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("invalid Tunnel grant identifier".into());
    }
    Ok(format!(
        "/v1/device/gateway/tunnel/access-grants/{grant_id}/port-forward-context"
    ))
}

/// A Gateway rechecks its mutable grant just before consuming the locally
/// cached one-shot context. Normal RustDesk PortForward sessions never set the
/// Gateway grant variable, so their native connection path is unchanged.
#[cfg(feature = "nexus-native-tunnel")]
pub(crate) fn gateway_port_forward_liveness_required() -> bool {
    std::env::var("NEXUS_GATEWAY_GRANT_ID")
        .ok()
        .is_some_and(|grant_id| !grant_id.is_empty())
}

/// Verifies that a Gateway's source-bound grant remains live. Production calls
/// require HTTPS; the feature-gated E2E binary alone may use loopback HTTP.
#[cfg(feature = "nexus-native-tunnel")]
pub(crate) async fn gateway_port_forward_grant_is_live() -> bool {
    let Ok(grant_id) = std::env::var("NEXUS_GATEWAY_GRANT_ID") else {
        return false;
    };
    let Ok(control_plane_url) = std::env::var("NEXUS_GATEWAY_CONTROL_PLANE_URL") else {
        return false;
    };
    let Ok(path) = gateway_port_forward_liveness_path(&grant_id) else {
        return false;
    };
    let allow_loopback_http = cfg!(feature = "nexus-e2e-gateway");
    if (!allow_loopback_http && require_https_control_plane(&control_plane_url).is_err())
        || (allow_loopback_http && !is_loopback_http(&control_plane_url))
    {
        return false;
    }
    let Ok(signed) = sign_control_plane_request("GET", &path, &[]) else {
        return false;
    };
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
    else {
        return false;
    };
    client
        .get(format!(
            "{}{}",
            control_plane_url.trim_end_matches('/'),
            path
        ))
        .header("x-nexus-device-uid", signed.device_uid)
        .header("x-nexus-timestamp", signed.timestamp)
        .header("x-nexus-nonce", signed.nonce_hex)
        .header("x-nexus-signature", signed.signature_hex)
        .send()
        .await
        .is_ok_and(|response| response.status().is_success())
}

/// Reports one native Gateway connection delta and/or byte total through the
/// same device signature boundary as liveness. Reporting is best-effort so a
/// control-plane outage never changes RustDesk's raw stream behavior.
#[cfg(feature = "nexus-native-tunnel")]
pub(crate) async fn report_gateway_port_forward_usage(connection_delta: i16, bytes: u64) {
    if connection_delta == 0 && bytes == 0 {
        return;
    }
    let Ok(grant_id) = std::env::var("NEXUS_GATEWAY_GRANT_ID") else {
        return;
    };
    let Ok(control_plane_url) = std::env::var("NEXUS_GATEWAY_CONTROL_PLANE_URL") else {
        return;
    };
    let Ok(path) = gateway_port_forward_usage_path(&grant_id) else {
        return;
    };
    let allow_loopback_http = cfg!(feature = "nexus-e2e-gateway");
    if (!allow_loopback_http && require_https_control_plane(&control_plane_url).is_err())
        || (allow_loopback_http && !is_loopback_http(&control_plane_url))
    {
        return;
    }
    let body = serde_json::json!({
        "connectionDelta": connection_delta,
        "bytes": bytes,
    });
    let Ok(body) = serde_json::to_vec(&body) else {
        return;
    };
    let Ok(signed) = sign_control_plane_request("POST", &path, &body) else {
        return;
    };
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
    else {
        return;
    };
    let _ = client
        .post(format!(
            "{}{}",
            control_plane_url.trim_end_matches('/'),
            path
        ))
        .header("content-type", "application/json")
        .header("x-nexus-device-uid", signed.device_uid)
        .header("x-nexus-timestamp", signed.timestamp)
        .header("x-nexus-nonce", signed.nonce_hex)
        .header("x-nexus-signature", signed.signature_hex)
        .body(body)
        .send()
        .await;
}

#[cfg(feature = "nexus-native-tunnel")]
fn gateway_port_forward_liveness_path(grant_id: &str) -> Result<String, String> {
    gateway_port_forward_context_path(grant_id)
        .map(|path| path.trim_end_matches("/port-forward-context").to_owned() + "/liveness")
}

#[cfg(feature = "nexus-native-tunnel")]
fn gateway_port_forward_usage_path(grant_id: &str) -> Result<String, String> {
    gateway_port_forward_context_path(grant_id)
        .map(|path| path.trim_end_matches("/port-forward-context").to_owned() + "/usage")
}

#[cfg(feature = "nexus-native-tunnel")]
async fn refresh_port_forward_credential_http(
    control_plane_url: &str,
    grant_id: &str,
    credential_path: &std::path::Path,
    allow_loopback_http: bool,
) -> Result<(), String> {
    if !grant_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("invalid Tunnel grant identifier".into());
    }
    refresh_port_forward_credential_path_http(
        control_plane_url,
        &format!("/v1/device/tunnel/access-grants/{grant_id}/port-forward-context"),
        credential_path,
        allow_loopback_http,
    )
    .await
}

/// Fetches the signed context bound to the dispatch execution. The URL is
/// fixed by the Host; no Agent or browser field can replace it with a grant.
#[cfg(all(feature = "nexus-agent", feature = "nexus-native-tunnel"))]
async fn refresh_execution_port_forward_credential(
    control_plane_url: &str,
    execution_id: &str,
    credential_path: &std::path::Path,
) -> Result<ExecutionPortForwardCredential, String> {
    if execution_id.is_empty()
        || !execution_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("invalid execution identifier".into());
    }
    refresh_port_forward_credential_path_http(
        control_plane_url,
        &format!("/v1/device/agent/executions/{execution_id}/tunnel-context"),
        credential_path,
        false,
    )
    .await?;
    let publishing_rustdesk_id = read_execution_publishing_rustdesk_id(credential_path)?;
    let target = crate::nexus::install_execution_port_forward_credential(credential_path)
        .ok_or_else(|| String::from("invalid execution PortForward target"))?;
    Ok(ExecutionPortForwardCredential {
        publishing_rustdesk_id,
        target,
    })
}

#[cfg(all(feature = "nexus-agent", feature = "nexus-native-tunnel"))]
fn read_execution_publishing_rustdesk_id(path: &std::path::Path) -> Result<String, String> {
    let credential: PortForwardCredentialResponse = serde_json::from_slice(
        &fs::read(path).map_err(|_| "invalid execution PortForward credential".to_string())?,
    )
    .map_err(|_| "invalid execution PortForward credential".to_string())?;
    if credential.publishing_rustdesk_id.trim().is_empty()
        || credential.publishing_rustdesk_id.len() > 128
        || credential
            .publishing_rustdesk_id
            .bytes()
            .any(|byte| byte.is_ascii_control())
    {
        return Err("invalid execution publishing RustDesk ID".into());
    }
    Ok(credential.publishing_rustdesk_id)
}

#[cfg(feature = "nexus-native-tunnel")]
async fn refresh_port_forward_credential_path_http(
    control_plane_url: &str,
    path: &str,
    credential_path: &std::path::Path,
    allow_loopback_http: bool,
) -> Result<(), String> {
    if !allow_loopback_http {
        require_https_control_plane(control_plane_url)?;
    } else if !is_loopback_http(control_plane_url) {
        return Err("Nexus control-plane URL must use HTTPS".into());
    }
    let signed = sign_control_plane_request("GET", &path, &[]).map_err(str::to_string)?;
    let base_url = control_plane_url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{base_url}{path}"))
        .header("x-nexus-device-uid", signed.device_uid)
        .header("x-nexus-timestamp", signed.timestamp)
        .header("x-nexus-nonce", signed.nonce_hex)
        .header("x-nexus-signature", signed.signature_hex)
        .send()
        .await
        .map_err(|_| "PortForward credential request failed".to_string())?;
    if !response.status().is_success() {
        return Err("control plane rejected PortForward credential request".into());
    }
    let credential: PortForwardCredentialResponse = response
        .json()
        .await
        .map_err(|_| "invalid PortForward credential response".to_string())?;
    verify_port_forward_credential(&client, base_url, &credential).await?;
    let encoded = serde_json::to_vec(&credential)
        .map_err(|_| "invalid PortForward credential response".to_string())?;
    atomic_write_credential(credential_path, &encoded)
}

#[cfg(all(test, feature = "nexus-native-tunnel"))]
async fn refresh_port_forward_credential_loopback(
    control_plane_url: &str,
    grant_id: &str,
    credential_path: &std::path::Path,
) -> Result<(), String> {
    refresh_port_forward_credential_http(control_plane_url, grant_id, credential_path, true).await
}

#[cfg(feature = "nexus-native-tunnel")]
async fn verify_port_forward_credential(
    client: &reqwest::Client,
    base_url: &str,
    credential: &PortForwardCredentialResponse,
) -> Result<(), String> {
    if credential.protocol_version != 1
        || credential.grant_id.trim().is_empty()
        || credential.session_id.trim().is_empty()
        || credential.key_id.trim().is_empty()
        || credential.source_device_uid.trim().is_empty()
        || credential.publishing_device_uid.trim().is_empty()
        || credential.relay_node_id.trim().is_empty()
        || credential.target_digest.trim().is_empty()
        || credential.target_host.trim().is_empty()
        || !(1..=u16::MAX as i32).contains(&credential.target_port)
        || credential.expires_at <= hbb_common::get_time()
    {
        return Err("invalid PortForward credential response".into());
    }
    let nonce = hex::decode(&credential.nonce_hex)
        .map_err(|_| "invalid PortForward credential nonce".to_string())?;
    let proof = hex::decode(&credential.admission_proof_hex)
        .map_err(|_| "invalid PortForward credential proof".to_string())?;
    let context = hbb_common::message_proto::NexusPortForwardContext {
        grant_id: credential.grant_id.clone(),
        session_id: credential.session_id.clone(),
        admission_proof: proof.clone().into(),
        target_digest: credential.target_digest.clone(),
        protocol_version: credential.protocol_version,
        expires_at: credential.expires_at,
        nonce: nonce.clone().into(),
        key_id: credential.key_id.clone(),
        source_device_uid: credential.source_device_uid.clone(),
        publishing_device_uid: credential.publishing_device_uid.clone(),
        relay_node_id: credential.relay_node_id.clone(),
        ..Default::default()
    };
    if nonce.is_empty() {
        return Err("invalid PortForward credential nonce".into());
    }
    let key_path = format!("/v1/device/tunnel/signing-keys/{}", credential.key_id);
    let signed = sign_control_plane_request("GET", &key_path, &[]).map_err(str::to_string)?;
    let response = client
        .get(format!("{base_url}{key_path}"))
        .header("x-nexus-device-uid", signed.device_uid)
        .header("x-nexus-timestamp", signed.timestamp)
        .header("x-nexus-nonce", signed.nonce_hex)
        .header("x-nexus-signature", signed.signature_hex)
        .send()
        .await
        .map_err(|_| "Tunnel signing key request failed".to_string())?;
    if !response.status().is_success() {
        return Err("control plane rejected Tunnel signing key request".into());
    }
    let key: DesiredStateSigningKeyResponse = response
        .json()
        .await
        .map_err(|_| "invalid Tunnel signing key response".to_string())?;
    let public_key =
        hex::decode(key.public_key_hex).map_err(|_| "invalid Tunnel signing key".to_string())?;
    let public_key =
        sign::PublicKey::from_slice(&public_key).ok_or("invalid Tunnel signing key")?;
    let signature = sign::Signature::from_bytes(&proof)
        .map_err(|_| "invalid PortForward credential proof".to_string())?;
    sign::verify_detached(
        &signature,
        &hbb_common::nexus_wire::canonical_port_forward_admission(&context),
        &public_key,
    )
    .then_some(())
    .ok_or_else(|| "PortForward credential signature verification failed".into())
}

#[cfg(feature = "nexus-native-tunnel")]
fn atomic_write_credential(path: &std::path::Path, contents: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("invalid PortForward credential path")?;
    fs::create_dir_all(parent).map_err(|_| "unable to create PortForward credential directory")?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("credential"),
        hbb_common::get_time()
    ));
    fs::write(&temporary, contents).map_err(|_| "unable to write PortForward credential")?;
    if fs::rename(&temporary, path).is_ok() {
        return Ok(());
    }
    // Windows does not replace an existing destination with `rename`; retain
    // the prior complete credential until its replacement is ready.
    let backup = parent.join(format!(
        ".{}.{}.bak",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("credential"),
        hbb_common::get_time()
    ));
    if fs::rename(path, &backup).is_err() || fs::rename(&temporary, path).is_err() {
        let _ = fs::rename(&backup, path);
        let _ = fs::remove_file(&temporary);
        return Err("unable to install PortForward credential".into());
    }
    let _ = fs::remove_file(backup);
    Ok(())
}

#[cfg(test)]
/// Test-only loopback variant for the complete RustDesk host contract test.
/// Production callers always route through the HTTPS-only public function.
async fn fetch_tunnel_desired_state_loopback(
    control_plane_url: &str,
) -> Result<VerifiedDesiredState, String> {
    fetch_tunnel_desired_state_http(control_plane_url, true).await
}

/// Applies a previously verified state without holding the runtime mutex across
/// network I/O. The mutable host state is the final trust boundary.
pub fn apply_verified_tunnel_desired_state(
    verified: VerifiedDesiredState,
) -> Result<(), &'static str> {
    #[cfg(feature = "nexus-frp-compat-smoke")]
    return apply_verified_tunnel_desired_state_with_frp(verified);

    #[cfg(not(feature = "nexus-frp-compat-smoke"))]
    {
        let mut slot = runtime_slot().lock().unwrap();
        let runtime = slot.as_mut().ok_or("Nexus runtime is not running")?;
        runtime
            .apply_tunnel_desired_state(verified.desired_state)
            .map(|_| ())
            .map_err(|_| "Tunnel Desired State was rejected")
    }
}

#[cfg(feature = "nexus-frp-compat-smoke")]
/// Applies an authenticated state through the upstream atomic reload path when
/// an active generation already exists. The synchronous compatibility entry
/// point remains available for local callers; production refresh uses this
/// async form so `ClientService::reload()` completes before state is applied.
pub async fn apply_verified_tunnel_desired_state_async(
    verified: VerifiedDesiredState,
) -> Result<(), String> {
    apply_verified_tunnel_desired_state_async_with_application(verified, None).await
}

#[cfg(feature = "nexus-frp-compat-smoke")]
async fn apply_verified_tunnel_desired_state_async_with_application(
    verified: VerifiedDesiredState,
    control_plane_url: Option<&str>,
) -> Result<(), String> {
    let next_application = control_plane_url.map(|control_plane_url| GenerationApplication {
        control_plane_url: control_plane_url.into(),
        version: verified.desired_state.version.0,
        digest_hex: verified.desired_state.digest().to_hex(),
    });
    let active = verified.desired_state.mode == TunnelMode::Active;
    let assignment = verified.data_plane_assignment.as_ref();
    if active && assignment.is_none() {
        return Err("Active Tunnel Desired State requires a Relay assignment".into());
    }
    let mut candidate = nexus_client::tunnel::TunnelRuntime::new();
    candidate
        .apply_desired_state(verified.desired_state.clone())
        .map_err(|_| "Tunnel Desired State was rejected".to_string())?;
    // Visitor and loopback listener construction is checked before the signed
    // generation is committed. They share the host cancellation boundary with
    // FRP but never become arbitrary user-owned background services.
    let next_auxiliary = prepare_auxiliary(&verified.desired_state, assignment).await?;
    let local_addr_overrides = next_auxiliary
        .as_ref()
        .map(|slot| slot.local_addr_overrides.as_slice())
        .unwrap_or_default();
    let next_frp = assignment
        .map(|assignment| {
            FrpRuntime::new_with_local_addr_overrides(&candidate, assignment, local_addr_overrides)
        })
        .transpose()
        .map_err(|_| {
            cancel_prepared_auxiliary(&next_auxiliary);
            "Tunnel Relay assignment was rejected".to_string()
        })?;

    if let Some(next_frp) = next_frp.as_ref() {
        let current = data_plane_slot()
            .lock()
            .unwrap()
            .as_ref()
            .map(|slot| slot.frp.clone());
        if let (Some(current), Some(assignment)) = (current, assignment) {
            let (old_runtime, old_assignment, old_overrides) = {
                let slot = data_plane_slot().lock().unwrap();
                let old = slot.as_ref().ok_or("Tunnel FRP generation missing")?;
                let mut runtime = nexus_client::tunnel::TunnelRuntime::new();
                runtime
                    .apply_desired_state(old.desired_state.clone())
                    .map_err(|_| "Tunnel previous generation is unavailable".to_string())?;
                (
                    runtime,
                    old.assignment.clone(),
                    old.local_addr_overrides.clone(),
                )
            };
            if current
                .reload_with_local_addr_overrides(&candidate, assignment, local_addr_overrides)
                .await
                .is_err()
            {
                // Treat a reported reload error like a readiness failure: the
                // fixed upstream owns its connection pool, so explicitly put
                // the last committed configuration back before returning.
                let _ = current
                    .reload_with_local_addr_overrides(&old_runtime, &old_assignment, &old_overrides)
                    .await;
                cancel_prepared_auxiliary(&next_auxiliary);
                return Err("Tunnel FRP atomic reload failed".to_string());
            }
            if hbb_common::tokio::time::timeout(
                Duration::from_secs(15),
                current.wait_until_connected(),
            )
            .await
            .is_err()
            {
                // The upstream reload may already have replaced its config;
                // restore the committed generation before returning failure.
                let _ = current
                    .reload_with_local_addr_overrides(&old_runtime, &old_assignment, &old_overrides)
                    .await;
                cancel_prepared_auxiliary(&next_auxiliary);
                return Err("Tunnel FRP reload readiness timed out".to_string());
            }
            let mut slot = runtime_slot().lock().unwrap();
            let runtime = slot.as_mut().ok_or("Nexus runtime is not running")?;
            let desired_state = verified.desired_state.clone();
            runtime
                .apply_tunnel_desired_state(desired_state)
                .map_err(|_| "Tunnel Desired State was rejected".to_string())?;
            let generation = runtime
                .tunnel()
                .generation()
                .ok_or("Tunnel generation missing")?;
            runtime
                .on_tunnel_activation_succeeded(generation)
                .map_err(|_| "Tunnel FRP readiness state was rejected".to_string())?;
            if let Some(slot) = data_plane_slot().lock().unwrap().as_mut() {
                slot.generation = generation;
                *slot.task_generation.lock().unwrap() = generation;
                slot.desired_state = verified.desired_state.clone();
                slot.assignment = assignment.clone();
                slot.local_addr_overrides = local_addr_overrides.to_vec();
                slot.application = next_application;
            }
            install_auxiliary(next_auxiliary);
            return Ok(());
        }
        let generation = {
            let mut slot = runtime_slot().lock().unwrap();
            let runtime = slot.as_mut().ok_or("Nexus runtime is not running")?;
            runtime
                .apply_tunnel_desired_state(verified.desired_state)
                .map_err(|_| "Tunnel Desired State was rejected".to_string())?;
            runtime
                .tunnel()
                .generation()
                .ok_or("Tunnel generation missing")?
        };
        let handle = hbb_common::tokio::runtime::Handle::try_current()
            .map_err(|_| "Tunnel data plane requires the RustDesk Tokio runtime")?;
        let cancellation = FrpCancellationToken::new();
        let task_generation = Arc::new(Mutex::new(generation));
        *data_plane_slot().lock().unwrap() = Some(DataPlaneSlot {
            generation,
            task_generation: task_generation.clone(),
            cancellation: cancellation.clone(),
            frp: next_frp.clone(),
            desired_state: candidate
                .desired_state()
                .cloned()
                .ok_or("Tunnel Desired State missing")?,
            assignment: assignment
                .cloned()
                .ok_or("Tunnel Relay assignment missing")?,
            local_addr_overrides: local_addr_overrides.to_vec(),
            application: next_application,
        });
        handle.spawn(run_data_plane(
            next_frp.clone(),
            task_generation,
            cancellation,
        ));
        // A successful ClientService spawn only proves configuration parsing.
        // Wait for the upstream work-connection callback before the caller can
        // report this signed generation as applied.
        if hbb_common::tokio::time::timeout(
            Duration::from_secs(15),
            next_frp.wait_until_connected(),
        )
        .await
        .is_err()
        {
            cancel_data_plane();
            if let Some(auxiliary) = next_auxiliary {
                auxiliary.cancellation.cancel();
            }
            return Err("Tunnel FRP readiness timed out".into());
        }
        if let Some(runtime) = runtime_slot().lock().unwrap().as_mut() {
            runtime
                .on_tunnel_activation_succeeded(generation)
                .map_err(|_| "Tunnel FRP readiness state was rejected".to_string())?;
        }
        install_auxiliary(next_auxiliary);
        return Ok(());
    }

    let mut slot = runtime_slot().lock().unwrap();
    let runtime = slot.as_mut().ok_or("Nexus runtime is not running")?;
    let desired_state = verified.desired_state.clone();
    runtime
        .apply_tunnel_desired_state(desired_state)
        .map_err(|_| "Tunnel Desired State was rejected".to_string())?;
    drop(slot);
    // Apply the passive generation before cancelling the old owner. Its
    // cancellation callback then completes the matching Draining transition
    // instead of observing the still-Active predecessor and being discarded.
    cancel_data_plane();
    install_auxiliary(next_auxiliary);
    Ok(())
}

#[cfg(feature = "nexus-frp-compat-smoke")]
fn apply_verified_tunnel_desired_state_with_frp(
    verified: VerifiedDesiredState,
) -> Result<(), &'static str> {
    let active = verified.desired_state.mode == TunnelMode::Active;
    let assignment = verified.data_plane_assignment.as_ref();
    if active && assignment.is_none() {
        return Err("Active Tunnel Desired State requires a Relay assignment");
    }
    let task_handle = active
        .then(hbb_common::tokio::runtime::Handle::try_current)
        .transpose()
        .map_err(|_| "Tunnel data plane requires the RustDesk Tokio runtime")?;
    let mut slot = runtime_slot().lock().unwrap();
    let runtime = slot.as_mut().ok_or("Nexus runtime is not running")?;
    let frp = if let Some(assignment) = assignment {
        let mut candidate = nexus_client::tunnel::TunnelRuntime::new();
        candidate
            .apply_desired_state(verified.desired_state.clone())
            .map_err(|_| "Tunnel Desired State was rejected")?;
        Some(
            FrpRuntime::new(&candidate, assignment)
                .map_err(|_| "Tunnel Relay assignment was rejected")?,
        )
    } else {
        None
    };
    let desired_state = verified.desired_state.clone();
    runtime
        .apply_tunnel_desired_state(desired_state)
        .map_err(|_| "Tunnel Desired State was rejected")?;
    let generation = runtime.tunnel().generation();
    drop(slot);

    cancel_data_plane();
    if let (Some(task_handle), Some(frp), Some(generation)) = (task_handle, frp, generation) {
        let cancellation = FrpCancellationToken::new();
        let task_generation = Arc::new(Mutex::new(generation));
        *data_plane_slot().lock().unwrap() = Some(DataPlaneSlot {
            generation,
            task_generation: task_generation.clone(),
            cancellation: cancellation.clone(),
            frp: frp.clone(),
            desired_state: verified.desired_state.clone(),
            assignment: assignment
                .cloned()
                .ok_or("Tunnel Relay assignment missing")?,
            local_addr_overrides: Vec::new(),
            application: None,
        });
        task_handle.spawn(run_data_plane(frp, task_generation, cancellation));
    }
    Ok(())
}

#[cfg(feature = "nexus-frp-compat-smoke")]
async fn run_data_plane(
    frp: FrpRuntime,
    task_generation: Arc<Mutex<ConfigGeneration>>,
    cancellation: FrpCancellationToken,
) {
    let readiness = frp.clone();
    let readiness_cancellation = cancellation.clone();
    let readiness_generation = task_generation.clone();
    hbb_common::tokio::spawn(async move {
        hbb_common::tokio::select! {
            _ = readiness.wait_until_connected() => {},
            _ = readiness_cancellation.cancelled() => return,
        }
        if !readiness_cancellation.is_cancelled() {
            if let Some(runtime) = runtime_slot().lock().unwrap().as_mut() {
                let generation = *readiness_generation.lock().unwrap();
                let _ = runtime.on_tunnel_activation_succeeded(generation);
            }
        }
    });

    loop {
        let generation = *task_generation.lock().unwrap();
        let run = frp.run(cancellation.clone()).await;
        if cancellation.is_cancelled() {
            if let Some(runtime) = runtime_slot().lock().unwrap().as_mut() {
                if let Some(drain_generation) = runtime.tunnel().generation() {
                    let _ = runtime.on_tunnel_drain_complete(drain_generation);
                }
            }
            clear_data_plane(generation);
            return;
        }
        let application = data_plane_slot().lock().unwrap().as_ref().and_then(|slot| {
            application_for_generation(slot.generation, slot.application.clone(), generation)
        });
        if run.is_err() {
            if let Some(application) = &application {
                // Error strings can contain upstream/network detail. The
                // control-plane record needs the signed generation outcome,
                // not credentials or transport diagnostics.
                let _ = record_tunnel_desired_state_application(
                    &application.control_plane_url,
                    application.version,
                    &application.digest_hex,
                    "rejected",
                    Some("Tunnel FRP generation stopped"),
                )
                .await;
            }
        }
        let retry_not_before_secs = {
            let mut slot = runtime_slot().lock().unwrap();
            let Some(runtime) = slot.as_mut() else {
                clear_data_plane(generation);
                return;
            };
            if runtime.on_tunnel_activation_failed(generation).is_err() {
                clear_data_plane(generation);
                return;
            }
            runtime.tunnel().status().retry_not_before_secs
        };
        let Some(retry_not_before_secs) = retry_not_before_secs else {
            clear_data_plane(generation);
            return;
        };
        let delay_secs = retry_not_before_secs.saturating_sub(hbb_common::get_time() as u64);
        hbb_common::tokio::select! {
            _ = hbb_common::tokio::time::sleep(Duration::from_secs(delay_secs)) => {},
            _ = cancellation.cancelled() => continue,
        }
        if cancellation.is_cancelled() {
            continue;
        }
        let mut slot = runtime_slot().lock().unwrap();
        let Some(runtime) = slot.as_mut() else {
            clear_data_plane(generation);
            return;
        };
        if runtime.on_tunnel_retry_ready(generation).is_err() {
            clear_data_plane(generation);
            return;
        }
    }
}

/// Records the local outcome against the exact signed generation. The control
/// plane accepts only its current version and digest, preventing a stale client
/// from writing an outcome for another generation.
pub async fn record_tunnel_desired_state_application(
    control_plane_url: &str,
    version: u64,
    digest_hex: &str,
    outcome: &str,
    detail: Option<&str>,
) -> Result<(), String> {
    HttpsTunnelApplicationReporter
        .report(control_plane_url, version, digest_hex, outcome, detail)
        .await
}

async fn record_tunnel_desired_state_application_http(
    control_plane_url: &str,
    version: u64,
    digest_hex: &str,
    outcome: &str,
    detail: Option<&str>,
    allow_loopback_http: bool,
) -> Result<(), String> {
    let body = serde_json::to_vec(&DesiredStateApplicationRequest {
        version,
        digest_hex,
        outcome,
        detail,
    })
    .map_err(|_| "failed to encode Tunnel Desired State application".to_string())?;
    let signed = sign_control_plane_request("POST", "/v1/device/tunnel/applications", &body)
        .map_err(str::to_string)?;
    if !allow_loopback_http {
        require_https_control_plane(control_plane_url)?;
    } else if !is_loopback_http(control_plane_url) {
        return Err("Nexus control-plane URL must use HTTPS".into());
    }
    let response = reqwest::Client::new()
        .post(format!(
            "{}/v1/device/tunnel/applications",
            control_plane_url.trim_end_matches('/')
        ))
        .header("x-nexus-device-uid", signed.device_uid)
        .header("x-nexus-timestamp", signed.timestamp)
        .header("x-nexus-nonce", signed.nonce_hex)
        .header("x-nexus-signature", signed.signature_hex)
        .body(body)
        .send()
        .await
        .map_err(|_| "control plane request failed".to_string())?;
    response
        .status()
        .is_success()
        .then_some(())
        .ok_or_else(|| "control plane rejected Tunnel Desired State application".into())
}

#[cfg(test)]
async fn record_tunnel_desired_state_application_loopback(
    control_plane_url: &str,
    version: u64,
    digest_hex: &str,
    outcome: &str,
    detail: Option<&str>,
) -> Result<(), String> {
    record_tunnel_desired_state_application_http(
        control_plane_url,
        version,
        digest_hex,
        outcome,
        detail,
        true,
    )
    .await
}

async fn report_tunnel_desired_state_application(
    reporter: &dyn TunnelApplicationReporter,
    control_plane_url: &str,
    version: u64,
    digest_hex: &str,
    outcome: &str,
    detail: Option<&str>,
) -> Result<(), String> {
    reporter
        .report(control_plane_url, version, digest_hex, outcome, detail)
        .await
}

/// Fetches, verifies, and applies the latest Desired State as one explicit
/// lifecycle operation for callers that own the RustDesk service loop.
pub async fn refresh_tunnel_desired_state(control_plane_url: &str) -> Result<(), String> {
    refresh_tunnel_desired_state_with_reporter(control_plane_url, &HttpsTunnelApplicationReporter)
        .await
}

async fn refresh_tunnel_desired_state_with_reporter(
    control_plane_url: &str,
    reporter: &dyn TunnelApplicationReporter,
) -> Result<(), String> {
    let verified = fetch_tunnel_desired_state(control_plane_url).await?;
    apply_and_report_tunnel_desired_state(control_plane_url, verified, reporter).await
}

#[cfg(test)]
async fn refresh_tunnel_desired_state_loopback(control_plane_url: &str) -> Result<(), String> {
    let verified = fetch_tunnel_desired_state_loopback(control_plane_url).await?;
    apply_and_report_tunnel_desired_state(
        control_plane_url,
        verified,
        &LoopbackTunnelApplicationReporter,
    )
    .await
}

/// Applies one already-verified generation and reports only its final local
/// outcome. Keeping this orchestration behind the application reporter lets
/// host tests exercise the same success and rejection rules without HTTP.
async fn apply_and_report_tunnel_desired_state(
    control_plane_url: &str,
    verified: VerifiedDesiredState,
    reporter: &dyn TunnelApplicationReporter,
) -> Result<(), String> {
    let version = verified.desired_state.version.0;
    let digest_hex = verified.desired_state.digest().to_hex();
    #[cfg(feature = "nexus-frp-compat-smoke")]
    let apply = apply_verified_tunnel_desired_state_async_with_application(
        verified,
        Some(control_plane_url),
    )
    .await;
    #[cfg(not(feature = "nexus-frp-compat-smoke"))]
    let apply = apply_verified_tunnel_desired_state(verified).map_err(str::to_string);
    match apply {
        Ok(()) => {
            report_tunnel_desired_state_application(
                reporter,
                control_plane_url,
                version,
                &digest_hex,
                "applied",
                None,
            )
            .await
        }
        Err(error) => {
            let _ = report_tunnel_desired_state_application(
                reporter,
                control_plane_url,
                version,
                &digest_hex,
                "rejected",
                Some(error.as_str()),
            )
            .await;
            Err(error.into())
        }
    }
}

/// Establishes one authenticated CPCC Presence session for the running
/// RustDesk service. Network endpoints are explicit deployment input: neither
/// the Gateway address nor its UDP port is inferred from the control-plane URL.
/// The returned client and lease are intentionally caller-owned so the native
/// service lifecycle decides heartbeat cadence and shutdown.
pub async fn establish_presence_client(
    control_plane_url: &str,
    bind_address: SocketAddr,
    gateway: SocketAddr,
    boot_id: u32,
) -> Result<(PresenceClient, PresenceSessionKeyLease), String> {
    let presence_device_id = runtime_slot()
        .lock()
        .unwrap()
        .as_ref()
        .and_then(NexusRuntime::presence_device_id)
        .ok_or("Nexus device is not enrolled")?;
    let lease = request_presence_session_key(control_plane_url).await?;
    let key_pair = Config::get_key_pair();
    let public_key: [u8; 32] = key_pair
        .1
        .as_slice()
        .try_into()
        .map_err(|_| "RustDesk device public key unavailable")?;
    let secret_key =
        sign::SecretKey::from_slice(&key_pair.0).ok_or("RustDesk device key unavailable")?;
    let nonce: [u8; 16] = hbb_common::sodiumoxide::randombytes::randombytes(16)
        .try_into()
        .map_err(|_| "failed to generate Presence nonce")?;
    let mut client = PresenceClient::bind(bind_address, gateway, presence_device_id, boot_id)
        .await
        .map_err(|_| "failed to bind Presence socket")?;
    client
        .register(public_key, nonce, lease.key_id, lease.key, |message| {
            sign::sign_detached(message, &secret_key).to_bytes()
        })
        .await
        .map_err(|_| "Presence registration rejected")?;
    Ok((client, lease))
}

/// Native-service-owned Presence session. It keeps the UDP socket and its
/// short-lived key together, and refuses to send after the control-plane lease
/// expires. The RustDesk service loop decides when to call `send_heartbeat`.
pub struct PresenceSession {
    client: PresenceClient,
    lease: PresenceSessionKeyLease,
}

impl PresenceSession {
    pub async fn send_heartbeat(&mut self, heartbeat: PresenceHeartbeat) -> Result<(), String> {
        if self.lease.expires_at <= hbb_common::get_time() {
            return Err("Presence session key lease expired".into());
        }
        self.client
            .send_heartbeat(self.lease.key_id, self.lease.key, heartbeat)
            .await
            .map_err(|_| "failed to send Presence heartbeat".to_string())
    }

    pub fn lease(&self) -> &PresenceSessionKeyLease {
        &self.lease
    }
}

/// Establishes a caller-owned session for service loops that need to keep
/// sending authenticated Presence heartbeats.
pub async fn establish_presence_session(
    control_plane_url: &str,
    bind_address: SocketAddr,
    gateway: SocketAddr,
    boot_id: u32,
) -> Result<PresenceSession, String> {
    let (client, lease) =
        establish_presence_client(control_plane_url, bind_address, gateway, boot_id).await?;
    Ok(PresenceSession { client, lease })
}

pub fn handle_request(request: Request) -> Response {
    match request {
        Request::GetStatus(GetStatusRequest { version }) if version == IPC_VERSION => {
            Response::Status(StatusResponse {
                version,
                status: status_snapshot(),
            })
        }
        Request::RefreshDesiredState(RefreshDesiredStateRequest { version })
            if version == IPC_VERSION =>
        {
            let Some(url) = host_control_plane_url().lock().unwrap().clone() else {
                return Response::Error(ErrorResponse {
                    version: IPC_VERSION,
                    message: "Nexus host service is not running".into(),
                });
            };
            let Ok(handle) = hbb_common::tokio::runtime::Handle::try_current() else {
                return Response::Error(ErrorResponse {
                    version: IPC_VERSION,
                    message: "Nexus IPC refresh requires the RustDesk Tokio runtime".into(),
                });
            };
            handle.spawn(async move {
                if let Err(error) = refresh_tunnel_desired_state(&url).await {
                    hbb_common::log::warn!("Nexus IPC Desired State refresh failed: {error}");
                }
            });
            Response::RefreshScheduled(RefreshScheduledResponse { version })
        }
        #[cfg(feature = "nexus-native-tunnel")]
        Request::RefreshPortForwardCredential(RefreshPortForwardCredentialRequest {
            version,
            grant_id,
        }) if version == IPC_VERSION => {
            let Some(url) = host_control_plane_url().lock().unwrap().clone() else {
                return Response::Error(ErrorResponse {
                    version: IPC_VERSION,
                    message: "Nexus host service is not running".into(),
                });
            };
            let Some(path) = std::env::var_os("NEXUS_TUNNEL_CREDENTIAL_FILE") else {
                return Response::Error(ErrorResponse {
                    version: IPC_VERSION,
                    message: "Nexus PortForward credential path is not configured".into(),
                });
            };
            let handle = hbb_common::tokio::runtime::Handle::current();
            handle.spawn(async move {
                if let Err(error) =
                    refresh_port_forward_credential(&url, &grant_id, path.as_ref()).await
                {
                    hbb_common::log::warn!(
                        "Nexus IPC PortForward credential refresh failed: {error}"
                    );
                }
            });
            Response::PortForwardCredentialRefreshScheduled(RefreshScheduledResponse { version })
        }
        Request::GetStatus(GetStatusRequest { version }) => Response::Error(ErrorResponse {
            version: IPC_VERSION,
            message: format!("unsupported nexus ipc version {version}"),
        }),
        Request::RefreshDesiredState(RefreshDesiredStateRequest { version }) => {
            Response::Error(ErrorResponse {
                version: IPC_VERSION,
                message: format!("unsupported nexus ipc version {version}"),
            })
        }
        Request::RefreshPortForwardCredential(RefreshPortForwardCredentialRequest {
            version,
            ..
        }) => Response::Error(ErrorResponse {
            version: IPC_VERSION,
            message: format!("unsupported nexus ipc version {version}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_and_report_tunnel_desired_state, apply_verified_tunnel_desired_state,
        bind_device_uid, establish_presence_client, handle_request,
        record_tunnel_desired_state_application, record_tunnel_desired_state_application_loopback,
        start_runtime, status_snapshot, stop_runtime, ErrorResponse, GetStatusRequest, HealthState,
        LoopbackTunnelApplicationReporter, PresenceHeartbeat, PresenceHostOps, PresenceSession,
        PresenceSessionKeyLease, RefreshDesiredStateRequest, Request, Response,
        TunnelApplicationReporter, TunnelHostConfig, TunnelState, VerifiedDesiredState,
    };
    use nexus_client::tunnel::{ConfigDigest, ConfigVersion, PresenceClient};
    use std::{
        fs,
        future::Future,
        net::SocketAddr,
        pin::Pin,
        sync::{Arc, Mutex},
        time::Duration,
    };

    #[cfg(feature = "nexus-native-tunnel")]
    #[test]
    fn port_forward_credential_install_replaces_only_complete_file() {
        let path = std::env::temp_dir().join(format!(
            "nexus-port-forward-{}.json",
            hbb_common::get_time()
        ));
        super::atomic_write_credential(&path, br#"{"grantId":"grant"}"#).unwrap();
        assert_eq!(fs::read(&path).unwrap(), br#"{"grantId":"grant"}"#);
        super::atomic_write_credential(&path, br#"{"grantId":"replacement"}"#).unwrap();
        assert_eq!(fs::read(&path).unwrap(), br#"{"grantId":"replacement"}"#);
        let _ = fs::remove_file(path);
    }

    #[cfg(feature = "nexus-native-tunnel")]
    #[test]
    fn gateway_configuration_is_explicit_and_fail_closed() {
        let credential = std::env::temp_dir().join("nexus-gateway-credential.json");
        assert_eq!(
            super::gateway_config_from_values(
                None,
                Some("peer".into()),
                None,
                None,
                None,
                None,
                None
            )
            .unwrap_err(),
            "NEXUS_TUNNEL_CREDENTIAL_FILE is required"
        );
        assert_eq!(
            super::gateway_config_from_values(
                Some(credential.clone()),
                Some(" ".into()),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_err(),
            "NEXUS_GATEWAY_PEER_ID is required"
        );
        assert_eq!(
            super::gateway_config_from_values(
                Some(credential.clone()),
                Some("peer".into()),
                Some("[::1]:21119".into()),
                None,
                None,
                None,
                None,
            )
            .unwrap_err(),
            "NEXUS_GATEWAY_BIND must be an IPv4 socket address"
        );
        assert_eq!(
            super::gateway_config_from_values(
                Some(credential.clone()),
                Some("peer".into()),
                Some("127.0.0.1:0".into()),
                None,
                None,
                None,
                None,
            )
            .unwrap_err(),
            "NEXUS_GATEWAY_BIND must use a non-zero port"
        );
        assert_eq!(
            super::gateway_config_from_values(
                Some(credential.clone()),
                Some("peer".into()),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_err(),
            "NEXUS_GATEWAY_DEVICE_UID is required"
        );
        let config = super::gateway_config_from_values(
            Some(credential),
            Some("peer".into()),
            None,
            None,
            Some("gateway-1".into()),
            Some("https://control.example".into()),
            Some("grant-1".into()),
        )
        .unwrap();
        assert_eq!(config.bind_addr, "127.0.0.1:21119".parse().unwrap());
        assert!(config.token.is_empty());
        assert_eq!(config.device_uid, "gateway-1");
        assert_eq!(config.grant_id, "grant-1");
        assert_eq!(
            super::gateway_port_forward_context_path("grant-1").unwrap(),
            "/v1/device/gateway/tunnel/access-grants/grant-1/port-forward-context"
        );
        assert!(super::gateway_port_forward_context_path("grant/1").is_err());
    }

    #[cfg(feature = "nexus-native-tunnel")]
    #[test]
    fn headless_gateway_reaches_native_listener_ready_state() {
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let interface = super::HeadlessPortForwardInterface::new("peer".into(), false);
            let listener_config = crate::client::Interface::get_lch(&interface);
            let (close, receiver) = hbb_common::tokio::sync::mpsc::unbounded_channel();
            let (ready, ready_receiver) = hbb_common::tokio::sync::oneshot::channel();
            let key = crate::common::get_key(false).await;
            let task = hbb_common::tokio::spawn(async move {
                crate::port_forward::listen_with_bind_ready(
                    "127.0.0.1",
                    "peer".into(),
                    String::new(),
                    0,
                    interface,
                    receiver,
                    &key,
                    "",
                    listener_config,
                    "127.0.0.1".into(),
                    1,
                    Some(ready),
                )
                .await
            });
            let endpoint = hbb_common::tokio::time::timeout(Duration::from_secs(2), ready_receiver)
                .await
                .expect("native listener readiness timed out")
                .expect("native listener readiness channel closed");
            assert_eq!(endpoint.ip().to_string(), "127.0.0.1");
            assert_ne!(endpoint.port(), 0);
            let _ = close.send(crate::client::Data::Close);
            let _ = task.await;
        });
    }

    #[cfg(feature = "nexus-native-tunnel")]
    #[test]
    fn port_forward_credential_refresh_verifies_before_atomic_install() {
        let _guard = start_runtime("123456789", "config");
        bind_device_uid("device-1").unwrap();
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            use hbb_common::{
                message_proto::NexusPortForwardContext,
                sodiumoxide::crypto::sign,
                tokio::io::{AsyncReadExt, AsyncWriteExt},
            };

            let (public_key, secret_key) = sign::gen_keypair();
            let expires_at = hbb_common::get_time() + 60;
            let nonce = vec![1, 2, 3, 4];
            let context = NexusPortForwardContext {
                grant_id: "grant-1".into(),
                session_id: "session-1".into(),
                target_digest: "ab".repeat(32),
                protocol_version: 1,
                expires_at,
                nonce: nonce.clone().into(),
                key_id: "key-1".into(),
                source_device_uid: "device-1".into(),
                publishing_device_uid: "publisher-1".into(),
                relay_node_id: "relay-1".into(),
                ..Default::default()
            };
            let proof = sign::sign_detached(
                &hbb_common::nexus_wire::canonical_port_forward_admission(&context),
                &secret_key,
            );
            let credential = serde_json::json!({
                "grantId": context.grant_id,
                "sessionId": context.session_id,
                "admissionProofHex": hex::encode(proof.to_bytes()),
                "targetDigest": context.target_digest,
                "protocolVersion": context.protocol_version,
                "expiresAt": context.expires_at,
                "nonceHex": hex::encode(nonce),
                "keyId": context.key_id,
                "sourceDeviceUid": context.source_device_uid,
                "publishingDeviceUid": context.publishing_device_uid,
                "relayNodeId": context.relay_node_id,
                "targetHost": "127.0.0.1",
                "targetPort": 22,
            })
            .to_string();
            let expected_credential = credential.clone();
            let key = format!(r#"{{"publicKeyHex":"{}"}}"#, hex::encode(public_key.as_ref()));
            let listener = hbb_common::tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let server = hbb_common::tokio::spawn(async move {
                let mut requests = Vec::new();
                for response in [credential, key] {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    let mut chunk = [0; 1024];
                    loop {
                        let read = socket.read(&mut chunk).await.unwrap();
                        request.extend_from_slice(&chunk[..read]);
                        if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                            break;
                        }
                    }
                    socket
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                response.len(), response
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                    requests.push(String::from_utf8(request).unwrap());
                }
                requests
            });
            let path = std::env::temp_dir().join(format!(
                "nexus-port-forward-refresh-{}-{}.json",
                std::process::id(),
                hbb_common::get_time()
            ));
            super::refresh_port_forward_credential_loopback(&base_url, "grant-1", &path)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&path).unwrap())
                    .unwrap(),
                serde_json::from_str::<serde_json::Value>(&expected_credential).unwrap()
            );
            let requests = server.await.unwrap();
            assert!(requests[0].starts_with(
                "GET /v1/device/tunnel/access-grants/grant-1/port-forward-context HTTP/1.1"
            ));
            assert!(requests[1].starts_with(
                "GET /v1/device/tunnel/signing-keys/key-1 HTTP/1.1"
            ));
            let _ = fs::remove_file(path);
        });
    }

    #[cfg(feature = "nexus-frp-compat-smoke")]
    use super::apply_verified_tunnel_desired_state_async;

    #[derive(Default)]
    struct RecordingReporter(Mutex<Vec<(u64, String, String, Option<String>)>>);

    impl TunnelApplicationReporter for RecordingReporter {
        fn report<'a>(
            &'a self,
            _: &'a str,
            version: u64,
            digest_hex: &'a str,
            outcome: &'a str,
            detail: Option<&'a str>,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            self.0.lock().unwrap().push((
                version,
                digest_hex.into(),
                outcome.into(),
                detail.map(Into::into),
            ));
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn lifecycle_runtime_is_visible_through_snapshot() {
        let _guard = start_runtime("123456789", "config");

        let status = status_snapshot().unwrap();

        assert_eq!(status.health, HealthState::Running);
        assert_eq!(status.tunnel.state, TunnelState::PresenceOnly);
    }

    #[test]
    fn host_config_requires_explicit_device_and_network_boundaries() {
        assert_eq!(
            TunnelHostConfig::parse("", "https://control.example", "127.0.0.1:21116", ""),
            Err("Nexus device UID is not configured")
        );
        assert_eq!(
            TunnelHostConfig::parse("device-1", "", "127.0.0.1:21116", ""),
            Err("Nexus control-plane URL is not configured")
        );
        assert_eq!(
            TunnelHostConfig::parse("device-1", "https://control.example", "invalid", ""),
            Err("Nexus Presence Gateway address is invalid")
        );
        let config = TunnelHostConfig::parse(
            " device-1 ",
            "https://control.example/",
            "127.0.0.1:21116",
            "",
        )
        .unwrap();
        assert_eq!(config.device_uid, "device-1");
        assert_eq!(config.control_plane_url, "https://control.example");
        assert_eq!(config.presence_bind, "0.0.0.0:0".parse().unwrap());
    }

    #[test]
    fn control_plane_helpers_refuse_plain_http_before_sending_credentials() {
        assert_eq!(
            super::require_https_control_plane("http://127.0.0.1:3000"),
            Err("Nexus control-plane URL must use HTTPS".into())
        );
        assert!(super::require_https_control_plane("https://control.example").is_ok());
    }

    #[test]
    fn presence_restarts_use_a_csprng_boot_source_and_bounded_backoff() {
        assert_eq!(
            super::new_presence_boot_uuid().get_version(),
            Some(uuid::Version::Random)
        );
        assert_eq!(super::next_presence_retry_secs(0), 1);
        assert_eq!(super::next_presence_retry_secs(4), 4);
        assert_eq!(
            super::next_presence_retry_secs(u64::MAX),
            super::PRESENCE_RETRY_MAX_SECS
        );
    }

    #[derive(Clone, Copy)]
    enum PresenceFailure {
        Registration,
        Heartbeat,
        LeaseRefresh,
    }

    struct TestPresenceSession {
        attempt: usize,
    }

    #[derive(Default)]
    struct PresenceRecoveryState {
        attempts: usize,
        boot_ids: Vec<u32>,
        sleeps: Vec<u64>,
    }

    async fn assert_presence_recovers_from(failure: PresenceFailure) {
        let state = Arc::new(Mutex::new(PresenceRecoveryState::default()));
        let cancellation = hbb_common::tokio_util::sync::CancellationToken::new();
        let establish_state = state.clone();
        let sleep_state = state.clone();
        let heartbeat_cancellation = cancellation.clone();
        let mut boot_id = 0;

        let task = hbb_common::tokio::spawn(super::run_presence_loop(
            PresenceHostOps {
                refresh: Box::new(|| Box::pin(async {})),
                establish: Box::new(move |next_boot_id| {
                    let state = establish_state.clone();
                    Box::pin(async move {
                        let mut state = state.lock().unwrap();
                        state.attempts += 1;
                        state.boot_ids.push(next_boot_id);
                        let rejected = matches!(failure, PresenceFailure::Registration)
                            && state.attempts == 1
                            || matches!(failure, PresenceFailure::LeaseRefresh)
                                && state.attempts == 2;
                        (!rejected)
                            .then_some(TestPresenceSession {
                                attempt: state.attempts,
                            })
                            .ok_or_else(|| "planned registration failure".to_string())
                    })
                }),
                heartbeat: Box::new(move |session| {
                    let cancellation = heartbeat_cancellation.clone();
                    Box::pin(async move {
                        if matches!(failure, PresenceFailure::Heartbeat) && session.attempt == 1 {
                            return Err("planned heartbeat failure".into());
                        }
                        if !matches!(failure, PresenceFailure::LeaseRefresh) || session.attempt > 1
                        {
                            cancellation.cancel();
                        }
                        Ok(())
                    })
                }),
                heartbeat_interval_secs: Box::new(|| 0),
                lease_needs_refresh: Box::new(move |session| {
                    matches!(failure, PresenceFailure::LeaseRefresh) && session.attempt == 1
                }),
                sleep: Box::new(move |secs| {
                    sleep_state.lock().unwrap().sleeps.push(secs);
                    Box::pin(async {})
                }),
                next_boot_id: Box::new(move || {
                    boot_id += 1;
                    boot_id
                }),
            },
            cancellation,
        ));

        hbb_common::tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("cancellation should stop the host task")
            .expect("host task should not panic");
        let state = state.lock().unwrap();
        let expected_boot_ids = match failure {
            PresenceFailure::Registration | PresenceFailure::Heartbeat => vec![1, 2],
            PresenceFailure::LeaseRefresh => vec![1, 2, 3],
        };
        assert_eq!(state.boot_ids, expected_boot_ids);
        assert!(state.sleeps.contains(&1));
        assert!(state
            .sleeps
            .iter()
            .all(|secs| *secs <= super::PRESENCE_RETRY_MAX_SECS));
    }

    #[test]
    fn presence_host_recovers_from_registration_failure_with_a_fresh_boot_id() {
        hbb_common::tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(assert_presence_recovers_from(PresenceFailure::Registration));
    }

    #[test]
    fn presence_host_recovers_from_heartbeat_failure_with_a_fresh_boot_id() {
        hbb_common::tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(assert_presence_recovers_from(PresenceFailure::Heartbeat));
    }

    #[test]
    fn presence_host_recovers_from_lease_refresh_failure_with_a_fresh_boot_id() {
        hbb_common::tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(assert_presence_recovers_from(PresenceFailure::LeaseRefresh));
    }

    #[test]
    fn ipc_handler_rejects_unknown_versions() {
        let response = handle_request(Request::GetStatus(GetStatusRequest { version: 99 }));

        match response {
            Response::Error(error) => {
                assert!(error.message.contains("unsupported nexus ipc version"));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn ipc_refresh_never_accepts_raw_configuration_or_runs_without_host_service() {
        stop_runtime();
        let response = handle_request(Request::RefreshDesiredState(
            RefreshDesiredStateRequest::default(),
        ));
        assert!(matches!(
            response,
            Response::Error(ErrorResponse { message, .. })
                if message == "Nexus host service is not running"
        ));
    }

    #[test]
    fn ipc_status_never_exposes_config_or_credentials() {
        let _guard = start_runtime("123456789", "config");

        let status = super::ipc_status();

        assert_eq!(status.version, super::IPC_VERSION);
        assert_eq!(status.health, "running");
        assert_eq!(status.tunnel_state, "presence-only");
        assert_eq!(status.desired_version, Some(1));
        assert_eq!(status.applied_version, Some(1));
    }

    #[test]
    fn presence_setup_rejects_an_unenrolled_runtime_before_network_io() {
        let _guard = start_runtime("123456789", "config");
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let gateway: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(establish_presence_client(
            "http://127.0.0.1:9",
            bind,
            gateway,
            1,
        ));

        assert!(matches!(result, Err(message) if message == "Nexus device is not enrolled"));
    }

    #[test]
    fn expired_presence_lease_is_rejected_before_udp_send() {
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(async {
            let client = PresenceClient::bind(
                "127.0.0.1:0".parse().unwrap(),
                "127.0.0.1:9".parse().unwrap(),
                1,
                1,
            )
            .await
            .unwrap();
            let mut session = PresenceSession {
                client,
                lease: PresenceSessionKeyLease {
                    key_id: 1,
                    key: [1; 32],
                    expires_at: hbb_common::get_time() - 1,
                },
            };
            session
                .send_heartbeat(PresenceHeartbeat {
                    config_version: ConfigVersion(1),
                    config_digest: ConfigDigest([2; 32]),
                    capability_digest: 3,
                })
                .await
        });

        assert_eq!(result.unwrap_err(), "Presence session key lease expired");
    }

    #[test]
    fn active_presence_lease_sends_a_heartbeat() {
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let gateway = hbb_common::tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .unwrap();
            let client = PresenceClient::bind(
                "127.0.0.1:0".parse().unwrap(),
                gateway.local_addr().unwrap(),
                1,
                1,
            )
            .await
            .unwrap();
            let mut session = PresenceSession {
                client,
                lease: PresenceSessionKeyLease {
                    key_id: 1,
                    key: [1; 32],
                    expires_at: hbb_common::get_time() + 60,
                },
            };
            session
                .send_heartbeat(PresenceHeartbeat {
                    config_version: ConfigVersion(1),
                    config_digest: ConfigDigest([2; 32]),
                    capability_digest: 3,
                })
                .await
                .unwrap();
            let mut datagram = [0; 128];
            assert!(gateway.recv_from(&mut datagram).await.unwrap().0 > 0);
        });
    }

    #[test]
    fn fixed_presence_bind_can_be_reused_for_lease_refresh() {
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let reserved = hbb_common::tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .unwrap();
            let bind = reserved.local_addr().unwrap();
            drop(reserved);

            let first = PresenceClient::bind(bind, "127.0.0.1:9".parse().unwrap(), 1, 1)
                .await
                .unwrap();
            drop(first);
            PresenceClient::bind(bind, "127.0.0.1:9".parse().unwrap(), 1, 2)
                .await
                .expect("replacement session should reuse the configured bind");
        });
    }

    #[test]
    fn verified_desired_state_is_the_only_state_allowed_into_the_runtime() {
        let _guard = start_runtime("123456789", "config");

        apply_verified_tunnel_desired_state(VerifiedDesiredState {
            desired_state: nexus_client::tunnel::TunnelDesiredState::presence_only(2),
            data_plane_assignment: None,
        })
        .unwrap();

        assert_eq!(
            status_snapshot().unwrap().tunnel.applied_version.unwrap().0,
            2
        );
    }

    #[test]
    fn application_outcome_reporter_records_the_verified_generation() {
        let _guard = start_runtime("123456789", "config");
        let reporter = RecordingReporter::default();
        let desired_state = nexus_client::tunnel::TunnelDesiredState::presence_only(2);
        let digest = desired_state.digest().to_hex();
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();

        runtime
            .block_on(apply_and_report_tunnel_desired_state(
                "https://control.example",
                VerifiedDesiredState {
                    desired_state,
                    data_plane_assignment: None,
                },
                &reporter,
            ))
            .unwrap();

        assert_eq!(
            reporter.0.lock().unwrap().as_slice(),
            &[(2, digest, "applied".into(), None)]
        );
    }

    #[test]
    fn application_outcome_reporter_records_rejected_apply() {
        let guard = start_runtime("123456789", "config");
        super::stop_runtime();
        let reporter = RecordingReporter::default();
        let desired_state = nexus_client::tunnel::TunnelDesiredState::presence_only(2);
        let digest = desired_state.digest().to_hex();
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();

        assert_eq!(
            runtime
                .block_on(apply_and_report_tunnel_desired_state(
                    "https://control.example",
                    VerifiedDesiredState {
                        desired_state,
                        data_plane_assignment: None,
                    },
                    &reporter,
                ))
                .unwrap_err(),
            "Nexus runtime is not running"
        );
        assert_eq!(
            reporter.0.lock().unwrap().as_slice(),
            &[(
                2,
                digest,
                "rejected".into(),
                Some("Nexus runtime is not running".into()),
            )]
        );
        drop(guard);
    }

    #[cfg(feature = "nexus-frp-compat-smoke")]
    #[test]
    fn application_outcome_reporter_records_rejected_active_without_assignment() {
        let _guard = start_runtime("123456789", "config");
        let reporter = RecordingReporter::default();
        let desired_state = nexus_client::tunnel::TunnelDesiredState::active(
            2,
            Vec::new(),
            Vec::new(),
            nexus_client::tunnel::TunnelPolicy::default(),
        );
        let digest = desired_state.digest().to_hex();
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();

        assert_eq!(
            runtime
                .block_on(apply_and_report_tunnel_desired_state(
                    "https://control.example",
                    VerifiedDesiredState {
                        desired_state,
                        data_plane_assignment: None,
                    },
                    &reporter,
                ))
                .unwrap_err(),
            "Active Tunnel Desired State requires a Relay assignment"
        );
        assert_eq!(
            reporter.0.lock().unwrap().as_slice(),
            &[(
                2,
                digest,
                "rejected".into(),
                Some("Active Tunnel Desired State requires a Relay assignment".into()),
            )]
        );
    }

    #[cfg(feature = "nexus-frp-compat-smoke")]
    #[test]
    fn application_outcome_reporter_records_rejected_expired_assignment() {
        let _guard = start_runtime("123456789", "config");
        let reporter = RecordingReporter::default();
        let desired_state = nexus_client::tunnel::TunnelDesiredState::active(
            2,
            Vec::new(),
            Vec::new(),
            nexus_client::tunnel::TunnelPolicy::default(),
        );
        let digest = desired_state.digest().to_hex();
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();
        let assignment = nexus_client::tunnel::TunnelDataPlaneAssignment {
            relay: nexus_client::tunnel::RelayAssignment {
                address: "127.0.0.1".into(),
                port: 7000,
                client_id: "device-1".into(),
                token: "short-lived".into(),
                oidc: None,
                expires_at: (hbb_common::get_time().saturating_sub(1)).max(0) as u64,
            },
            remote_ports: Vec::new(),
        };

        assert_eq!(
            runtime
                .block_on(apply_and_report_tunnel_desired_state(
                    "https://control.example",
                    VerifiedDesiredState {
                        desired_state,
                        data_plane_assignment: Some(assignment),
                    },
                    &reporter,
                ))
                .unwrap_err(),
            "Tunnel Desired State was rejected"
        );
        assert_eq!(
            reporter.0.lock().unwrap().as_slice(),
            &[(
                2,
                digest,
                "rejected".into(),
                Some("Tunnel Desired State was rejected".into()),
            )]
        );
    }

    #[cfg(feature = "nexus-frp-compat-smoke")]
    #[test]
    fn local_access_auxiliary_is_host_owned_and_cancellable_without_a_relay() {
        use nexus_client::tunnel::{LocalAccessListener, LocalAccessProtocol};

        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let desired = nexus_client::tunnel::TunnelDesiredState::presence_only(2);
            assert!(super::prepare_auxiliary(&desired, None)
                .await
                .unwrap()
                .is_none());

            let mut desired = desired;
            desired.local_access_listeners.push(LocalAccessListener {
                listener_id: "local-support".into(),
                protocol: LocalAccessProtocol::HttpConnect,
                bind: "127.0.0.1:0".parse().unwrap(),
                allowed_targets: vec!["127.0.0.1:3389".parse().unwrap()],
                max_connections: 1,
            });
            let auxiliary = super::prepare_auxiliary(&desired, None)
                .await
                .unwrap()
                .unwrap();
            let cancellation = auxiliary.cancellation.clone();
            super::install_auxiliary(Some(auxiliary));
            cancellation.cancel();
            hbb_common::tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            super::cancel_auxiliary();
        });
    }

    #[cfg(feature = "nexus-frp-compat-smoke")]
    #[test]
    fn frp_failure_reports_only_the_current_signed_generation() {
        let current = super::ConfigGeneration {
            version: ConfigVersion(2),
            digest: ConfigDigest([2; 32]),
        };
        let application = super::GenerationApplication {
            control_plane_url: "https://control.example".into(),
            version: 2,
            digest_hex: "02".repeat(32),
        };

        assert_eq!(
            super::application_for_generation(current, Some(application.clone()), current)
                .unwrap()
                .version,
            2
        );
        assert!(super::application_for_generation(
            current,
            Some(application),
            super::ConfigGeneration {
                version: ConfigVersion(1),
                digest: ConfigDigest([1; 32]),
            },
        )
        .is_none());
    }

    #[cfg(feature = "nexus-frp-compat-smoke")]
    #[test]
    fn host_reloads_two_active_generations_through_the_controlled_relay() {
        let Some(frps) = std::env::var_os("NEXUS_TUNNEL_FRPS_BIN") else {
            return;
        };
        use nexus_client::tunnel::{
            RelayAssignment, TunnelDataPlaneAssignment, TunnelDesiredState, TunnelPolicy,
            TunnelRoute, TunnelService,
        };
        use nexus_tunnel_server::{ExternalFrpsRuntime, RelayRuntimeConfig};

        let _guard = start_runtime("123456789", "config");
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            use hbb_common::tokio::io::{AsyncReadExt, AsyncWriteExt};

            let control_port = free_tcp_port();
            let mut relay = ExternalFrpsRuntime::start(
                std::path::Path::new(&frps),
                &RelayRuntimeConfig {
                    bind_addr: "127.0.0.1".parse().unwrap(),
                    bind_port: control_port,
                    token: "nexus-rustdesk-host-smoke".into(),
                    tcpmux_httpconnect_port: None,
                    vhost_http_port: None,
                    vhost_https_port: None,
                },
            )
            .unwrap();
            hbb_common::tokio::time::sleep(Duration::from_millis(100)).await;

            let first = hbb_common::tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let first_port = first.local_addr().unwrap().port();
            let first_echo = hbb_common::tokio::spawn(async move {
                let (mut stream, _) = first.accept().await.unwrap();
                let mut payload = [0; 4];
                stream.read_exact(&mut payload).await.unwrap();
                stream.write_all(&payload).await.unwrap();
            });
            let first_remote = free_tcp_port();
            let first_apply = hbb_common::tokio::spawn(apply_verified_tunnel_desired_state_async(
                host_active_state(2, first_port, first_remote, control_port),
            ));
            echo_host_tunnel(first_remote, b"one!").await;
            first_apply.await.unwrap().unwrap();
            first_echo.await.unwrap();
            wait_for_applied_version(2).await;

            let second = hbb_common::tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let second_port = second.local_addr().unwrap().port();
            let second_echo = hbb_common::tokio::spawn(async move {
                let mut echoed_requests = 0;
                loop {
                    let (mut stream, _) = second.accept().await.unwrap();
                    let mut payload = [0; 4];
                    if stream.read_exact(&mut payload).await.is_ok() {
                        stream.write_all(&payload).await.unwrap();
                        echoed_requests += 1;
                        if echoed_requests == 2 {
                            return;
                        }
                    }
                }
            });
            let second_remote = free_tcp_port();
            let second_apply = hbb_common::tokio::spawn(apply_verified_tunnel_desired_state_async(
                host_active_state(3, second_port, second_remote, control_port),
            ));
            echo_host_tunnel(second_remote, b"two!").await;
            second_apply.await.unwrap().unwrap();
            wait_for_applied_version(3).await;

            // A rejected replacement must leave the last serving generation
            // intact. A zero public port is rejected while compiling the
            // candidate, before it can replace the live upstream generation.
            let mut rejected = host_active_state(4, second_port, free_tcp_port(), control_port);
            rejected
                .data_plane_assignment
                .as_mut()
                .unwrap()
                .remote_ports[0]
                .1 = 0;
            assert_eq!(
                apply_verified_tunnel_desired_state_async(rejected)
                    .await
                    .unwrap_err(),
                "Tunnel Relay assignment was rejected"
            );
            echo_host_tunnel(second_remote, b"stay").await;
            second_echo.await.unwrap();
            wait_for_applied_version(3).await;
            relay.shutdown().await.unwrap();
        });

        fn host_active_state(
            version: u64,
            local_port: u16,
            remote_port: u16,
            control_port: u16,
        ) -> VerifiedDesiredState {
            VerifiedDesiredState {
                desired_state: TunnelDesiredState::active(
                    version,
                    vec![TunnelService {
                        service_id: "host-service".into(),
                        name: "host-service".into(),
                        local_addr: format!("127.0.0.1:{local_port}"),
                        protocol: nexus_client::tunnel::TransportProtocol::Tcp,
                        virtual_host: None,
                        protected_access: None,
                    }],
                    vec![TunnelRoute {
                        route_id: "host-route".into(),
                        service: "host-service".into(),
                        remote_addr: "edge://host-service".into(),
                    }],
                    TunnelPolicy::default(),
                ),
                data_plane_assignment: Some(TunnelDataPlaneAssignment {
                    relay: RelayAssignment {
                        address: "127.0.0.1".into(),
                        port: control_port,
                        client_id: "rustdesk-host-smoke".into(),
                        token: "nexus-rustdesk-host-smoke".into(),
                        oidc: None,
                        expires_at: u64::MAX,
                    },
                    remote_ports: vec![("edge://host-service".into(), remote_port)],
                }),
            }
        }

        fn free_tcp_port() -> u16 {
            std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        }

        async fn echo_host_tunnel(port: u16, payload: &[u8; 4]) {
            use hbb_common::tokio::io::{AsyncReadExt, AsyncWriteExt};
            for _ in 0..80 {
                if let Ok(mut stream) =
                    hbb_common::tokio::net::TcpStream::connect(("127.0.0.1", port)).await
                {
                    if stream.write_all(payload).await.is_ok() {
                        let mut echoed = [0; 4];
                        match stream.read_exact(&mut echoed).await {
                            Ok(_) => {
                                assert_eq!(&echoed, payload);
                                return;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                            Err(error) => panic!("host Relay proxy did not echo: {error}"),
                        }
                    }
                }
                hbb_common::tokio::time::sleep(Duration::from_millis(25)).await;
            }
            panic!("host Relay proxy did not become ready");
        }

        async fn wait_for_applied_version(version: u64) {
            for _ in 0..80 {
                if status_snapshot().and_then(|status| status.tunnel.applied_version)
                    == Some(ConfigVersion(version))
                {
                    return;
                }
                hbb_common::tokio::time::sleep(Duration::from_millis(25)).await;
            }
            panic!("host did not commit the ready generation");
        }
    }

    #[cfg(feature = "nexus-frp-compat-smoke")]
    #[test]
    fn rejected_active_replacement_reports_the_signed_generation_to_loopback_control_plane() {
        let _guard = start_runtime("123456789", "config");
        bind_device_uid("device-1").unwrap();
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            use hbb_common::tokio::io::{AsyncReadExt, AsyncWriteExt};

            let listener = hbb_common::tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let control_plane_url = format!("http://{}", listener.local_addr().unwrap());
            let server = hbb_common::tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0; 1024];
                loop {
                    let read = socket.read(&mut chunk).await.unwrap();
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        break;
                    }
                }
                socket
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
                String::from_utf8(request).unwrap()
            });
            let rejected = VerifiedDesiredState {
                desired_state: nexus_client::tunnel::TunnelDesiredState::active(
                    9,
                    vec![nexus_client::tunnel::TunnelService {
                        service_id: "rejected-service".into(),
                        name: "rejected-service".into(),
                        local_addr: "127.0.0.1:1".into(),
                        protocol: nexus_client::tunnel::TransportProtocol::Tcp,
                        virtual_host: None,
                        protected_access: None,
                    }],
                    vec![nexus_client::tunnel::TunnelRoute {
                        route_id: "rejected-route".into(),
                        service: "rejected-service".into(),
                        remote_addr: "edge://rejected-service".into(),
                    }],
                    nexus_client::tunnel::TunnelPolicy::default(),
                ),
                data_plane_assignment: Some(nexus_client::tunnel::TunnelDataPlaneAssignment {
                    relay: nexus_client::tunnel::RelayAssignment {
                        address: "127.0.0.1".into(),
                        port: 7000,
                        client_id: "device-1".into(),
                        token: "test-token".into(),
                        oidc: None,
                        expires_at: u64::MAX,
                    },
                    remote_ports: vec![("edge://rejected-service".into(), 0)],
                }),
            };
            let digest = rejected.desired_state.digest().to_hex();
            assert_eq!(
                apply_and_report_tunnel_desired_state(
                    &control_plane_url,
                    rejected,
                    &LoopbackTunnelApplicationReporter,
                )
                .await
                .unwrap_err(),
                "Tunnel Relay assignment was rejected"
            );
            let request = server.await.unwrap();
            assert!(request.starts_with("POST /v1/device/tunnel/applications HTTP/1.1"));
            assert!(request.contains("\"version\":9"));
            assert!(request.contains(&format!("\"digestHex\":\"{digest}\"")));
            assert!(request.contains("\"outcome\":\"rejected\""));
        });
    }

    #[test]
    fn application_result_rejects_an_unenrolled_runtime_before_network_io() {
        let _guard = start_runtime("123456789", "config");
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();

        let result = runtime.block_on(record_tunnel_desired_state_application(
            "http://127.0.0.1:9",
            1,
            "0123456789abcdef",
            "applied",
            None,
        ));

        assert_eq!(result.unwrap_err(), "Nexus device is not enrolled");
    }

    #[test]
    fn loopback_application_result_keeps_production_https_boundary_explicit() {
        let _guard = start_runtime("123456789", "config");
        bind_device_uid("device-1").unwrap();
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();

        runtime.block_on(async {
            use hbb_common::tokio::io::{AsyncReadExt, AsyncWriteExt};

            let listener = hbb_common::tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let server = hbb_common::tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0; 1024];
                loop {
                    let read = socket.read(&mut chunk).await.unwrap();
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        break;
                    }
                }
                socket
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
                String::from_utf8(request).unwrap()
            });

            record_tunnel_desired_state_application_loopback(
                &base_url,
                7,
                "ab".repeat(32).as_str(),
                "applied",
                None,
            )
            .await
            .unwrap();
            let request = server.await.unwrap();
            assert!(request.starts_with("POST /v1/device/tunnel/applications HTTP/1.1"));
            assert!(request.contains("x-nexus-device-uid: device-1"));
            assert!(request.contains("\"version\":7"));
            assert!(request.contains("\"outcome\":\"applied\""));
        });
    }

    #[test]
    fn loopback_host_refresh_fetches_verifies_applies_and_reports() {
        let _guard = start_runtime("123456789", "config");
        bind_device_uid("device-1").unwrap();
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();

        runtime.block_on(async {
            use hbb_common::{
                sodiumoxide::crypto::sign,
                tokio::io::{AsyncReadExt, AsyncWriteExt},
            };
            use sha2::{Digest, Sha256};

            let desired = nexus_client::tunnel::TunnelDesiredState::presence_only(2);
            let digest_hex = desired.v2_digest().to_hex();
            let key_id = "key-1";
            let not_before = 1_i64;
            let expires_at = hbb_common::get_time() + 60;
            let mut canonical = Sha256::new();
            canonical.update(b"nexusflow-tunnel-desired-state-v1\0");
            for value in ["account-1", "device-1", key_id, digest_hex.as_str()] {
                canonical.update((value.len() as u64).to_le_bytes());
                canonical.update(value.as_bytes());
            }
            canonical.update([1]);
            canonical.update(("sha256-v2".len() as u64).to_le_bytes());
            canonical.update(b"sha256-v2");
            canonical.update(2_u64.to_le_bytes());
            canonical.update(not_before.to_le_bytes());
            canonical.update(expires_at.to_le_bytes());
            canonical.update([0]);
            let (public_key, secret_key) = sign::gen_keypair();
            let signature_hex = hex::encode(sign::sign_detached(&canonical.finalize(), &secret_key));
            let desired_payload = format!(
                r#"{{"ownerAccountId":"account-1","deviceUid":"device-1","keyId":"{key_id}","version":2,"digestAlgorithm":"sha256-v2","digestHex":"{digest_hex}","notBefore":{not_before},"expiresAt":{expires_at},"signatureHex":"{signature_hex}","mode":"presenceonly","services":[],"routes":[],"policy":{{"presenceIntervalSecs":30,"initialBackoffSecs":1,"maxBackoffSecs":30}}}}"#
            );
            let listener = hbb_common::tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let signing_key_payload =
                format!("{{\"publicKeyHex\":\"{}\"}}", hex::encode(public_key.as_ref()));
            let server = hbb_common::tokio::spawn(async move {
                let mut requests = Vec::new();
                for response in [
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        desired_payload.len(), desired_payload
                    ),
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{signing_key_payload}",
                        signing_key_payload.len(),
                    ),
                    "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
                ] {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    let mut chunk = [0; 1024];
                    loop {
                        let read = socket.read(&mut chunk).await.unwrap();
                        request.extend_from_slice(&chunk[..read]);
                        if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                            break;
                        }
                    }
                    socket.write_all(response.as_bytes()).await.unwrap();
                    requests.push(String::from_utf8(request).unwrap());
                }
                requests
            });

            super::refresh_tunnel_desired_state_loopback(&base_url)
                .await
                .unwrap();
            let requests = server.await.unwrap();
            assert!(requests[0].starts_with("GET /v1/device/tunnel/desired-state HTTP/1.1"));
            assert!(requests[1].starts_with("GET /v1/device/tunnel/signing-keys/key-1 HTTP/1.1"));
            assert!(requests[2].starts_with("POST /v1/device/tunnel/applications HTTP/1.1"));
            assert!(requests[2].contains("\"version\":2"));
            assert!(requests[2].contains("\"digestHex\":\""));
            assert!(requests[2].contains("\"outcome\":\"applied\""));
            assert_eq!(status_snapshot().unwrap().tunnel.applied_version, Some(ConfigVersion(2)));
        });
    }

    #[cfg(feature = "nexus-agent")]
    #[test]
    fn machine_socket_token_exchange_rejects_an_unenrolled_runtime_before_network_io() {
        let _guard = start_runtime("123456789", "config");
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();

        let result = runtime.block_on(super::request_machine_socket_token("http://127.0.0.1:9"));

        assert_eq!(result.unwrap_err(), "Nexus device is not enrolled");
    }

    #[cfg(feature = "nexus-agent")]
    #[test]
    fn agent_socket_packets_preserve_ack_and_never_accept_a_path_execution_id() {
        let (ack, event, payload) =
            super::parse_agent_socket_event("421[\"rpc-request\",{\"executionId\":\"exec-1\"}]")
                .expect("Socket.IO event");
        assert_eq!(ack, Some("1"));
        assert_eq!(event, "rpc-request");
        assert_eq!(payload["executionId"], "exec-1");

        let dispatch = super::AgentDispatch {
            execution_id: "../exec".into(),
            dispatch_token: "dispatch".into(),
            tenant_id: "tenant".into(),
            provider: "codex".into(),
            model: Some("gpt-5".into()),
            prompt: "do work".into(),
            timeout_ms: 1_000,
            tunnel_access: false,
        };
        assert!(super::agent_job_from_dispatch(&dispatch, "machine").is_err());
    }

    #[cfg(feature = "nexus-agent")]
    #[test]
    fn agent_nonzero_exit_is_reported_as_failed_without_output() {
        let exit = nexus_client::agent::AgentExit {
            state: nexus_client::agent::AgentProcessState::Completed,
            exit_code: Some(7),
            stdout: "secret output".into(),
            stderr: "secret error".into(),
        };
        assert_eq!(
            super::agent_exit_status(&exit),
            ("failed", Some(7), Some("agent_exit_nonzero"))
        );
    }

    #[cfg(feature = "nexus-agent")]
    #[test]
    fn remote_agent_cancellation_only_targets_the_registered_execution() {
        let execution_id = "remote-cancel-regression";
        let cancellation = super::register_agent_cancellation(execution_id)
            .expect("register active agent execution");
        assert!(!cancellation.is_cancelled());
        assert!(!super::cancel_active_agent("other-execution"));
        assert!(super::cancel_active_agent(execution_id));
        assert!(cancellation.is_cancelled());
        drop(super::ActiveAgentCancellationGuard(
            execution_id.to_string(),
        ));
        assert!(super::register_agent_cancellation(execution_id).is_some());
        drop(super::ActiveAgentCancellationGuard(
            execution_id.to_string(),
        ));
    }

    #[cfg(feature = "nexus-agent")]
    #[test]
    fn agent_rejects_a_second_active_execution() {
        let first = super::register_agent_cancellation("first-execution")
            .expect("first execution is accepted");
        assert!(super::register_agent_cancellation("second-execution").is_none());
        drop(super::ActiveAgentCancellationGuard(
            "first-execution".to_string(),
        ));
        assert!(super::register_agent_cancellation("second-execution").is_some());
        drop(super::ActiveAgentCancellationGuard(
            "second-execution".to_string(),
        ));
        drop(first);
    }

    #[cfg(feature = "nexus-agent")]
    #[test]
    fn agent_queue_is_fifo_bounded_deduplicated_and_cancellable() {
        use std::collections::VecDeque;

        fn dispatch(execution_id: impl Into<String>) -> super::AgentDispatch {
            super::AgentDispatch {
                execution_id: execution_id.into(),
                dispatch_token: "dispatch".into(),
                tenant_id: "tenant".into(),
                provider: "codex".into(),
                model: None,
                prompt: "do work".into(),
                timeout_ms: 1_000,
                tunnel_access: false,
            }
        }

        let mut queued = VecDeque::new();
        for index in 0..super::AGENT_QUEUE_CAPACITY {
            assert!(super::enqueue_agent_dispatch(
                &mut queued,
                dispatch(format!("queued-{index}")),
            ));
        }
        assert_eq!(queued.len(), super::AGENT_QUEUE_CAPACITY);
        assert!(!super::enqueue_agent_dispatch(
            &mut queued,
            dispatch("queued-0")
        ));
        assert!(!super::enqueue_agent_dispatch(
            &mut queued,
            dispatch("overflow")
        ));
        assert!(super::remove_queued_agent(&mut queued, "queued-1"));
        assert!(!super::remove_queued_agent(&mut queued, "queued-1"));
        assert_eq!(queued.pop_front().unwrap().execution_id, "queued-0");
        assert_eq!(queued.pop_front().unwrap().execution_id, "queued-2");
        super::retain_queued_agent(&mut queued, dispatch("retry-first"));
        assert_eq!(queued.pop_front().unwrap().execution_id, "retry-first");
        assert!(super::enqueue_agent_dispatch(
            &mut queued,
            dispatch("replacement")
        ));
    }

    #[cfg(feature = "nexus-agent")]
    #[test]
    fn agent_finish_retry_uses_five_bounded_backoff_delays() {
        assert_eq!(super::AGENT_FINISH_RETRY_DELAYS_SECS, [1, 2, 5, 10, 30]);
        assert_eq!(super::AGENT_FINISH_RETRY_DELAYS_SECS.len() + 1, 6);
    }

    #[cfg(feature = "nexus-agent")]
    #[test]
    fn agent_socket_loopback_performs_websocket_engineio_and_socketio_ack() {
        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let listener = hbb_common::tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let server = hbb_common::tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = super::WsFramedStream::accept(stream).await.unwrap();
                socket.send_text("0{\"sid\":\"loopback\"}").await.unwrap();
                let auth =
                    String::from_utf8(socket.next().await.unwrap().unwrap().to_vec()).unwrap();
                let auth: serde_json::Value = serde_json::from_str(&auth[2..]).unwrap();
                assert_eq!(auth["token"], "loopback-token");
                assert_eq!(auth["machineId"], "machine-loopback");
                socket.send_text("40{\"sid\":\"socket\"}").await.unwrap();
                let register =
                    String::from_utf8(socket.next().await.unwrap().unwrap().to_vec()).unwrap();
                let (_, event, payload) = super::parse_agent_socket_event(&register).unwrap();
                assert_eq!(event, "rpc-register");
                assert_eq!(payload["method"], "machine-loopback:orchestrator-dispatch");
                socket.send_text("42[\"rpc-registered\",{}]").await.unwrap();
                let cancel_register =
                    String::from_utf8(socket.next().await.unwrap().unwrap().to_vec()).unwrap();
                let (_, event, payload) =
                    super::parse_agent_socket_event(&cancel_register).unwrap();
                assert_eq!(event, "rpc-register");
                assert_eq!(payload["method"], "machine-loopback:orchestrator-cancel");
                socket.send_text("42[\"rpc-registered\",{}]").await.unwrap();
                socket
                    .send_text("421[\"rpc-request\",{\"method\":\"machine-loopback:orchestrator-dispatch\",\"params\":{\"invalid\":true}}]")
                    .await
                    .unwrap();
                let ack =
                    String::from_utf8(socket.next().await.unwrap().unwrap().to_vec()).unwrap();
                assert_eq!(ack, "431[{\"accepted\":false}]");
            });
            let mut client =
                super::WsFramedStream::new(format!("ws://{address}"), None, None, 1_000)
                    .await
                    .unwrap();
            let result = super::run_agent_socket_frames(
                &mut client,
                "https://control.example",
                super::MachineSocketLease {
                    token: "loopback-token".into(),
                    machine_id: "machine-loopback".into(),
                    expires_at: hbb_common::get_time() + 60_000,
                },
                hbb_common::tokio_util::sync::CancellationToken::new(),
            )
            .await;
            assert!(result.is_err(), "server closes after the expected ACK");
            server.await.unwrap();
        });
    }

    #[cfg(all(feature = "nexus-agent", not(windows)))]
    #[test]
    fn agent_socket_loopback_launches_a_restricted_host_child_and_reports_lifecycle() {
        struct PathRestore(Option<std::ffi::OsString>);

        impl Drop for PathRestore {
            fn drop(&mut self) {
                if let Some(path) = self.0.take() {
                    std::env::set_var("PATH", path);
                } else {
                    std::env::remove_var("PATH");
                }
            }
        }

        let config_dir =
            std::env::temp_dir().join(format!("nexus-agent-host-{}", hbb_common::get_time()));
        let bin_dir = config_dir.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let shim = bin_dir.join("codex");
        use std::os::unix::fs::PermissionsExt;
        fs::write(&shim, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).unwrap();
        let previous_path = std::env::var_os("PATH");
        let mut paths = vec![bin_dir.clone()];
        if let Some(path) = previous_path.as_deref() {
            paths.extend(std::env::split_paths(path));
        }
        std::env::set_var("PATH", std::env::join_paths(paths).unwrap());
        let _path_restore = PathRestore(previous_path);
        let _runtime_guard = start_runtime("agent-host-loopback", &config_dir);
        bind_device_uid("device-loopback").unwrap();
        super::test_agent_execution_reports()
            .lock()
            .unwrap()
            .clear();

        let runtime = hbb_common::tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let listener = hbb_common::tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let server = hbb_common::tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = super::WsFramedStream::accept(stream).await.unwrap();
                socket.send_text("0{\"sid\":\"loopback\"}").await.unwrap();
                let _auth = socket.next().await.unwrap().unwrap();
                socket.send_text("40{\"sid\":\"socket\"}").await.unwrap();
                let _register = socket.next().await.unwrap().unwrap();
                socket.send_text("42[\"rpc-registered\",{}]").await.unwrap();
                let _cancel_register = socket.next().await.unwrap().unwrap();
                socket.send_text("42[\"rpc-registered\",{}]").await.unwrap();
                socket
                    .send_text(
                        "421[\"rpc-request\",{\"method\":\"machine-loopback:orchestrator-dispatch\",\"params\":{\"executionId\":\"host-child-1\",\"dispatchToken\":\"dispatch-loopback\",\"tenantId\":\"tenant-loopback\",\"provider\":\"codex\",\"prompt\":\"test-only host child\",\"timeoutMs\":1000}}]",
                    )
                    .await
                    .unwrap();
                let ack = String::from_utf8(socket.next().await.unwrap().unwrap().to_vec()).unwrap();
                assert_eq!(ack, "431[{\"accepted\":true}]");
            });
            let mut client =
                super::WsFramedStream::new(format!("ws://{address}"), None, None, 1_000)
                    .await
                    .unwrap();
            let result = super::run_agent_socket_frames(
                &mut client,
                super::TEST_AGENT_CONTROL_PLANE_URL,
                super::MachineSocketLease {
                    token: "loopback-token".into(),
                    machine_id: "machine-loopback".into(),
                    expires_at: hbb_common::get_time() + 60_000,
                },
                hbb_common::tokio_util::sync::CancellationToken::new(),
            )
            .await;
            assert!(result.is_err(), "server closes after the dispatch ACK");
            server.await.unwrap();

            for _ in 0..100 {
                if super::test_agent_execution_reports().lock().unwrap().len() == 2 {
                    break;
                }
                hbb_common::tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        let reports = super::test_agent_execution_reports()
            .lock()
            .unwrap()
            .clone();
        assert_eq!(reports.len(), 2);
        assert_eq!(
            reports[0].0,
            "/v1/device/agent/executions/host-child-1/start"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&reports[0].1).unwrap()["dispatchToken"],
            "dispatch-loopback"
        );
        assert_eq!(
            reports[1].0,
            "/v1/device/agent/executions/host-child-1/finish"
        );
        let finish: serde_json::Value = serde_json::from_slice(&reports[1].1).unwrap();
        assert_eq!(finish["status"], "completed");
        assert_eq!(finish["exitCode"], 0);
        assert!(finish.get("errorCode").unwrap().is_null());
        drop(_runtime_guard);
        let _ = fs::remove_dir_all(config_dir);
    }
}
