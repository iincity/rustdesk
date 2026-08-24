use std::sync::{Arc, RwLock};

use crate::client::*;
use hbb_common::{
    allow_err, bail,
    config::READ_TIMEOUT,
    futures::{SinkExt, StreamExt},
    log,
    message_proto::*,
    protobuf::Message as _,
    rendezvous_proto::ConnType,
    tcp, timeout,
    tokio::{
        self,
        net::TcpStream,
        sync::{mpsc, oneshot},
    },
    tokio_util::codec::{BytesCodec, Framed},
    ResultType, Stream,
};

#[cfg(feature = "nexus")]
fn native_port_forward_revoked(target: &(String, i32)) -> bool {
    crate::nexus::native_port_forward_revoked(target)
}

#[cfg(not(feature = "nexus"))]
fn native_port_forward_revoked(_target: &(String, i32)) -> bool {
    false
}

/// Keeps the Nexus-only session guard out of the original feature-off build.
enum NexusCancellation {
    #[cfg(feature = "nexus")]
    Active(Option<crate::nexus::NativeTunnelSessionCancellation>),
    #[cfg(not(feature = "nexus"))]
    Disabled,
}

impl NexusCancellation {
    fn register(target: &(String, i32)) -> Self {
        #[cfg(feature = "nexus")]
        {
            Self::Active(crate::nexus::register_native_tunnel_session(target))
        }
        #[cfg(not(feature = "nexus"))]
        {
            let _ = target;
            Self::Disabled
        }
    }

    #[cfg(feature = "nexus")]
    async fn cancelled(&mut self) {
        match self {
            Self::Active(Some(cancellation)) => cancellation.cancelled().await,
            Self::Active(None) => std::future::pending::<()>().await,
        }
    }

    #[cfg(not(feature = "nexus"))]
    async fn cancelled(&mut self) {
        std::future::pending::<()>().await
    }
}

fn run_rdp(port: u16) {
    std::process::Command::new("cmdkey")
        .arg("/delete:localhost")
        .output()
        .ok();
    let username = std::env::var("rdp_username").unwrap_or_default();
    let password = std::env::var("rdp_password").unwrap_or_default();
    if !username.is_empty() || !password.is_empty() {
        let mut args = vec!["/generic:localhost".to_owned()];
        if !username.is_empty() {
            args.push(format!("/user:{}", username));
        }
        if !password.is_empty() {
            args.push(format!("/pass:{}", password));
        }
        std::process::Command::new("cmdkey")
            .args(&args)
            .output()
            .ok();
    }
    std::process::Command::new("mstsc")
        .arg(format!("/v:localhost:{}", port))
        .spawn()
        .ok();
}

pub async fn listen(
    id: String,
    password: String,
    port: i32,
    interface: impl Interface,
    ui_receiver: mpsc::UnboundedReceiver<Data>,
    key: &str,
    token: &str,
    lc: Arc<RwLock<LoginConfigHandler>>,
    remote_host: String,
    remote_port: i32,
) -> ResultType<()> {
    listen_with_ready(
        id,
        password,
        port,
        interface,
        ui_receiver,
        key,
        token,
        lc,
        remote_host,
        remote_port,
        None,
    )
    .await
}

/// Native PortForward listener with an optional one-shot readiness signal.
/// The signal exposes only its loopback bound address and is emitted after
/// RustDesk has created the listener, before any connection is accepted.
pub(crate) async fn listen_with_ready(
    id: String,
    password: String,
    port: i32,
    interface: impl Interface,
    ui_receiver: mpsc::UnboundedReceiver<Data>,
    key: &str,
    token: &str,
    lc: Arc<RwLock<LoginConfigHandler>>,
    remote_host: String,
    remote_port: i32,
    ready: Option<oneshot::Sender<std::net::SocketAddr>>,
) -> ResultType<()> {
    listen_with_bind_ready(
        "127.0.0.1",
        id,
        password,
        port,
        interface,
        ui_receiver,
        key,
        token,
        lc,
        remote_host,
        remote_port,
        ready,
    )
    .await
}

/// Same native PortForward loop with an explicit listener address for the
/// feature-gated headless Gateway. The remote target still comes only from
/// the signed credential; this address controls exposure, not authorization.
pub(crate) async fn listen_with_bind_ready(
    bind_host: &str,
    id: String,
    password: String,
    port: i32,
    interface: impl Interface,
    ui_receiver: mpsc::UnboundedReceiver<Data>,
    key: &str,
    token: &str,
    lc: Arc<RwLock<LoginConfigHandler>>,
    remote_host: String,
    remote_port: i32,
    ready: Option<oneshot::Sender<std::net::SocketAddr>>,
) -> ResultType<()> {
    let is_rdp = port == 0 && ready.is_none();
    let listener = tcp::new_listener(format!("{}:{}", bind_host, port), true).await?;
    let addr = listener.local_addr()?;
    log::info!("listening on port {:?}", addr);
    if let Some(ready) = ready {
        let _ = ready.send(addr);
    }
    // A readiness hook asks the OS for an ephemeral port; it is not the
    // legacy RDP sentinel, whose public wrapper still passes no hook.
    if is_rdp {
        run_rdp(addr.port());
    }
    let mut ui_receiver = ui_receiver;
    loop {
        tokio::select! {
            Ok((forward, addr)) = listener.accept() => {
                log::info!("new connection from {:?}", addr);
                #[cfg(feature = "nexus-native-tunnel")]
                if crate::nexus::gateway_port_forward_liveness_required()
                    && !crate::nexus::gateway_port_forward_grant_is_live().await
                {
                    interface.on_establish_connection_error(
                        "Nexus Tunnel grant is unavailable".to_owned(),
                    );
                    continue;
                }
                lc.write().unwrap().port_forward = (remote_host.clone(), remote_port);
                let id = id.clone();
                let password = password.clone();
                let mut forward = Framed::new(forward, BytesCodec::new());
                let mut close_port_forward = false;
                match connect_and_login(&id, &password, &mut ui_receiver, interface.clone(), &mut forward, key, token, is_rdp, &mut close_port_forward).await {
                    Ok(Some((stream, kcp))) => {
                        let interface = interface.clone();
                        let target = (remote_host.clone(), remote_port);
                        #[cfg(feature = "nexus-native-tunnel")]
                        let gateway_usage = crate::nexus::gateway_port_forward_liveness_required();
                        #[cfg(feature = "nexus-native-tunnel")]
                        if gateway_usage {
                            crate::nexus::report_gateway_port_forward_usage(1, 0).await;
                        }
                        tokio::spawn(async move {
                            let result = run_forward(forward, stream, kcp, target).await;
                            #[cfg(feature = "nexus-native-tunnel")]
                            if gateway_usage {
                                let bytes = result.as_ref().copied().unwrap_or_default();
                                crate::nexus::report_gateway_port_forward_usage(-1, bytes).await;
                            }
                            if let Err(err) = result {
                                interface.msgbox("error", "Error", &err.to_string(), "");
                            }
                            log::info!("connection from {:?} closed", addr);
                       });
                    }
                    _ if close_port_forward => {
                        break;
                    }
                    Err(err) => {
                        interface.on_establish_connection_error(err.to_string());
                    }
                    _ => {}
                }
            }
            d = ui_receiver.recv() => {
                match d {
                    Some(Data::Close) => {
                        break;
                    }
                    Some(Data::NewRDP) => {
                        println!("receive run_rdp from ui_receiver");
                        run_rdp(addr.port());
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

async fn connect_and_login(
    id: &str,
    password: &str,
    ui_receiver: &mut mpsc::UnboundedReceiver<Data>,
    interface: impl Interface,
    forward: &mut Framed<TcpStream, BytesCodec>,
    key: &str,
    token: &str,
    is_rdp: bool,
    close_port_forward: &mut bool,
) -> ResultType<Option<(Stream, Option<crate::kcp_stream::KcpStream>)>> {
    let conn_type = if is_rdp {
        ConnType::RDP
    } else {
        ConnType::PORT_FORWARD
    };
    let ((mut stream, direct, _pk, kcp, _stream_type), (feedback, rendezvous_server)) =
        Client::start(id, key, token, conn_type, interface.clone()).await?;
    interface.update_direct(Some(direct));
    if !stream.is_secured() && !crate::common::is_direct_ip_access(id) {
        if !confirm_insecure_connection(&interface, ui_receiver).await {
            *close_port_forward = true;
            return Ok(None);
        }
    }
    let mut buffer = Vec::new();
    let mut received = false;

    let _keep_it = hc_connection(feedback, rendezvous_server, token).await;

    loop {
        tokio::select! {
            res = timeout(READ_TIMEOUT, stream.next()) => match res {
                Err(_) => {
                    bail!("Timeout");
                }
                Ok(Some(Ok(bytes))) => {
                    if !received {
                        received = true;
                        interface.update_received(true);
                    }
                    let msg_in = Message::parse_from_bytes(&bytes)?;
                    match msg_in.union {
                        Some(message::Union::Hash(hash)) => {
                            interface.handle_hash(password, hash, &mut stream).await;
                        }
                        Some(message::Union::LoginResponse(lr)) => match lr.union {
                            Some(login_response::Union::Error(err)) => {
                                if !interface.handle_login_error(&err) {
                                    return Ok(None);
                                }
                            }
                            Some(login_response::Union::PeerInfo(pi)) => {
                                interface.handle_peer_info(pi);
                                break;
                            }
                            _ => {}
                        }
                        Some(message::Union::TestDelay(t)) => {
                            interface.handle_test_delay(t, &mut stream).await;
                        }
                        _ => {}
                    }
                }
                Ok(Some(Err(err))) => {
                    bail!("Connection closed: {}", err);
                }
                _ => {
                    bail!("Reset by the peer");
                }
            },
            d = ui_receiver.recv() => {
                match d {
                    Some(Data::Login((os_username, os_password, password, remember))) => {
                        interface.handle_login_from_ui(os_username, os_password, password, remember, &mut stream).await;
                    }
                    Some(Data::Message(msg)) => {
                        allow_err!(stream.send(&msg).await);
                    }
                    _ => {}
                }
            },
            res = forward.next() => {
                if let Some(Ok(bytes)) = res {
                    buffer.extend(bytes);
                } else {
                    return Ok(None);
                }
            },
        }
    }
    stream.set_raw();
    if !buffer.is_empty() {
        allow_err!(stream.send_bytes(buffer.into()).await);
    }
    Ok(Some((stream, kcp)))
}

async fn run_forward(
    forward: Framed<TcpStream, BytesCodec>,
    stream: Stream,
    // KCP owns the UDP I/O task. Retain it for the raw PortForward session.
    _kcp: Option<crate::kcp_stream::KcpStream>,
    target: (String, i32),
) -> ResultType<u64> {
    log::info!("new port forwarding connection started");
    let mut forward = forward;
    let mut stream = stream;
    let mut bytes = 0u64;
    let mut revoke_check = hbb_common::tokio::time::interval(std::time::Duration::from_secs(1));
    // Native session cancellation exists only with the additive Nexus feature;
    // feature-off PortForward must retain RustDesk's original build and flow.
    let mut nexus_cancellation = NexusCancellation::register(&target);
    loop {
        tokio::select! {
            res = forward.next() => {
                if let Some(Ok(chunk)) = res {
                    bytes = bytes.saturating_add(chunk.len() as u64);
                    if std::env::var("NEXUS_E2E_TRACE_PORT_FORWARD").as_deref() == Ok("1") {
                        log::info!("NEXUS_E2E_TRACE_PORT_FORWARD: local -> peer {} bytes", chunk.len());
                    }
                    stream.send_bytes(chunk.into()).await?;
                } else {
                    break;
                }
            },
            res = stream.next() => {
                if let Some(Ok(chunk)) = res {
                    bytes = bytes.saturating_add(chunk.len() as u64);
                    if std::env::var("NEXUS_E2E_TRACE_PORT_FORWARD").as_deref() == Ok("1") {
                        log::info!("NEXUS_E2E_TRACE_PORT_FORWARD: peer -> local {} bytes", chunk.len());
                    }
                    forward.send(chunk).await?;
                } else {
                    break;
                }
            },
            _ = revoke_check.tick() => {
                if native_port_forward_revoked(&target) {
                    log::info!("native PortForward credential revoked or expired; closing session");
                    break;
                }
                #[cfg(feature = "nexus-native-tunnel")]
                if crate::nexus::gateway_port_forward_liveness_required()
                    && !crate::nexus::gateway_port_forward_grant_is_live().await
                {
                    log::info!("native Gateway PortForward grant is no longer live; closing session");
                    break;
                }
            },
            _ = async {
                nexus_cancellation.cancelled().await
            } => {
                log::info!("Nexus Tunnel revoke closed an active direct/KCP PortForward session");
                break;
            },
        }
    }
    Ok(bytes)
}
