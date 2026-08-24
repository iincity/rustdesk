//! Native RustDesk Host ownership for Presence and the optional Agent loop.
//!
//! The Host owns only Nexus background tasks. Runtime state, RustDesk startup,
//! Remote sessions, and IPC authorization remain in the implementation facade.

#[cfg(feature = "nexus-agent")]
use super::implementation::run_agent_socket_loop;
use super::implementation::{
    establish_presence_session, presence_interval_secs, refresh_tunnel_desired_state,
    status_snapshot, PresenceHeartbeat, TunnelHostConfig,
};
use std::{future::Future, pin::Pin, time::Duration};

pub(super) const PRESENCE_RETRY_MAX_SECS: u64 = 30;

pub(super) fn new_presence_boot_uuid() -> uuid::Uuid {
    // UUID v4 draws from the operating-system CSPRNG. A new client starts its
    // packet sequence at zero, so every registration needs a fresh nonce domain.
    uuid::Uuid::new_v4()
}

pub(super) fn next_presence_boot_id() -> u32 {
    new_presence_boot_uuid().as_u128() as u32
}

pub(super) fn next_presence_retry_secs(current: u64) -> u64 {
    current.clamp(1, PRESENCE_RETRY_MAX_SECS)
}

pub(super) type PresenceFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

pub(super) struct PresenceHostOps<S> {
    pub(super) refresh: Box<dyn FnMut() -> PresenceFuture<()> + Send>,
    pub(super) establish: Box<dyn FnMut(u32) -> PresenceFuture<Result<S, String>> + Send>,
    pub(super) heartbeat: Box<
        dyn for<'a> FnMut(
                &'a mut S,
            )
                -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>
            + Send,
    >,
    pub(super) heartbeat_interval_secs: Box<dyn Fn() -> u64 + Send>,
    pub(super) lease_needs_refresh: Box<dyn Fn(&S) -> bool + Send>,
    pub(super) sleep: Box<dyn FnMut(u64) -> PresenceFuture<()> + Send>,
    pub(super) next_boot_id: Box<dyn FnMut() -> u32 + Send>,
}

pub(super) async fn run_presence_loop<S>(
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

pub(super) async fn run_host_service(
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
                u64::try_from(presence_interval_secs()).unwrap_or(30)
            }),
            lease_needs_refresh: Box::new(|session| {
                session.lease().expires_at
                    <= hbb_common::get_time().saturating_add(presence_interval_secs())
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
