//! Agent Socket.IO wire models isolated from Host runtime ownership.
//!
//! This module parses only protocol frames and serializes execution reports.
//! Authentication, queueing, process launch, and all RustDesk credentials
//! remain in `nexus_impl`.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use hbb_common::websocket::WsFramedStream;
use nexus_client::{encode_socket_io_ack, encode_socket_io_event, AgentDispatch};

/// A Host deliberately accepts at most one active execution and 32 pending
/// dispatches. This bound belongs to the Agent protocol, not RustDesk's
/// remote-desktop lifecycle.
pub(super) const AGENT_QUEUE_CAPACITY: usize = 32;

pub(super) async fn next_agent_socket_frame(
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

pub(super) async fn send_agent_socket_event(
    socket: &mut WsFramedStream,
    event: &str,
    payload: &serde_json::Value,
) -> Result<(), String> {
    socket
        .send_text(encode_socket_io_event(event, payload))
        .await
        .map_err(|_| "Nexus Agent Socket write failed".to_string())
}

pub(super) fn send_agent_socket_ack(ack_id: &str, accepted: bool) -> String {
    encode_socket_io_ack(ack_id, accepted)
}

/// Tracks the single execution that the Host may run at a time. Keeping this
/// beside Agent wire handling makes cancellation ownership explicit without
/// giving the module access to process or credential state.
pub(super) fn register_agent_cancellation(
    execution_id: &str,
) -> Option<hbb_common::tokio_util::sync::CancellationToken> {
    let mut active = active_agent_cancellations().lock().ok()?;
    if !active.is_empty() {
        return None;
    }
    let cancellation = hbb_common::tokio_util::sync::CancellationToken::new();
    active.insert(execution_id.to_string(), cancellation.clone());
    Some(cancellation)
}

pub(super) fn is_agent_execution_active(execution_id: &str) -> bool {
    active_agent_cancellations()
        .lock()
        .is_ok_and(|active| active.contains_key(execution_id))
}

pub(super) fn cancel_active_agent(execution_id: &str) -> bool {
    let cancellation = active_agent_cancellations()
        .lock()
        .ok()
        .and_then(|active| active.get(execution_id).cloned());
    cancellation.is_some_and(|cancellation| {
        cancellation.cancel();
        true
    })
}

pub(super) struct ActiveAgentCancellationGuard(pub(super) String);

impl Drop for ActiveAgentCancellationGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = active_agent_cancellations().lock() {
            active.remove(&self.0);
        }
    }
}

fn active_agent_cancellations(
) -> &'static Mutex<HashMap<String, hbb_common::tokio_util::sync::CancellationToken>> {
    static CANCELLATIONS: OnceLock<
        Mutex<HashMap<String, hbb_common::tokio_util::sync::CancellationToken>>,
    > = OnceLock::new();
    CANCELLATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Keeps pending dispatches bounded and idempotent before the Host has an
/// execution slot. Process launch remains owned by the native Host runtime.
pub(super) fn enqueue_agent_dispatch(
    queued: &mut std::collections::VecDeque<AgentDispatch>,
    dispatch: AgentDispatch,
) -> bool {
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

pub(super) fn remove_queued_agent(
    queued: &mut std::collections::VecDeque<AgentDispatch>,
    execution_id: &str,
) -> bool {
    queued
        .iter()
        .position(|queued| queued.execution_id == execution_id)
        .map(|index| queued.remove(index))
        .is_some()
}

pub(super) fn retain_queued_agent(
    queued: &mut std::collections::VecDeque<AgentDispatch>,
    dispatch: AgentDispatch,
) {
    queued.push_front(dispatch);
}
