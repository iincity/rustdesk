#[cfg(feature = "nexus-native-tunnel")]
use hbb_common::sha2::Digest;
#[cfg(feature = "nexus-native-tunnel")]
use hbb_common::tokio::sync::oneshot;
#[cfg(feature = "nexus-native-tunnel")]
use serde::Deserialize;
#[cfg(feature = "nexus-native-tunnel")]
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
    sync::{Mutex, OnceLock},
};
/// Returns the optional registration metadata for the existing RustDesk
/// rendezvous message. The extension is advisory; the internal registration
/// token is never placed on the wire and the native registration path remains
/// authoritative.
#[cfg(feature = "nexus-native-tunnel")]
pub(crate) fn native_registration_extension(
) -> Option<hbb_common::rendezvous_proto::NexusRegistration> {
    static REGISTRATION: OnceLock<Option<hbb_common::rendezvous_proto::NexusRegistration>> =
        OnceLock::new();
    REGISTRATION
        .get_or_init(|| {
            let control_plane = std::env::var("NEXUS_CONTROL_PLANE_URL").ok()?;
            let registration_token = std::env::var("NEXUS_RUSTDESK_REGISTRATION_TOKEN").ok()?;
            if control_plane.trim().is_empty() || registration_token.trim().is_empty() {
                return None;
            }
            let capabilities = vec![
                "native-port-forward".to_owned(),
                "relay-admission-v2".to_owned(),
                "execution-grant-v1".to_owned(),
            ];
            let capability_digest =
                hbb_common::sha2::Sha256::digest(capabilities.join("\0").as_bytes());
            Some(hbb_common::rendezvous_proto::NexusRegistration {
                protocol_version: 1,
                capabilities,
                capability_digest: format_hex(&capability_digest),
                boot_id: format_hex(&hbb_common::get_uuid()),
                sequence: 1,
                ..Default::default()
            })
        })
        .clone()
}

/// Builds an execution-scoped PortForward context from deployment-injected
/// short-lived values. A configured credential file is authoritative.
#[cfg(feature = "nexus-native-tunnel")]
pub(crate) fn native_port_forward_context(
    target: &(String, i32),
) -> Option<hbb_common::message_proto::NexusPortForwardContext> {
    let context = if let Some(context) = execution_port_forward_contexts()
        .lock()
        .ok()
        .and_then(|contexts| contexts.get(target).cloned())
    {
        Some(context)
    } else if let Some(path) = std::env::var_os("NEXUS_TUNNEL_CREDENTIAL_FILE") {
        read_port_forward_credential(Path::new(&path), target)
    } else {
        read_port_forward_context_from_environment(target)
    };
    context.filter(|context| !native_port_forward_context_is_revoked(context))
}

/// Applies the signed persistent revoke snapshot. It controls only Nexus
/// PortForward admission and never changes legacy PortForward or Remote paths.
#[cfg(feature = "nexus-native-tunnel")]
pub(crate) fn apply_desired_state_revocation(
    revocation: &nexus_client::desired_state::DesiredStateRevocation,
) {
    let mut state = revocation_state().lock().expect("revocation state lock");
    if revocation.version <= state.version {
        return;
    }
    state.version = revocation.version;
    state.grant_ids = revocation.revoked_grant_ids.iter().cloned().collect();
    state.session_ids = revocation.revoked_session_ids.iter().cloned().collect();
    cancel_active_tunnel_sessions(&state.grant_ids, &state.session_ids);
}

#[cfg(feature = "nexus-native-tunnel")]
fn cancel_active_tunnel_sessions(grant_ids: &HashSet<String>, session_ids: &HashSet<String>) {
    let mut sessions = active_tunnel_sessions()
        .lock()
        .expect("active tunnel session lock");
    let revoked = sessions
        .entries
        .iter()
        .filter_map(|(id, entry)| {
            (grant_ids.contains(&entry.grant_id) || session_ids.contains(&entry.session_id))
                .then_some(*id)
        })
        .collect::<Vec<_>>();
    for id in revoked {
        if let Some(entry) = sessions.entries.remove(&id) {
            let _ = entry.cancel.send(());
        }
    }
}

#[cfg(not(feature = "nexus-native-tunnel"))]
pub(crate) fn apply_desired_state_revocation(
    _revocation: &nexus_client::desired_state::DesiredStateRevocation,
) {
}

#[cfg(feature = "nexus-native-tunnel")]
fn read_port_forward_context_from_environment(
    target: &(String, i32),
) -> Option<hbb_common::message_proto::NexusPortForwardContext> {
    // Deployment environment variables remain a migration-only compatibility
    // path. A configured credential file always wins and disables this path.
    let grant_id = std::env::var("NEXUS_TUNNEL_GRANT_ID").ok()?;
    let session_id = std::env::var("NEXUS_TUNNEL_SESSION_ID").ok()?;
    let target_digest_value = std::env::var("NEXUS_TUNNEL_TARGET_DIGEST").ok()?;
    let proof_hex = std::env::var("NEXUS_TUNNEL_ADMISSION_PROOF_HEX").ok()?;
    let expires_at = std::env::var("NEXUS_TUNNEL_EXPIRES_AT")
        .ok()?
        .parse()
        .ok()?;
    if grant_id.trim().is_empty()
        || session_id.trim().is_empty()
        || target_digest_value.trim().is_empty()
        || target_digest_value != target_digest(target)
        || expires_at <= hbb_common::get_time()
    {
        return None;
    }
    let admission_proof = decode_hex(&proof_hex)?;
    let nonce = decode_hex(&std::env::var("NEXUS_TUNNEL_NONCE_HEX").unwrap_or_default())?;
    (!admission_proof.is_empty() && !nonce.is_empty()).then_some(
        hbb_common::message_proto::NexusPortForwardContext {
            grant_id,
            session_id,
            admission_proof: admission_proof.into(),
            target_digest: target_digest_value,
            protocol_version: 1,
            expires_at,
            nonce: nonce.into(),
            ..Default::default()
        },
    )
}

#[cfg(feature = "nexus-native-tunnel")]
fn has_execution_port_forward_context(target: &(String, i32)) -> bool {
    execution_port_forward_contexts()
        .lock()
        .ok()
        .is_some_and(|contexts| contexts.contains_key(target))
}

#[cfg(feature = "nexus-native-tunnel")]
fn execution_port_forward_contexts(
) -> &'static Mutex<HashMap<(String, i32), hbb_common::message_proto::NexusPortForwardContext>> {
    static CONTEXTS: OnceLock<
        Mutex<HashMap<(String, i32), hbb_common::message_proto::NexusPortForwardContext>>,
    > = OnceLock::new();
    CONTEXTS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(feature = "nexus-native-tunnel")]
#[derive(Default)]
struct RevocationState {
    version: u64,
    grant_ids: HashSet<String>,
    session_ids: HashSet<String>,
}

#[cfg(feature = "nexus-native-tunnel")]
fn revocation_state() -> &'static Mutex<RevocationState> {
    static STATE: OnceLock<Mutex<RevocationState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(RevocationState::default()))
}

#[cfg(feature = "nexus-native-tunnel")]
fn native_port_forward_context_is_revoked(
    context: &hbb_common::message_proto::NexusPortForwardContext,
) -> bool {
    revocation_state().lock().ok().is_some_and(|state| {
        state.grant_ids.contains(&context.grant_id)
            || state.session_ids.contains(&context.session_id)
    })
}

/// A direct/KCP PortForward task holds this cancellation guard only when its
/// connection carries a Nexus context. Dropping it deregisters the task and
/// never touches Remote or legacy PortForward ownership.
#[cfg(feature = "nexus-native-tunnel")]
pub(crate) struct NativeTunnelSessionCancellation {
    id: u64,
    cancel: oneshot::Receiver<()>,
}

#[cfg(feature = "nexus-native-tunnel")]
impl NativeTunnelSessionCancellation {
    pub(crate) async fn cancelled(&mut self) {
        let _ = (&mut self.cancel).await;
    }
}

#[cfg(feature = "nexus-native-tunnel")]
impl Drop for NativeTunnelSessionCancellation {
    fn drop(&mut self) {
        if let Ok(mut sessions) = active_tunnel_sessions().lock() {
            sessions.entries.remove(&self.id);
        }
    }
}

#[cfg(feature = "nexus-native-tunnel")]
struct ActiveTunnelSession {
    grant_id: String,
    session_id: String,
    cancel: oneshot::Sender<()>,
}

#[cfg(feature = "nexus-native-tunnel")]
#[derive(Default)]
struct ActiveTunnelSessions {
    next_id: u64,
    entries: HashMap<u64, ActiveTunnelSession>,
}

#[cfg(feature = "nexus-native-tunnel")]
fn active_tunnel_sessions() -> &'static Mutex<ActiveTunnelSessions> {
    static SESSIONS: OnceLock<Mutex<ActiveTunnelSessions>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(ActiveTunnelSessions::default()))
}

/// Registers only an already-admitted Nexus context. A revoke arriving before
/// registration keeps the normal admission path fail-closed instead.
#[cfg(feature = "nexus-native-tunnel")]
pub(crate) fn register_native_tunnel_session(
    target: &(String, i32),
) -> Option<NativeTunnelSessionCancellation> {
    let context = native_port_forward_context(target)?;
    let (cancel_tx, cancel) = oneshot::channel();
    let mut sessions = active_tunnel_sessions().lock().ok()?;
    sessions.next_id = sessions.next_id.wrapping_add(1);
    let id = sessions.next_id;
    sessions.entries.insert(
        id,
        ActiveTunnelSession {
            grant_id: context.grant_id,
            session_id: context.session_id,
            cancel: cancel_tx,
        },
    );
    Some(NativeTunnelSessionCancellation { id, cancel })
}

#[cfg(not(feature = "nexus-native-tunnel"))]
pub(crate) struct NativeTunnelSessionCancellation;

#[cfg(not(feature = "nexus-native-tunnel"))]
impl NativeTunnelSessionCancellation {
    pub(crate) async fn cancelled(&mut self) {
        std::future::pending::<()>().await;
    }
}

#[cfg(not(feature = "nexus-native-tunnel"))]
pub(crate) fn register_native_tunnel_session(
    _target: &(String, i32),
) -> Option<NativeTunnelSessionCancellation> {
    None
}

/// Installs a Host-verified execution credential without changing process
/// environment. The native Client lookup remains keyed by its exact target.
#[cfg(feature = "nexus-native-tunnel")]
pub(crate) fn install_execution_port_forward_credential(path: &Path) -> Option<(String, i32)> {
    let target = native_port_forward_credential_target(path)?;
    let context = read_port_forward_credential(path, &target)?;
    execution_port_forward_contexts()
        .lock()
        .ok()?
        .insert(target.clone(), context);
    Some(target)
}

#[cfg(feature = "nexus-native-tunnel")]
pub(crate) fn remove_execution_port_forward_context(target: &(String, i32)) {
    if let Ok(mut contexts) = execution_port_forward_contexts().lock() {
        contexts.remove(target);
    }
}

#[cfg(feature = "nexus-native-tunnel")]
pub(crate) fn native_port_forward_credential_configured() -> bool {
    std::env::var_os("NEXUS_TUNNEL_CREDENTIAL_FILE").is_some()
}

/// Reads the Host-only target included in a verified credential. The same
/// digest check used for the native Login context prevents a credential file
/// from selecting a different private endpoint.
#[cfg(feature = "nexus-native-tunnel")]
pub(crate) fn native_port_forward_credential_target(path: &Path) -> Option<(String, i32)> {
    let credential: PortForwardCredential =
        serde_json::from_str(&fs::read_to_string(path).ok()?).ok()?;
    let target = (credential.target_host, credential.target_port);
    (target.1 > 0 && target.1 <= u16::MAX as i32)
        .then_some(())
        .and_then(|()| read_port_forward_credential(path, &target).map(|_| target))
}

pub(crate) fn native_port_forward_revoked(target: &(String, i32)) -> bool {
    #[cfg(feature = "nexus-native-tunnel")]
    {
        return (native_port_forward_credential_configured()
            || has_execution_port_forward_context(target))
            && native_port_forward_context(target).is_none();
    }
    #[cfg(not(feature = "nexus-native-tunnel"))]
    {
        let _ = target;
        false
    }
}

#[cfg(feature = "nexus-native-tunnel")]
pub(crate) fn native_port_forward_context_required(target: &(String, i32)) -> bool {
    native_port_forward_credential_configured() || has_execution_port_forward_context(target)
}

#[cfg(feature = "nexus-native-tunnel")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PortForwardCredential {
    grant_id: String,
    session_id: String,
    admission_proof_hex: String,
    target_digest: String,
    expires_at: i64,
    nonce_hex: String,
    #[serde(default)]
    key_id: String,
    #[serde(default)]
    source_device_uid: String,
    #[serde(default)]
    publishing_device_uid: String,
    #[serde(default)]
    tenant_ref: String,
    #[serde(default)]
    relay_pool_id: String,
    #[serde(default)]
    relay_node_id: String,
    #[serde(default)]
    publishing_rustdesk_id: String,
    #[serde(default)]
    target_host: String,
    #[serde(default)]
    target_port: i32,
    #[serde(default)]
    revoked: bool,
    #[serde(default)]
    protocol_version: u32,
}

#[cfg(feature = "nexus-native-tunnel")]
fn read_port_forward_credential(
    path: &Path,
    target: &(String, i32),
) -> Option<hbb_common::message_proto::NexusPortForwardContext> {
    let credential: PortForwardCredential =
        serde_json::from_str(&fs::read_to_string(path).ok()?).ok()?;
    let now = hbb_common::get_time();
    let protocol_version = credential.protocol_version;
    let nonce = decode_hex(&credential.nonce_hex)?;
    let admission_proof = decode_hex(&credential.admission_proof_hex)?;
    let expected_digest = target_digest(target);
    if credential.revoked
        || credential.grant_id.trim().is_empty()
        || credential.session_id.trim().is_empty()
        || credential.key_id.trim().is_empty()
        || credential.source_device_uid.trim().is_empty()
        || credential.publishing_device_uid.trim().is_empty()
        || credential.tenant_ref.trim().is_empty()
        || credential.relay_pool_id.trim().is_empty()
        || credential.relay_node_id.trim().is_empty()
        || admission_proof.is_empty()
        || nonce.is_empty()
        || protocol_version != 2
        || credential.expires_at <= now
        || credential.target_digest != expected_digest
    {
        return None;
    }
    Some(hbb_common::message_proto::NexusPortForwardContext {
        grant_id: credential.grant_id,
        session_id: credential.session_id,
        admission_proof: admission_proof.into(),
        target_digest: credential.target_digest,
        protocol_version,
        expires_at: credential.expires_at,
        nonce: nonce.into(),
        key_id: credential.key_id,
        source_device_uid: credential.source_device_uid,
        publishing_device_uid: credential.publishing_device_uid,
        tenant_ref: credential.tenant_ref,
        relay_pool_id: credential.relay_pool_id,
        relay_node_id: credential.relay_node_id,
        ..Default::default()
    })
}

#[cfg(feature = "nexus-native-tunnel")]
fn target_digest(target: &(String, i32)) -> String {
    let addr = format!("{}:{}", target.0.trim(), target.1);
    format_hex(&hbb_common::sha2::Sha256::digest(
        format!("nexus-port-forward-target-v1\0{addr}").as_bytes(),
    ))
}

#[cfg(feature = "nexus-native-tunnel")]
fn format_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                HEX[(byte >> 4) as usize] as char,
                HEX[(byte & 0xf) as usize] as char,
            ]
        })
        .collect()
}

#[cfg(feature = "nexus-native-tunnel")]
fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

#[cfg(all(test, feature = "nexus-native-tunnel"))]
mod tests {
    use super::{
        active_tunnel_sessions, apply_desired_state_revocation, cancel_active_tunnel_sessions,
        decode_hex, execution_port_forward_contexts, install_execution_port_forward_credential,
        native_port_forward_context, native_registration_extension, read_port_forward_credential,
        register_native_tunnel_session, remove_execution_port_forward_context, target_digest,
    };
    use hbb_common::{
        message_proto::NexusPortForwardContext,
        tokio::{runtime::Runtime, time::timeout},
    };
    use std::{
        collections::HashSet,
        fs,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn malformed_admission_proof_is_not_accepted() {
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("zz"), None);
        assert_eq!(decode_hex("00abff"), Some(vec![0, 0xab, 0xff]));
    }

    #[test]
    fn target_digest_is_deterministic_and_bound_to_port() {
        assert_eq!(
            target_digest(&("127.0.0.1".into(), 8080)),
            target_digest(&("127.0.0.1".into(), 8080))
        );
        assert_ne!(
            target_digest(&("127.0.0.1".into(), 8080)),
            target_digest(&("127.0.0.1".into(), 8081))
        );
    }

    #[test]
    fn credential_store_rejects_revoked_and_allows_reuse_before_authoritative_validation() {
        let target = ("127.0.0.1".to_owned(), 8082);
        let path = std::env::temp_dir().join(format!(
            "nexus-credential-{}.json",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let digest = target_digest(&target);
        let json = format!(
            r#"{{"grantId":"g","sessionId":"s","admissionProofHex":"01","targetDigest":"{digest}","expiresAt":{},"nonceHex":"a1b2","keyId":"key","sourceDeviceUid":"source","publishingDeviceUid":"publisher","tenantRef":"tenant","relayPoolId":"relay","relayNodeId":"relay","protocolVersion":2}}"#,
            hbb_common::get_time() + 600
        );
        fs::write(&path, json).unwrap();
        assert!(read_port_forward_credential(&path, &target).is_some());
        assert!(read_port_forward_credential(&path, &target).is_some());
        fs::write(&path, format!(r#"{{"grantId":"g","sessionId":"s","admissionProofHex":"01","targetDigest":"{digest}","expiresAt":{},"nonceHex":"c3d4","revoked":true}}"#, hbb_common::get_time() + 600)).unwrap();
        assert!(read_port_forward_credential(&path, &target).is_none());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn execution_credential_is_scoped_in_memory_without_environment_mutation() {
        let target = ("127.0.0.1".to_owned(), 8083);
        let path = std::env::temp_dir().join(format!(
            "nexus-execution-credential-{}.json",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let digest = target_digest(&target);
        fs::write(
            &path,
            format!(
                r#"{{"grantId":"g","sessionId":"s","admissionProofHex":"01","targetDigest":"{digest}","expiresAt":{},"nonceHex":"a1b2","keyId":"key","sourceDeviceUid":"source","publishingDeviceUid":"publisher","tenantRef":"tenant","relayPoolId":"relay","relayNodeId":"relay","protocolVersion":2,"targetHost":"127.0.0.1","targetPort":8083}}"#,
                hbb_common::get_time() + 600
            ),
        )
        .unwrap();
        assert_eq!(
            install_execution_port_forward_credential(&path),
            Some(target.clone())
        );
        assert_eq!(native_port_forward_context(&target).unwrap().grant_id, "g");
        remove_execution_port_forward_context(&target);
        assert!(native_port_forward_context(&target).is_none());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn signed_revocation_snapshot_disables_a_matching_execution_context() {
        let target = ("127.0.0.1".to_owned(), 8084);
        let path = std::env::temp_dir().join(format!(
            "nexus-revoked-execution-credential-{}.json",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let digest = target_digest(&target);
        fs::write(
            &path,
            format!(
                r#"{{"grantId":"grant-revoked","sessionId":"session-live","admissionProofHex":"01","targetDigest":"{digest}","expiresAt":{},"nonceHex":"a1b2","keyId":"key","sourceDeviceUid":"source","publishingDeviceUid":"publisher","tenantRef":"tenant","relayPoolId":"relay","relayNodeId":"relay","protocolVersion":2,"targetHost":"127.0.0.1","targetPort":8084}}"#,
                hbb_common::get_time() + 600
            ),
        )
        .unwrap();
        install_execution_port_forward_credential(&path).unwrap();
        assert!(native_port_forward_context(&target).is_some());
        apply_desired_state_revocation(&nexus_client::desired_state::DesiredStateRevocation {
            version: u64::MAX - 1,
            revoked_grant_ids: vec!["grant-revoked".into()],
            revoked_session_ids: Vec::new(),
        });
        assert!(native_port_forward_context(&target).is_none());
        remove_execution_port_forward_context(&target);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn active_native_tunnel_sessions_close_only_for_matching_revocations() {
        let by_grant = ("127.0.0.1".to_owned(), 8085);
        let by_session = ("127.0.0.1".to_owned(), 8086);
        let unaffected = ("127.0.0.1".to_owned(), 8087);
        {
            let mut contexts = execution_port_forward_contexts().lock().unwrap();
            contexts.insert(
                by_grant.clone(),
                NexusPortForwardContext {
                    grant_id: "active-registry-grant".into(),
                    session_id: "active-registry-session-live".into(),
                    ..Default::default()
                },
            );
            contexts.insert(
                by_session.clone(),
                NexusPortForwardContext {
                    grant_id: "active-registry-grant-live".into(),
                    session_id: "active-registry-session".into(),
                    ..Default::default()
                },
            );
            contexts.insert(
                unaffected.clone(),
                NexusPortForwardContext {
                    grant_id: "active-registry-grant-live".into(),
                    session_id: "active-registry-session-live".into(),
                    ..Default::default()
                },
            );
        }
        let mut cancelled_by_grant = register_native_tunnel_session(&by_grant).unwrap();
        let mut cancelled_by_session = register_native_tunnel_session(&by_session).unwrap();
        let mut still_live = register_native_tunnel_session(&unaffected).unwrap();

        cancel_active_tunnel_sessions(
            &HashSet::from(["active-registry-grant".to_owned()]),
            &HashSet::from(["active-registry-session".to_owned()]),
        );

        Runtime::new().unwrap().block_on(async {
            assert!(
                timeout(Duration::from_millis(100), cancelled_by_grant.cancelled())
                    .await
                    .is_ok()
            );
            assert!(
                timeout(Duration::from_millis(100), cancelled_by_session.cancelled())
                    .await
                    .is_ok()
            );
            assert!(timeout(Duration::from_millis(10), still_live.cancelled())
                .await
                .is_err());
        });
        assert_eq!(active_tunnel_sessions().lock().unwrap().entries.len(), 1);
        drop(cancelled_by_grant);
        drop(cancelled_by_session);
        drop(still_live);
        assert!(active_tunnel_sessions().lock().unwrap().entries.is_empty());
        let mut contexts = execution_port_forward_contexts().lock().unwrap();
        contexts.remove(&by_grant);
        contexts.remove(&by_session);
        contexts.remove(&unaffected);
    }

    #[test]
    fn native_registration_extension_uses_the_existing_register_peer_metadata() {
        let previous_url = std::env::var_os("NEXUS_CONTROL_PLANE_URL");
        let previous_token = std::env::var_os("NEXUS_RUSTDESK_REGISTRATION_TOKEN");
        std::env::set_var("NEXUS_CONTROL_PLANE_URL", "https://control-plane.invalid");
        std::env::set_var("NEXUS_RUSTDESK_REGISTRATION_TOKEN", "test-token");
        let registration = native_registration_extension().expect("native extension");
        assert_eq!(registration.protocol_version, 1);
        assert_eq!(
            registration.capabilities,
            vec![
                "native-port-forward",
                "relay-admission-v2",
                "execution-grant-v1",
            ]
        );
        assert_eq!(registration.capability_digest.len(), 64);
        assert!(!registration.boot_id.is_empty());
        assert_eq!(registration.sequence, 1);
        match previous_url {
            Some(value) => std::env::set_var("NEXUS_CONTROL_PLANE_URL", value),
            None => std::env::remove_var("NEXUS_CONTROL_PLANE_URL"),
        }
        match previous_token {
            Some(value) => std::env::set_var("NEXUS_RUSTDESK_REGISTRATION_TOKEN", value),
            None => std::env::remove_var("NEXUS_RUSTDESK_REGISTRATION_TOKEN"),
        }
    }
}
