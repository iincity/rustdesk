//! Stable Nexus facade for RustDesk integration points.
//!
//! Runtime implementation lives in `nexus_impl` so native RustDesk call sites
//! depend on this small boundary and can remain unchanged during migration.

#[path = "nexus_impl.rs"]
mod implementation;

pub use implementation::*;

#[cfg(feature = "nexus-native-tunnel")]
use hbb_common::sha2::Digest;
#[cfg(feature = "nexus-native-tunnel")]
use serde::Deserialize;
#[cfg(feature = "nexus-native-tunnel")]
use std::{
    collections::HashMap,
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
                "relay-admission-v1".to_owned(),
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
    if let Some(context) = execution_port_forward_contexts()
        .lock()
        .ok()
        .and_then(|contexts| contexts.get(target).cloned())
    {
        return Some(context);
    }
    if let Some(path) = std::env::var_os("NEXUS_TUNNEL_CREDENTIAL_FILE") {
        return read_port_forward_credential(Path::new(&path), target);
    }
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
    if admission_proof.is_empty() {
        return None;
    }
    let nonce = decode_hex(&std::env::var("NEXUS_TUNNEL_NONCE_HEX").unwrap_or_default())?;
    if nonce.is_empty() {
        return None;
    }
    Some(hbb_common::message_proto::NexusPortForwardContext {
        grant_id,
        session_id,
        admission_proof: admission_proof.into(),
        target_digest: target_digest_value,
        protocol_version: 1,
        expires_at,
        nonce: nonce.into(),
        ..Default::default()
    })
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
    let protocol_version = if credential.protocol_version == 0 {
        1
    } else {
        credential.protocol_version
    };
    let nonce = decode_hex(&credential.nonce_hex)?;
    let admission_proof = decode_hex(&credential.admission_proof_hex)?;
    let expected_digest = target_digest(target);
    if credential.revoked
        || credential.grant_id.trim().is_empty()
        || credential.session_id.trim().is_empty()
        || admission_proof.is_empty()
        || nonce.is_empty()
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
        decode_hex, install_execution_port_forward_credential, native_port_forward_context,
        native_registration_extension, read_port_forward_credential,
        remove_execution_port_forward_context, target_digest,
    };
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
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
            r#"{{"grantId":"g","sessionId":"s","admissionProofHex":"01","targetDigest":"{digest}","expiresAt":{},"nonceHex":"a1b2","protocolVersion":1}}"#,
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
                r#"{{"grantId":"g","sessionId":"s","admissionProofHex":"01","targetDigest":"{digest}","expiresAt":{},"nonceHex":"a1b2","targetHost":"127.0.0.1","targetPort":8083}}"#,
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
                "relay-admission-v1",
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
