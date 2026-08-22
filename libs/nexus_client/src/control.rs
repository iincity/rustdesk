use crate::tunnel::ConfigVersion;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneStatus {
    pub desired_state_version: Option<ConfigVersion>,
    pub connected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedControlPlaneRequest {
    pub device_uid: String,
    pub timestamp: i64,
    pub nonce_hex: String,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresenceSessionKeyLease {
    pub key_id: u8,
    pub key: [u8; 32],
    pub expires_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlPlaneRequestError {
    MissingDeviceUid,
    InvalidMethod,
    InvalidPath,
}

/// Builds the exact signed envelope accepted by the control-plane device routes.
/// The signer is supplied by the RustDesk adapter so this crate never handles a
/// native private key.
pub fn sign_control_plane_request(
    device_uid: &str,
    method: &str,
    path: &str,
    timestamp: i64,
    nonce: [u8; 16],
    body: &[u8],
    sign: impl FnOnce(&[u8]) -> [u8; 64],
) -> Result<SignedControlPlaneRequest, ControlPlaneRequestError> {
    if device_uid.trim().is_empty() {
        return Err(ControlPlaneRequestError::MissingDeviceUid);
    }
    if method.trim().is_empty() {
        return Err(ControlPlaneRequestError::InvalidMethod);
    }
    if !path.starts_with('/') {
        return Err(ControlPlaneRequestError::InvalidPath);
    }
    let nonce_hex = hex::encode(nonce);
    let signature_hex = hex::encode(sign(&canonical_request(
        device_uid, method, path, timestamp, &nonce_hex, body,
    )));
    Ok(SignedControlPlaneRequest {
        device_uid: device_uid.into(),
        timestamp,
        nonce_hex,
        signature_hex,
    })
}

fn canonical_request(
    device_uid: &str,
    method: &str,
    path: &str,
    timestamp: i64,
    nonce_hex: &str,
    body: &[u8],
) -> Vec<u8> {
    let body_digest: [u8; 32] = Sha256::digest(body).into();
    let mut payload = Vec::with_capacity(128);
    payload.extend_from_slice(b"nexusflow-device-request-v1\0");
    for field in [
        device_uid.as_bytes(),
        method.as_bytes(),
        path.as_bytes(),
        nonce_hex.as_bytes(),
        &body_digest,
    ] {
        payload.extend_from_slice(&(field.len() as u64).to_le_bytes());
        payload.extend_from_slice(field);
    }
    payload.extend_from_slice(&timestamp.to_le_bytes());
    payload
}

#[cfg(test)]
mod tests {
    use super::{sign_control_plane_request, ControlPlaneRequestError};

    #[test]
    fn signed_request_is_deterministic_and_does_not_accept_invalid_route_data() {
        let signed = sign_control_plane_request(
            "device-1",
            "POST",
            "/v1/device/presence/session-key",
            1_000,
            [7; 16],
            b"{}",
            |_| [9; 64],
        )
        .unwrap();

        assert_eq!(signed.nonce_hex, "07".repeat(16));
        assert_eq!(signed.signature_hex, "09".repeat(64));
        assert_eq!(
            sign_control_plane_request("", "GET", "/v1/device", 0, [0; 16], &[], |_| [0; 64]),
            Err(ControlPlaneRequestError::MissingDeviceUid)
        );
    }
}
