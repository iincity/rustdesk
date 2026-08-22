//! Stable mappings from control-plane identity to protocol identity.

use sha2::{Digest, Sha256};

/// Derives the CPCC V2 numeric identity from the control-plane device UID.
///
/// PostgreSQL uniqueness remains the collision boundary for this deliberately
/// truncated hash; callers must not use it as an authorization credential.
pub fn derive_presence_device_id(device_uid: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"nexusflow-presence-device-v1\0");
    hasher.update(device_uid.as_bytes());
    let digest = hasher.finalize();
    let bytes: [u8; 8] = digest[..8].try_into().expect("SHA-256 digest length");
    u64::from_be_bytes(bytes) & i64::MAX as u64
}

#[cfg(test)]
mod tests {
    use super::derive_presence_device_id;

    #[test]
    fn is_stable_and_uses_the_positive_bigint_range() {
        let first = derive_presence_device_id("device-1");
        assert_eq!(first, derive_presence_device_id("device-1"));
        assert_ne!(first, derive_presence_device_id("device-2"));
        assert!(first <= i64::MAX as u64);
    }
}
