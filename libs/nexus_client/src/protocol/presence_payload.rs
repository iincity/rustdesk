//! Fixed-size CPCC registration and Presence notification payloads.

use super::CpccV2Frame;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresenceCookie {
    pub issued_at: u64,
    pub tag: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CookieRequestPayload {
    pub client_nonce: [u8; 16],
    pub public_key: [u8; 32],
}
impl CookieRequestPayload {
    pub const ENCODED_LEN: usize = 48;
    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut encoded = [0; Self::ENCODED_LEN];
        encoded[..16].copy_from_slice(&self.client_nonce);
        encoded[16..].copy_from_slice(&self.public_key);
        encoded
    }
    pub fn decode(encoded: &[u8]) -> Result<Self, RegistrationPayloadError> {
        if encoded.len() != Self::ENCODED_LEN {
            return Err(RegistrationPayloadError::InvalidLength(encoded.len()));
        }
        let mut client_nonce = [0; 16];
        client_nonce.copy_from_slice(&encoded[..16]);
        let mut public_key = [0; 32];
        public_key.copy_from_slice(&encoded[16..]);
        Ok(Self {
            client_nonce,
            public_key,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CookieChallengePayload {
    pub cookie: PresenceCookie,
}
impl CookieChallengePayload {
    pub const ENCODED_LEN: usize = 40;
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut encoded = [0; Self::ENCODED_LEN];
        encoded[..8].copy_from_slice(&self.cookie.issued_at.to_be_bytes());
        encoded[8..].copy_from_slice(&self.cookie.tag);
        encoded
    }
    pub fn decode(encoded: &[u8]) -> Result<Self, RegistrationPayloadError> {
        if encoded.len() != Self::ENCODED_LEN {
            return Err(RegistrationPayloadError::InvalidLength(encoded.len()));
        }
        let mut tag = [0; 32];
        tag.copy_from_slice(&encoded[8..]);
        Ok(Self {
            cookie: PresenceCookie {
                issued_at: u64::from_be_bytes(encoded[..8].try_into().unwrap()),
                tag,
            },
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationPayload {
    pub client_nonce: [u8; 16],
    pub cookie: PresenceCookie,
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}
impl RegistrationPayload {
    pub const UNSIGNED_LEN: usize = 88;
    pub const ENCODED_LEN: usize = 152;
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = self.unsigned_bytes();
        encoded.extend_from_slice(&self.signature);
        encoded
    }
    pub fn decode(encoded: &[u8]) -> Result<Self, RegistrationPayloadError> {
        if encoded.len() != Self::ENCODED_LEN {
            return Err(RegistrationPayloadError::InvalidLength(encoded.len()));
        }
        let mut client_nonce = [0; 16];
        client_nonce.copy_from_slice(&encoded[..16]);
        let mut tag = [0; 32];
        tag.copy_from_slice(&encoded[24..56]);
        let mut public_key = [0; 32];
        public_key.copy_from_slice(&encoded[56..88]);
        let mut signature = [0; 64];
        signature.copy_from_slice(&encoded[88..]);
        Ok(Self {
            client_nonce,
            cookie: PresenceCookie {
                issued_at: u64::from_be_bytes(encoded[16..24].try_into().unwrap()),
                tag,
            },
            public_key,
            signature,
        })
    }
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(Self::UNSIGNED_LEN);
        encoded.extend_from_slice(&self.client_nonce);
        encoded.extend_from_slice(&self.cookie.issued_at.to_be_bytes());
        encoded.extend_from_slice(&self.cookie.tag);
        encoded.extend_from_slice(&self.public_key);
        encoded
    }
}

pub fn registration_signature_message(
    frame: &CpccV2Frame,
    registration: &RegistrationPayload,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(38 + RegistrationPayload::UNSIGNED_LEN);
    message.extend_from_slice(b"nexusflow-cpcc-v2-register\0");
    message.push(frame.message_type as u8);
    message.push(frame.flags);
    message.push(frame.key_id);
    message.extend_from_slice(&frame.device_id.to_be_bytes());
    message.extend_from_slice(&frame.boot_id.to_be_bytes());
    message.extend_from_slice(&frame.sequence.to_be_bytes());
    message.extend_from_slice(&(RegistrationPayload::ENCODED_LEN as u16).to_be_bytes());
    message.extend_from_slice(&registration.unsigned_bytes());
    message
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistrationPayloadError {
    InvalidLength(usize),
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConfigVersion(pub u64);
impl ConfigVersion {
    pub fn is_newer_than(self, other: Option<Self>) -> bool {
        other.map(|current| self > current).unwrap_or(true)
    }
}
/// Versioned SHA-256 digest of a canonical Desired State payload.
///
/// The Presence protocol carries the full digest so a short status hint cannot
/// become the authorization decision for a signed configuration.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConfigDigest(pub [u8; 32]);
impl ConfigDigest {
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    #[cfg(test)]
    pub const fn test_value(byte: u8) -> Self {
        Self([byte; 32])
    }
}
/// Authenticated state advertised by a heartbeat; it never carries full Desired State.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PresenceHeartbeat {
    pub config_version: ConfigVersion,
    pub config_digest: ConfigDigest,
    pub capability_digest: u64,
}
impl PresenceHeartbeat {
    pub const ENCODED_LEN: usize = 48;
    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut encoded = [0; Self::ENCODED_LEN];
        encoded[..8].copy_from_slice(&self.config_version.0.to_be_bytes());
        encoded[8..40].copy_from_slice(&self.config_digest.0);
        encoded[40..].copy_from_slice(&self.capability_digest.to_be_bytes());
        encoded
    }
    pub fn decode(encoded: &[u8]) -> Result<Self, PresencePayloadError> {
        if encoded.len() != Self::ENCODED_LEN {
            return Err(PresencePayloadError::InvalidLength(encoded.len()));
        }
        Ok(Self {
            config_version: ConfigVersion(u64::from_be_bytes(encoded[..8].try_into().unwrap())),
            config_digest: ConfigDigest(encoded[8..40].try_into().unwrap()),
            capability_digest: u64::from_be_bytes(encoded[40..].try_into().unwrap()),
        })
    }
}
/// A server notice instructs the client to fetch the complete signed Desired State.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigNotice {
    pub config_version: ConfigVersion,
    pub config_digest: ConfigDigest,
}
impl ConfigNotice {
    pub const ENCODED_LEN: usize = 40;
    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut encoded = [0; Self::ENCODED_LEN];
        encoded[..8].copy_from_slice(&self.config_version.0.to_be_bytes());
        encoded[8..].copy_from_slice(&self.config_digest.0);
        encoded
    }
    pub fn decode(encoded: &[u8]) -> Result<Self, PresencePayloadError> {
        if encoded.len() != Self::ENCODED_LEN {
            return Err(PresencePayloadError::InvalidLength(encoded.len()));
        }
        Ok(Self {
            config_version: ConfigVersion(u64::from_be_bytes(encoded[..8].try_into().unwrap())),
            config_digest: ConfigDigest(encoded[8..].try_into().unwrap()),
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresencePayloadError {
    InvalidLength(usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConfigDigest, ConfigNotice, ConfigVersion};

    #[test]
    fn presence_payloads_are_fixed_size_and_only_notify_of_config_changes() {
        let heartbeat = PresenceHeartbeat {
            config_version: ConfigVersion(9),
            config_digest: ConfigDigest::test_value(10),
            capability_digest: 11,
        };
        let notice = ConfigNotice {
            config_version: ConfigVersion(12),
            config_digest: ConfigDigest::test_value(13),
        };
        assert_eq!(
            PresenceHeartbeat::decode(&heartbeat.encode()).unwrap(),
            heartbeat
        );
        assert_eq!(ConfigNotice::decode(&notice.encode()).unwrap(), notice);
        assert_eq!(
            ConfigNotice::decode(&[0; 39]),
            Err(PresencePayloadError::InvalidLength(39))
        );
    }
}
