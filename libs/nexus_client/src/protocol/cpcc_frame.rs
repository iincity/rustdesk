//! CPCC V2 bounded frame encoding and authenticated encryption.

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};

pub const CPCC_V2_VERSION: u8 = 2;
pub const CPCC_V2_AUTH_TAG_LEN: usize = 16;
pub const CPCC_V2_MAX_PAYLOAD_LEN: usize = 1200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CpccMessageType {
    Register = 1,
    CookieChallenge = 2,
    Heartbeat = 3,
    ConfigNotice = 4,
    ApplyResult = 5,
}

impl TryFrom<u8> for CpccMessageType {
    type Error = CpccFrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Register),
            2 => Ok(Self::CookieChallenge),
            3 => Ok(Self::Heartbeat),
            4 => Ok(Self::ConfigNotice),
            5 => Ok(Self::ApplyResult),
            _ => Err(CpccFrameError::UnknownMessageType(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpccV2Frame {
    pub message_type: CpccMessageType,
    pub flags: u8,
    pub key_id: u8,
    pub device_id: u64,
    pub boot_id: u32,
    pub sequence: u32,
    pub payload: Vec<u8>,
    /// The AEAD tag must verify before the payload reaches any stateful logic.
    pub auth_tag: [u8; CPCC_V2_AUTH_TAG_LEN],
}

impl CpccV2Frame {
    const HEADER_LEN: usize = 22;

    pub fn encode(&self) -> Result<Vec<u8>, CpccFrameError> {
        if self.payload.len() > CPCC_V2_MAX_PAYLOAD_LEN {
            return Err(CpccFrameError::PayloadTooLarge(self.payload.len()));
        }
        let mut encoded =
            Vec::with_capacity(Self::HEADER_LEN + self.payload.len() + CPCC_V2_AUTH_TAG_LEN);
        encoded.push(CPCC_V2_VERSION);
        encoded.push(self.message_type as u8);
        encoded.push(self.flags);
        encoded.push(self.key_id);
        encoded.extend_from_slice(&self.device_id.to_be_bytes());
        encoded.extend_from_slice(&self.boot_id.to_be_bytes());
        encoded.extend_from_slice(&self.sequence.to_be_bytes());
        encoded.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&self.payload);
        encoded.extend_from_slice(&self.auth_tag);
        Ok(encoded)
    }

    /// Rejects malformed length and version fields before allocating payload state.
    pub fn decode(encoded: &[u8]) -> Result<Self, CpccFrameError> {
        if encoded.len() < Self::HEADER_LEN + CPCC_V2_AUTH_TAG_LEN {
            return Err(CpccFrameError::Truncated);
        }
        if encoded[0] != CPCC_V2_VERSION {
            return Err(CpccFrameError::UnsupportedVersion(encoded[0]));
        }
        let payload_len = u16::from_be_bytes([encoded[20], encoded[21]]) as usize;
        if payload_len > CPCC_V2_MAX_PAYLOAD_LEN {
            return Err(CpccFrameError::PayloadTooLarge(payload_len));
        }
        let expected_len = Self::HEADER_LEN + payload_len + CPCC_V2_AUTH_TAG_LEN;
        if encoded.len() != expected_len {
            return Err(CpccFrameError::InvalidLength {
                expected: expected_len,
                received: encoded.len(),
            });
        }
        let mut auth_tag = [0; CPCC_V2_AUTH_TAG_LEN];
        auth_tag.copy_from_slice(&encoded[Self::HEADER_LEN + payload_len..]);
        Ok(Self {
            message_type: CpccMessageType::try_from(encoded[1])?,
            flags: encoded[2],
            key_id: encoded[3],
            device_id: u64::from_be_bytes(
                encoded[4..12]
                    .try_into()
                    .map_err(|_| CpccFrameError::Truncated)?,
            ),
            boot_id: u32::from_be_bytes(
                encoded[12..16]
                    .try_into()
                    .map_err(|_| CpccFrameError::Truncated)?,
            ),
            sequence: u32::from_be_bytes(
                encoded[16..20]
                    .try_into()
                    .map_err(|_| CpccFrameError::Truncated)?,
            ),
            payload: encoded[Self::HEADER_LEN..Self::HEADER_LEN + payload_len].to_vec(),
            auth_tag,
        })
    }

    /// Encrypts a bounded frame for one in-memory `(device_id, key_id)` session key.
    pub fn seal(&mut self, key: CpccAeadKey) -> Result<(), CpccCryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|_| CpccCryptoError::InvalidKey)?;
        let nonce = Nonce::from(self.nonce());
        let tag = cipher
            .encrypt_in_place_detached(&nonce, &self.aad(), &mut self.payload)
            .map_err(|_| CpccCryptoError::AuthenticationFailed)?;
        self.auth_tag.copy_from_slice(&tag);
        Ok(())
    }

    /// Does not alter the encrypted payload if authentication fails.
    pub fn open(&mut self, key: CpccAeadKey) -> Result<(), CpccCryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|_| CpccCryptoError::InvalidKey)?;
        let nonce = Nonce::from(self.nonce());
        let tag = Tag::from(self.auth_tag);
        let mut payload = self.payload.clone();
        cipher
            .decrypt_in_place_detached(&nonce, &self.aad(), &mut payload, &tag)
            .map_err(|_| CpccCryptoError::AuthenticationFailed)?;
        self.payload = payload;
        Ok(())
    }

    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0; 12];
        nonce[4..8].copy_from_slice(&self.boot_id.to_be_bytes());
        nonce[8..12].copy_from_slice(&self.sequence.to_be_bytes());
        nonce
    }

    fn aad(&self) -> [u8; Self::HEADER_LEN] {
        let mut aad = [0; Self::HEADER_LEN];
        aad[0] = CPCC_V2_VERSION;
        aad[1] = self.message_type as u8;
        aad[2] = self.flags;
        aad[3] = self.key_id;
        aad[4..12].copy_from_slice(&self.device_id.to_be_bytes());
        aad[12..16].copy_from_slice(&self.boot_id.to_be_bytes());
        aad[16..20].copy_from_slice(&self.sequence.to_be_bytes());
        aad[20..22].copy_from_slice(&(self.payload.len() as u16).to_be_bytes());
        aad
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CpccFrameError {
    Truncated,
    UnsupportedVersion(u8),
    UnknownMessageType(u8),
    PayloadTooLarge(usize),
    InvalidLength { expected: usize, received: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpccAeadKey(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpccCryptoError {
    InvalidKey,
    AuthenticationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpcc_v2_round_trips_a_compact_heartbeat() {
        let frame = CpccV2Frame {
            message_type: CpccMessageType::Heartbeat,
            flags: 0,
            key_id: 7,
            device_id: 42,
            boot_id: 9,
            sequence: 11,
            payload: vec![1, 2, 3],
            auth_tag: [4; 16],
        };
        assert_eq!(
            CpccV2Frame::decode(&frame.encode().unwrap()).unwrap(),
            frame
        );
    }

    #[test]
    fn cpcc_v2_rejects_length_mismatches_before_payload_use() {
        let frame = CpccV2Frame {
            message_type: CpccMessageType::Register,
            flags: 1,
            key_id: 1,
            device_id: 2,
            boot_id: 3,
            sequence: 4,
            payload: vec![5],
            auth_tag: [0; 16],
        };
        let mut encoded = frame.encode().unwrap();
        encoded.pop();
        assert_eq!(
            CpccV2Frame::decode(&encoded),
            Err(CpccFrameError::InvalidLength {
                expected: 39,
                received: 38
            })
        );
    }

    #[test]
    fn cpcc_v2_aead_round_trips_and_rejects_tampering() {
        let key = CpccAeadKey([9; 32]);
        let mut frame = CpccV2Frame {
            message_type: CpccMessageType::Heartbeat,
            flags: 0,
            key_id: 1,
            device_id: 2,
            boot_id: 3,
            sequence: 4,
            payload: vec![5, 6],
            auth_tag: [0; 16],
        };
        frame.seal(key).unwrap();
        let mut tampered = frame.clone();
        tampered.payload[0] ^= 1;
        let encrypted_payload = tampered.payload.clone();
        assert!(tampered.open(key).is_err());
        assert_eq!(tampered.payload, encrypted_payload);
        frame.open(key).unwrap();
        assert_eq!(frame.payload, vec![5, 6]);
    }
}
