//! Authenticated CPCC Presence transport over UDP.

use std::{net::SocketAddr, time::Duration};

use nexus_tunnel_core::{
    registration_signature_message, CookieChallengePayload, CookieRequestPayload, CpccAeadKey,
    CpccMessageType, CpccV2Frame, PresenceHeartbeat, RegistrationPayload,
};
use tokio::net::UdpSocket;

const CPCC_FLAG_RESPONSE: u8 = 1 << 1;

/// UDP client for one explicit Gateway and one in-memory Presence boot session.
pub struct PresenceClient {
    socket: UdpSocket,
    gateway: SocketAddr,
    device_id: u64,
    boot_id: u32,
    sequence: u32,
}

impl PresenceClient {
    pub async fn bind(
        bind_address: SocketAddr,
        gateway: SocketAddr,
        device_id: u64,
        boot_id: u32,
    ) -> Result<Self, PresenceClientError> {
        Ok(Self {
            socket: UdpSocket::bind(bind_address).await?,
            gateway,
            device_id,
            boot_id,
            sequence: 0,
        })
    }

    /// Registers using a host-provided device signature and waits for a
    /// session-key-authenticated acknowledgement. This crate never receives
    /// the device private key.
    pub async fn register(
        &mut self,
        public_key: [u8; 32],
        client_nonce: [u8; 16],
        key_id: u8,
        session_key: [u8; 32],
        sign: impl FnOnce(&[u8]) -> [u8; 64],
    ) -> Result<(), PresenceClientError> {
        if key_id == 0 {
            return Err(PresenceClientError::InvalidKeyId);
        }
        let request = self.frame(
            CpccMessageType::Register,
            0,
            CookieRequestPayload {
                client_nonce,
                public_key,
            }
            .encode()
            .to_vec(),
        );
        self.send(&request).await?;
        let challenge = self.receive().await?;
        if challenge.message_type != CpccMessageType::CookieChallenge
            || challenge.flags != CPCC_FLAG_RESPONSE
            || challenge.key_id != 0
            || challenge.device_id != self.device_id
            || challenge.boot_id != self.boot_id
            || challenge.sequence != request.sequence
        {
            return Err(PresenceClientError::InvalidChallenge);
        }
        let cookie = CookieChallengePayload::decode(&challenge.payload)
            .map_err(|_| PresenceClientError::InvalidChallenge)?
            .cookie;
        let mut registration = RegistrationPayload {
            client_nonce,
            cookie,
            public_key,
            signature: [0; 64],
        };
        let mut frame = self.frame(CpccMessageType::Register, key_id, registration.encode());
        registration.signature = sign(&registration_signature_message(&frame, &registration));
        frame.payload = registration.encode();
        // UDP can drop the accepted registration response. Retrying the exact
        // signed frame is safe: the Gateway treats the replay as idempotent
        // and returns the same authenticated acknowledgement.
        for _ in 0..2 {
            self.send(&frame).await?;
            let acknowledgement =
                match tokio::time::timeout(Duration::from_secs(2), self.receive()).await {
                    Ok(frame) => frame?,
                    Err(_) => continue,
                };
            if acknowledgement.message_type != CpccMessageType::Register
                || acknowledgement.flags != CPCC_FLAG_RESPONSE
                || acknowledgement.key_id != key_id
                || acknowledgement.device_id != self.device_id
                || acknowledgement.boot_id != self.boot_id
                || acknowledgement.sequence != frame.sequence
            {
                return Err(PresenceClientError::InvalidRegistrationAcknowledgement);
            }
            let mut acknowledgement = acknowledgement;
            acknowledgement
                .open(CpccAeadKey(session_key))
                .map_err(|_| PresenceClientError::InvalidRegistrationAcknowledgement)?;
            if acknowledgement.payload.is_empty() {
                return Ok(());
            }
            return Err(PresenceClientError::InvalidRegistrationAcknowledgement);
        }
        Err(PresenceClientError::RegistrationTimeout)
    }

    /// Encrypts and sends a heartbeat; the caller retains responsibility for lease validity.
    pub async fn send_heartbeat(
        &mut self,
        key_id: u8,
        key: [u8; 32],
        heartbeat: PresenceHeartbeat,
    ) -> Result<(), PresenceClientError> {
        if key_id == 0 {
            return Err(PresenceClientError::InvalidKeyId);
        }
        let mut frame = self.frame(
            CpccMessageType::Heartbeat,
            key_id,
            heartbeat.encode().to_vec(),
        );
        frame
            .seal(CpccAeadKey(key))
            .map_err(|_| PresenceClientError::Encryption)?;
        self.send(&frame).await
    }

    fn frame(
        &mut self,
        message_type: CpccMessageType,
        key_id: u8,
        payload: Vec<u8>,
    ) -> CpccV2Frame {
        self.sequence = self.sequence.wrapping_add(1);
        CpccV2Frame {
            message_type,
            flags: 0,
            key_id,
            device_id: self.device_id,
            boot_id: self.boot_id,
            sequence: self.sequence,
            payload,
            auth_tag: [0; 16],
        }
    }
    async fn send(&self, frame: &CpccV2Frame) -> Result<(), PresenceClientError> {
        self.socket
            .send_to(
                &frame.encode().map_err(|_| PresenceClientError::Frame)?,
                self.gateway,
            )
            .await?;
        Ok(())
    }
    async fn receive(&self) -> Result<CpccV2Frame, PresenceClientError> {
        let mut buffer = [0; 1_238];
        let (length, peer) = self.socket.recv_from(&mut buffer).await?;
        if peer != self.gateway {
            return Err(PresenceClientError::UnexpectedPeer);
        }
        CpccV2Frame::decode(&buffer[..length]).map_err(|_| PresenceClientError::Frame)
    }
}

#[derive(Debug)]
pub enum PresenceClientError {
    Io(std::io::Error),
    Frame,
    InvalidChallenge,
    InvalidRegistrationAcknowledgement,
    RegistrationTimeout,
    InvalidKeyId,
    Encryption,
    UnexpectedPeer,
}
impl From<std::io::Error> for PresenceClientError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
