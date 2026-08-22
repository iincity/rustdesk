//! CPCC V2 protocol primitives and validation rules.

mod cpcc_frame;
mod presence_payload;
mod replay;

pub use cpcc_frame::{
    CpccAeadKey, CpccCryptoError, CpccFrameError, CpccMessageType, CpccV2Frame,
    CPCC_V2_AUTH_TAG_LEN, CPCC_V2_MAX_PAYLOAD_LEN, CPCC_V2_VERSION,
};
pub use presence_payload::{
    registration_signature_message, ConfigDigest, ConfigNotice, ConfigVersion,
    CookieChallengePayload, CookieRequestPayload, PresenceCookie, PresenceHeartbeat,
    PresencePayloadError, RegistrationPayload, RegistrationPayloadError,
};
pub use replay::{ReplayDecision, ReplayWindow};
