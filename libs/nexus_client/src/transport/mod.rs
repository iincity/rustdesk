//! Network transports.  UDP framing is kept out of application orchestration.

pub mod authi_socket;
mod presence_udp;

pub use presence_udp::{PresenceClient, PresenceClientError};
