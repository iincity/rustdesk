#[path = "native_presence_impl.rs"]
mod presence_udp;

pub use presence_udp::{PresenceClient, PresenceClientError};
