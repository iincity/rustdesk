//! Bounded, signed inputs for local access listeners.

use std::net::SocketAddr;

/// Local proxy protocol exposed only on the device loopback interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalAccessProtocol {
    Socks5,
    HttpConnect,
}

/// A signed local listener with a finite target allow-list.
///
/// This is intentionally separate from FRP plugins: it describes the Nexus
/// access decision rather than forwarding arbitrary plugin configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAccessListener {
    pub listener_id: String,
    pub protocol: LocalAccessProtocol,
    pub bind: SocketAddr,
    pub allowed_targets: Vec<SocketAddr>,
    pub max_connections: u16,
}

impl LocalAccessListener {
    /// Rejects public binds, empty targets, and unbounded connection requests.
    pub fn validate(&self) -> Result<(), LocalAccessError> {
        if self.listener_id.trim().is_empty()
            || !self.bind.ip().is_loopback()
            || self.allowed_targets.is_empty()
            || self.allowed_targets.len() > 64
            || self.allowed_targets.iter().any(|target| target.port() == 0)
            || self.max_connections == 0
            || self.listener_id.contains(['\r', '\n', '"', '\\'])
        {
            return Err(LocalAccessError::InvalidListener);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalAccessError {
    InvalidListener,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_access_rejects_public_listener_and_unbounded_targets() {
        let listener = LocalAccessListener {
            listener_id: "support-local".into(),
            protocol: LocalAccessProtocol::Socks5,
            bind: "127.0.0.1:1080".parse().unwrap(),
            allowed_targets: vec!["127.0.0.1:3389".parse().unwrap()],
            max_connections: 1,
        };
        assert!(listener.validate().is_ok());
        let mut public = listener;
        public.bind = "0.0.0.0:1080".parse().unwrap();
        assert_eq!(public.validate(), Err(LocalAccessError::InvalidListener));
    }
}
