//! Signed, bounded inputs for protected-service visitors.

use std::net::SocketAddr;

/// The protected upstream visitor kinds NexusFlow can safely compile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisitorProtocol {
    Stcp,
    Sudp,
    /// NAT-traversed protected access. The signed visitor selects its KCP or
    /// QUIC hole-punch transport through [`XtcpNatProtocol`].
    Xtcp,
}

/// The only NAT-hole transports admitted for a signed XTCP visitor.
///
/// This deliberately exposes no upstream retry, fallback, or STUN options;
/// fixed safe defaults remain owned by the native transport implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtcpNatProtocol {
    Kcp,
    Quic,
}

/// A control-plane-authorized local listener for one protected service.
///
/// Bind addresses are deliberately loopback-only: exposing a visitor listener
/// on a host interface would bypass the control-plane access decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunnelVisitor {
    pub visitor_id: String,
    pub protocol: VisitorProtocol,
    /// Required only for XTCP; selects the signed NAT-hole transport.
    pub xtcp_nat_protocol: Option<XtcpNatProtocol>,
    pub service_id: String,
    /// Publishing device identity used by upstream `serverUser` routing.
    pub server_device_uid: String,
    /// Accessing device identity checked against the protected-service grant.
    pub visitor_device_uid: String,
    pub secret: String,
    pub bind: SocketAddr,
    pub max_connections: u16,
    /// Opaque control-plane grant carried by the signed visitor assignment.
    /// It is not sent to the transport; the Relay usage reporter consumes it.
    pub grant_id: Option<String>,
}

impl TunnelVisitor {
    /// Validates identity, local bind, and the bounded authorization inputs.
    pub fn validate(&self) -> Result<(), VisitorError> {
        if self.visitor_id.trim().is_empty()
            || self.service_id.trim().is_empty()
            || self.server_device_uid.trim().is_empty()
            || self.visitor_device_uid.trim().is_empty()
            || self.secret.len() < 16
            || self.max_connections == 0
            || !self.bind.ip().is_loopback()
            || [
                &self.visitor_id,
                &self.service_id,
                &self.server_device_uid,
                &self.visitor_device_uid,
                &self.secret,
            ]
            .iter()
            .any(|value| value.contains(['\r', '\n', '"', '\\']))
        {
            return Err(VisitorError::InvalidVisitor);
        }
        if matches!(self.protocol, VisitorProtocol::Xtcp) != self.xtcp_nat_protocol.is_some() {
            return Err(VisitorError::InvalidVisitor);
        }
        if self
            .grant_id
            .as_deref()
            .is_some_and(|grant| grant.trim().is_empty() || grant.contains(['\r', '\n', '"', '\\']))
        {
            return Err(VisitorError::InvalidVisitor);
        }
        Ok(())
    }

}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisitorError {
    InvalidVisitor,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visitor_validation_rejects_public_binds_and_invalid_xtcp_modes() {
        let visitor = TunnelVisitor {
            visitor_id: "visitor-1".into(),
            protocol: VisitorProtocol::Stcp,
            xtcp_nat_protocol: None,
            service_id: "support".into(),
            server_device_uid: "device-publisher".into(),
            visitor_device_uid: "device-visitor".into(),
            secret: "0123456789abcdef".into(),
            bind: "127.0.0.1:19000".parse().unwrap(),
            max_connections: 1,
            grant_id: None,
        };
        assert_eq!(visitor.validate(), Ok(()));
        let mut public = visitor;
        public.bind = "0.0.0.0:19000".parse().unwrap();
        assert_eq!(public.validate(), Err(VisitorError::InvalidVisitor));
        let mut injected = public;
        injected.bind = "127.0.0.1:19000".parse().unwrap();
        injected.secret = "0123456789abcdef\nplugin = \"socks5\"".into();
        assert_eq!(injected.validate(), Err(VisitorError::InvalidVisitor));

        let mut xtcp = TunnelVisitor {
            protocol: VisitorProtocol::Xtcp,
            xtcp_nat_protocol: Some(XtcpNatProtocol::Quic),
            ..injected
        };
        xtcp.secret = "0123456789abcdef".into();
        assert_eq!(xtcp.validate(), Ok(()));
        xtcp.xtcp_nat_protocol = None;
        assert_eq!(xtcp.validate(), Err(VisitorError::InvalidVisitor));
    }
}
