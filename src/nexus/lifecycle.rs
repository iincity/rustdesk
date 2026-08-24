//! Desired State application outcome boundary.
//!
//! This module owns only the report projection after a verified Desired State
//! application. It deliberately has no RustDesk session, PortForward, or
//! Remote Desktop dependency, keeping an unavailable Control Plane from
//! affecting native traffic.

use std::{future::Future, pin::Pin};

/// Application-layer boundary for reporting one verified Desired State outcome.
/// Production uses the signed HTTPS adapter; tests may inject loopback without
/// changing the production transport policy.
pub trait TunnelApplicationReporter: Send + Sync {
    fn report<'a>(
        &'a self,
        control_plane_url: &'a str,
        version: u64,
        digest_hex: &'a str,
        outcome: &'a str,
        detail: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

pub(super) struct HttpsTunnelApplicationReporter;

impl TunnelApplicationReporter for HttpsTunnelApplicationReporter {
    fn report<'a>(
        &'a self,
        control_plane_url: &'a str,
        version: u64,
        digest_hex: &'a str,
        outcome: &'a str,
        detail: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(
            super::implementation::record_tunnel_desired_state_application_http(
                control_plane_url,
                version,
                digest_hex,
                outcome,
                detail,
                false,
            ),
        )
    }
}

#[cfg(test)]
pub(super) struct LoopbackTunnelApplicationReporter;

#[cfg(test)]
impl TunnelApplicationReporter for LoopbackTunnelApplicationReporter {
    fn report<'a>(
        &'a self,
        control_plane_url: &'a str,
        version: u64,
        digest_hex: &'a str,
        outcome: &'a str,
        detail: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(
            super::implementation::record_tunnel_desired_state_application_loopback(
                control_plane_url,
                version,
                digest_hex,
                outcome,
                detail,
            ),
        )
    }
}
