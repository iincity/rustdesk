//! Pure Config Notice refresh decision.

use crate::{ConfigNotice, TunnelStatus};

/// Returns whether an unauthenticated notice warrants fetching signed Desired State.
pub fn should_refresh_from_notice(status: &TunnelStatus, notice: ConfigNotice) -> bool {
    match status.desired_version {
        None => true,
        Some(version) if notice.config_version > version => true,
        Some(version) if notice.config_version < version => false,
        Some(_) => status.desired_digest != Some(notice.config_digest),
    }
}

#[cfg(test)]
mod tests {
    use crate::{ConfigDigest, ConfigNotice, ConfigVersion, TunnelState, TunnelStatus};

    use super::should_refresh_from_notice;

    #[test]
    fn refreshes_only_for_a_newer_or_conflicting_digest() {
        let status = TunnelStatus {
            state: TunnelState::PresenceOnly,
            desired_version: Some(ConfigVersion(4)),
            desired_digest: Some(ConfigDigest([5; 32])),
            ..TunnelStatus::default()
        };
        assert!(!should_refresh_from_notice(
            &status,
            ConfigNotice {
                config_version: ConfigVersion(3),
                config_digest: ConfigDigest([9; 32])
            }
        ));
        assert!(!should_refresh_from_notice(
            &status,
            ConfigNotice {
                config_version: ConfigVersion(4),
                config_digest: ConfigDigest([5; 32])
            }
        ));
        assert!(should_refresh_from_notice(
            &status,
            ConfigNotice {
                config_version: ConfigVersion(4),
                config_digest: ConfigDigest([9; 32])
            }
        ));
        assert!(should_refresh_from_notice(
            &status,
            ConfigNotice {
                config_version: ConfigVersion(5),
                config_digest: ConfigDigest([9; 32])
            }
        ));
    }
}
