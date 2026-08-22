//! Pure replay protection for authenticated CPCC packets.

/// Result of evaluating one sequence number against a session replay window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDecision {
    Accepted,
    Duplicate,
    TooOld,
}

/// A 64-packet sliding replay window for one authenticated `(device_id, boot_id)` session.
///
/// Callers must invoke this only after Cookie/signature or AEAD authentication succeeds;
/// accepting an unauthenticated sequence would let a peer advance the window.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReplayWindow {
    highest_sequence: Option<u32>,
    seen: u64,
}

impl ReplayWindow {
    pub fn accept(&mut self, sequence: u32) -> ReplayDecision {
        let Some(highest) = self.highest_sequence else {
            self.highest_sequence = Some(sequence);
            self.seen = 1;
            return ReplayDecision::Accepted;
        };

        if sequence > highest {
            let advance = sequence - highest;
            self.seen = if advance >= 64 {
                1
            } else {
                (self.seen << advance) | 1
            };
            self.highest_sequence = Some(sequence);
            return ReplayDecision::Accepted;
        }

        let distance = highest - sequence;
        if distance >= 64 {
            return ReplayDecision::TooOld;
        }
        let bit = 1_u64 << distance;
        if self.seen & bit != 0 {
            ReplayDecision::Duplicate
        } else {
            self.seen |= bit;
            ReplayDecision::Accepted
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ReplayDecision, ReplayWindow};

    #[test]
    fn accepts_reordering_once_and_rejects_duplicates_and_old_packets() {
        let mut window = ReplayWindow::default();

        assert_eq!(window.accept(10), ReplayDecision::Accepted);
        assert_eq!(window.accept(12), ReplayDecision::Accepted);
        assert_eq!(window.accept(11), ReplayDecision::Accepted);
        assert_eq!(window.accept(11), ReplayDecision::Duplicate);
        assert_eq!(window.accept(100), ReplayDecision::Accepted);
        assert_eq!(window.accept(0), ReplayDecision::TooOld);
    }
}
