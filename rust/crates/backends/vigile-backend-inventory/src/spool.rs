// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded priority spool (ISS-021, SEC-604 / FM-08): local event queue
//! with priorities — security first, health second, telemetry last.
//! When full, the LOWEST-priority newest items are dropped first and
//! counted; enforcement never depends on this queue (ADR-0010), only
//! visibility does.

use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Security,
    Health,
    Telemetry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpooledEvent<T> {
    pub priority: Priority,
    pub event: T,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolStats {
    pub len: usize,
    pub dropped: usize,
    /// Number of pushes rejected because the SECURITY portion alone is
    /// saturated (should stay zero; if not, alert — FM-17).
    pub security_saturated: usize,
}

/// Bounded FIFO with priority-aware eviction.
#[derive(Debug)]
pub struct PrioritySpool<T> {
    queues: [VecDeque<T>; 3],
    capacity: usize,
    pub dropped: usize,
    pub security_saturated: usize,
}

impl<T> PrioritySpool<T> {
    /// `capacity` is the TOTAL bound across priorities.
    pub fn new(capacity: usize) -> Self {
        Self {
            queues: [VecDeque::new(), VecDeque::new(), VecDeque::new()],
            capacity,
            dropped: 0,
            security_saturated: 0,
        }
    }

    fn index(priority: Priority) -> usize {
        match priority {
            Priority::Security => 0,
            Priority::Health => 1,
            Priority::Telemetry => 2,
        }
    }

    pub fn len(&self) -> usize {
        self.queues.iter().map(VecDeque::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Pushes an event. Eviction policy when full: drop the newest
    /// TELEMETRY item, then HEALTH; never evict SECURITY. Security
    /// pushes on a full-of-security spool are refused and counted
    /// (`security_saturated`) — the caller must alert.
    pub fn push(&mut self, priority: Priority, event: T) -> bool {
        if self.len() >= self.capacity {
            // Try evicting from the lowest priority that has items and
            // is not the one being pushed.
            for victim_idx in (Self::index(priority) + 1..3).rev() {
                if let Some(evicted) = self.queues[victim_idx].pop_back() {
                    drop(evicted);
                    self.dropped += 1;
                    break;
                }
            }
            if self.len() >= self.capacity {
                if priority == Priority::Security {
                    self.security_saturated += 1;
                } else {
                    self.dropped += 1;
                }
                return false;
            }
        }
        self.queues[Self::index(priority)].push_back(event);
        true
    }

    /// Drains up to `max` events, highest priority first, FIFO within a
    /// priority (security events are never delayed behind telemetry).
    pub fn drain(&mut self, max: usize) -> Vec<SpooledEvent<T>> {
        let mut out = Vec::with_capacity(max.min(self.len()));
        while out.len() < max {
            let idx = (0..3).find(|i| !self.queues[*i].is_empty());
            let Some(idx) = idx else { break };
            let event = self.queues[idx].pop_front();
            if let Some(event) = event {
                out.push(SpooledEvent {
                    priority: match idx {
                        0 => Priority::Security,
                        1 => Priority::Health,
                        _ => Priority::Telemetry,
                    },
                    event,
                });
            }
        }
        out
    }

    pub fn stats(&self) -> SpoolStats {
        SpoolStats {
            len: self.len(),
            dropped: self.dropped,
            security_saturated: self.security_saturated,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn drain_is_priority_ordered_then_fifo() {
        let mut spool: PrioritySpool<u32> = PrioritySpool::new(100);
        spool.push(Priority::Telemetry, 1);
        spool.push(Priority::Security, 10);
        spool.push(Priority::Health, 20);
        spool.push(Priority::Telemetry, 2);
        spool.push(Priority::Security, 11);

        let drained = spool.drain(100);
        let priorities: Vec<Priority> = drained.iter().map(|e| e.priority).collect();
        assert_eq!(
            priorities,
            vec![
                Priority::Security,
                Priority::Security,
                Priority::Health,
                Priority::Telemetry,
                Priority::Telemetry
            ]
        );
        let security: Vec<u32> = drained
            .iter()
            .filter(|e| e.priority == Priority::Security)
            .map(|e| e.event)
            .collect();
        assert_eq!(security, vec![10, 11], "FIFO within a priority");
    }

    #[test]
    fn telemetry_evicted_first_when_full() {
        let mut spool: PrioritySpool<u32> = PrioritySpool::new(2);
        assert!(spool.push(Priority::Telemetry, 1));
        assert!(spool.push(Priority::Telemetry, 2));
        // Security push evicts the newest telemetry.
        assert!(spool.push(Priority::Security, 3));
        assert_eq!(spool.stats().dropped, 1);
        let drained = spool.drain(10);
        assert_eq!(drained.len(), 2);
        assert!(drained
            .iter()
            .all(|e| e.event != 2 || e.priority == Priority::Telemetry));
        // The oldest telemetry survived, the newest was evicted.
        assert_eq!(drained[1].event, 1);
    }

    #[test]
    fn security_is_never_evicted() {
        let mut spool: PrioritySpool<u32> = PrioritySpool::new(2);
        spool.push(Priority::Security, 1);
        spool.push(Priority::Security, 2);
        // Full of security: a telemetry push is refused, security intact.
        assert!(!spool.push(Priority::Telemetry, 3));
        assert_eq!(spool.stats().dropped, 1);
        assert_eq!(spool.len(), 2);

        // A third security push is refused and counted as saturation.
        assert!(!spool.push(Priority::Security, 4));
        assert_eq!(spool.stats().security_saturated, 1);
        assert_eq!(spool.len(), 2);
    }

    #[test]
    fn partial_drain_keeps_the_rest() {
        let mut spool: PrioritySpool<u32> = PrioritySpool::new(100);
        for i in 0..5 {
            spool.push(Priority::Telemetry, i);
        }
        let first = spool.drain(2);
        assert_eq!(first.len(), 2);
        assert_eq!(spool.len(), 3);
        let rest = spool.drain(100);
        assert_eq!(rest.len(), 3);
        assert!(spool.is_empty());
    }
}
