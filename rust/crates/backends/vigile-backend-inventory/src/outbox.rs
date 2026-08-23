// SPDX-License-Identifier: AGPL-3.0-or-later
//! Deferred incremental upload (ISS-022, FR-108): inventory diffs and
//! reconnect backoff. Pure and deterministic — the jitter source is
//! INJECTED (`rng01: f64` in [0,1)), so bounds are provable; the real
//! caller feeds it from the OS RNG. The network transport arrives with
//! the server (ISS-030): this module decides WHAT to send and WHEN to
//! retry, never how.

use std::collections::BTreeMap;

/// Inventory diff between two scans (keyed by path).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InventoryDiff {
    pub added: Vec<String>,
    pub changed: Vec<String>,
    pub removed: Vec<String>,
}

impl InventoryDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.changed.is_empty() && self.removed.is_empty()
    }

    /// Computes previous → current. `hash_of` takes the value type so
    /// the diff works for any inventory (executables, packages…).
    pub fn compute<V>(previous: &BTreeMap<String, V>, current: &BTreeMap<String, V>) -> Self
    where
        V: PartialEq,
    {
        let mut diff = InventoryDiff::default();
        for (path, value) in current {
            match previous.get(path) {
                None => diff.added.push(path.clone()),
                Some(old) if old != value => diff.changed.push(path.clone()),
                Some(_) => {}
            }
        }
        for path in previous.keys() {
            if !current.contains_key(path) {
                diff.removed.push(path.clone());
            }
        }
        diff
    }
}

/// Exponential backoff with jitter: `base * 2^attempt` capped at `max`,
/// then jittered DOWN by up to `jitter_ratio` of the value (never above
/// the cap, never below `base`). `rng01` must be in [0,1) — values
/// outside are clamped (defensive: a broken RNG must not zero the
/// delay).
pub fn backoff_with_jitter(
    attempt: u32,
    base_ms: u64,
    max_ms: u64,
    jitter_ratio: f64,
    rng01: f64,
) -> u64 {
    let ratio = jitter_ratio.clamp(0.0, 0.9);
    let rng = rng01.clamp(0.0, 0.999_999);
    let exp = attempt.min(20);
    let raw = base_ms.saturating_mul(1u64 << exp);
    let capped = raw.min(max_ms).max(base_ms);
    let jitter_factor = 1.0 - rng * ratio;
    let result = capped as f64 * jitter_factor;
    (result as u64).max(base_ms).min(max_ms)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    fn inventory(items: &[(&str, u32)]) -> BTreeMap<String, u32> {
        items.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn diff_added_changed_removed() {
        let previous = inventory(&[
            ("/usr/bin/keep", 1),
            ("/usr/bin/changed", 2),
            ("/usr/bin/gone", 3),
        ]);
        let current = inventory(&[
            ("/usr/bin/keep", 1),
            ("/usr/bin/changed", 9),
            ("/usr/bin/new", 4),
        ]);
        let diff = InventoryDiff::compute(&previous, &current);
        assert_eq!(diff.added, vec!["/usr/bin/new"]);
        assert_eq!(diff.changed, vec!["/usr/bin/changed"]);
        assert_eq!(diff.removed, vec!["/usr/bin/gone"]);
    }

    #[test]
    fn diff_identical_is_empty() {
        let a = inventory(&[("x", 1)]);
        let b = inventory(&[("x", 1)]);
        assert!(InventoryDiff::compute(&a, &b).is_empty());
    }

    #[test]
    fn backoff_grows_and_caps() {
        // No jitter.
        assert_eq!(backoff_with_jitter(0, 1000, 60_000, 0.0, 0.0), 1000);
        assert_eq!(backoff_with_jitter(1, 1000, 60_000, 0.0, 0.0), 2000);
        assert_eq!(backoff_with_jitter(4, 1000, 60_000, 0.0, 0.0), 16_000);
        // Cap reached.
        assert_eq!(backoff_with_jitter(10, 1000, 60_000, 0.0, 0.0), 60_000);
        // Absurd attempt does not overflow.
        assert_eq!(backoff_with_jitter(1000, 1000, 60_000, 0.0, 0.5), 60_000);
    }

    #[test]
    fn jitter_stays_within_bounds_for_all_rng() {
        for rng in [0.0, 0.25, 0.5, 0.9, 0.999, 1.0, -1.0, 42.0] {
            for attempt in [0u32, 3, 7, 30] {
                let delay = backoff_with_jitter(attempt, 1000, 60_000, 0.3, rng);
                assert!(
                    (1000..=60_000).contains(&delay),
                    "attempt={attempt} rng={rng} -> {delay}"
                );
            }
        }
    }

    #[test]
    fn jitter_reduces_but_never_below_base() {
        let no_jitter = backoff_with_jitter(4, 1000, 60_000, 0.0, 0.0);
        let full_jitter = backoff_with_jitter(4, 1000, 60_000, 0.5, 0.999);
        assert!(full_jitter < no_jitter);
        assert!(full_jitter >= 8000); // 16000 * (1 - 0.999*0.5) ≈ 8008
    }
}
