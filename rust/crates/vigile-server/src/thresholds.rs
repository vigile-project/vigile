// SPDX-License-Identifier: AGPL-3.0-or-later
//! Deployment monitoring and automatic stop thresholds (ISS-043, SEC-803).
//!
//! When a policy deployment causes an abnormal rate of denials or loss
//! of contact with multiple machines, the deployment is PAUSED
//! automatically — never silently resumed, always visible to the admin.

use serde::Serialize;
use std::time::SystemTime;

/// Configuration for automatic stop thresholds (DEC-09 proposals).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ThresholdConfig {
    /// Maximum denials per agent per window before pausing.
    pub max_denials_per_agent: u64,
    /// Window in seconds for the denial rate calculation.
    pub denial_window_secs: u64,
    /// Maximum consecutive failed health checks before pausing.
    pub max_failed_health_checks: u64,
    /// Maximum rollbacks in a window before pausing.
    pub max_rollbacks: u64,
    /// Rollback window in seconds.
    pub rollback_window_secs: u64,
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            max_denials_per_agent: 100,
            denial_window_secs: 60,
            max_failed_health_checks: 3,
            max_rollbacks: 5,
            rollback_window_secs: 300,
        }
    }
}

/// The reason a deployment was paused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PauseReason {
    /// Denial rate exceeded threshold.
    DenialRateExceeded {
        count: u64,
        threshold: u64,
        window_secs: u64,
    },
    /// Health checks failing repeatedly.
    HealthCheckFailures { count: u64, threshold: u64 },
    /// Too many rollbacks in the window.
    RollbackRateExceeded {
        count: u64,
        threshold: u64,
        window_secs: u64,
    },
    /// Manual pause by an administrator.
    Manual { note: String },
}

/// Tracks denials and health for a single agent.
#[derive(Debug, Clone)]
struct AgentTracker {
    agent_id: String,
    /// Recent denial timestamps (unix secs) — pruned to the window.
    denial_timestamps: Vec<i64>,
    /// Consecutive health check failures.
    health_failures: u64,
}

/// Monitors a deployment and decides whether to pause.
#[derive(Debug)]
pub struct DeploymentMonitor {
    config: ThresholdConfig,
    agents: Vec<AgentTracker>,
    rollback_count: u64,
    rollback_window_start: i64,
    pub paused: Option<PauseReason>,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl DeploymentMonitor {
    pub fn new(config: ThresholdConfig) -> Self {
        Self {
            config,
            agents: Vec::new(),
            rollback_count: 0,
            rollback_window_start: now_secs(),
            paused: None,
        }
    }

    /// Records a denial event for an agent. Returns true if the
    /// deployment should be paused.
    pub fn record_denial(&mut self, agent_id: &str) -> bool {
        if self.paused.is_some() {
            return true; // Already paused.
        }

        let now = now_secs();
        let window_start = now - self.config.denial_window_secs as i64;

        if !self.agents.iter().any(|t| t.agent_id == agent_id) {
            self.agents.push(AgentTracker {
                agent_id: agent_id.to_string(),
                denial_timestamps: Vec::new(),
                health_failures: 0,
            });
        }
        let Some(tracker) = self.agents.iter_mut().find(|t| t.agent_id == agent_id) else {
            return false; // unreachable: just pushed above
        };

        tracker.denial_timestamps.push(now);
        // Prune old entries outside the window.
        tracker.denial_timestamps.retain(|t| *t >= window_start);

        if tracker.denial_timestamps.len() as u64 >= self.config.max_denials_per_agent {
            self.paused = Some(PauseReason::DenialRateExceeded {
                count: tracker.denial_timestamps.len() as u64,
                threshold: self.config.max_denials_per_agent,
                window_secs: self.config.denial_window_secs,
            });
            return true;
        }

        false
    }

    /// Records a health check result. Returns true if the deployment
    /// should be paused.
    pub fn record_health(&mut self, agent_id: &str, passed: bool) -> bool {
        if self.paused.is_some() {
            return true;
        }

        if !self.agents.iter().any(|t| t.agent_id == agent_id) {
            self.agents.push(AgentTracker {
                agent_id: agent_id.to_string(),
                denial_timestamps: Vec::new(),
                health_failures: 0,
            });
        }
        let Some(tracker) = self.agents.iter_mut().find(|t| t.agent_id == agent_id) else {
            return false; // unreachable: just pushed above
        };

        if passed {
            tracker.health_failures = 0;
        } else {
            tracker.health_failures += 1;
            if tracker.health_failures >= self.config.max_failed_health_checks {
                self.paused = Some(PauseReason::HealthCheckFailures {
                    count: tracker.health_failures,
                    threshold: self.config.max_failed_health_checks,
                });
                return true;
            }
        }

        false
    }

    /// Records a rollback. Returns true if the deployment should be paused.
    pub fn record_rollback(&mut self) -> bool {
        if self.paused.is_some() {
            return true;
        }

        let now = now_secs();
        // Reset the rollback counter if we're outside the window.
        if now - self.rollback_window_start > self.config.rollback_window_secs as i64 {
            self.rollback_count = 0;
            self.rollback_window_start = now;
        }

        self.rollback_count += 1;
        if self.rollback_count >= self.config.max_rollbacks {
            self.paused = Some(PauseReason::RollbackRateExceeded {
                count: self.rollback_count,
                threshold: self.config.max_rollbacks,
                window_secs: self.config.rollback_window_secs,
            });
            return true;
        }

        false
    }

    /// Manually pauses the deployment.
    pub fn pause(&mut self, note: &str) {
        if self.paused.is_none() {
            self.paused = Some(PauseReason::Manual {
                note: note.to_string(),
            });
        }
    }

    /// Resumes the deployment (admin action, clears the pause reason
    /// and resets counters).
    pub fn resume(&mut self) {
        self.paused = None;
        self.rollback_count = 0;
        self.rollback_window_start = now_secs();
        for tracker in &mut self.agents {
            tracker.denial_timestamps.clear();
            tracker.health_failures = 0;
        }
    }

    /// Current status.
    pub fn status(&self) -> Option<&PauseReason> {
        self.paused.as_ref()
    }

    /// Whether the deployment is currently paused.
    pub fn is_paused(&self) -> bool {
        self.paused.is_some()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn strict_config() -> ThresholdConfig {
        ThresholdConfig {
            max_denials_per_agent: 5,
            denial_window_secs: 60,
            max_failed_health_checks: 2,
            max_rollbacks: 3,
            rollback_window_secs: 300,
        }
    }

    #[test]
    fn denial_threshold_triggers_pause() {
        let mut monitor = DeploymentMonitor::new(strict_config());
        for i in 0..4 {
            assert!(
                !monitor.record_denial("agent-1"),
                "denial {i} should not pause"
            );
        }
        // 5th denial hits the threshold.
        assert!(monitor.record_denial("agent-1"));
        assert!(monitor.is_paused());
        match monitor.status().unwrap() {
            PauseReason::DenialRateExceeded {
                count, threshold, ..
            } => {
                assert_eq!(*count, 5);
                assert_eq!(*threshold, 5);
            }
            other => panic!("expected DenialRateExceeded, got {other:?}"),
        }
    }

    #[test]
    fn different_agents_have_separate_counters() {
        let mut monitor = DeploymentMonitor::new(strict_config());
        for _ in 0..4 {
            monitor.record_denial("agent-1");
            monitor.record_denial("agent-2");
        }
        // Neither has hit the threshold (5 per agent).
        assert!(!monitor.is_paused());
        // One more for agent-1 triggers it.
        assert!(monitor.record_denial("agent-1"));
    }

    #[test]
    fn health_failures_trigger_pause() {
        let mut monitor = DeploymentMonitor::new(strict_config());
        assert!(!monitor.record_health("agent-1", false));
        // Second failure hits the threshold (max_failed_health_checks=2).
        assert!(monitor.record_health("agent-1", false));
        assert!(matches!(
            monitor.status().unwrap(),
            PauseReason::HealthCheckFailures { .. }
        ));
    }

    #[test]
    fn successful_health_resets_counter() {
        let mut monitor = DeploymentMonitor::new(strict_config());
        monitor.record_health("agent-1", false);
        monitor.record_health("agent-1", true); // resets
        assert!(!monitor.record_health("agent-1", false)); // back to 1
    }

    #[test]
    fn rollback_threshold_triggers_pause() {
        let mut monitor = DeploymentMonitor::new(strict_config());
        assert!(!monitor.record_rollback());
        assert!(!monitor.record_rollback());
        assert!(monitor.record_rollback()); // 3rd rollback
        assert!(matches!(
            monitor.status().unwrap(),
            PauseReason::RollbackRateExceeded { .. }
        ));
    }

    #[test]
    fn manual_pause_and_resume() {
        let mut monitor = DeploymentMonitor::new(strict_config());
        monitor.pause("testing");
        assert!(monitor.is_paused());
        assert!(matches!(
            monitor.status().unwrap(),
            PauseReason::Manual { .. }
        ));

        monitor.resume();
        assert!(!monitor.is_paused());
        // Counters were reset.
        assert!(!monitor.record_denial("agent-1"));
    }

    #[test]
    fn paused_monitor_stays_paused_on_new_events() {
        let mut monitor = DeploymentMonitor::new(strict_config());
        monitor.pause("manual");
        // Any event while paused returns true (stays paused).
        assert!(monitor.record_denial("agent-1"));
        assert!(monitor.record_health("agent-1", false));
        assert!(monitor.record_rollback());
    }
}
