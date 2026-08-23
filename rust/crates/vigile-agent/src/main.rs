// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile agent — unprivileged system service (ADR-0002).
//!
//! Sprint 3 scope: the `inventory` subcommand produces the M2 inventory
//! report (platform, capabilities, packages, executables, optional
//! journal sample) as JSON on stdout. No network, no policy, no
//! enforcement — observation only.

use serde::Serialize;
use std::path::{Path, PathBuf};
use vigile_backend_inventory::{
    capabilities::detect_capabilities, executables, journal, packages, platform,
};

#[derive(Serialize)]
struct AgentReport {
    agent_version: String,
    platform: platform::OsRelease,
    family: String,
    capabilities: Vec<capabilities_report::DetectedCapabilityJson>,
    packages: PackagesReport,
    executables: executables::ScanReport,
    journal_sample: Option<Vec<journal::JournalRecord>>,
}

mod capabilities_report {
    use serde::Serialize;
    use vigile_backend_inventory::capabilities::DetectedCapability;
    use vigile_backend_inventory::SupportLevel;

    #[derive(Serialize)]
    pub struct DetectedCapabilityJson {
        pub backend: String,
        pub declared: SupportLevel,
        pub present_locally: bool,
        pub effective: SupportLevel,
    }

    impl From<DetectedCapability> for DetectedCapabilityJson {
        fn from(c: DetectedCapability) -> Self {
            Self {
                backend: c.backend,
                declared: c.declared,
                present_locally: c.present_locally,
                effective: c.effective,
            }
        }
    }
}

#[derive(Serialize)]
struct PackagesReport {
    available: bool,
    count: usize,
    signed_count: usize,
    packages: Vec<packages::RpmPackage>,
}

fn collect_packages() -> PackagesReport {
    match packages::run_rpm_qa() {
        Ok(output) => {
            let list = packages::parse_rpm_qa(&output);
            let signed_count = list.iter().filter(|p| p.signed()).count();
            PackagesReport {
                available: true,
                count: list.len(),
                signed_count,
                packages: list,
            }
        }
        Err(_) => PackagesReport {
            available: false,
            count: 0,
            signed_count: 0,
            packages: Vec::new(),
        },
    }
}

fn run_inventory(with_journal: bool) -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new("/");
    let os = platform::read_os_release(root)?;
    let capability_report = detect_capabilities(root, &os);
    let family = format!("{:?}", capability_report.family).to_lowercase();

    // Home resolved from the environment by the caller process — the
    // library never reads env vars itself.
    let home: Option<PathBuf> = std::env::var_os("HOME").map(PathBuf::from);

    let executables_report =
        executables::scan(root, executables::DEFAULT_SCAN_ROOTS, home.as_deref());

    let journal_sample = if with_journal {
        journal::run_journalctl(&["-n", "50"])
            .ok()
            .map(|out| journal::parse_output(&out).0)
    } else {
        None
    };

    let report = AgentReport {
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        platform: os,
        family,
        capabilities: capability_report
            .capabilities
            .into_iter()
            .map(Into::into)
            .collect(),
        packages: collect_packages(),
        executables: executables_report,
        journal_sample,
    };

    let json = serde_json::to_string_pretty(&report)?;
    println!("{json}");
    Ok(())
}

fn main() {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next().as_deref()) {
        (Some("inventory"), None) => {
            if let Err(e) = run_inventory(false) {
                eprintln!("vigile-agent: inventory failed: {e}");
                std::process::exit(1);
            }
        }
        (Some("inventory"), Some("--journal")) => {
            if let Err(e) = run_inventory(true) {
                eprintln!("vigile-agent: inventory failed: {e}");
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!(
                "vigile-agent {} (skeleton + inventory)\n\
                 usage: vigile-agent inventory [--journal]",
                env!("CARGO_PKG_VERSION")
            );
            std::process::exit(2);
        }
    }
}
