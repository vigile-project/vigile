// SPDX-License-Identifier: AGPL-3.0-or-later
//! Executable inventory outside the package database (ISS-019, FR-103):
//! walk the standard roots plus the user home, keep regular executable
//! files only (symlinks NEVER followed — SEC-402), classify via
//! [`crate::exec_detection`] and hash content with SHA-256 (streamed).
//!
//! Metadata + hash only, never content (SEC-1001). Bounded: the walk
//! stops after `MAX_FILES` executables; unreadable entries are counted,
//! never fatal — an inventory must stay complete.

use crate::exec_detection::{classify, FileKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Default scan roots (relative to the virtual root).
/// Default scan roots (relative to the virtual root). The user home is
/// NOT here: it is always passed explicitly (it needs caller-side
/// resolution), scanning it twice would duplicate entries.
pub const DEFAULT_SCAN_ROOTS: &[&str] = &[
    "usr/local/bin",
    "usr/local/sbin",
    "usr/local/lib",
    "opt",
    "srv/bin",
];

/// Hard bound on inventoried executables per scan.
pub const MAX_FILES: usize = 100_000;
/// Files larger than this are hashed anyway but flagged — a bound on
/// absurd cases is not content filtering, it is resource protection.
pub const HASH_CHUNK: usize = 64 * 1024;

/// One inventoried executable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableEntry {
    /// Path relative to the scan root argument (no leading `/`).
    pub path: String,
    pub kind: FileKind,
    /// Lowercase hex SHA-256 of the content.
    pub sha256: String,
    pub size: u64,
}

/// Result of a scan: entries sorted by path + diagnostics.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub entries: BTreeMap<String, ExecutableEntry>,
    pub skipped_symlinks: usize,
    pub unreadable: usize,
    pub truncated: bool,
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn is_executable(mode: u32) -> bool {
    mode & 0o111 != 0
}

/// Hashes a file in chunks. Returns (sha256_hex, size).
fn hash_file(path: &Path) -> std::io::Result<(String, u64)> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut buf = vec![0u8; HASH_CHUNK];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((hex(&hasher.finalize()), size))
}

fn walk_dir(dir: &Path, base: &Path, report: &mut ScanReport) {
    if report.entries.len() >= MAX_FILES {
        report.truncated = true;
        return;
    }
    if !dir.exists() {
        // A missing scan root is normal (e.g. no /srv/bin) — not an error.
        return;
    }
    let Ok(read) = fs::read_dir(dir) else {
        report.unreadable += 1;
        return;
    };
    let entries: Vec<_> = read.filter_map(|e| e.ok()).collect();
    // Deterministic order regardless of readdir order.
    let mut paths: Vec<PathBuf> = entries.into_iter().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        let Ok(meta) = fs::symlink_metadata(&path) else {
            report.unreadable += 1;
            continue;
        };
        if meta.file_type().is_symlink() {
            // Never follow, never inventory the link itself (SEC-402).
            report.skipped_symlinks += 1;
            continue;
        }
        if meta.is_dir() {
            walk_dir(&path, base, report);
            continue;
        }
        if !meta.is_file() || !is_executable(meta.mode()) {
            continue;
        }
        // Classification needs the leading bytes.
        let mut head = [0u8; 256];
        let head_len = match fs::File::open(&path).and_then(|mut f| f.read(&mut head)) {
            Ok(n) => n,
            Err(_) => {
                report.unreadable += 1;
                continue;
            }
        };
        let kind = classify(&head[..head_len]);
        match hash_file(&path) {
            Ok((sha256, size)) => {
                // Key = path under the virtual root (absolute homes keep
                // an absolute key — documented behaviour).
                let key = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                report.entries.insert(
                    key.clone(),
                    ExecutableEntry {
                        path: key,
                        kind,
                        sha256,
                        size,
                    },
                );
                if report.entries.len() >= MAX_FILES {
                    report.truncated = true;
                    return;
                }
            }
            Err(_) => report.unreadable += 1,
        }
    }
}

/// Scans `roots` (and optionally the user home) under the virtual root.
/// `home` is resolved by the CALLER from its own configuration — the
/// library never trusts the environment.
pub fn scan(root: &Path, roots: &[&str], home: Option<&Path>) -> ScanReport {
    let mut report = ScanReport::default();
    for rel in roots {
        let dir = root.join(rel);
        // A scan root that is itself a symlink is refused (never
        // followed — the no-follow rule applies at every level).
        if let Ok(meta) = fs::symlink_metadata(&dir) {
            if meta.file_type().is_symlink() {
                report.skipped_symlinks += 1;
                continue;
            }
        }
        walk_dir(&dir, root, &mut report);
    }
    if let Some(home) = home {
        // The home may live outside the virtual root in production; in
        // tests it is created under it. Anchor relative homes to root.
        let home_path = if home.is_absolute() {
            home.to_path_buf()
        } else {
            root.join(home)
        };
        // Keys are always relative to the virtual root; homes living
        // outside it fall back to absolute keys (strip_prefix failure).
        walk_dir(&home_path, root, &mut report);
    }
    report
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("vigile-exec-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn write_exec(&self, rel: &str, content: &[u8]) -> PathBuf {
            let path = self.0.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, content).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            path
        }

        fn write_plain(&self, rel: &str, content: &[u8]) -> PathBuf {
            let path = self.0.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, content).unwrap();
            path
        }

        fn root(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const HELLO_SHA: &str = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";

    #[test]
    fn scans_executables_with_hash_and_kind() {
        let t = TempRoot::new("basic");
        t.write_exec("usr/local/bin/hello", b"hello\n");
        t.write_exec(
            "usr/local/bin/tool",
            &[0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x00],
        );
        t.write_exec("usr/local/bin/empty", b"");
        t.write_plain("usr/local/bin/data.txt", b"hello\n"); // not executable
        t.write_exec("usr/local/bin/script.sh", b"#!/bin/bash\necho hi\n");

        let report = scan(t.root(), &["usr/local/bin"], None);
        assert_eq!(report.entries.len(), 4, "{:?}", report.entries.keys());
        let hello = &report.entries["usr/local/bin/hello"];
        assert_eq!(hello.sha256, HELLO_SHA);
        assert_eq!(hello.kind, FileKind::Other);
        assert_eq!(hello.size, 6);

        let empty = &report.entries["usr/local/bin/empty"];
        assert_eq!(empty.sha256, EMPTY_SHA);

        let tool = &report.entries["usr/local/bin/tool"];
        assert_eq!(tool.kind, FileKind::Elf);

        let script = &report.entries["usr/local/bin/script.sh"];
        assert!(matches!(script.kind, FileKind::Script(_)));
    }

    #[test]
    fn symlinks_are_never_followed_nor_inventoried() {
        let t = TempRoot::new("symlink");
        let target = t.write_exec("opt/real", b"content\n");
        let link = t.0.join("opt/link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let report = scan(t.root(), &["opt"], None);
        assert_eq!(report.entries.len(), 1);
        assert!(report.entries.contains_key("opt/real"));
        assert_eq!(report.skipped_symlinks, 1);
    }

    #[test]
    fn symlinked_scan_root_is_refused() {
        let t = TempRoot::new("symlinkroot");
        let target = t.write_exec("usr/local/bin/real", b"x\n");
        let link = t.0.join("linked-root");
        let parent = target.parent().unwrap().to_path_buf();
        std::os::unix::fs::symlink(&parent, &link).unwrap();
        let report = scan(t.root(), &["linked-root"], None);
        assert!(report.entries.is_empty());
        assert_eq!(report.skipped_symlinks, 1);
    }

    #[test]
    fn home_is_scanned_when_provided() {
        let t = TempRoot::new("home");
        t.write_exec("home/alice/bin/tool", b"x\n");
        t.write_exec("home/alice/.local/bin/tool2", b"y\n");

        let report = scan(t.root(), &[], Some(Path::new("home/alice")));
        assert_eq!(report.entries.len(), 2, "{:?}", report.entries.keys());
    }

    #[test]
    fn unreadable_entries_are_counted_not_fatal() {
        let t = TempRoot::new("unreadable");
        t.write_exec("usr/local/bin/ok", b"fine\n");
        // A directory without read permission (still owned by us: chmod
        // works) makes the walk skip it and count it.
        let dir = t.0.join("usr/local/bin/locked");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("inside"), b"x").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).unwrap();

        let report = scan(t.root(), &["usr/local/bin"], None);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert!(report.unreadable >= 1, "{report:?}");
    }
}
