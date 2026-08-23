// SPDX-License-Identifier: AGPL-3.0-or-later
//! Compiles a policy JSON file and writes artifacts + manifest to a
//! directory. Used by the lab VM validation (fapolicyd-cli --check-rules)
//! and as the CLI-facing reference for the compiler.

use std::path::PathBuf;
use vigile_policy::{compile, model::PolicyDocument, parse_and_validate};

fn main() {
    let mut args = std::env::args().skip(1);
    let (input, out_dir) = match (args.next(), args.next()) {
        (Some(input), Some(out_dir)) => (PathBuf::from(input), PathBuf::from(out_dir)),
        _ => {
            eprintln!("usage: compile-policy <policy.json> <output-dir>");
            std::process::exit(2);
        }
    };

    let source = std::fs::read_to_string(&input).unwrap_or_else(|e| {
        eprintln!("cannot read {}: {e}", input.display());
        std::process::exit(1);
    });
    let value = parse_and_validate(&source).unwrap_or_else(|e| {
        eprintln!("invalid policy: {e}");
        std::process::exit(1);
    });
    let document: PolicyDocument = serde_json::from_value(value).unwrap_or_else(|e| {
        eprintln!("model mismatch: {e}");
        std::process::exit(1);
    });

    let compiled = compile(&document.policy).unwrap_or_else(|e| {
        eprintln!("compilation failed: {e}");
        std::process::exit(1);
    });

    std::fs::create_dir_all(&out_dir).ok();
    for artifact in &compiled.artifacts {
        let path = out_dir.join(&artifact.name);
        std::fs::write(&path, &artifact.content).unwrap_or_else(|e| {
            eprintln!("cannot write {}: {e}", path.display());
            std::process::exit(1);
        });
        println!("artefact : {}", path.display());
    }
    let manifest = out_dir.join("manifest.json");
    std::fs::write(
        &manifest,
        serde_json::to_string_pretty(&compiled.manifest).unwrap_or_default(),
    )
    .unwrap_or_else(|e| {
        eprintln!("cannot write {}: {e}", manifest.display());
        std::process::exit(1);
    });
    println!("manifeste: {}", manifest.display());
}
