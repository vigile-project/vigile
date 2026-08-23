// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vecteurs de politiques du dépôt (`tests/vectors/` + `examples/`) contre
//! le schéma `policy/v0`. Convention de nommage :
//! - `policy-invalid-*` → doit être REJETÉ par le schéma ;
//! - `policy-valid-*` et `policy-semantic-*` → acceptés par le schéma
//!   (les `semantic` sont rejetés par le COMPILATEUR, ISS-024, pas ici).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use vigile_policy::parse_and_validate;

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../")
}

#[test]
fn vecteurs_de_politiques() {
    let root = repo_root();
    let mut cases: Vec<(String, bool)> = vec![
        ("examples/policy-workstation-firefox.v0.json".into(), true),
        ("tests/vectors/policy-valid-minimal.v0.json".into(), true),
        (
            "tests/vectors/policy-semantic-contradiction-interpreter.v0.json".into(),
            true,
        ),
    ];
    for entry in std::fs::read_dir(root.join("tests/vectors")).expect("dir vectors") {
        let p = entry.expect("entrée").path();
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        if name.starts_with("policy-invalid-") && name.ends_with(".json") {
            cases.push((format!("tests/vectors/{name}"), false));
        }
    }
    // 3 cas fixes + 4 vecteurs policy-invalid-* au 2026-08-21.
    assert!(cases.len() >= 7, "vecteurs manquants : {}", cases.len());

    for (path, expected_ok) in &cases {
        let text = std::fs::read_to_string(root.join(path)).expect("lecture vecteur");
        let res = parse_and_validate(&text);
        assert_eq!(
            res.is_ok(),
            *expected_ok,
            "{path} → {:?}",
            res.err().map(|e| e.to_string())
        );
    }
}
