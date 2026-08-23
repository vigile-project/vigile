// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vecteurs officiels RFC 8785 (dépôt cyberphone/json-canonicalization,
//! testdata) rejoués sur la canonisation de production — relais de
//! continuité avec le spike ISS-007.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use serde_json::Value;
use vigile_policy::canonical_json;

#[test]
fn vecteurs_officiels_rfc8785() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/jcs");
    let mut count = 0usize;
    for entry in std::fs::read_dir(base.join("input")).expect("répertoire input") {
        let path = entry.expect("entrée").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path.file_name().expect("nom").to_string_lossy().to_string();
        let input: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("lecture input"))
                .expect("JSON valide");
        let expected = std::fs::read_to_string(base.join("output").join(&name))
            .expect("lecture output")
            .trim()
            .to_string();
        let got = canonical_json(&input).expect("canonisation sans erreur");
        assert_eq!(got, expected, "vecteur {name}");
        count += 1;
    }
    assert!(count >= 6, "vecteurs attendus manquants ({count})");
}
