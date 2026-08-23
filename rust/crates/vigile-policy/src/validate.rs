// SPDX-License-Identifier: AGPL-3.0-or-later
//! Validation des politiques contre le schéma embarqué `policy/v0`
//! (SEC-208 : rejet des champs inconnus ; SEC-603 : aucun champ ignoré
//! silencieusement). Les règles SÉMANTIQUES (contradictions, exceptions
//! bornées, fusion des listes protégées) relèvent du compilateur
//! (ISS-024), pas de cette couche.

use jsonschema::Validator;
use serde_json::Value;

/// Erreur de validation d'un document de politique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// Le texte n'est pas du JSON valide (ou contient des données après la
    /// racine).
    InvalidJson(String),
    /// Le document viole le schéma `policy/v0` ; chaque violation est
    /// décrite. Couvre aussi l'échec de chargement du schéma embarqué
    /// (corruption de binaire).
    Schema(Vec<String>),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::InvalidJson(e) => write!(f, "JSON invalide : {e}"),
            PolicyError::Schema(errors) => {
                write!(f, "schéma policy/v0 violé ({} erreur(s)) :", errors.len())?;
                for e in errors {
                    write!(f, "\n  - {e}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for PolicyError {}

/// Validateur construit à partir du schéma embarqué.
///
/// NOTE : le schéma n'utilise que des références locales (`#/$defs/…`) et
/// la crate `jsonschema` est compilée sans résolution réseau : aucune
/// référence distante ne peut être résolue, même si un document hostile en
/// contenait.
pub struct PolicyValidator {
    inner: Validator,
}

impl PolicyValidator {
    /// Construit le validateur depuis le schéma embarqué.
    pub fn new() -> Result<Self, String> {
        let schema: Value = serde_json::from_str(crate::SCHEMA_JSON)
            .map_err(|e| format!("schéma embarqué illisible : {e}"))?;
        let inner = jsonschema::validator_for(&schema)
            .map_err(|e| format!("schéma embarqué inutilisable : {e}"))?;
        Ok(Self { inner })
    }

    /// Valide un document déjà parsé. `Ok(())` = conforme au schéma.
    pub fn validate(&self, document: &Value) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for err in self.inner.iter_errors(document) {
            errors.push(format!("{err} (à « {}/ »)", err.instance_path()));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Analyse un texte JSON puis le valide contre `policy/v0`.
/// Rejette également tout contenu après la racine JSON.
pub fn parse_and_validate(json_text: &str) -> Result<Value, PolicyError> {
    let value: Value =
        serde_json::from_str(json_text).map_err(|e| PolicyError::InvalidJson(e.to_string()))?;
    let validator = PolicyValidator::new().map_err(|e| PolicyError::Schema(vec![e]))?;
    validator.validate(&value).map_err(PolicyError::Schema)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn champ_inconnu_rejete() {
        let doc = r#"{"policy":{"id":"11111111-2222-3333-4444-555555555555",
            "version":1,"schema_version":"policy/v0",
            "tenant":"00000000-0000-0000-0000-000000000001",
            "target":{"groups":["lab"]},
            "execution":{"decision":"audit-only","shell_command":"rm -rf /"},
            "validity":{"not_before":"2026-09-01T00:00:00Z","not_after":null}}}"#;
        let err = parse_and_validate(doc).expect_err("doit être rejeté");
        let PolicyError::Schema(errors) = err else {
            panic!("attendu Schema");
        };
        assert!(errors.iter().any(|e| e.contains("shell_command")));
    }

    #[test]
    fn contenu_apres_racine_rejete() {
        let doc = "{} {}";
        assert!(matches!(
            parse_and_validate(doc),
            Err(PolicyError::InvalidJson(_))
        ));
    }
}
