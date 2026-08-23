// SPDX-License-Identifier: AGPL-3.0-or-later
//! Canonisation JSON RFC 8785 (JCS) — prérequis de la signature des
//! politiques (ADR-0004). Validée sur les vecteurs officiels du RFC par le
//! spike ISS-007 (`spikes/jcs-canonicalization`, rapport :
//! `docs/spikes/ISS-007-canonisation-jcs.md`).
//!
//! Aucune panique : les nombres non finis (impossibles en JSON, uniquement
//! constructibles programmatiquement) produisent une erreur typée.

use serde_json::Value;
use std::cmp::Ordering;

/// Erreurs de canonisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// Nombre non fini rencontré dans une `Value` construite en mémoire.
    NonFiniteNumber,
}

/// Sérialise une valeur JSON en forme canonique RFC 8785 (JCS).
pub fn canonical_json(v: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_value(v, &mut out)?;
    Ok(out)
}

fn write_value(v: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            let s = number_to_ecma(n)?;
            out.push_str(&s);
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Clés triées par unités de code UTF-16 (RFC 8785 §3.2.3) —
            // PAS par points de code : les caractères hors BMP précèdent
            // U+E000..U+FFFF en UTF-16 et le suivent en points de code.
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| cmp_utf16(a, b));
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(&map[*key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn cmp_utf16(a: &str, b: &str) -> Ordering {
    let mut ia = a.encode_utf16();
    let mut ib = b.encode_utf16();
    loop {
        match (ia.next(), ib.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => match x.cmp(&y) {
                Ordering::Equal => {}
                ord => return ord,
            },
        }
    }
}

/// Échappement RFC 8785 §3.2.2.2 : formes courtes obligatoires
/// (\b \t \n \f \r), \uXXXX minuscule pour les autres contrôles, aucun
/// échappement des caractères non ASCII.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn number_to_ecma(n: &serde_json::Number) -> Result<String, CanonicalError> {
    let f = n.as_f64().ok_or(CanonicalError::NonFiniteNumber)?;
    ecma_f64(f).ok_or(CanonicalError::NonFiniteNumber)
}

/// Sérialisation ECMAScript `Number::toString(10)` exigée par RFC 8785
/// §3.2.2.3, reconstruite depuis les chiffres les plus courts de ryu
/// (ryu ne suit pas les seuils de notation ECMAScript).
/// Retourne `None` pour un nombre non fini.
fn ecma_f64(f: f64) -> Option<String> {
    if !f.is_finite() {
        return None;
    }
    if f == 0.0 {
        return Some("0".to_string()); // couvre aussi -0.0
    }
    let neg = f.is_sign_negative();
    let mut buf = ryu::Buffer::new();
    let (digits, n) = parse_ryu(buf.format_finite(f.abs()))?;
    let k = digits.len() as i64;
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if k <= n && n <= 21 {
        out.push_str(&digits);
        for _ in 0..(n - k) {
            out.push('0');
        }
    } else if 0 < n && n <= 21 {
        out.push_str(&digits[..n as usize]);
        out.push('.');
        out.push_str(&digits[n as usize..]);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        for _ in 0..(-n) {
            out.push('0');
        }
        out.push_str(&digits);
    } else {
        out.push_str(&digits[..1]);
        if k > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let e = n - 1;
        out.push('e');
        if e >= 0 {
            out.push('+');
        } else {
            out.push('-');
        }
        out.push_str(&e.abs().to_string());
    }
    Some(out)
}

/// Décompose la sortie ryu (« 123.456 », « 1.5e300 », « 5e-324 ») en
/// (chiffres significatifs, n) tels que valeur = 0.chiffres × 10^n.
/// Robuste au choix fixed/exponentiel fait par ryu.
fn parse_ryu(s: &str) -> Option<(String, i64)> {
    let (mantissa, exp): (&str, i64) = match s.split_once(['e', 'E']) {
        Some((m, e)) => (m, e.parse::<i64>().ok()?),
        None => (s, 0),
    };
    let (int_part, frac_part) = match mantissa.split_once('.') {
        Some((i, f)) => (i, f),
        None => (mantissa, ""),
    };
    let n0 = exp + int_part.len() as i64;
    let mut all = format!("{}{}", int_part, frac_part);
    let lead = all.len() - all.trim_start_matches('0').len();
    all = all.trim_start_matches('0').to_string();
    let n = n0 - lead as i64;
    let digits = all.trim_end_matches('0').to_string();
    Some((digits, n))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;
    use serde_json::json;

    // La « précision excessive » des littéraux est le sujet même du test
    // (arrondi IEEE 754 au plus proche double).
    #[allow(clippy::excessive_precision)]
    #[test]
    fn rfc8785_exemples_nombres() {
        assert_eq!(
            ecma_f64(333333333.33333329),
            Some("333333333.3333333".into())
        );
        assert_eq!(ecma_f64(1e30), Some("1e+30".into()));
        assert_eq!(ecma_f64(4.50), Some("4.5".into()));
        assert_eq!(ecma_f64(2e-3), Some("0.002".into()));
        assert_eq!(ecma_f64(1e-27), Some("1e-27".into()));
    }

    #[test]
    fn frontieres_ecmascript() {
        assert_eq!(ecma_f64(1e21), Some("1e+21".into()));
        assert_eq!(ecma_f64(1e20), Some("100000000000000000000".into()));
        assert_eq!(ecma_f64(1e-6), Some("0.000001".into()));
        assert_eq!(ecma_f64(1e-7), Some("1e-7".into()));
        assert_eq!(ecma_f64(-0.0), Some("0".into()));
        assert_eq!(ecma_f64(5e-324), Some("5e-324".into()));
        assert_eq!(
            ecma_f64(9007199254740993.0),
            Some("9007199254740992".into())
        );
    }

    #[test]
    fn cles_triees_par_unites_utf16() {
        // U+1F600 (paire D83D DE00) précède U+FFFD en UTF-16
        // mais le suit en ordre de points de code.
        let v = json!({ "\u{FFFD}": 1, "\u{1F600}": 2 });
        assert_eq!(
            canonical_json(&v),
            Ok("{\"😀\":2,\"\u{FFFD}\":1}".to_string())
        );
    }

    #[test]
    fn echappement_formes_courtes() {
        let v = json!("a\u{08}b\u{0c}c\u{01}d\"e\\f");
        assert_eq!(
            canonical_json(&v),
            Ok("\"a\\bb\\fc\\u0001d\\\"e\\\\f\"".to_string())
        );
    }

    #[test]
    fn nombre_non_fini_rejete_sans_panique() {
        let n = serde_json::Number::from_f64(f64::NAN);
        assert!(n.is_none()); // serde_json refuse déjà de représenter NaN
    }
}
