// SPDX-License-Identifier: AGPL-3.0-or-later
//! Spike ISS-007 — canonisation JSON conforme RFC 8785 (JCS).
//!
//! Code de validation jetable (sprint 1). Si les vecteurs officiels du RFC
//! passent, la logique sera reportée dans `vigile-policy` après revue et
//! check-list d'adoption des dépendances (serde_json, ryu).

use serde_json::Value;
use std::cmp::Ordering;

/// Sérialise une valeur JSON en forme canonique RFC 8785 (JCS).
///
/// Panique uniquement sur un nombre non fini, impossible en JSON et
/// constructible seulement programmatiquement.
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_value(v, &mut out);
    out
}

fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&number_to_ecma(n)),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Les clés sont triées par unités de code UTF-16 (RFC 8785 §3.2.3),
            // PAS par ordre de points de code : les différences portent sur
            // les caractères hors BMP face à U+E000..U+FFFF.
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| cmp_utf16(a, b));
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(&map[*key], out);
            }
            out.push('}');
        }
    }
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

/// Échappement des chaînes (RFC 8785 §3.2.2.2) : formes courtes
/// obligatoires pour \b \t \n \f \r, \uXXXX en minuscules pour les autres
/// contrôles, aucun échappement des caractères non ASCII.
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

fn number_to_ecma(n: &serde_json::Number) -> String {
    let f = n.as_f64().expect("nombre JSON toujours convertible en f64");
    ecma_f64(f)
}

/// Sérialisation ECMAScript `Number::toString(10)` exigée par RFC 8785
/// §3.2.2.3, reconstruite depuis les chiffres les plus courts de ryu.
fn ecma_f64(f: f64) -> String {
    if !f.is_finite() {
        panic!("nombre non fini impossible en JSON canonique");
    }
    if f == 0.0 {
        return "0".to_string(); // couvre aussi -0.0
    }
    let neg = f.is_sign_negative();
    let mut buf = ryu::Buffer::new();
    let (digits, n) = parse_ryu(buf.format_finite(f.abs()));
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
    out
}

/// Décompose la sortie ryu (« 123.456 », « 1.5e300 », « 5e-324 ») en
/// (chiffres significatifs, n) tels que valeur = 0.chiffres × 10^n.
/// Robuste au choix fixed/exponentiel fait par ryu.
fn parse_ryu(s: &str) -> (String, i64) {
    let (mantissa, exp): (&str, i64) = match s.split_once(['e', 'E']) {
        Some((m, e)) => (m, e.parse::<i64>().expect("exposant ryu valide")),
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
    (digits, n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // La « précision excessive » des littéraux est le sujet même du test
    // (arrondi IEEE 754 au plus proche double).
    #[allow(clippy::excessive_precision)]
    #[test]
    fn rfc8785_exemples_nombres() {
        assert_eq!(ecma_f64(333333333.33333329), "333333333.3333333");
        assert_eq!(ecma_f64(1e30), "1e+30");
        assert_eq!(ecma_f64(4.50), "4.5");
        assert_eq!(ecma_f64(2e-3), "0.002");
        assert_eq!(ecma_f64(1e-27), "1e-27");
    }

    #[test]
    fn frontieres_ecmascript() {
        assert_eq!(ecma_f64(1e21), "1e+21");
        assert_eq!(ecma_f64(1e20), "100000000000000000000");
        assert_eq!(ecma_f64(1e-6), "0.000001");
        assert_eq!(ecma_f64(1e-7), "1e-7");
        assert_eq!(ecma_f64(-0.0), "0");
        assert_eq!(ecma_f64(5e-324), "5e-324");
        assert_eq!(ecma_f64(9007199254740993.0), "9007199254740992");
    }

    #[test]
    fn cles_triees_par_unites_utf16() {
        // U+1F600 (paire D83D DE00) précède U+FFFD en UTF-16
        // mais le suit en ordre de points de code.
        let v = json!({ "\u{FFFD}": 1, "\u{1F600}": 2 });
        assert_eq!(canonical_json(&v), "{\"😀\":2,\"\u{FFFD}\":1}");
    }

    #[test]
    fn echappement_formes_courtes() {
        let v = json!("a\u{08}b\u{0c}c\u{01}d\"e\\f");
        assert_eq!(canonical_json(&v), "\"a\\bb\\fc\\u0001d\\\"e\\\\f\"");
    }
}
