// SPDX-License-Identifier: AGPL-3.0-or-later
//! Executable detection (ISS-020): ELF magic, shebang parsing and
//! interpreter classification — the input layer for allowlisting
//! decisions on scripts and indirect executions (TM-021). Pure parsers,
//! hostile-input safe (truncations, CRLF, no newline, junk).

/// How a file announces its executable nature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileKind {
    Elf,
    Script(Shebang),
    /// Not executable by magic/first line (data, text without shebang…).
    Other,
}

/// A parsed `#!interpreter [argument]` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shebang {
    /// Interpreter path exactly as written (not resolved).
    pub interpreter: String,
    /// Single optional argument after the path (Linux passes the rest as
    /// ONE argument).
    pub argument: Option<String>,
}

/// ELF magic: 0x7f 'E' 'L' 'F'.
pub fn is_elf(header: &[u8]) -> bool {
    header.len() >= 4 && header[..4] == [0x7f, b'E', b'L', b'F']
}

/// Parses a shebang from the first line bytes (typically the first
/// 256–1024 bytes of the file). Returns `None` for anything that is not
/// a valid `#!` line.
pub fn parse_shebang(first_line: &[u8]) -> Option<Shebang> {
    if first_line.len() < 2 || &first_line[..2] != b"#!" {
        return None;
    }
    let rest = &first_line[2..];
    let line_end = rest.iter().position(|b| *b == b'\n').unwrap_or(rest.len());
    let mut line = &rest[..line_end];
    // Tolerate CRLF.
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    let text = std::str::from_utf8(line).ok()?;
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    // Interpreter path, then at most one argument.
    let mut parts = text.splitn(2, char::is_whitespace);
    let interpreter = parts.next()?;
    if interpreter.is_empty() {
        return None;
    }
    let argument = parts
        .next()
        .map(|a| a.trim())
        .filter(|a| !a.is_empty())
        .map(str::to_string);
    Some(Shebang {
        interpreter: interpreter.to_string(),
        argument,
    })
}

/// Classifies a file from its leading bytes.
pub fn classify(header: &[u8]) -> FileKind {
    if is_elf(header) {
        return FileKind::Elf;
    }
    // Find the first line within the buffer.
    let line_end = header
        .iter()
        .position(|b| *b == b'\n')
        .unwrap_or(header.len());
    if let Some(shebang) = parse_shebang(&header[..line_end]) {
        return FileKind::Script(shebang);
    }
    FileKind::Other
}

/// Interpreter families Vigile reasons about (allow/deny semantics for
/// indirect execution — POLICY_MODEL §2 `execution.interpreters`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Interpreter {
    Sh,
    Bash,
    Python,
    Perl,
    Ruby,
    Node,
    Php,
    /// Starts with `#!/usr/bin/env` — resolved interpreter unknown here.
    Env,
    Other,
}

/// Maps an interpreter path to its family. Only canonical paths are
/// recognized; anything unknown is `Other` (and stays subject to
/// policy, never silently trusted).
pub fn interpreter_family(interpreter: &str) -> Interpreter {
    let base = interpreter.rsplit('/').next().unwrap_or(interpreter);
    // `env` indirection: /usr/bin/env python3 — caller must treat the
    // FIRST argument as the resolved interpreter.
    if base == "env" {
        return Interpreter::Env;
    }
    match base {
        "sh" | "dash" | "ash" => Interpreter::Sh,
        "bash" => Interpreter::Bash,
        "python" | "python3" | "python2" => Interpreter::Python,
        "perl" => Interpreter::Perl,
        "ruby" => Interpreter::Ruby,
        "node" | "nodejs" => Interpreter::Node,
        "php" => Interpreter::Php,
        _ => Interpreter::Other,
    }
}

/// For `#!/usr/bin/env X …` shebangs, resolves the family from the
/// argument; plain shebangs resolve directly.
pub fn effective_interpreter(shebang: &Shebang) -> Interpreter {
    match interpreter_family(&shebang.interpreter) {
        Interpreter::Env => match &shebang.argument {
            Some(arg) => {
                // Skip env flags (`-S`, `-u`…): the interpreter is the
                // first argument that is not an option.
                let first = arg
                    .split_whitespace()
                    .find(|word| !word.starts_with('-'))
                    .unwrap_or("");
                interpreter_family(first)
            }
            None => Interpreter::Other,
        },
        family => family,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn elf_magic() {
        assert!(is_elf(&[0x7f, b'E', b'L', b'F', 0x02, 0x01]));
        assert!(is_elf(&[0x7f, b'E', b'L', b'F']));
        assert!(!is_elf(&[0x7f, b'E', b'L']));
        assert!(!is_elf(&[0x7f, b'E', b'L', b'G']));
        assert!(!is_elf(b""));
    }

    #[test]
    fn shebang_plain_and_with_argument() {
        let sb = parse_shebang(b"#!/bin/sh\nrest ignored").unwrap();
        assert_eq!(sb.interpreter, "/bin/sh");
        assert_eq!(sb.argument, None);

        let sb = parse_shebang(b"#!/usr/bin/python3 -Eu\n").unwrap();
        assert_eq!(sb.interpreter, "/usr/bin/python3");
        assert_eq!(sb.argument.as_deref(), Some("-Eu"));
    }

    #[test]
    fn shebang_hostile_inputs() {
        assert_eq!(parse_shebang(b""), None);
        assert_eq!(parse_shebang(b"#"), None);
        assert_eq!(parse_shebang(b"#!\n"), None); // empty interpreter
        assert_eq!(parse_shebang(b"#!   \n"), None);
        assert_eq!(parse_shebang(b"/bin/sh\n"), None); // no #!
                                                       // Truncated: "#!/bin/sh" without newline still parses.
        let sb = parse_shebang(b"#!/bin/sh").unwrap();
        assert_eq!(sb.interpreter, "/bin/sh");
        // Non-UTF8 body after #!.
        assert_eq!(parse_shebang(b"#!\xff\xfe\n"), None);
    }

    #[test]
    fn shebang_crlf() {
        let sb = parse_shebang(b"#!/usr/bin/env python\r\n").unwrap();
        assert_eq!(sb.interpreter, "/usr/bin/env");
        assert_eq!(sb.argument.as_deref(), Some("python"));
    }

    #[test]
    fn classify_mixes() {
        assert_eq!(classify(&[0x7f, b'E', b'L', b'F', 0x02]), FileKind::Elf);
        let sb = classify(b"#!/usr/bin/perl\nprint 1;\n");
        assert!(matches!(sb, FileKind::Script(_)));
        assert_eq!(classify(b"hello world\n"), FileKind::Other);
        assert_eq!(classify(b""), FileKind::Other);
    }

    #[test]
    fn interpreter_families_including_env() {
        let mk = |line: &str| parse_shebang(line.as_bytes()).unwrap();
        assert_eq!(
            effective_interpreter(&mk("#!/bin/bash\n")),
            Interpreter::Bash
        );
        assert_eq!(effective_interpreter(&mk("#!/bin/dash\n")), Interpreter::Sh);
        assert_eq!(
            effective_interpreter(&mk("#!/usr/bin/env python3\n")),
            Interpreter::Python
        );
        assert_eq!(
            effective_interpreter(&mk("#!/usr/bin/env -S python3 -u\n")),
            Interpreter::Python
        );
        assert_eq!(
            effective_interpreter(&mk("#!/usr/bin/env\n")),
            Interpreter::Other
        );
        assert_eq!(
            effective_interpreter(&mk("#!/opt/weird/runtime\n")),
            Interpreter::Other
        );
    }
}
