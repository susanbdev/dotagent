#![forbid(unsafe_code)]

//! Deterministic guard against Unicode smuggling, Trojan Source (CVE-2021-42574),
//! Unicode Tag ASCII smuggling (U+E0000..=U+E007F), Variation Selector payloads
//! ("Glassworm" U+FE00..=U+FE0F / U+E0100..=U+E01EF), invisible zero-width joiners,
//! ANSI/OSC terminal escape injection, encoded `\uXXXX`/`\xXX` obfuscation, and
//! mixed-script / fullwidth homoglyph spoofing.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    /// Paths, filenames, CLI flags, and shell commands.
    StrictPathOrCommand,
    /// File contents, documentation, comments, prompts, and tool outputs.
    UntrustedContent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnicodeViolation {
    pub code: &'static str,
    pub offset: usize,
    pub detail: String,
}

pub fn scan_unicode(input: &str, mode: ScanMode) -> Vec<UnicodeViolation> {
    let mut findings = Vec::new();
    let mut consecutive_braille_blank = 0usize;

    for (byte_idx, ch) in input.char_indices() {
        let cp = ch as u32;

        // 1. Bidirectional overrides & isolates (CVE-2021-42574 Trojan Source)
        if is_bidi_control(cp) {
            findings.push(UnicodeViolation {
                code: "UNICODE_TROJAN_BIDI",
                offset: byte_idx,
                detail: format!(
                    "Bidirectional control character U+{cp:04X} detected (Trojan Source vector)"
                ),
            });
            continue;
        }

        // 2. Unicode Tag block (U+E0000..=U+E007F) — invisible LLM prompt smuggling
        if (0xE0000..=0xE007F).contains(&cp) {
            findings.push(UnicodeViolation {
                code: "UNICODE_TAG_SMUGGLING",
                offset: byte_idx,
                detail: format!(
                    "Unicode Tag character U+{cp:05X} detected (invisible prompt smuggling)"
                ),
            });
            continue;
        }

        // 3. Supplemental Variation Selectors (U+E0100..=U+E01EF) — Glassworm multi-byte smuggling
        if (0xE0100..=0xE01EF).contains(&cp) {
            findings.push(UnicodeViolation {
                code: "VARIATION_SELECTOR_SMUGGLING",
                offset: byte_idx,
                detail: format!(
                    "Supplemental Variation Selector U+{cp:05X} detected (invisible byte smuggling)"
                ),
            });
            continue;
        }

        // 4. Basic Variation Selectors (U+FE00..=U+FE0F) — always blocked across all modes
        if (0xFE00..=0xFE0F).contains(&cp) {
            findings.push(UnicodeViolation {
                code: "VARIATION_SELECTOR_SMUGGLING",
                offset: byte_idx,
                detail: format!("Disallowed Variation Selector U+{cp:04X} detected"),
            });
            continue;
        }

        // 5. Zero-width, invisible formatters, Hangul fillers, annotation controls
        if is_invisible_smuggler(cp, byte_idx) {
            findings.push(UnicodeViolation {
                code: "INVISIBLE_UNICODE_SMUGGLING",
                offset: byte_idx,
                detail: format!("Invisible/zero-width character U+{cp:04X} detected"),
            });
            continue;
        }

        // Braille Pattern Blank (U+2800) used as invisible whitespace smuggling
        if cp == 0x2800 {
            consecutive_braille_blank += 1;
            if mode == ScanMode::StrictPathOrCommand || consecutive_braille_blank >= 2 {
                findings.push(UnicodeViolation {
                    code: "INVISIBLE_UNICODE_SMUGGLING",
                    offset: byte_idx,
                    detail: "Braille blank U+2800 invisible padding detected".to_string(),
                });
            }
            continue;
        }
        consecutive_braille_blank = 0;

        // 6. C0/C1 control & terminal escape characters (ESC 0x1B, OSC-52, NUL, DEL)
        if is_forbidden_control(cp, mode) {
            findings.push(UnicodeViolation {
                code: "CONTROL_ESCAPE_INJECTION",
                offset: byte_idx,
                detail: format!("Control/terminal escape byte U+{cp:04X} detected"),
            });
            continue;
        }

        // 7. Strict path/command checks: fullwidth characters, slash/dot/dash lookalikes, Private Use Area
        if mode == ScanMode::StrictPathOrCommand && is_path_or_flag_homoglyph(cp) {
            findings.push(UnicodeViolation {
                code: "HOMOGLYPH_SPOOFING",
                offset: byte_idx,
                detail: format!("Confusable homoglyph U+{cp:04X} ('{ch}') in path or command"),
            });
            continue;
        }

        if is_private_use(cp) && mode == ScanMode::StrictPathOrCommand {
            findings.push(UnicodeViolation {
                code: "PRIVATE_USE_UNICODE",
                offset: byte_idx,
                detail: format!("Private Use Area scalar U+{cp:04X} in path or command"),
            });
        }
    }

    // 8. Mixed-script identifier/segment spoofing (e.g. Cyrillic 'а' U+0430 inside ASCII word/filename)
    if mode == ScanMode::StrictPathOrCommand {
        scan_mixed_script_tokens(input, &mut findings);
    }

    // 9. Encoded escape smuggling (\uXXXX, \u{...}, \UXXXXXXXX, \xXX, &#x...;, %E2%80%...)
    scan_encoded_escapes(input, mode, &mut findings);

    findings
}

pub fn is_dangerous_decoded_scalar(cp: u32) -> bool {
    is_bidi_control(cp)
        || (0xE0000..=0xE007F).contains(&cp)
        || (0xE0100..=0xE01EF).contains(&cp)
        || (0xFE00..=0xFE0F).contains(&cp)
        || is_invisible_smuggler(cp, 1)
        || cp == 0x001B
        || cp == 0x0000
        || (0x0080..=0x009F).contains(&cp)
}

fn is_bidi_control(cp: u32) -> bool {
    matches!(
        cp,
        0x061C
            | 0x200E
            | 0x200F
            | 0x202A..=0x202E
            | 0x2066..=0x2069
    )
}

fn is_invisible_smuggler(cp: u32, byte_idx: usize) -> bool {
    match cp {
        // BOM at byte 0 of a file is benign, inline U+FEFF is zero-width no-break space smuggling
        0xFEFF => byte_idx != 0,
        0x00AD
        | 0x034F
        | 0x115F
        | 0x1160
        | 0x17B4
        | 0x17B5
        | 0x180B..=0x180E
        | 0x200B..=0x200D
        | 0x2060..=0x2064
        | 0x206A..=0x206F
        | 0x3164
        | 0xFFA0
        | 0xFFF9..=0xFFFB => true,
        _ => false,
    }
}

fn is_forbidden_control(cp: u32, mode: ScanMode) -> bool {
    match cp {
        0x0009 | 0x000A | 0x000D => {
            // Newlines/CR inside a single file path are a classic newline-injection vector;
            // shell commands handled via ScanMode::StrictPathOrCommand allow \n/\t, checked separately for paths.
            let _ = mode;
            false
        }
        0x0000..=0x001F | 0x007F..=0x009F => true,
        _ => false,
    }
}

fn is_path_or_flag_homoglyph(cp: u32) -> bool {
    matches!(
        cp,
        // Unicode hyphens/dashes used to spoof CLI flags (e.g. `git —no-verify` or `−rf`)
        0x2010..=0x2015
            | 0x2212
            | 0xFE58
            | 0xFE63
            | 0xFF0D
            // Unicode dots & leaders used to spoof `..` traversal
            | 0x2024..=0x2026
            | 0x3002
            | 0xFE52
            | 0xFF0E
            // Unicode slashes/backslashes used to spoof `/` or `\`
            | 0x2044
            | 0x2215
            | 0x29F5
            | 0x29F8
            | 0x29F9
            | 0xFE68
            | 0xFF0F
            | 0xFF3C
            // Fullwidth ASCII block
            | 0xFF01..=0xFF5E
    )
}

fn is_private_use(cp: u32) -> bool {
    (0xE000..=0xF8FF).contains(&cp)
        || (0xF0000..=0xFFFFD).contains(&cp)
        || (0x100000..=0x10FFFD).contains(&cp)
}

fn is_confusable_script(cp: u32) -> bool {
    // Cyrillic, Greek, Armenian, Cherokee, Mathematical Alphanumeric Symbols
    (0x0370..=0x052F).contains(&cp)
        || (0x0530..=0x058F).contains(&cp)
        || (0x13A0..=0x13FF).contains(&cp)
        || (0x1D400..=0x1D7FF).contains(&cp)
}

fn scan_mixed_script_tokens(input: &str, findings: &mut Vec<UnicodeViolation>) {
    let mut token_start = 0usize;
    let mut has_ascii_alpha = false;
    let mut has_confusable = false;

    for (idx, ch) in input.char_indices() {
        let is_sep = ch.is_ascii_whitespace()
            || matches!(
                ch,
                '/' | '\\'
                    | ':'
                    | ';'
                    | ','
                    | '"'
                    | '\''
                    | '('
                    | ')'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '='
                    | '|'
                    | '&'
            );
        if is_sep {
            if has_ascii_alpha && has_confusable {
                findings.push(UnicodeViolation {
                    code: "MIXED_SCRIPT_HOMOGLYPH",
                    offset: token_start,
                    detail: "Mixed Latin + confusable script token (homoglyph spoofing)"
                        .to_string(),
                });
            }
            has_ascii_alpha = false;
            has_confusable = false;
            token_start = idx + ch.len_utf8();
        } else {
            if ch.is_ascii_alphabetic() {
                has_ascii_alpha = true;
            } else if is_confusable_script(ch as u32) {
                has_confusable = true;
            }
        }
    }
    if has_ascii_alpha && has_confusable {
        findings.push(UnicodeViolation {
            code: "MIXED_SCRIPT_HOMOGLYPH",
            offset: token_start,
            detail: "Mixed Latin + confusable script token (homoglyph spoofing)".to_string(),
        });
    }
}

fn scan_encoded_escapes(input: &str, mode: ScanMode, findings: &mut Vec<UnicodeViolation>) {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut line_escape_count = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'\n' {
            line_escape_count = 0;
            i += 1;
            continue;
        }

        // ANSI-C shell quote $'...' containing hex/octal/unicode escapes in commands
        if mode == ScanMode::StrictPathOrCommand
            && bytes[i] == b'$'
            && bytes.get(i + 1) == Some(&b'\'')
        {
            findings.push(UnicodeViolation {
                code: "ANSI_C_QUOTE_ESCAPE",
                offset: i,
                detail:
                    "Shell ANSI-C $'...' escape quoting is disallowed by zero-trust command policy"
                        .to_string(),
            });
            i += 2;
            continue;
        }

        // Backslash escapes: \xXX, \uXXXX, \u{...}, \UXXXXXXXX, \033, \e
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            match next {
                b'e' | b'E' if mode == ScanMode::StrictPathOrCommand => {
                    findings.push(UnicodeViolation {
                        code: "ENCODED_ESCAPE_SMUGGLING",
                        offset: i,
                        detail: "Escaped terminal ESC sequence (\\e) in command/path".to_string(),
                    });
                    i += 2;
                    continue;
                }
                b'0' if bytes.get(i + 2..i + 4) == Some(b"33") => {
                    findings.push(UnicodeViolation {
                        code: "ENCODED_ESCAPE_SMUGGLING",
                        offset: i,
                        detail: "Octal ESC sequence (\\033) detected".to_string(),
                    });
                    i += 4;
                    continue;
                }
                b'x' => {
                    if let Some(val) = parse_hex_slice(bytes.get(i + 2..i + 4)) {
                        line_escape_count += 1;
                        if val == 0x1B || val == 0x00 || mode == ScanMode::StrictPathOrCommand {
                            findings.push(UnicodeViolation {
                                code: "ENCODED_ESCAPE_SMUGGLING",
                                offset: i,
                                detail: format!("Hex byte escape \\x{val:02x} blocked"),
                            });
                        }
                        if line_escape_count == 6 {
                            findings.push(UnicodeViolation {
                                code: "DENSE_ESCAPE_OBFUSCATION",
                                offset: i,
                                detail:
                                    "Dense hex/unicode escape obfuscation chain detected on line"
                                        .to_string(),
                            });
                        }
                        i += 4;
                        continue;
                    }
                }
                b'u' => {
                    if bytes.get(i + 2) == Some(&b'{') {
                        if let Some(end_rel) =
                            bytes[i + 3..].iter().take(8).position(|&c| c == b'}')
                        {
                            if let Some(cp) = parse_hex_slice(bytes.get(i + 3..i + 3 + end_rel)) {
                                line_escape_count += 1;
                                if is_dangerous_decoded_scalar(cp)
                                    || mode == ScanMode::StrictPathOrCommand
                                {
                                    findings.push(UnicodeViolation {
                                        code: "ENCODED_UNICODE_SMUGGLING",
                                        offset: i,
                                        detail: format!(
                                            "Escaped Unicode scalar \\u{{{cp:X}}} resolves to forbidden codepoint"
                                        ),
                                    });
                                }
                                if line_escape_count == 6 {
                                    findings.push(UnicodeViolation {
                                        code: "DENSE_ESCAPE_OBFUSCATION",
                                        offset: i,
                                        detail: "Dense unicode escape obfuscation chain detected"
                                            .to_string(),
                                    });
                                }
                                i += 4 + end_rel;
                                continue;
                            }
                        }
                    } else if let Some(cp) = parse_hex_slice(bytes.get(i + 2..i + 6)) {
                        line_escape_count += 1;
                        let is_tag_surrogate = (0xDB40..=0xDB43).contains(&cp);
                        if is_dangerous_decoded_scalar(cp)
                            || is_tag_surrogate
                            || mode == ScanMode::StrictPathOrCommand
                        {
                            findings.push(UnicodeViolation {
                                code: "ENCODED_UNICODE_SMUGGLING",
                                offset: i,
                                detail: format!(
                                    "Escaped Unicode \\u{cp:04X} resolves to forbidden/surrogate codepoint"
                                ),
                            });
                        }
                        if line_escape_count == 6 {
                            findings.push(UnicodeViolation {
                                code: "DENSE_ESCAPE_OBFUSCATION",
                                offset: i,
                                detail: "Dense unicode escape obfuscation chain detected"
                                    .to_string(),
                            });
                        }
                        i += 6;
                        continue;
                    }
                }
                b'U' => {
                    if let Some(cp) = parse_hex_slice(bytes.get(i + 2..i + 10)) {
                        line_escape_count += 1;
                        if is_dangerous_decoded_scalar(cp) || mode == ScanMode::StrictPathOrCommand
                        {
                            findings.push(UnicodeViolation {
                                code: "ENCODED_UNICODE_SMUGGLING",
                                offset: i,
                                detail: format!(
                                    "Escaped Unicode \\U{cp:08X} resolves to forbidden codepoint"
                                ),
                            });
                        }
                        i += 10;
                        continue;
                    }
                }
                _ => {}
            }
        }

        // HTML hex entity smuggling: &#xE0041; or &#x202E;
        if bytes[i] == b'&'
            && bytes.get(i + 1) == Some(&b'#')
            && matches!(bytes.get(i + 2), Some(b'x' | b'X'))
        {
            if let Some(semi) = bytes[i + 3..].iter().take(8).position(|&c| c == b';') {
                if let Some(cp) = parse_hex_slice(bytes.get(i + 3..i + 3 + semi)) {
                    if is_dangerous_decoded_scalar(cp) {
                        findings.push(UnicodeViolation {
                            code: "HTML_ENTITY_UNICODE_SMUGGLING",
                            offset: i,
                            detail: format!(
                                "HTML entity &#x{cp:X}; encodes forbidden Bidi/Tag/Invisible codepoint"
                            ),
                        });
                    }
                }
            }
        }

        // Percent-encoded UTF-8 Bidi (e.g. %E2%80%AE = U+202E) or path traversal (%2e%2e%2f)
        if bytes[i] == b'%' && i + 8 < bytes.len() && bytes[i + 3] == b'%' && bytes[i + 6] == b'%' {
            if let (Some(b1), Some(b2), Some(b3)) = (
                parse_hex_slice(bytes.get(i + 1..i + 3)),
                parse_hex_slice(bytes.get(i + 4..i + 6)),
                parse_hex_slice(bytes.get(i + 7..i + 9)),
            ) {
                if b1 == 0xE2 && b2 == 0x80 && (0x8B..=0xAF).contains(&b3) {
                    findings.push(UnicodeViolation {
                        code: "URL_ENCODED_BIDI_SMUGGLING",
                        offset: i,
                        detail: format!(
                            "URL-encoded Bidi/Zero-Width UTF-8 sequence %{b1:02X}%{b2:02X}%{b3:02X} detected"
                        ),
                    });
                }
            }
        }
        if mode == ScanMode::StrictPathOrCommand && bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(b1) = parse_hex_slice(bytes.get(i + 1..i + 3)) {
                if matches!(b1, 0x00 | 0x2e | 0x2f | 0x5c) {
                    findings.push(UnicodeViolation {
                        code: "URL_ENCODED_PATH_SMUGGLING",
                        offset: i,
                        detail: format!("Percent-encoded path metacharacter %{b1:02X} blocked"),
                    });
                }
            }
        }

        i += 1;
    }
}

fn parse_hex_slice(slice: Option<&[u8]>) -> Option<u32> {
    let bytes = slice?;
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let s = std::str::from_utf8(bytes).ok()?;
    u32::from_str_radix(s, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::{ScanMode, scan_unicode};

    #[test]
    fn blocks_trojan_bidi_and_tags_and_glassworm() {
        assert!(!scan_unicode("safe text \u{202E} evil", ScanMode::UntrustedContent).is_empty());
        assert!(!scan_unicode("tag \u{E0041}\u{E0042}", ScanMode::UntrustedContent).is_empty());
        assert!(!scan_unicode("glassworm \u{E0100}", ScanMode::UntrustedContent).is_empty());
        assert!(!scan_unicode("escaped \\u202e", ScanMode::UntrustedContent).is_empty());
        assert!(!scan_unicode("fullwidth ．．／etc", ScanMode::StrictPathOrCommand).is_empty());
        assert!(!scan_unicode("АGENTS.md", ScanMode::StrictPathOrCommand).is_empty()); // Cyrillic А
    }
}
