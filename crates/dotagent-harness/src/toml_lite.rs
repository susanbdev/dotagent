//! Minimal, deterministic, zero-dependency TOML subset parser for declarative
//! `dotagent-harness` scenario files.
//!
//! Supports:
//! - `#` line and trailing comments
//! - `[[scenario]]`, `[[scenario.setup_files]]`, `[[scenario.steps]]`, and `[scenario.env]`
//! - Basic strings `"..."` (with `\"`, `\\`, `\n`, `\r`, `\t`, `\uXXXX`, `\UXXXXXXXX`)
//! - Multiline basic strings `"""..."""` and literal strings `'...'`
//! - Signed integers, booleans (`true`/`false`), arrays of strings/inline-tables, and inline tables `{ k = v }`

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum TomlValue {
    Str(String),
    Int(i64),
    Bool(bool),
    Array(Vec<TomlValue>),
    Table(BTreeMap<String, TomlValue>),
}

impl TomlValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[TomlValue]> {
        match self {
            Self::Array(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    pub fn as_table(&self) -> Option<&BTreeMap<String, TomlValue>> {
        match self {
            Self::Table(map) => Some(map),
            _ => None,
        }
    }
}

pub type TomlTable = BTreeMap<String, TomlValue>;

pub fn parse_toml_document(input: &str) -> Result<TomlTable, String> {
    let mut parser = Parser::new(input);
    parser.parse_document()
}

struct Parser<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
    line: usize,
}

#[derive(Debug, Clone)]
enum SectionTarget {
    Root,
    ScenarioItem,
    ScenarioSubTable(String),
    ScenarioSubArray(String),
}

impl<'a> Parser<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            bytes: src.as_bytes(),
            pos: 0,
            line: 1,
        }
    }

    fn parse_document(&mut self) -> Result<TomlTable, String> {
        let mut root = TomlTable::new();
        let mut target = SectionTarget::Root;

        loop {
            self.skip_ws_and_comments();
            if self.pos >= self.bytes.len() {
                break;
            }

            if self.peek_two() == Some((b'[', b'[')) {
                self.advance(2);
                let header = self.read_until_double_close()?;
                target = self.open_array_table(&mut root, header.trim())?;
                self.skip_line_remainder()?;
                continue;
            }

            if self.peek() == Some(b'[') {
                self.advance(1);
                let header = self.read_until_single_close()?;
                target = self.open_sub_table(&mut root, header.trim())?;
                self.skip_line_remainder()?;
                continue;
            }

            let key = self.parse_key()?;
            self.skip_inline_ws();
            if self.peek() != Some(b'=') {
                return Err(format!(
                    "line {}: expected '=' after key '{key}'",
                    self.line
                ));
            }
            self.advance(1);
            self.skip_inline_ws();
            let val = self.parse_value()?;
            self.insert_kv(&mut root, &target, key, val)?;
            self.skip_line_remainder()?;
        }

        Ok(root)
    }

    fn open_array_table(
        &self,
        root: &mut TomlTable,
        header: &str,
    ) -> Result<SectionTarget, String> {
        if header == "scenario" {
            let arr = root
                .entry("scenario".to_string())
                .or_insert_with(|| TomlValue::Array(Vec::new()));
            let TomlValue::Array(items) = arr else {
                return Err(format!("line {}: 'scenario' is not an array", self.line));
            };
            items.push(TomlValue::Table(TomlTable::new()));
            return Ok(SectionTarget::ScenarioItem);
        }
        if let Some(sub) = header.strip_prefix("scenario.") {
            let scen = current_scenario_mut(root, self.line)?;
            let arr = scen
                .entry(sub.to_string())
                .or_insert_with(|| TomlValue::Array(Vec::new()));
            let TomlValue::Array(items) = arr else {
                return Err(format!(
                    "line {}: 'scenario.{sub}' is not an array",
                    self.line
                ));
            };
            items.push(TomlValue::Table(TomlTable::new()));
            return Ok(SectionTarget::ScenarioSubArray(sub.to_string()));
        }
        Err(format!(
            "line {}: unsupported [[{header}]] header (expected [[scenario]] or [[scenario.<field>]])",
            self.line
        ))
    }

    fn open_sub_table(&self, root: &mut TomlTable, header: &str) -> Result<SectionTarget, String> {
        if let Some(sub) = header.strip_prefix("scenario.") {
            let scen = current_scenario_mut(root, self.line)?;
            scen.entry(sub.to_string())
                .or_insert_with(|| TomlValue::Table(TomlTable::new()));
            return Ok(SectionTarget::ScenarioSubTable(sub.to_string()));
        }
        Err(format!(
            "line {}: unsupported [{header}] table header (expected [scenario.<field>])",
            self.line
        ))
    }

    fn insert_kv(
        &self,
        root: &mut TomlTable,
        target: &SectionTarget,
        key: String,
        val: TomlValue,
    ) -> Result<(), String> {
        let table = match target {
            SectionTarget::Root => root,
            SectionTarget::ScenarioItem => current_scenario_mut(root, self.line)?,
            SectionTarget::ScenarioSubTable(sub) => {
                let scen = current_scenario_mut(root, self.line)?;
                let Some(TomlValue::Table(tbl)) = scen.get_mut(sub) else {
                    return Err(format!(
                        "line {}: missing subtable 'scenario.{sub}'",
                        self.line
                    ));
                };
                tbl
            }
            SectionTarget::ScenarioSubArray(sub) => {
                let scen = current_scenario_mut(root, self.line)?;
                let Some(TomlValue::Array(items)) = scen.get_mut(sub) else {
                    return Err(format!(
                        "line {}: missing array 'scenario.{sub}'",
                        self.line
                    ));
                };
                let Some(TomlValue::Table(tbl)) = items.last_mut() else {
                    return Err(format!(
                        "line {}: empty array-of-tables 'scenario.{sub}'",
                        self.line
                    ));
                };
                tbl
            }
        };
        if table.insert(key.clone(), val).is_some() {
            return Err(format!("line {}: duplicate key '{key}'", self.line));
        }
        Ok(())
    }

    fn parse_key(&mut self) -> Result<String, String> {
        self.skip_inline_ws();
        if self.peek() == Some(b'"') {
            return self.parse_basic_string();
        }
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
                self.advance(1);
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(format!("line {}: expected key", self.line));
        }
        Ok(self.src[start..self.pos].to_string())
    }

    fn parse_value(&mut self) -> Result<TomlValue, String> {
        self.skip_inline_ws();
        match self.peek() {
            Some(b'"') => {
                if self.starts_with(b"\"\"\"") {
                    self.parse_multiline_basic_string().map(TomlValue::Str)
                } else {
                    self.parse_basic_string().map(TomlValue::Str)
                }
            }
            Some(b'\'') => self.parse_literal_string().map(TomlValue::Str),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_inline_table(),
            Some(b't') if self.starts_with(b"true") => {
                self.advance(4);
                Ok(TomlValue::Bool(true))
            }
            Some(b'f') if self.starts_with(b"false") => {
                self.advance(5);
                Ok(TomlValue::Bool(false))
            }
            Some(b'-' | b'+' | b'0'..=b'9') => self.parse_integer(),
            _ => Err(format!("line {}: unexpected token in value", self.line)),
        }
    }

    fn parse_basic_string(&mut self) -> Result<String, String> {
        self.advance(1); // opening "
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == b'"' {
                self.advance(1);
                return Ok(out);
            }
            if b == b'\n' {
                return Err(format!("line {}: unterminated string literal", self.line));
            }
            if b == b'\\' {
                self.advance(1);
                let ch = self.parse_escape()?;
                out.push(ch);
            } else {
                let ch = self.next_utf8_char()?;
                out.push(ch);
            }
        }
        Err(format!("line {}: EOF inside string literal", self.line))
    }

    fn parse_multiline_basic_string(&mut self) -> Result<String, String> {
        self.advance(3); // opening """
        if self.peek() == Some(b'\n') {
            self.advance(1);
        } else if self.peek_two() == Some((b'\r', b'\n')) {
            self.advance(2);
        }
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            if self.starts_with(b"\"\"\"") {
                self.advance(3);
                return Ok(out);
            }
            if self.bytes[self.pos] == b'\\' {
                self.advance(1);
                if matches!(self.peek(), Some(b'\n' | b'\r' | b' ' | b'\t')) {
                    while let Some(ws) = self.peek() {
                        if matches!(ws, b' ' | b'\t' | b'\n' | b'\r') {
                            self.advance(1);
                        } else {
                            break;
                        }
                    }
                    continue;
                }
                let ch = self.parse_escape()?;
                out.push(ch);
            } else {
                let ch = self.next_utf8_char()?;
                out.push(ch);
            }
        }
        Err(format!("line {}: EOF inside multiline string", self.line))
    }

    fn parse_literal_string(&mut self) -> Result<String, String> {
        self.advance(1); // opening '
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b == b'\'' {
                let s = self.src[start..self.pos].to_string();
                self.advance(1);
                return Ok(s);
            }
            if b == b'\n' {
                return Err(format!("line {}: unterminated literal string", self.line));
            }
            let _ = self.next_utf8_char()?;
        }
        Err(format!("line {}: EOF inside literal string", self.line))
    }

    fn parse_escape(&mut self) -> Result<char, String> {
        let Some(esc) = self.peek() else {
            return Err(format!("line {}: trailing backslash", self.line));
        };
        self.advance(1);
        match esc {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => self.parse_hex_scalar(4),
            b'U' => self.parse_hex_scalar(8),
            other => Err(format!(
                "line {}: unsupported escape '\\{}'",
                self.line, other as char
            )),
        }
    }

    fn parse_hex_scalar(&mut self, digits: usize) -> Result<char, String> {
        if self.pos + digits > self.bytes.len() {
            return Err(format!("line {}: truncated unicode escape", self.line));
        }
        let hex = &self.src[self.pos..self.pos + digits];
        self.advance(digits);
        let cp = u32::from_str_radix(hex, 16)
            .map_err(|_| format!("line {}: invalid hex escape '{hex}'", self.line))?;
        char::from_u32(cp)
            .ok_or_else(|| format!("line {}: invalid unicode scalar U+{cp:04X}", self.line))
    }

    fn parse_integer(&mut self) -> Result<TomlValue, String> {
        let start = self.pos;
        if matches!(self.peek(), Some(b'-' | b'+')) {
            self.advance(1);
        }
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() || b == b'_' {
                self.advance(1);
            } else {
                break;
            }
        }
        let cleaned = self.src[start..self.pos].replace('_', "");
        let val = cleaned
            .parse::<i64>()
            .map_err(|_| format!("line {}: invalid integer '{cleaned}'", self.line))?;
        Ok(TomlValue::Int(val))
    }

    fn parse_array(&mut self) -> Result<TomlValue, String> {
        self.advance(1); // [
        let mut items = Vec::new();
        loop {
            self.skip_ws_and_comments();
            if self.peek() == Some(b']') {
                self.advance(1);
                return Ok(TomlValue::Array(items));
            }
            items.push(self.parse_value()?);
            self.skip_ws_and_comments();
            match self.peek() {
                Some(b',') => self.advance(1),
                Some(b']') => {
                    self.advance(1);
                    return Ok(TomlValue::Array(items));
                }
                _ => {
                    return Err(format!("line {}: expected ',' or ']' in array", self.line));
                }
            }
        }
    }

    fn parse_inline_table(&mut self) -> Result<TomlValue, String> {
        self.advance(1); // {
        let mut map = TomlTable::new();
        loop {
            self.skip_inline_ws();
            if self.peek() == Some(b'}') {
                self.advance(1);
                return Ok(TomlValue::Table(map));
            }
            let key = self.parse_key()?;
            self.skip_inline_ws();
            if self.peek() != Some(b'=') {
                return Err(format!(
                    "line {}: expected '=' inside inline table",
                    self.line
                ));
            }
            self.advance(1);
            self.skip_inline_ws();
            let val = self.parse_value()?;
            if map.insert(key.clone(), val).is_some() {
                return Err(format!(
                    "line {}: duplicate inline table key '{key}'",
                    self.line
                ));
            }
            self.skip_inline_ws();
            match self.peek() {
                Some(b',') => self.advance(1),
                Some(b'}') => {
                    self.advance(1);
                    return Ok(TomlValue::Table(map));
                }
                _ => {
                    return Err(format!(
                        "line {}: expected ',' or '}}' in inline table",
                        self.line
                    ));
                }
            }
        }
    }

    fn read_until_double_close(&mut self) -> Result<String, String> {
        let start = self.pos;
        while self.pos < self.bytes.len() {
            if self.peek_two() == Some((b']', b']')) {
                let s = self.src[start..self.pos].to_string();
                self.advance(2);
                return Ok(s);
            }
            if self.peek() == Some(b'\n') {
                break;
            }
            self.advance(1);
        }
        Err(format!("line {}: unterminated [[...]] header", self.line))
    }

    fn read_until_single_close(&mut self) -> Result<String, String> {
        let start = self.pos;
        while self.pos < self.bytes.len() {
            if self.peek() == Some(b']') {
                let s = self.src[start..self.pos].to_string();
                self.advance(1);
                return Ok(s);
            }
            if self.peek() == Some(b'\n') {
                break;
            }
            self.advance(1);
        }
        Err(format!("line {}: unterminated [...] header", self.line))
    }

    fn skip_line_remainder(&mut self) -> Result<(), String> {
        self.skip_inline_ws();
        if self.peek() == Some(b'#') {
            while let Some(b) = self.peek() {
                if b == b'\n' {
                    break;
                }
                let _ = self.next_utf8_char()?;
            }
        }
        if let Some(b) = self.peek() {
            if b == b'\n' {
                self.advance(1);
            } else if b == b'\r' {
                self.advance(1);
                if self.peek() == Some(b'\n') {
                    self.advance(1);
                }
            } else {
                return Err(format!(
                    "line {}: unexpected trailing characters after statement",
                    self.line
                ));
            }
        }
        Ok(())
    }

    fn skip_ws_and_comments(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\r' | b'\n' => self.advance(1),
                b'#' => {
                    while self.pos < self.bytes.len() && self.bytes[self.pos] != b'\n' {
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
    }

    fn skip_inline_ws(&mut self) {
        while let Some(b' ' | b'\t') = self.peek() {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn peek_two(&self) -> Option<(u8, u8)> {
        Some((*self.bytes.get(self.pos)?, *self.bytes.get(self.pos + 1)?))
    }

    fn starts_with(&self, prefix: &[u8]) -> bool {
        self.bytes
            .get(self.pos..self.pos + prefix.len())
            .is_some_and(|slice| slice == prefix)
    }

    fn advance(&mut self, count: usize) {
        for &b in &self.bytes[self.pos..(self.pos + count).min(self.bytes.len())] {
            if b == b'\n' {
                self.line += 1;
            }
        }
        self.pos = (self.pos + count).min(self.bytes.len());
    }

    fn next_utf8_char(&mut self) -> Result<char, String> {
        let tail = &self.src[self.pos..];
        let ch = tail
            .chars()
            .next()
            .ok_or_else(|| format!("line {}: unexpected EOF", self.line))?;
        if ch == '\n' {
            self.line += 1;
        }
        self.pos += ch.len_utf8();
        Ok(ch)
    }
}

fn current_scenario_mut(root: &mut TomlTable, line: usize) -> Result<&mut TomlTable, String> {
    let Some(TomlValue::Array(items)) = root.get_mut("scenario") else {
        return Err(format!(
            "line {line}: section appeared before any [[scenario]] header"
        ));
    };
    let Some(TomlValue::Table(tbl)) = items.last_mut() else {
        return Err(format!("line {line}: empty [[scenario]] list"));
    };
    Ok(tbl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scenarios_and_unicode_escapes() {
        let raw = r#"
# Scenario test
[[scenario]]
id = "demo"
harness = "claude"
setup_files = [
  { path = "a.txt", content = "line1\nline2\u00e9" },
]

[scenario.env]
AGENT_GUARD_WRAP_BASH_ASCII = "1"

[[scenario.steps]]
kind = "pre_tool"
tool_name = "Read"
file_path = "a.txt"
expect_exit = 2
expect_output_ascii_7bit = true
"#;
        let doc = parse_toml_document(raw).expect("parse toml");
        let scenarios = doc.get("scenario").and_then(TomlValue::as_array).unwrap();
        assert_eq!(scenarios.len(), 1);
        let scen = scenarios[0].as_table().unwrap();
        assert_eq!(scen.get("id").and_then(TomlValue::as_str), Some("demo"));
        let files = scen
            .get("setup_files")
            .and_then(TomlValue::as_array)
            .unwrap();
        let f0 = files[0].as_table().unwrap();
        assert_eq!(
            f0.get("content").and_then(TomlValue::as_str),
            Some("line1\nline2\u{00e9}")
        );
        let steps = scen.get("steps").and_then(TomlValue::as_array).unwrap();
        assert_eq!(steps.len(), 1);
    }
}
