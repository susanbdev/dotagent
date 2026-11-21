#![forbid(unsafe_code)]

//! Strict RFC 8259 + RFC 7493 (I-JSON) parser and serializer with:
//! - Recursion-depth cap (`MAX_JSON_DEPTH = 32`)
//! - Duplicate object-key rejection (closing first-wins vs last-wins parser differentials)
//! - Exact 64-bit signed/unsigned integer preservation (`Int(i64)` / `Uint(u64)`) so integers
//!   above `2^53` never round silently through `f64`
//! - Strict RFC 8259 number grammar (rejecting leading zeros `01`, trailing dots `1.`, and `NaN`/`Inf`)
//! - Full UTF-16 surrogate-pair decoding so JSON-escaped Unicode Tag surrogate pairs
//!   (`DB40..DC41`) or Bidi (`U+202E`) payloads cannot evade inspection.

use std::fmt::Write as _;

const MAX_JSON_DEPTH: usize = 32;
/// Exact `2^64` in `f64` (`18446744073709551616.0`); values must be strictly `<` this bound
/// when converting `f64` to `u64` to avoid `u64::MAX` saturation rounding.
const TWO_POW_64_F64: f64 = 18_446_744_073_709_551_616.0;
const TWO_POW_63_F64: f64 = 9_223_372_036_854_775_808.0;

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Number(f64),
    Str(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut parser = Parser {
            bytes: input.as_bytes(),
            pos: 0,
        };
        let val = parser.parse_value(0)?;
        parser.skip_ws();
        if parser.pos != parser.bytes.len() {
            return Err(format!("trailing bytes in JSON at offset {}", parser.pos));
        }
        Ok(val)
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(entries) => {
                entries.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v)
            }
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            JsonValue::Uint(u) => Some(*u),
            JsonValue::Int(i) if *i >= 0 => Some(*i as u64),
            JsonValue::Number(n)
                if n.is_finite() && *n >= 0.0 && n.fract() == 0.0 && *n < TWO_POW_64_F64 =>
            {
                Some(*n as u64)
            }
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            JsonValue::Int(i) => Some(*i),
            JsonValue::Uint(u) => i64::try_from(*u).ok(),
            JsonValue::Number(n)
                if n.is_finite()
                    && n.fract() == 0.0
                    && *n >= (i64::MIN as f64)
                    && *n < TWO_POW_63_F64 =>
            {
                Some(*n as i64)
            }
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonValue::Number(n) if n.is_finite() => Some(*n),
            JsonValue::Int(i) => Some(*i as f64),
            JsonValue::Uint(u) => Some(*u as f64),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            JsonValue::Array(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, JsonValue)]> {
        match self {
            JsonValue::Object(entries) => Some(entries.as_slice()),
            _ => None,
        }
    }

    pub fn to_json_string(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out);
        out
    }

    fn write_json(&self, out: &mut String) {
        match self {
            JsonValue::Null => out.push_str("null"),
            JsonValue::Bool(true) => out.push_str("true"),
            JsonValue::Bool(false) => out.push_str("false"),
            JsonValue::Int(i) => {
                let _ = write!(out, "{i}");
            }
            JsonValue::Uint(u) => {
                let _ = write!(out, "{u}");
            }
            JsonValue::Number(n) => {
                if n.is_finite() {
                    if n.fract() == 0.0 && *n >= (i64::MIN as f64) && *n < TWO_POW_63_F64 {
                        let _ = write!(out, "{}", *n as i64);
                    } else {
                        let _ = write!(out, "{n}");
                    }
                } else {
                    out.push_str("null");
                }
            }
            JsonValue::Str(s) => write_escaped_str(out, s),
            JsonValue::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_json(out);
                }
                out.push(']');
            }
            JsonValue::Object(entries) => {
                out.push('{');
                for (i, (k, v)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_escaped_str(out, k);
                    out.push(':');
                    v.write_json(out);
                }
                out.push('}');
            }
        }
    }
}

pub fn write_escaped_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, String> {
        if depth > MAX_JSON_DEPTH {
            return Err("JSON nesting depth exceeded security limit".to_string());
        }
        self.skip_ws();
        let b = self
            .peek()
            .ok_or_else(|| "unexpected end of JSON input".to_string())?;
        match b {
            b'n' => self.parse_literal(b"null", JsonValue::Null),
            b't' => self.parse_literal(b"true", JsonValue::Bool(true)),
            b'f' => self.parse_literal(b"false", JsonValue::Bool(false)),
            b'"' => self.parse_string().map(JsonValue::Str),
            b'[' => self.parse_array(depth + 1),
            b'{' => self.parse_object(depth + 1),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(format!("unexpected byte 0x{b:02x} at offset {}", self.pos)),
        }
    }

    fn parse_literal(&mut self, lit: &[u8], val: JsonValue) -> Result<JsonValue, String> {
        if self.bytes.get(self.pos..self.pos + lit.len()) == Some(lit) {
            self.pos += lit.len();
            Ok(val)
        } else {
            Err(format!("invalid JSON literal at offset {}", self.pos))
        }
    }

    fn parse_number(&mut self) -> Result<JsonValue, String> {
        let start = self.pos;
        let negative = if self.peek() == Some(b'-') {
            self.pos += 1;
            true
        } else {
            false
        };

        // RFC 8259 Section 6: integer part must be either a single '0' or '1'..'9' followed by digits.
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(format!(
                        "leading zero in JSON number forbidden (RFC 8259) at offset {start}"
                    ));
                }
            }
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => {
                return Err(format!(
                    "expected digit in JSON number at offset {}",
                    self.pos
                ));
            }
        }

        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            let frac_start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == frac_start {
                return Err(format!(
                    "expected digit after decimal point in JSON number at offset {start}"
                ));
            }
        }

        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            let exp_start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == exp_start {
                return Err(format!("expected digit in JSON exponent at offset {start}"));
            }
        }

        let slice = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "invalid UTF-8 in number".to_string())?;

        if !is_float && slice != "-0" {
            if negative {
                if let Ok(i) = slice.parse::<i64>() {
                    return Ok(JsonValue::Int(i));
                }
            } else if let Ok(u) = slice.parse::<u64>() {
                return Ok(JsonValue::Uint(u));
            }
        }

        let num: f64 = slice
            .parse()
            .map_err(|_| format!("invalid JSON number '{slice}'"))?;
        if !num.is_finite() {
            return Err(format!("non-finite JSON number '{slice}' rejected"));
        }
        Ok(JsonValue::Number(num))
    }

    fn parse_hex4(&mut self) -> Result<u16, String> {
        if self.pos + 4 > self.bytes.len() {
            return Err("truncated \\uXXXX escape in JSON".to_string());
        }
        let hex_str = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
            .map_err(|_| "non-ASCII in \\uXXXX escape".to_string())?;
        let val =
            u16::from_str_radix(hex_str, 16).map_err(|_| format!("invalid hex in \\u{hex_str}"))?;
        self.pos += 4;
        Ok(val)
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.peek() != Some(b'"') {
            return Err("expected '\"' starting JSON string".to_string());
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if b == b'\\' {
                self.pos += 1;
                let esc = self
                    .peek()
                    .ok_or_else(|| "unterminated escape in JSON string".to_string())?;
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\x08'),
                    b'f' => out.push('\x0c'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let first = self.parse_hex4()?;
                        if (0xD800..=0xDBFF).contains(&first) {
                            if self.bytes.get(self.pos..self.pos + 2) != Some(b"\\u") {
                                return Err("unpaired UTF-16 high surrogate in JSON".to_string());
                            }
                            self.pos += 2;
                            let second = self.parse_hex4()?;
                            if !(0xDC00..=0xDFFF).contains(&second) {
                                return Err("invalid UTF-16 low surrogate in JSON".to_string());
                            }
                            let combined = 0x10000
                                + (((first as u32 - 0xD800) << 10) | (second as u32 - 0xDC00));
                            let ch = char::from_u32(combined)
                                .ok_or_else(|| "invalid surrogate scalar".to_string())?;
                            out.push(ch);
                        } else if (0xDC00..=0xDFFF).contains(&first) {
                            return Err("unpaired UTF-16 low surrogate in JSON".to_string());
                        } else {
                            let ch = char::from_u32(first as u32)
                                .ok_or_else(|| "invalid Unicode scalar".to_string())?;
                            out.push(ch);
                        }
                    }
                    _ => return Err(format!("invalid JSON string escape '\\{}'", esc as char)),
                }
            } else if b < 0x20 {
                return Err("unescaped control character in JSON string".to_string());
            } else {
                // Decode next UTF-8 character starting at self.pos
                let tail = std::str::from_utf8(&self.bytes[self.pos..])
                    .map_err(|_| "invalid UTF-8 in JSON string".to_string())?;
                let ch = tail
                    .chars()
                    .next()
                    .ok_or_else(|| "empty UTF-8 slice".to_string())?;
                out.push(ch);
                self.pos += ch.len_utf8();
            }
        }
        Err("unterminated JSON string".to_string())
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, String> {
        self.pos += 1; // '['
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            items.push(self.parse_value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => return Err(format!("expected ',' or ']' at offset {}", self.pos)),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, String> {
        self.pos += 1; // '{'
        self.skip_ws();
        let mut entries: Vec<(String, JsonValue)> = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(entries));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            if !is_unique_object_key(&entries, &key) {
                return Err(format!(
                    "duplicate JSON object key '{key}' rejected (RFC 7493 I-JSON anti-differential)"
                ));
            }
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected ':' after key at offset {}", self.pos));
            }
            self.pos += 1;
            let val = self.parse_value(depth)?;
            entries.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(entries));
                }
                _ => return Err(format!("expected ',' or '}}' at offset {}", self.pos)),
            }
        }
    }
}

/// Pure RFC 7493 duplicate-key check used by `Parser::parse_object` and Kani formal proofs.
pub fn is_unique_object_key(entries: &[(String, JsonValue)], candidate_key: &str) -> bool {
    !entries
        .iter()
        .any(|(existing, _)| existing == candidate_key)
}

/// Zero-heap-allocation RFC 7493 duplicate-key predicate for bounded Kani verification.
pub fn is_unique_str_key(existing: &[&str], candidate_key: &str) -> bool {
    let mut i = 0usize;
    while i < existing.len() {
        if existing[i] == candidate_key {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::JsonValue;

    #[test]
    fn decodes_surrogate_pair_unicode_tag() {
        let raw = concat!("{\"payload\":\"\\", "udb40\\", "udc41\"}");
        let v = JsonValue::parse(raw).expect("valid JSON");
        let s = v.get("payload").and_then(JsonValue::as_str).expect("str");
        assert_eq!(s.chars().next(), char::from_u32(0xE0041));
    }

    #[test]
    fn rejects_duplicate_object_keys_and_malformed_numbers() {
        let dup = r#"{"tool_input":{"command":"rm -rf /"},"tool_input":{"command":"echo ok"}}"#;
        let err = JsonValue::parse(dup).expect_err("duplicate keys must be rejected");
        assert!(err.contains("duplicate JSON object key"));

        for bad_num in ["01", "-01", "1.", "1.e2", "1e", "1e+", "-"] {
            assert!(
                JsonValue::parse(bad_num).is_err(),
                "must reject non-RFC8259 number '{bad_num}'"
            );
        }
    }

    #[test]
    fn preserves_exact_64_bit_integers_beyond_f64_mantissa() {
        let raw = format!(
            r#"{{"u_max":{},"i_min":{},"above_53":{}}}"#,
            u64::MAX,
            i64::MIN,
            9_007_199_254_740_993u64
        );
        let parsed = JsonValue::parse(&raw).expect("parse exact 64-bit ints");
        assert_eq!(
            parsed.get("u_max").and_then(JsonValue::as_u64),
            Some(u64::MAX)
        );
        assert_eq!(
            parsed.get("i_min").and_then(JsonValue::as_i64),
            Some(i64::MIN)
        );
        assert_eq!(
            parsed.get("above_53").and_then(JsonValue::as_u64),
            Some(9_007_199_254_740_993u64)
        );
        let roundtrip = JsonValue::parse(&parsed.to_json_string()).expect("roundtrip");
        assert_eq!(roundtrip, parsed);
    }
}
