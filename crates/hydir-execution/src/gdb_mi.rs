//! Bounded parser for the GDB/MI records used by process capture.

use std::collections::BTreeSet;

const MAX_LINE: usize = 1024 * 1024;
const MAX_NODES: usize = 16_384;
const MAX_DEPTH: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MiValue {
    CString(Vec<u8>),
    Tuple(Vec<(String, MiValue)>),
    List(Vec<MiListEntry>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MiListEntry {
    Value(MiValue),
    Result(String, MiValue),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MiRecord {
    Prompt,
    Result {
        token: Option<u64>,
        class: String,
        fields: Vec<(String, MiValue)>,
    },
    Async {
        token: Option<u64>,
        kind: u8,
        class: String,
        fields: Vec<(String, MiValue)>,
    },
    Stream {
        kind: u8,
        bytes: Vec<u8>,
    },
}

impl MiValue {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::CString(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        std::str::from_utf8(self.as_bytes()?).ok()
    }
}

impl MiRecord {
    pub fn field(&self, name: &str) -> Option<&MiValue> {
        let fields = match self {
            Self::Result { fields, .. } | Self::Async { fields, .. } => fields,
            _ => return None,
        };
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    }
}

pub fn parse_mi_line(line: &[u8]) -> Result<MiRecord, String> {
    if line.len() > MAX_LINE {
        return Err("GDB/MI line exceeds 1 MiB".into());
    }
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line == b"(gdb)" || line == b"(gdb) " {
        return Ok(MiRecord::Prompt);
    }
    let mut parser = Parser {
        bytes: line,
        position: 0,
        nodes: 0,
    };
    let token = parser.number()?;
    let kind = parser.take().ok_or("empty GDB/MI record")?;
    let record = match kind {
        b'^' | b'*' | b'+' | b'=' => {
            let class = parser.identifier()?;
            let fields = parser.fields(0, None)?;
            if kind == b'^' {
                MiRecord::Result {
                    token,
                    class,
                    fields,
                }
            } else {
                MiRecord::Async {
                    token,
                    kind,
                    class,
                    fields,
                }
            }
        }
        b'~' | b'@' | b'&' if token.is_none() => MiRecord::Stream {
            kind,
            bytes: parser.c_string()?,
        },
        _ => return Err("unsupported GDB/MI record kind".into()),
    };
    if parser.position != parser.bytes.len() {
        return Err("trailing GDB/MI record bytes".into());
    }
    Ok(record)
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
    nodes: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn take(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.position += 1;
        Some(byte)
    }

    fn expect(&mut self, expected: u8) -> Result<(), String> {
        if self.take() == Some(expected) {
            Ok(())
        } else {
            Err(format!("expected GDB/MI byte {}", expected as char))
        }
    }

    fn node(&mut self, depth: usize) -> Result<(), String> {
        if depth > MAX_DEPTH || self.nodes >= MAX_NODES {
            return Err("GDB/MI nesting or item limit exceeded".into());
        }
        self.nodes += 1;
        Ok(())
    }

    fn number(&mut self) -> Result<Option<u64>, String> {
        let start = self.position;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.position += 1;
        }
        if self.position == start {
            return Ok(None);
        }
        let digits = std::str::from_utf8(&self.bytes[start..self.position])
            .map_err(|_| "bad GDB/MI token")?;
        Ok(Some(digits.parse().map_err(|_| "GDB/MI token overflow")?))
    }

    fn identifier(&mut self) -> Result<String, String> {
        let start = self.position;
        while self
            .peek()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            self.position += 1;
        }
        if self.position == start {
            return Err("empty GDB/MI identifier".into());
        }
        std::str::from_utf8(&self.bytes[start..self.position])
            .map(str::to_owned)
            .map_err(|_| "non-ASCII GDB/MI identifier".into())
    }

    fn c_string(&mut self) -> Result<Vec<u8>, String> {
        self.expect(b'"')?;
        let mut result = Vec::new();
        loop {
            let byte = self.take().ok_or("unterminated GDB/MI string")?;
            match byte {
                b'"' => break,
                b'\\' => {
                    let escaped = self.take().ok_or("unterminated GDB/MI escape")?;
                    match escaped {
                        b'\\' | b'"' | b'\'' | b'?' => result.push(escaped),
                        b'n' => result.push(b'\n'),
                        b'r' => result.push(b'\r'),
                        b't' => result.push(b'\t'),
                        b'a' => result.push(7),
                        b'b' => result.push(8),
                        b'f' => result.push(12),
                        b'v' => result.push(11),
                        b'x' => {
                            let first = self
                                .take()
                                .and_then(hex_digit)
                                .ok_or("bad GDB/MI hex escape")?;
                            let second = self.peek().and_then(hex_digit);
                            let value = if let Some(second) = second {
                                self.position += 1;
                                first * 16 + second
                            } else {
                                first
                            };
                            result.push(value);
                        }
                        b'0'..=b'7' => {
                            let mut value = escaped - b'0';
                            for _ in 0..2 {
                                match self.peek() {
                                    Some(next @ b'0'..=b'7') => {
                                        self.position += 1;
                                        value = value.wrapping_mul(8).wrapping_add(next - b'0');
                                    }
                                    _ => break,
                                }
                            }
                            result.push(value);
                        }
                        _ => return Err("unsupported GDB/MI string escape".into()),
                    }
                }
                b'\n' | b'\r' => return Err("raw newline inside GDB/MI string".into()),
                _ => result.push(byte),
            }
        }
        Ok(result)
    }

    fn fields(&mut self, depth: usize, end: Option<u8>) -> Result<Vec<(String, MiValue)>, String> {
        let mut fields = Vec::new();
        let mut names = BTreeSet::new();
        loop {
            if self.peek() == end {
                break;
            }
            self.expect(b',')?;
            self.node(depth)?;
            let name = self.identifier()?;
            if !names.insert(name.clone()) {
                return Err("duplicate GDB/MI result field".into());
            }
            self.expect(b'=')?;
            let value = self.value(depth + 1)?;
            fields.push((name, value));
        }
        Ok(fields)
    }

    fn value(&mut self, depth: usize) -> Result<MiValue, String> {
        self.node(depth)?;
        match self.peek() {
            Some(b'"') => Ok(MiValue::CString(self.c_string()?)),
            Some(b'{') => {
                self.position += 1;
                let fields = if self.peek() == Some(b'}') {
                    Vec::new()
                } else {
                    self.tuple_fields(depth + 1)?
                };
                self.expect(b'}')?;
                Ok(MiValue::Tuple(fields))
            }
            Some(b'[') => {
                self.position += 1;
                let mut entries = Vec::new();
                while self.peek() != Some(b']') {
                    if !entries.is_empty() {
                        self.expect(b',')?;
                    }
                    self.node(depth + 1)?;
                    let start = self.position;
                    let entry = if self
                        .peek()
                        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
                    {
                        let name = self.identifier()?;
                        if self.peek() == Some(b'=') {
                            self.position += 1;
                            MiListEntry::Result(name, self.value(depth + 1)?)
                        } else {
                            self.position = start;
                            MiListEntry::Value(self.value(depth + 1)?)
                        }
                    } else {
                        MiListEntry::Value(self.value(depth + 1)?)
                    };
                    entries.push(entry);
                    if self.peek().is_none() {
                        return Err("unterminated GDB/MI list".into());
                    }
                }
                self.position += 1;
                Ok(MiValue::List(entries))
            }
            _ => Err("unsupported GDB/MI value".into()),
        }
    }

    fn tuple_fields(&mut self, depth: usize) -> Result<Vec<(String, MiValue)>, String> {
        let mut fields = Vec::new();
        let mut names = BTreeSet::new();
        loop {
            self.node(depth)?;
            let name = self.identifier()?;
            if !names.insert(name.clone()) {
                return Err("duplicate GDB/MI tuple field".into());
            }
            self.expect(b'=')?;
            fields.push((name, self.value(depth + 1)?));
            if self.peek() != Some(b',') {
                break;
            }
            self.position += 1;
        }
        Ok(fields)
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stop_record_and_nested_frame() {
        let record = parse_mi_line(b"17*stopped,reason=\"breakpoint-hit\",thread-id=\"1\",frame={addr=\"0x401000\",func=\"main\",args=[{name=\"argc\",value=\"1\"}]}\n").unwrap();
        assert!(
            matches!(record, MiRecord::Async { token: Some(17), kind: b'*', ref class, .. } if class == "stopped")
        );
        assert_eq!(
            record.field("reason").and_then(MiValue::as_text),
            Some("breakpoint-hit")
        );
        let Some(MiValue::Tuple(frame)) = record.field("frame") else {
            panic!("missing frame")
        };
        assert!(
            frame
                .iter()
                .any(|(name, value)| name == "addr" && value.as_text() == Some("0x401000"))
        );
    }

    #[test]
    fn parses_register_result_and_console_stream() {
        let record = parse_mi_line(b"23^done,register-values=[{number=\"0\",value=\"0x1\"},{number=\"1\",value=\"0x2\"}]\r\n").unwrap();
        assert!(
            matches!(record, MiRecord::Result { token: Some(23), ref class, .. } if class == "done")
        );
        let Some(MiValue::List(values)) = record.field("register-values") else {
            panic!("missing registers")
        };
        assert_eq!(values.len(), 2);
        assert!(
            matches!(parse_mi_line(b"~\"hello\\n\\x41\\101\"\n").unwrap(), MiRecord::Stream { kind: b'~', bytes } if bytes == b"hello\nAA")
        );
        assert_eq!(parse_mi_line(b"(gdb)\n").unwrap(), MiRecord::Prompt);
    }

    #[test]
    fn rejects_truncated_and_oversized_records() {
        assert!(parse_mi_line(b"^done,frame={addr=\"0x1\"\n").is_err());
        assert!(parse_mi_line(b"~\"bad\\q\"\n").is_err());
        assert!(parse_mi_line(b"^done,reason=\"ok\",reason=\"bad\"\n").is_err());
        assert!(parse_mi_line(&vec![b'a'; MAX_LINE + 1]).is_err());
    }
}
