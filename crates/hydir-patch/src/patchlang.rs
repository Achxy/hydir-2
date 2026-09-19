use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{Atom, ReturnExpression, SourceRange};

pub const PATCH_LANG_VERSION: u32 = 1;
const MAX_PATCH_SOURCE_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchType {
    U64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PatchExpressionKind {
    Variable {
        name: String,
    },
    Constant {
        value: u64,
    },
    Add {
        left: Box<PatchExpression>,
        right: Box<PatchExpression>,
    },
    Subtract {
        left: Box<PatchExpression>,
        right: Box<PatchExpression>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PatchExpression {
    pub r#type: PatchType,
    pub source_range: SourceRange,
    pub expression: PatchExpressionKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PatchStatement {
    Declare {
        name: String,
        r#type: PatchType,
        value: PatchExpression,
        source_range: SourceRange,
    },
    Assign {
        name: String,
        value: PatchExpression,
        source_range: SourceRange,
    },
    Return {
        value: PatchExpression,
        source_range: SourceRange,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PatchProgram {
    pub schema_version: u32,
    pub statements: Vec<PatchStatement>,
    pub source_range: SourceRange,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TokenKind {
    Identifier(String),
    Number(u64),
    Plus,
    Minus,
    Equals,
    Semicolon,
    LeftParen,
    RightParen,
    End,
}

#[derive(Clone, Debug)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
}

struct SpannedExpression {
    value: PatchExpression,
    start: usize,
    end: usize,
}

struct Lexer<'a> {
    source: &'a str,
    at: usize,
}

impl<'a> Lexer<'a> {
    fn error(&self, at: usize, message: &str) -> String {
        let (line, column) = position(self.source, at);
        format!("replacement:{line}:{column}: {message}")
    }

    fn next(&mut self) -> Result<Token, String> {
        let bytes = self.source.as_bytes();
        while bytes.get(self.at).is_some_and(u8::is_ascii_whitespace) {
            self.at += 1;
        }
        let start = self.at;
        let Some(byte) = bytes.get(self.at).copied() else {
            return Ok(Token {
                kind: TokenKind::End,
                start,
                end: start,
            });
        };
        let single = match byte {
            b'+' => Some(TokenKind::Plus),
            b'-' => Some(TokenKind::Minus),
            b'=' => Some(TokenKind::Equals),
            b';' => Some(TokenKind::Semicolon),
            b'(' => Some(TokenKind::LeftParen),
            b')' => Some(TokenKind::RightParen),
            _ => None,
        };
        if let Some(kind) = single {
            self.at += 1;
            return Ok(Token {
                kind,
                start,
                end: self.at,
            });
        }
        if byte.is_ascii_alphabetic() || byte == b'_' {
            self.at += 1;
            while bytes
                .get(self.at)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                self.at += 1;
            }
            return Ok(Token {
                kind: TokenKind::Identifier(self.source[start..self.at].to_owned()),
                start,
                end: self.at,
            });
        }
        if byte.is_ascii_digit() {
            self.at += 1;
            while bytes
                .get(self.at)
                .is_some_and(|byte| byte.is_ascii_hexdigit() || *byte == b'x' || *byte == b'X')
            {
                self.at += 1;
            }
            let token = &self.source[start..self.at];
            let value = if let Some(hex) = token
                .strip_prefix("0x")
                .or_else(|| token.strip_prefix("0X"))
            {
                if hex.is_empty() {
                    return Err(self.error(start, "hexadecimal literal has no digits"));
                }
                u64::from_str_radix(hex, 16)
            } else {
                token.parse::<u64>()
            }
            .map_err(|_| self.error(start, "expected an exact u64 literal"))?;
            return Ok(Token {
                kind: TokenKind::Number(value),
                start,
                end: self.at,
            });
        }
        Err(self.error(start, "unsupported PatchLang token"))
    }
}

struct Parser<'a> {
    source: &'a str,
    lexer: Lexer<'a>,
    current: Token,
    variables: BTreeMap<String, PatchType>,
    returned: bool,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Result<Self, String> {
        let mut lexer = Lexer { source, at: 0 };
        let current = lexer.next()?;
        Ok(Self {
            source,
            lexer,
            current,
            variables: BTreeMap::from([
                ("arg0".to_owned(), PatchType::U64),
                ("arg1".to_owned(), PatchType::U64),
            ]),
            returned: false,
        })
    }

    fn error_at(&self, at: usize, message: &str) -> String {
        let (line, column) = position(self.source, at);
        format!("replacement:{line}:{column}: {message}")
    }

    fn advance(&mut self) -> Result<Token, String> {
        let next = self.lexer.next()?;
        Ok(std::mem::replace(&mut self.current, next))
    }

    fn expect_punctuation(&mut self, expected: TokenKind, message: &str) -> Result<Token, String> {
        if std::mem::discriminant(&self.current.kind) != std::mem::discriminant(&expected) {
            return Err(self.error_at(self.current.start, message));
        }
        self.advance()
    }

    fn expression(&mut self) -> Result<SpannedExpression, String> {
        let mut expression = self.primary()?;
        loop {
            let subtract = match self.current.kind {
                TokenKind::Plus => false,
                TokenKind::Minus => true,
                _ => break,
            };
            self.advance()?;
            let right = self.primary()?;
            expression = SpannedExpression {
                start: expression.start,
                end: right.end,
                value: PatchExpression {
                    r#type: PatchType::U64,
                    source_range: range(self.source, expression.start, right.end),
                    expression: if subtract {
                        PatchExpressionKind::Subtract {
                            left: Box::new(expression.value),
                            right: Box::new(right.value),
                        }
                    } else {
                        PatchExpressionKind::Add {
                            left: Box::new(expression.value),
                            right: Box::new(right.value),
                        }
                    },
                },
            };
        }
        Ok(expression)
    }

    fn primary(&mut self) -> Result<SpannedExpression, String> {
        let token = self.advance()?;
        match token.kind {
            TokenKind::Identifier(name) => {
                let r#type = self.variables.get(&name).copied().ok_or_else(|| {
                    self.error_at(token.start, &format!("undefined variable `{name}`"))
                })?;
                Ok(SpannedExpression {
                    start: token.start,
                    end: token.end,
                    value: PatchExpression {
                        r#type,
                        source_range: range(self.source, token.start, token.end),
                        expression: PatchExpressionKind::Variable { name },
                    },
                })
            }
            TokenKind::Number(value) => Ok(SpannedExpression {
                start: token.start,
                end: token.end,
                value: PatchExpression {
                    r#type: PatchType::U64,
                    source_range: range(self.source, token.start, token.end),
                    expression: PatchExpressionKind::Constant { value },
                },
            }),
            TokenKind::LeftParen => {
                let mut expression = self.expression()?;
                let right = self.expect_punctuation(
                    TokenKind::RightParen,
                    "expected `)` after PatchLang expression",
                )?;
                expression.start = token.start;
                expression.end = right.end;
                expression.value.source_range = range(self.source, token.start, right.end);
                Ok(expression)
            }
            _ => Err(self.error_at(
                token.start,
                "expected a variable, u64 literal, or parenthesized expression",
            )),
        }
    }

    fn statement(&mut self) -> Result<PatchStatement, String> {
        if self.returned {
            return Err(self.error_at(
                self.current.start,
                "statements after `return` are unreachable",
            ));
        }
        let start = self.current.start;
        let first = self.advance()?;
        let TokenKind::Identifier(keyword_or_name) = first.kind else {
            return Err(self.error_at(first.start, "expected PatchLang statement"));
        };
        if keyword_or_name == "return" {
            let value = self.expression()?.value;
            let end = self
                .expect_punctuation(TokenKind::Semicolon, "expected `;` after return")?
                .end;
            self.returned = true;
            return Ok(PatchStatement::Return {
                value,
                source_range: range(self.source, start, end),
            });
        }
        if keyword_or_name == "u64" {
            let name_token = self.advance()?;
            let TokenKind::Identifier(name) = name_token.kind else {
                return Err(self.error_at(name_token.start, "expected variable name after `u64`"));
            };
            if self.variables.contains_key(&name) {
                return Err(
                    self.error_at(name_token.start, &format!("duplicate variable `{name}`"))
                );
            }
            self.expect_punctuation(TokenKind::Equals, "expected `=` in declaration")?;
            let value = self.expression()?.value;
            let end = self
                .expect_punctuation(TokenKind::Semicolon, "expected `;` after declaration")?
                .end;
            self.variables.insert(name.clone(), PatchType::U64);
            return Ok(PatchStatement::Declare {
                name,
                r#type: PatchType::U64,
                value,
                source_range: range(self.source, start, end),
            });
        }
        if !self.variables.contains_key(&keyword_or_name) {
            return Err(self.error_at(
                first.start,
                &format!("assignment to undefined variable `{keyword_or_name}`"),
            ));
        }
        if matches!(keyword_or_name.as_str(), "arg0" | "arg1") {
            return Err(self.error_at(first.start, "function inputs are immutable"));
        }
        self.expect_punctuation(TokenKind::Equals, "expected `=` in assignment")?;
        let value = self.expression()?.value;
        let end = self
            .expect_punctuation(TokenKind::Semicolon, "expected `;` after assignment")?
            .end;
        Ok(PatchStatement::Assign {
            name: keyword_or_name,
            value,
            source_range: range(self.source, start, end),
        })
    }

    fn program(mut self) -> Result<PatchProgram, String> {
        let mut statements = Vec::new();
        while self.current.kind != TokenKind::End {
            statements.push(self.statement()?);
        }
        if !self.returned {
            return Err(self.error_at(self.source.len(), "PatchLang program requires `return`"));
        }
        Ok(PatchProgram {
            schema_version: PATCH_LANG_VERSION,
            statements,
            source_range: range(self.source, 0, self.source.len()),
        })
    }
}

fn position(source: &str, offset: usize) -> (u32, u32) {
    let before = &source.as_bytes()[..offset.min(source.len())];
    let line = before.iter().filter(|byte| **byte == b'\n').count() as u32 + 1;
    let column = before
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(before.len() as u32 + 1, |index| {
            (before.len() - index) as u32
        });
    (line, column)
}

fn range(source: &str, start: usize, end: usize) -> SourceRange {
    let (start_line, start_column) = position(source, start);
    let (end_line, end_column) = position(source, end);
    SourceRange {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

pub fn parse_patch_program(source: &str) -> Result<PatchProgram, String> {
    if source.is_empty() || source.len() > MAX_PATCH_SOURCE_BYTES || !source.is_ascii() {
        return Err(format!(
            "replacement must be 1..={MAX_PATCH_SOURCE_BYTES} ASCII bytes"
        ));
    }
    Parser::new(source)?.program()
}

fn resolve_expression(
    expression: &PatchExpression,
    values: &BTreeMap<String, PatchExpression>,
) -> Result<PatchExpression, String> {
    let resolved = match &expression.expression {
        PatchExpressionKind::Variable { name } if matches!(name.as_str(), "arg0" | "arg1") => {
            return Ok(expression.clone());
        }
        PatchExpressionKind::Variable { name } => values
            .get(name)
            .cloned()
            .ok_or_else(|| format!("PatchIR variable `{name}` has no reaching definition"))?,
        PatchExpressionKind::Constant { .. } => return Ok(expression.clone()),
        PatchExpressionKind::Add { left, right } => PatchExpression {
            r#type: PatchType::U64,
            source_range: expression.source_range.clone(),
            expression: PatchExpressionKind::Add {
                left: Box::new(resolve_expression(left, values)?),
                right: Box::new(resolve_expression(right, values)?),
            },
        },
        PatchExpressionKind::Subtract { left, right } => PatchExpression {
            r#type: PatchType::U64,
            source_range: expression.source_range.clone(),
            expression: PatchExpressionKind::Subtract {
                left: Box::new(resolve_expression(left, values)?),
                right: Box::new(resolve_expression(right, values)?),
            },
        },
    };
    Ok(resolved)
}

fn atom(expression: &PatchExpression) -> Option<Atom> {
    match &expression.expression {
        PatchExpressionKind::Variable { name } if name == "arg0" => Some(Atom::Arg0),
        PatchExpressionKind::Variable { name } if name == "arg1" => Some(Atom::Arg1),
        PatchExpressionKind::Constant { value } => Some(Atom::Constant(*value)),
        _ => None,
    }
}

pub fn lower_scalar_return(program: &PatchProgram) -> Result<ReturnExpression, String> {
    let mut values = BTreeMap::new();
    for statement in &program.statements {
        match statement {
            PatchStatement::Declare { name, value, .. }
            | PatchStatement::Assign { name, value, .. } => {
                let value = resolve_expression(value, &values)?;
                values.insert(name.clone(), value);
            }
            PatchStatement::Return { value, .. } => {
                let value = resolve_expression(value, &values)?;
                if let Some(value) = atom(&value) {
                    return Ok(ReturnExpression::Atom(value));
                }
                return match &value.expression {
                    PatchExpressionKind::Add { left, right } => atom(left)
                        .zip(atom(right))
                        .map(|(left, right)| ReturnExpression::Add(left, right))
                        .ok_or_else(|| {
                            "PatchLang program is valid, but the scalar backend cannot lower nested addition"
                                .to_owned()
                        }),
                    PatchExpressionKind::Subtract { left, right } => atom(left)
                        .zip(atom(right))
                        .map(|(left, right)| ReturnExpression::Sub(left, right))
                        .ok_or_else(|| {
                            "PatchLang program is valid, but the scalar backend cannot lower nested subtraction"
                                .to_owned()
                        }),
                    PatchExpressionKind::Variable { .. }
                    | PatchExpressionKind::Constant { .. } => Err(
                        "PatchLang program is valid, but the scalar backend has no lowering"
                            .to_owned(),
                    ),
                };
            }
        }
    }
    Err("PatchIR has no return terminator".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declarations_assignments_and_ranges_lower_to_scalar_adapter() {
        let source = "u64 result = arg0;\nresult = result - arg1;\nreturn result;";
        let program = parse_patch_program(source).unwrap();
        assert_eq!(program.statements.len(), 3);
        assert_eq!(program.source_range.end_line, 3);
        assert_eq!(
            lower_scalar_return(&program).unwrap(),
            ReturnExpression::Sub(Atom::Arg0, Atom::Arg1)
        );
    }

    #[test]
    fn valid_nested_expression_has_precise_range_and_explicit_lowering_refusal() {
        let source = "u64 sum = (arg0 + arg1);\nreturn sum - arg1;";
        let program = parse_patch_program(source).unwrap();
        let PatchStatement::Declare { value, .. } = &program.statements[0] else {
            panic!("expected declaration");
        };
        assert_eq!(value.source_range.start_column, 11);
        assert_eq!(value.source_range.end_column, 24);
        assert!(
            lower_scalar_return(&program)
                .unwrap_err()
                .contains("nested subtraction")
        );
    }

    #[test]
    fn rejects_undefined_duplicate_immutable_and_unreachable_statements() {
        assert!(
            parse_patch_program("return missing;")
                .unwrap_err()
                .contains("undefined")
        );
        assert!(
            parse_patch_program("u64 arg0 = 1; return arg0;")
                .unwrap_err()
                .contains("duplicate")
        );
        assert!(
            parse_patch_program("arg0 = 1; return arg0;")
                .unwrap_err()
                .contains("immutable")
        );
        assert!(
            parse_patch_program("return arg0; u64 x = 1;")
                .unwrap_err()
                .contains("unreachable")
        );
    }
}
