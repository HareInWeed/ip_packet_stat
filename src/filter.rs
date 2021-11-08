use crate::record::Record;
use crate::utils::{str_to_trans_protocol, AppProtocol};
use anyhow::Result;
use chrono::prelude::*;
use packet::ip::Protocol;
use std::{net::Ipv4Addr, str::FromStr};

#[derive(Debug, PartialEq, Clone)]
enum Literal {
    Time(DateTime<Local>),
    Ipv4(Ipv4Addr),
    Port(u16),
    Len(u16),
    TransProtocol(Protocol),
    AppProtocol(AppProtocol),
}

#[derive(Debug, PartialEq, Clone)]
enum Field {
    Time,
    SrcIp,
    SrcPort,
    DestIp,
    DestPort,
    Len,
    IpPayloadLen,
    TransProto,
    TransPayloadLen,
    AppProto,
}

#[derive(Debug, PartialEq, Clone)]
enum Operation {
    Eq(Field, Literal),
    Ne(Field, Literal),
    Gt(Field, Literal),
    Ge(Field, Literal),
    Lt(Field, Literal),
    Le(Field, Literal),
}

#[derive(Debug, PartialEq, Clone)]
enum Pred {
    FieldPred(Operation),
    Not(Box<Pred>),
    And(Box<Pred>, Box<Pred>),
    Or(Box<Pred>, Box<Pred>),
}

fn filter_trans_proto_eq(a: &Protocol, b: &Protocol) -> bool {
    a == b || matches!(a, &Protocol::Unknown(_)) && matches!(b, &Protocol::Unknown(_))
}
fn filter_app_proto_eq(a: &AppProtocol, b: &AppProtocol) -> bool {
    a == b
}

fn record_filter(pred: &Pred, record: &Record) -> bool {
    match pred {
        Pred::FieldPred(f) => match f {
            Operation::Eq(f, l) => match (f, l) {
                (Field::Time, Literal::Time(l)) => &record.time == l,
                (Field::SrcIp, Literal::Ipv4(l)) => record.src_ip.as_ref() == Some(l),
                (Field::SrcPort, Literal::Port(l)) => record.src_port.as_ref() == Some(l),
                (Field::DestIp, Literal::Ipv4(l)) => record.dest_ip.as_ref() == Some(l),
                (Field::DestPort, Literal::Port(l)) => record.dest_port.as_ref() == Some(l),
                (Field::Len, Literal::Len(l)) => &record.len == l,
                (Field::IpPayloadLen, Literal::Len(l)) => record.ip_payload_len.as_ref() == Some(l),
                (Field::TransProto, Literal::TransProtocol(l)) => {
                    filter_trans_proto_eq(&record.trans_proto, l)
                }
                (Field::TransPayloadLen, Literal::Len(l)) => {
                    record.trans_payload_len.as_ref() == Some(l)
                }
                (Field::AppProto, Literal::AppProtocol(l)) => {
                    filter_app_proto_eq(&record.app_proto, l)
                }
                _ => unreachable!(),
            },
            Operation::Ne(f, l) => match (f, l) {
                (Field::Time, Literal::Time(l)) => &record.time != l,
                (Field::SrcIp, Literal::Ipv4(l)) => record.src_ip.as_ref() != Some(l),
                (Field::SrcPort, Literal::Port(l)) => record.src_port.as_ref() != Some(l),
                (Field::DestIp, Literal::Ipv4(l)) => record.dest_ip.as_ref() != Some(l),
                (Field::DestPort, Literal::Port(l)) => record.dest_port.as_ref() != Some(l),
                (Field::Len, Literal::Len(l)) => &record.len != l,
                (Field::IpPayloadLen, Literal::Len(l)) => record.ip_payload_len.as_ref() != Some(l),
                (Field::TransProto, Literal::TransProtocol(l)) => {
                    !filter_trans_proto_eq(&record.trans_proto, l)
                }
                (Field::TransPayloadLen, Literal::Len(l)) => {
                    record.trans_payload_len.as_ref() != Some(l)
                }
                (Field::AppProto, Literal::AppProtocol(l)) => {
                    !filter_app_proto_eq(&record.app_proto, l)
                }
                _ => unreachable!(),
            },
            Operation::Gt(f, l) => match (f, l) {
                (Field::Time, Literal::Time(l)) => &record.time > l,
                (Field::SrcPort, Literal::Port(l)) => record.src_port.as_ref() > Some(l),
                (Field::DestPort, Literal::Port(l)) => record.dest_port.as_ref() > Some(l),
                (Field::Len, Literal::Len(l)) => &record.len > l,
                (Field::IpPayloadLen, Literal::Len(l)) => record.ip_payload_len.as_ref() > Some(l),
                (Field::TransPayloadLen, Literal::Len(l)) => {
                    record.trans_payload_len.as_ref() > Some(l)
                }
                _ => unreachable!(),
            },
            Operation::Ge(f, l) => match (f, l) {
                (Field::Time, Literal::Time(l)) => &record.time >= l,
                (Field::SrcPort, Literal::Port(l)) => record.src_port.as_ref() >= Some(l),
                (Field::DestPort, Literal::Port(l)) => record.dest_port.as_ref() >= Some(l),
                (Field::Len, Literal::Len(l)) => &record.len >= l,
                (Field::IpPayloadLen, Literal::Len(l)) => record.ip_payload_len.as_ref() >= Some(l),
                (Field::TransPayloadLen, Literal::Len(l)) => {
                    record.trans_payload_len.as_ref() >= Some(l)
                }
                _ => unreachable!(),
            },
            Operation::Lt(f, l) => match (f, l) {
                (Field::Time, Literal::Time(l)) => &record.time < l,
                (Field::SrcPort, Literal::Port(l)) => record.src_port.as_ref() < Some(l),
                (Field::DestPort, Literal::Port(l)) => record.dest_port.as_ref() < Some(l),
                (Field::Len, Literal::Len(l)) => &record.len < l,
                (Field::IpPayloadLen, Literal::Len(l)) => record.ip_payload_len.as_ref() < Some(l),
                (Field::TransPayloadLen, Literal::Len(l)) => {
                    record.trans_payload_len.as_ref() < Some(l)
                }
                _ => unreachable!(),
            },
            Operation::Le(f, l) => match (f, l) {
                (Field::Time, Literal::Time(l)) => &record.time <= l,
                (Field::SrcPort, Literal::Port(l)) => record.src_port.as_ref() <= Some(l),
                (Field::DestPort, Literal::Port(l)) => record.dest_port.as_ref() <= Some(l),
                (Field::Len, Literal::Len(l)) => &record.len <= l,
                (Field::IpPayloadLen, Literal::Len(l)) => record.ip_payload_len.as_ref() <= Some(l),
                (Field::TransPayloadLen, Literal::Len(l)) => {
                    record.trans_payload_len.as_ref() <= Some(l)
                }
                _ => unreachable!(),
            },
        },
        Pred::Not(p) => !record_filter(p, record),
        Pred::And(l, r) => record_filter(l, record) && record_filter(r, record),
        Pred::Or(l, r) => record_filter(l, record) | record_filter(r, record),
    }
}

fn pred_to_filter(pred: Pred) -> impl Fn(&Record) -> bool {
    Box::new(move |r: &Record| -> bool { record_filter(&pred, r) })
}

use nom::{
    self,
    branch::alt,
    bytes::complete::tag,
    character::complete::{char, multispace0},
    combinator::{complete, opt, recognize},
    error::{ErrorKind, ParseError},
    multi::{many0, many1},
    sequence::{delimited, preceded, tuple},
    Err::Error as NomErr,
    IResult,
};

use nom_unicode::complete::{alpha1, digit1};

#[derive(Debug, PartialEq)]
pub enum FilterError<'a, I> {
    InvalidLiteral(&'a str),
    InvalidField(&'a str),
    InvalidOperator(&'a str),
    UnsupportedOperator(&'a str, &'a str),
    Failed,
    Nom(I, ErrorKind),
}

impl<'a, I> ParseError<I> for FilterError<'a, I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        FilterError::Nom(input, kind)
    }

    fn append(_: I, _: ErrorKind, other: Self) -> Self {
        other
    }
}

type IRes<'a, I, O> = IResult<I, O, FilterError<'a, I>>;

pub fn create_filter<'a>(
    input: &'a str,
) -> Result<impl Fn(&Record) -> bool, FilterError<'a, &'a str>> {
    match parse_pred(input) {
        Ok((_, pred)) => Ok(pred_to_filter(pred)),
        Err(NomErr(err)) => Err(err),
        _ => Err(FilterError::Failed),
    }
}

fn parse_pred(input: &str) -> IRes<&str, Pred> {
    let (input, pred) = parse_or(input)?;
    if input.is_empty() {
        Ok((input, pred))
    } else {
        Err(NomErr(FilterError::Failed))
    }
}

fn parse_parens(input: &str) -> IRes<&str, Pred> {
    delimited(char('('), parse_or, char(')'))(input)
}

fn parse_or(input: &str) -> IRes<&str, Pred> {
    let (input, and) = parse_and(input)?;
    let (input, ands) = many0(preceded(tag("||"), parse_and))(input)?;
    Ok((
        input,
        ands.into_iter()
            .rev()
            .fold(and, |pred, and| Pred::Or(Box::new(and), Box::new(pred))),
    ))
}

fn parse_and(input: &str) -> IRes<&str, Pred> {
    let (input, and) = parse_term(input)?;
    let (input, ands) = many0(preceded(tag("&&"), parse_term))(input)?;
    Ok((
        input,
        ands.into_iter()
            .rev()
            .fold(and, |pred, and| Pred::And(Box::new(and), Box::new(pred))),
    ))
}

fn parse_not(input: &str) -> IRes<&str, Pred> {
    let (input, (_, _, pred)) = delimited(
        multispace0,
        tuple((tag("!"), multispace0, parse_parens)),
        multispace0,
    )(input)?;
    Ok((input, Pred::Not(Box::new(pred))))
}

fn parse_term(input: &str) -> IRes<&str, Pred> {
    delimited(
        multispace0,
        alt((parse_parens, parse_not, parse_operation)),
        multispace0,
    )(input)
}

fn parse_operator(input: &str) -> IRes<&str, &str> {
    let res: IRes<&str, &str> = alt((
        tag("=="),
        tag("!="),
        tag(">="),
        tag(">"),
        tag("<="),
        tag("<"),
    ))(input);
    if res.is_err() {
        Err(NomErr(FilterError::InvalidOperator(input)))
    } else {
        res
    }
}

fn parse_field_str(input: &str) -> IRes<&str, &str> {
    recognize(tuple((
        alt((tag("_"), alpha1)),
        many0(alt((tag("_"), alpha1, digit1))),
    )))(input)
}

fn parse_field(input: &str) -> IRes<&str, (&str, Field)> {
    let (input, field) = parse_field_str(input)?;
    match field {
        "time" | "时间" => Ok((input, (field, Field::Time))),
        "src_ip" | "源IP" => Ok((input, (field, Field::SrcIp))),
        "src_port" | "源端口" => Ok((input, (field, Field::SrcPort))),
        "dest_ip" | "目的IP" => Ok((input, (field, Field::DestIp))),
        "dest_port" | "目的端口" => Ok((input, (field, Field::DestPort))),
        "len" | "IP分组长度" => Ok((input, (field, Field::Len))),
        "ip_payload_len" | "IP数据长度" => Ok((input, (field, Field::IpPayloadLen))),
        "trans_proto" | "trans_protocol" | "传输层协议" => {
            Ok((input, (field, Field::TransProto)))
        }
        "trans_payload_len" | "报文段数据长度" => {
            Ok((input, (field, Field::TransPayloadLen)))
        }
        "app_proto" | "app_protocol" | "应用层协议" => Ok((input, (field, Field::AppProto))),
        _ => Err(NomErr(FilterError::InvalidField(field))),
    }
}

fn parse_time(input: &str) -> IRes<&str, &str> {
    recognize(tuple((
        digit1,
        char('-'),
        digit1,
        char('-'),
        digit1,
        opt(tuple((
            char(' '),
            digit1,
            char(':'),
            digit1,
            char(':'),
            digit1,
            opt(tuple((char('.'), digit1))),
        ))),
    )))(input)
}

fn parse_literal(input: &str) -> IRes<&str, &str> {
    recognize(alt((
        parse_time,
        recognize(many1(alt((tag("."), alpha1, digit1)))),
    )))(input)
}

fn parse_operation(input: &str) -> IRes<&str, Pred> {
    let (input, (field, f)) = parse_field(input)?;
    let (input, (_, operator, _, literal)) =
        tuple((multispace0, parse_operator, multispace0, parse_literal))(input)?;
    match f {
        Field::Time => {
            if let Ok(l) = NaiveDateTime::parse_from_str(literal, "%Y-%m-%d %H:%M:%S") {
                let l = Literal::Time(Local.from_local_datetime(&l).unwrap());
                match operator {
                    "==" => Ok((input, Pred::FieldPred(Operation::Eq(f, l)))),
                    "!=" => Ok((input, Pred::FieldPred(Operation::Ne(f, l)))),
                    ">" => Ok((input, Pred::FieldPred(Operation::Gt(f, l)))),
                    ">=" => Ok((input, Pred::FieldPred(Operation::Ge(f, l)))),
                    "<" => Ok((input, Pred::FieldPred(Operation::Lt(f, l)))),
                    "<=" => Ok((input, Pred::FieldPred(Operation::Le(f, l)))),
                    _ => Err(NomErr(FilterError::UnsupportedOperator(field, operator))),
                }
            } else {
                Err(NomErr(FilterError::InvalidLiteral(literal)))
            }
        }
        Field::SrcIp => {
            if let Ok(l) = Ipv4Addr::from_str(literal) {
                let l = Literal::Ipv4(l);
                match operator {
                    "==" => Ok((input, Pred::FieldPred(Operation::Eq(f, l)))),
                    "!=" => Ok((input, Pred::FieldPred(Operation::Ne(f, l)))),
                    _ => Err(NomErr(FilterError::UnsupportedOperator(field, operator))),
                }
            } else {
                Err(NomErr(FilterError::InvalidLiteral(literal)))
            }
        }
        Field::SrcPort => {
            if let Ok(l) = u16::from_str(literal) {
                let l = Literal::Port(l);
                match operator {
                    "==" => Ok((input, Pred::FieldPred(Operation::Eq(f, l)))),
                    "!=" => Ok((input, Pred::FieldPred(Operation::Ne(f, l)))),
                    ">" => Ok((input, Pred::FieldPred(Operation::Gt(f, l)))),
                    ">=" => Ok((input, Pred::FieldPred(Operation::Ge(f, l)))),
                    "<" => Ok((input, Pred::FieldPred(Operation::Lt(f, l)))),
                    "<=" => Ok((input, Pred::FieldPred(Operation::Le(f, l)))),
                    _ => Err(NomErr(FilterError::UnsupportedOperator(field, operator))),
                }
            } else {
                Err(NomErr(FilterError::InvalidLiteral(literal)))
            }
        }
        Field::DestIp => {
            if let Ok(l) = Ipv4Addr::from_str(literal) {
                let l = Literal::Ipv4(l);
                match operator {
                    "==" => Ok((input, Pred::FieldPred(Operation::Eq(f, l)))),
                    "!=" => Ok((input, Pred::FieldPred(Operation::Ne(f, l)))),
                    _ => Err(NomErr(FilterError::UnsupportedOperator(field, operator))),
                }
            } else {
                Err(NomErr(FilterError::InvalidLiteral(literal)))
            }
        }
        Field::DestPort => {
            if let Ok(l) = u16::from_str(literal) {
                let l = Literal::Port(l);
                match operator {
                    "==" => Ok((input, Pred::FieldPred(Operation::Eq(f, l)))),
                    "!=" => Ok((input, Pred::FieldPred(Operation::Ne(f, l)))),
                    ">" => Ok((input, Pred::FieldPred(Operation::Gt(f, l)))),
                    ">=" => Ok((input, Pred::FieldPred(Operation::Ge(f, l)))),
                    "<" => Ok((input, Pred::FieldPred(Operation::Lt(f, l)))),
                    "<=" => Ok((input, Pred::FieldPred(Operation::Le(f, l)))),
                    _ => Err(NomErr(FilterError::UnsupportedOperator(field, operator))),
                }
            } else {
                Err(NomErr(FilterError::InvalidLiteral(literal)))
            }
        }
        Field::Len => {
            if let Ok(l) = u32::from_str(literal) {
                let l = Literal::Len(if l > u16::max_value() as u32 {
                    u16::max_value()
                } else {
                    l as u16
                });
                match operator {
                    "==" => Ok((input, Pred::FieldPred(Operation::Eq(f, l)))),
                    "!=" => Ok((input, Pred::FieldPred(Operation::Ne(f, l)))),
                    ">" => Ok((input, Pred::FieldPred(Operation::Gt(f, l)))),
                    ">=" => Ok((input, Pred::FieldPred(Operation::Ge(f, l)))),
                    "<" => Ok((input, Pred::FieldPred(Operation::Lt(f, l)))),
                    "<=" => Ok((input, Pred::FieldPred(Operation::Le(f, l)))),
                    _ => Err(NomErr(FilterError::UnsupportedOperator(field, operator))),
                }
            } else {
                Err(NomErr(FilterError::InvalidLiteral(literal)))
            }
        }
        Field::IpPayloadLen => {
            if let Ok(l) = u32::from_str(literal) {
                let l = Literal::Len(if l > u16::max_value() as u32 {
                    u16::max_value()
                } else {
                    l as u16
                });
                match operator {
                    "==" => Ok((input, Pred::FieldPred(Operation::Eq(f, l)))),
                    "!=" => Ok((input, Pred::FieldPred(Operation::Ne(f, l)))),
                    ">" => Ok((input, Pred::FieldPred(Operation::Gt(f, l)))),
                    ">=" => Ok((input, Pred::FieldPred(Operation::Ge(f, l)))),
                    "<" => Ok((input, Pred::FieldPred(Operation::Lt(f, l)))),
                    "<=" => Ok((input, Pred::FieldPred(Operation::Le(f, l)))),
                    _ => Err(NomErr(FilterError::UnsupportedOperator(field, operator))),
                }
            } else {
                Err(NomErr(FilterError::InvalidLiteral(literal)))
            }
        }
        Field::TransProto => {
            if let Ok(l) = str_to_trans_protocol(literal) {
                let l = Literal::TransProtocol(l);
                match operator {
                    "==" => Ok((input, Pred::FieldPred(Operation::Eq(f, l)))),
                    "!=" => Ok((input, Pred::FieldPred(Operation::Ne(f, l)))),
                    _ => Err(NomErr(FilterError::UnsupportedOperator(field, operator))),
                }
            } else {
                Err(NomErr(FilterError::InvalidLiteral(literal)))
            }
        }
        Field::TransPayloadLen => {
            if let Ok(l) = u32::from_str(literal) {
                let l = Literal::Len(if l > u16::max_value() as u32 {
                    u16::max_value()
                } else {
                    l as u16
                });
                match operator {
                    "==" => Ok((input, Pred::FieldPred(Operation::Eq(f, l)))),
                    "!=" => Ok((input, Pred::FieldPred(Operation::Ne(f, l)))),
                    ">" => Ok((input, Pred::FieldPred(Operation::Gt(f, l)))),
                    ">=" => Ok((input, Pred::FieldPred(Operation::Ge(f, l)))),
                    "<" => Ok((input, Pred::FieldPred(Operation::Lt(f, l)))),
                    "<=" => Ok((input, Pred::FieldPred(Operation::Le(f, l)))),
                    _ => Err(NomErr(FilterError::InvalidOperator(operator))),
                }
            } else {
                Err(NomErr(FilterError::InvalidLiteral(literal)))
            }
        }
        Field::AppProto => {
            if let Ok(l) = AppProtocol::from_str(literal) {
                let l = Literal::AppProtocol(l);
                match operator {
                    "==" => Ok((input, Pred::FieldPred(Operation::Eq(f, l)))),
                    "!=" => Ok((input, Pred::FieldPred(Operation::Ne(f, l)))),
                    _ => Err(NomErr(FilterError::UnsupportedOperator(field, operator))),
                }
            } else {
                Err(NomErr(FilterError::InvalidLiteral(literal)))
            }
        }
    }
}

#[cfg(test)]
mod filter_test {
    use super::*;

    #[test]
    fn test_operation() {
        let input = "src_port == 80";
        assert_eq!(
            parse_pred(input),
            Ok((
                "",
                Pred::FieldPred(Operation::Eq(Field::SrcPort, Literal::Port(80)))
            ))
        );
        let input = "源端口 == 80";
        assert_eq!(
            parse_pred(input),
            Ok((
                "",
                Pred::FieldPred(Operation::Eq(Field::SrcPort, Literal::Port(80)))
            ))
        );
    }

    #[test]
    fn test_parens() {
        let input = "(src_port == 80)";
        assert_eq!(
            parse_pred(input),
            Ok((
                "",
                Pred::FieldPred(Operation::Eq(Field::SrcPort, Literal::Port(80)))
            ))
        );
    }
}
