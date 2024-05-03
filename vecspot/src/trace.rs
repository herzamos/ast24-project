use std::str::FromStr;

/// Struct representing one line of the trace file, we call this a `TracePoint`
pub struct TracePoint {
    pub ip: u64,
    pub op: TraceOperation,
}

/// Type of operation that has been recorded in the `TracePoint`
pub enum TraceOperation {
    BinOp(TraceBinOp),
    MemOp(TraceMemOp),
}

/// Binary operation like addition etc.
#[derive(Debug, Clone)]
pub struct TraceBinOp {
    pub op: String,
    pub reg1: String,
    pub reg2: String,
}

/// Type of the memory operation
#[derive(Debug, Clone, Copy)]
pub enum TraceMemOpType {
    Read,
    Write,
}

/// Memory operation like reads and writes
#[derive(Debug, Clone)]
pub struct TraceMemOp {
    pub typ: TraceMemOpType,
    pub addr: u64,
    pub reg: String,
}

/// Error to be returned when parsing fails
#[derive(Debug)]
pub struct ParseError(String);

/// Parse a hex numeral prefixed by `0x`
fn parse0x(s: &str) -> Result<u64, ParseError> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|_| ParseError("failed to parse addr".into()))
}

impl FromStr for TracePoint {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let colon_split = s.split(": ").collect::<Vec<_>>();
        if colon_split.len() != 2 {
            return Err(ParseError("wrong col split".into()));
        }
        let ip = parse0x(colon_split[0])?;

        let ins = colon_split[1].split_ascii_whitespace().collect::<Vec<_>>();
        let op = if ins[0] == "READ" {
            if ins.len() != 3 {
                return Err(ParseError(format!(
                    "wrong amount of args, got {}",
                    ins.len()
                )));
            }
            let addr = parse0x(ins[1])?;
            let reg = ins[2].into();
            let typ = TraceMemOpType::Read;
            TraceOperation::MemOp(TraceMemOp { typ, addr, reg })
        } else if ins[0] == "WRITE" {
            if ins.len() != 3 {
                return Err(ParseError(format!(
                    "wrong amount of args, got {}",
                    ins.len()
                )));
            }
            let addr = parse0x(ins[2])?;
            let reg = ins[1].into();
            let typ = TraceMemOpType::Write;
            TraceOperation::MemOp(TraceMemOp { typ, addr, reg })
        } else if ins[0] == "BinOp" {
            if ins.len() != 4 {
                return Err(ParseError(format!(
                    "wrong amount of args, got {}",
                    ins.len()
                )));
            }
            let op = ins[1].into();
            let reg1 = ins[2].into();
            let reg2 = ins[3].into();
            TraceOperation::BinOp(TraceBinOp { op, reg1, reg2 })
        } else {
            panic!("illegal instruction")
        };
        Ok(TracePoint { ip, op })
    }
}
