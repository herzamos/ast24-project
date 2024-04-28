use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::str::FromStr;

use std::fmt::Debug;

use graphviz_rust::{cmd::Format, exec_dot};
use petgraph::dot::{Config, Dot};
use petgraph::graph::DiGraph;
use petgraph::Graph;

fn main() {
    let args = env::args().collect::<Vec<_>>();

    let lines = fs::read_to_string(&args[1]).unwrap();

    let instructions: Vec<Instruction> = lines.lines().map(|l| l.parse().unwrap()).collect();
    println!("ok");
    let mut graph: Graph<Operand, String> = DiGraph::new();

    let mut mem_map = HashMap::new();
    let mut reg_map = HashMap::new();

    for ins in instructions {
        // if let Op::MemOp(op) = ins.op {
        // graph.add_node(Operand::Memory(op.addr));
        // }
        // TODO: this is dogshit pls fix
        match ins.op {
            Op::BinOp(op) => {
                let reg1 = reg_map.get(&op.reg1);
                let reg2 = reg_map.get(&op.reg2);

                if reg1.is_none() || reg2.is_none() {
                    continue;
                }
                let new_reg2 = graph.add_node(Operand::Register(op.reg2.clone()));
                graph.add_edge(*reg1.unwrap(), new_reg2, op.op.clone());
                graph.add_edge(*reg2.unwrap(), new_reg2, op.op.clone());
                reg_map.insert(op.reg2, new_reg2);
            }
            Op::MemOp(op) => {
                let mem = match mem_map.get(&op.addr) {
                    None => {
                        let index = graph.add_node(Operand::Memory(op.addr));
                        mem_map.insert(op.addr, index);
                        index
                    }
                    Some(x) => *x,
                };

                match op.typ {
                    MemOpType::Read => {
                        let reg_idx = graph.add_node(Operand::Register(op.reg.clone()));
                        reg_map.insert(op.reg, reg_idx);
                        graph.add_edge(mem, reg_idx, "Read".into())
                    }
                    MemOpType::Write => {
                        let reg = *reg_map.get(&op.reg).unwrap();
                        graph.add_edge(reg, mem, "Write".into())
                    }
                };
            }
        }
    }
    to_svg(&graph);
}

fn to_svg(graph: &Graph<Operand, String>) {
    let svg = exec_dot(
        format!("{:?}", Dot::with_config(graph, &[])),
        vec![Format::Png.into()],
    )
    .unwrap();
    File::create("output.png").unwrap().write_all(&svg).unwrap();
}

enum Operand {
    Memory(u64),
    Register(String),
}

impl Debug for Operand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory(arg0) => write!(f, "{:#x}", arg0),
            Self::Register(arg0) => write!(f, "{}", arg0),
        }
    }
}

struct Node {
    id: u32,
    loc: Operand,
}

enum Op {
    BinOp(BinOp),
    MemOp(MemOp),
}

struct Instruction {
    ip: u64,
    op: Op,
}

#[derive(Debug)]
struct ParseError(String);

fn parse0x(s: &str) -> Result<u64, ParseError> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|_| ParseError("failed to parse addr".into()))
}

impl FromStr for Instruction {
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
            let typ = MemOpType::Read;
            Op::MemOp(MemOp { typ, addr, reg })
        } else if ins[0] == "WRITE" {
            if ins.len() != 3 {
                return Err(ParseError(format!(
                    "wrong amount of args, got {}",
                    ins.len()
                )));
            }
            let addr = parse0x(ins[2])?;
            let reg = ins[1].into();
            let typ = MemOpType::Write;
            Op::MemOp(MemOp { typ, addr, reg })
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
            Op::BinOp(BinOp { op, reg1, reg2 })
        } else {
            panic!("illegal instruction")
        };
        Ok(Instruction { ip, op })
    }
}

#[derive(Debug, Clone)]
struct BinOp {
    op: String,
    reg1: String,
    reg2: String,
}

#[derive(Debug, Clone, Copy)]
enum MemOpType {
    Read,
    Write,
}

#[derive(Debug, Clone)]
struct MemOp {
    typ: MemOpType,
    addr: u64,
    reg: String,
}
