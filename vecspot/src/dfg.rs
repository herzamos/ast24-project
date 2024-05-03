use std::fs::File;
use std::io::Write;
use std::{collections::HashMap, fmt::Debug};

use graphviz_rust::{cmd::Format, exec_dot};
use petgraph::{dot::Dot, graph::DiGraph, Graph};

use crate::trace::{TraceMemOpType, TraceOperation, TracePoint};

pub type Dfg = Graph<Operand, String>;

pub trait DfgOperations {
    fn from_trace(trace: Vec<TracePoint>) -> Self;
    fn to_png(&self);
}

impl DfgOperations for Dfg {
    fn from_trace(trace: Vec<TracePoint>) -> Self {
        let mut graph: Graph<Operand, String> = DiGraph::new();

        let mut mem_map = HashMap::new();
        let mut reg_map = HashMap::new();

        for trace_point in trace {
            // if let Op::MemOp(op) = ins.op {
            // graph.add_node(Operand::Memory(op.addr));
            // }
            // TODO: this is dogshit pls fix
            match trace_point.op {
                TraceOperation::BinOp(op) => {
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
                TraceOperation::MemOp(op) => {
                    let mem = match mem_map.get(&op.addr) {
                        None => {
                            let index = graph.add_node(Operand::Memory(op.addr));
                            mem_map.insert(op.addr, index);
                            index
                        }
                        Some(x) => *x,
                    };

                    match op.typ {
                        TraceMemOpType::Read => {
                            let reg_idx = graph.add_node(Operand::Register(op.reg.clone()));
                            reg_map.insert(op.reg, reg_idx);
                            graph.add_edge(mem, reg_idx, "Read".into())
                        }
                        TraceMemOpType::Write => {
                            let reg = *reg_map.get(&op.reg).unwrap();
                            graph.add_edge(reg, mem, "Write".into())
                        }
                    };
                }
            }
        }
        graph
    }

    fn to_png(&self) {
        let png = exec_dot(
            format!("{:?}", Dot::with_config(self, &[])),
            vec![Format::Png.into()],
        )
        .unwrap();
        File::create("output.png").unwrap().write_all(&png).unwrap();
    }
}

/// Node of the `DfgGraph` representing an operand of the instruction
// pub struct DfgNode {
//     id: u32,
//     loc: Operand,
// }

/// An operand of the computation
pub enum Operand {
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
