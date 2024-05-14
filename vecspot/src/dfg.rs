use std::fs::File;
use std::io::Write;
use std::{collections::HashMap, fmt::Debug};

use graphviz_rust::{cmd::Format, exec_dot};
use petgraph::{dot::Dot, graph::DiGraph, Graph};

use crate::trace::{TraceMemOpType, TraceOperation, TracePoint};

pub type Dfg = Graph<Operand, String>;

pub trait DfgOperations {
    fn from_trace(trace: Vec<TracePoint>) -> Self;
    fn to_png(&self, name: &str);
}

impl DfgOperations for Dfg {
    fn from_trace(trace: Vec<TracePoint>) -> Self {
        let mut graph: Graph<Operand, String> = DiGraph::new();

        let mut mem_map = HashMap::new();
        let mut reg_map = HashMap::new();

        for trace_point in trace {
            // TODO: this is dogshit pls fix
            match trace_point.op {
                TraceOperation::Pass => (),
                TraceOperation::BinOp(op) => {
                    let reg1 = reg_map.get(&op.reg1);
                    let reg2 = reg_map.get(&op.reg2);

                    // this skips registers that have not been written by to by
                    // an access to memory
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
                            graph.add_edge(mem, reg_idx, "Read".into());
                        }
                        TraceMemOpType::Write => {
                            let reg = *reg_map.get(&op.reg).unwrap();
                            graph.add_edge(reg, mem, "Write".into());
                            mem_map.insert(op.addr, graph.add_node(Operand::Memory(op.addr)));
                        }
                    };
                }
            }
        }

        // remove memory locations that are not used
        graph.filter_map(
            |i, node| {
                if graph.neighbors_undirected(i).next().is_none() {
                    None
                } else {
                    Some((*node).clone())
                }
            },
            |_, edge| Some(edge.clone()),
        )
    }

    fn to_png(&self, name: &str) {
        let png = exec_dot(
            format!("{:?}", Dot::with_config(self, &[])),
            vec![Format::Png.into()],
        )
        .unwrap();
        File::create(format!("{}.png", name))
            .unwrap()
            .write_all(&png)
            .unwrap();
    }
}

/// Node of the `DfgGraph` representing an operand of the instruction
// pub struct DfgNode {
//     id: u32,
//     loc: Operand,
// }

/// An operand of the computation
#[derive(Clone)]
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
