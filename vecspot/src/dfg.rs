use std::collections::hash_map::Entry;
use std::fs::File;
use std::io::Write;
use std::{collections::HashMap, fmt::Debug};

use graphviz_rust::{cmd::Format, exec_dot};
use petgraph::graph::NodeIndex;
use petgraph::{dot::Dot, graph::DiGraph, Graph};

use crate::trace::{TraceMemOpType, TraceOperation, TracePoint};

// pub type Dfg = Graph<Operand, String>;

pub struct Dfg {
    graph: Graph<Operand, String>,
    reg_map: HashMap<String, NodeIndex>,
    mem_map: HashMap<u64, NodeIndex>,
}

impl Dfg {
    fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            mem_map: HashMap::new(),
            reg_map: HashMap::new(),
        }
    }

    fn access_reg(&mut self, reg_name: String, read: bool) -> NodeIndex {
        match self.reg_map.entry(reg_name.clone()) {
            Entry::Occupied(o) => {
                if read {
                    *o.get()
                } else {
                    let new_idx = self.graph.add_node(Operand::Register(reg_name.clone()));
                    self.reg_map.insert(reg_name, new_idx);
                    new_idx
                }
            }
            Entry::Vacant(v) => {
                let name = if read {
                    format!("{}**", &reg_name)
                } else {
                    reg_name
                };
                let idx = self.graph.add_node(Operand::Register(name));
                v.insert(idx);
                idx
            }
        }
    }

    fn access_mem(&mut self, mem_addr: u64, read: bool) -> NodeIndex {
        match self.mem_map.entry(mem_addr) {
            Entry::Occupied(o) => {
                if read {
                    *o.get()
                } else {
                    let new_idx = self.graph.add_node(Operand::Memory(mem_addr));
                    self.mem_map.insert(mem_addr, new_idx);
                    new_idx
                }
            }
            Entry::Vacant(v) => {
                let idx = self.graph.add_node(Operand::Memory(mem_addr));
                v.insert(idx);
                idx
            }
        }
    }

    fn add_trace_point(&mut self, trace_point: TracePoint) {
        match trace_point.op {
            TraceOperation::Pass => (),
            TraceOperation::BinOp(op) => {
                let reg1 = self.reg_map.get(&op.reg1);
                let reg2 = self.reg_map.get(&op.reg2);

                // this skips registers that have not been written by to by
                // an access to memory
                if reg1.is_none() || reg2.is_none() {
                    return;
                }
                let reg1_idx = self.access_reg(op.reg1, true);
                let reg2_idx = self.access_reg(op.reg2.clone(), true);

                let reg3_idx = self.access_reg(op.reg2, false);

                self.graph.add_edge(reg1_idx, reg3_idx, op.op.clone());
                self.graph.add_edge(reg2_idx, reg3_idx, op.op.clone());
            }
            TraceOperation::MemOp(op) => {
                let is_read = match op.typ {
                    TraceMemOpType::Read => true,
                    TraceMemOpType::Write => false,
                };
                let mem_idx = self.access_mem(op.addr, is_read);
                let reg_idx = self.access_reg(op.reg.clone(), !is_read);
                if is_read {
                    self.graph.add_edge(mem_idx, reg_idx, "Read".into());
                } else {
                    self.graph.add_edge(reg_idx, mem_idx, "Write".into());
                }
            }
        }
    }
}

pub trait DfgOperations {
    fn from_trace(trace: Vec<TracePoint>) -> Self;
    fn to_png(&self, name: &str);
}

impl DfgOperations for Dfg {
    fn from_trace(trace: Vec<TracePoint>) -> Self {
        let mut s = Self::new();

        for trace_point in trace {
            s.add_trace_point(trace_point);
        }

        // remove memory locations that are not used
        s.graph.filter_map(
            |i, node| {
                if s.graph.neighbors_undirected(i).next().is_none() {
                    None
                } else {
                    Some((*node).clone())
                }
            },
            |_, edge| Some(edge.clone()),
        );
        s
    }

    fn to_png(&self, name: &str) {
        let png = exec_dot(
            format!("{:?}", Dot::with_config(&self.graph, &[])),
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
