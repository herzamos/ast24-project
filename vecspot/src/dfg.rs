use std::collections::hash_map::Entry;
use std::fs::File;
use std::io::Write;
use std::{collections::HashMap, fmt::Debug};

use graphviz_rust::{cmd::Format, exec_dot};
use petgraph::dot::Dot;
use petgraph::graph::NodeIndex;
use petgraph::stable_graph::StableDiGraph;

use crate::trace::{TraceMemOpType, TraceOperation, TracePoint};

// pub type Dfg = Graph<Operand, String>;

#[derive(Default)]
pub struct Dfg {
    pub graph: StableDiGraph<Operand, String>,
    reg_map: HashMap<String, NodeIndex>,
    mem_map: HashMap<u64, NodeIndex>,
    pub read_ip_map: HashMap<NodeIndex, u64>,
    pub write_ip_map: HashMap<NodeIndex, u64>,
}

impl Dfg {
    fn new() -> Self {
        Self::default()
    }

    fn access_reg(&mut self, reg_name: String, read: bool) -> NodeIndex {
        if reg_name.starts_with('#') {
            println!("Adde new imm");
            let idx = self.graph.add_node(Operand::Register(reg_name.clone()));
            self.reg_map.insert(reg_name, idx);
            return idx;
        }
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
                let reg1_idx = self.access_reg(op.src1, true);
                let reg2_idx = self.access_reg(op.src2.clone(), true);

                let reg3_idx = self.access_reg(op.dest, false);

                self.graph.add_edge(reg1_idx, reg3_idx, op.op.clone());
                self.graph.add_edge(reg2_idx, reg3_idx, op.op.clone());

                self.read_ip_map.insert(reg1_idx, op.ip);
                self.read_ip_map.insert(reg2_idx, op.ip);
                self.write_ip_map.insert(reg3_idx, op.ip);
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
                    self.read_ip_map.insert(mem_idx, op.ip);
                    self.write_ip_map.insert(reg_idx, op.ip);
                } else {
                    self.graph.add_edge(reg_idx, mem_idx, "Write".into());
                    self.read_ip_map.insert(reg_idx, op.ip);
                    self.write_ip_map.insert(mem_idx, op.ip);
                }
            }
        }
    }

    pub fn get_read_ip(&self, idx: NodeIndex) -> Option<u64> {
        self.read_ip_map.get(&idx).copied()
    }

    pub fn get_write_ip(&self, idx: NodeIndex) -> Option<u64> {
        self.write_ip_map.get(&idx).copied()
    }
}

/// Trait to to create and save a dataflow graph generated from a trace
pub trait DfgOperations {
    fn from_trace(trace: Vec<TracePoint>) -> Self;
    fn save(&self, name: &str);
}

impl DfgOperations for Dfg {
    fn from_trace(trace: Vec<TracePoint>) -> Self {
        let mut s = Self::new();

        for trace_point in trace {
            s.add_trace_point(trace_point);
        }

        s
    }

    fn save(&self, name: &str) {
        let png = exec_dot(
            format!("{:?}", Dot::with_config(&self.graph, &[])),
            vec![Format::Png.into()],
        )
        .unwrap();
        File::create(format!("{}.png", name))
            .unwrap()
            .write_all(&png)
            .unwrap();
        let svg = exec_dot(
            format!("{:?}", Dot::with_config(&self.graph, &[])),
            vec![Format::Svg.into()],
        )
        .unwrap();
        File::create(format!("{}.svg", name))
            .unwrap()
            .write_all(&svg)
            .unwrap();
    }
}

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
