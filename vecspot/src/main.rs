use std::env;
use std::fs;

use crate::dfg::{Dfg, DfgOperations};
use crate::graph_algos::color_graph;
use crate::graph_algos::connected_components;
use crate::trace::TraceBinOp;
use crate::trace::TraceMemOp;
use crate::trace::TraceMemOpType;
use crate::trace::TraceOperation;
use crate::trace::TracePoint;

mod dfg;
mod graph_algos;
mod trace;

fn main() {
    let args = env::args().collect::<Vec<_>>();

    let lines = fs::read_to_string(&args[1]).unwrap();

    let trace_points: Vec<TracePoint> = lines
        .lines()
        .map(|l| l.parse().unwrap_or_else(|_| panic!("Error parsing: {}", l)))
        .collect();

    println!("TRACE POINTS:\n");
    for tp in &trace_points {
        println!("{:?}", tp);
    }

    let insns = TraceInstruction::combine(trace_points);
    println!("INSNS:\n");
    for ins in &insns {
        println!("{:?}", ins);
    }

    let trace_points = TraceInstruction::merge_instructions(insns);
    println!("parsing of trace done");
    for tp in &trace_points {
        println!("{:?}", tp);
    }
    let mut graph = Dfg::from_trace(trace_points);
    println!("creation of graph done");
    graph.save("out");
    connected_components(&mut graph);
    graph.save("reduced");
    println!("export to png done");
    // color_graph(&graph);
}

#[derive(Debug, Default)]
struct TraceInstruction {
    ip: u64,
    read: Option<TraceMemOp>,
    binop: Option<TraceBinOp>,
    write: Option<TraceMemOp>,
}

impl TraceInstruction {
    fn add_memop(&mut self, memop: &TraceMemOp) -> bool {
        println!("Memop");
        let target = match memop.typ {
            TraceMemOpType::Read => {
                if self.read.is_some() {
                    return false;
                } else {
                    &mut self.read
                }
            }
            TraceMemOpType::Write => {
                if self.write.is_some() {
                    return false;
                } else {
                    &mut self.write
                }
            }
        };
        *target = Some(memop.clone());

        true
    }

    fn add_binop(&mut self, binop: &TraceBinOp) -> bool {
        println!("Binop");
        if self.binop.is_some() {
            false
        } else {
            self.binop = Some(binop.clone());
            true
        }
    }

    pub fn try_add(&mut self, trace: &TracePoint, ip: u64) -> bool {
        let added = match &trace.op {
            TraceOperation::BinOp(binop) => self.add_binop(binop),
            TraceOperation::MemOp(memop) => self.add_memop(memop),
            TraceOperation::Pass => true,
        };
        if added {
            self.ip = ip;
        }
        added
    }

    pub fn merge_instructions(instructions: Vec<TraceInstruction>) -> Vec<TracePoint> {
        instructions
            .into_iter()
            .flat_map(|ins| {
                let ops = match (ins.read, ins.binop, ins.write) {
                    (None, None, None) => vec![TraceOperation::Pass],
                    (None, None, Some(x)) | (Some(x), None, None) => vec![TraceOperation::MemOp(x)],
                    (None, Some(x), None) => vec![TraceOperation::BinOp(x)],
                    (Some(mut read), Some(mut binop), None) => {
                        read.reg = "tmp_r".into();
                        if binop.src1 == "*invalid*" {
                            binop.src1 = "tmp_r".into();
                        }
                        vec![TraceOperation::MemOp(read), TraceOperation::BinOp(binop)]
                    }
                    (None, Some(mut binop), Some(mut write)) => {
                        write.reg = "tmp_w".into();
                        binop.src2 = "tmp_w".into();
                        vec![TraceOperation::BinOp(binop), TraceOperation::MemOp(write)]
                    }
                    (Some(mut read), Some(mut binop), Some(mut write)) => {
                        if read.reg == "*invalid*" {
                            read.reg = "tmp_r".into();
                        }
                        if binop.src1 == "*invalid*" {
                            binop.src1 = "tmp_r".into();
                        }
                        if binop.src2 == "*invalid*" {
                            binop.src2 = "tmp_r".into();
                        }
                        binop.dest = "tmp_w".into();
                        write.reg = "tmp_w".into();
                        vec![
                            TraceOperation::MemOp(read),
                            TraceOperation::BinOp(binop),
                            TraceOperation::MemOp(write),
                        ]
                    }
                    _ => panic!(),
                };
                ops.into_iter().map(move |op| TracePoint { ip: ins.ip, op })
            })
            .collect()
    }

    fn combine(trace_points: Vec<TracePoint>) -> Vec<TraceInstruction> {
        let mut trace = vec![];
        let mut curr_ins = TraceInstruction::default();
        let mut curr_ip = 0;
        for p in trace_points {
            let ip = p.ip;

            if curr_ip != ip || !curr_ins.try_add(&p, ip) {
                trace.push(curr_ins);
                curr_ins = TraceInstruction::default();
                assert!(curr_ins.try_add(&p, ip));
                curr_ip = ip;
            }
        }
        trace.push(curr_ins);
        trace
    }
}
