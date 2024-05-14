use std::env;
use std::fs;

use crate::dfg::{Dfg, DfgOperations};
use crate::trace::TraceBinOp;
use crate::trace::TraceMemOp;
use crate::trace::TraceMemOpType;
use crate::trace::TraceOperation;
use crate::trace::TracePoint;

mod dfg;
mod trace;

fn main() {
    let args = env::args().collect::<Vec<_>>();

    let lines = fs::read_to_string(&args[1]).unwrap();

    let mut trace_points: Vec<TracePoint> = lines
        .lines()
        .map(|l| l.parse().unwrap_or_else(|_| panic!("Error parsing: {}", l)))
        .collect();

    combine_mem_bin_op(&mut trace_points);

    println!("parsing of trace done");
    for tp in &trace_points {
        println!("{:?}", tp);
    }
    let graph = Dfg::from_trace(trace_points);
    println!("creation of graph done");
    graph.to_png("out");
    println!("export to png done");
}

fn combine_mem_bin_op(trace_points: &mut [TracePoint]) {
    let mut i = 0;
    while i < trace_points.len() - 1 {
        let ip = trace_points[i].ip;
        if trace_points[i].ip == trace_points[i + 1].ip {
            println!("Funny");
            if let TraceOperation::MemOp(memop) = &trace_points[i].op {
                if let TraceOperation::BinOp(bop) = &trace_points[i + 1].op {
                    assert!(memop.typ == TraceMemOpType::Read);
                    let trace_op = TraceOperation::BinOp(TraceBinOp {
                        op: bop.op.clone(),
                        reg1: "tmp".into(),
                        reg2: bop.reg2.clone(),
                    });

                    trace_points[i] = TracePoint {
                        ip,
                        op: TraceOperation::MemOp(TraceMemOp {
                            typ: TraceMemOpType::Read,
                            addr: memop.addr,
                            reg: "tmp".into(),
                        }),
                    };

                    trace_points[i + 1] = TracePoint { ip, op: trace_op };
                }
            }
        }
        i += 1;
    }
}
