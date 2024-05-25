use std::env;
use std::fs;

use crate::dfg::{Dfg, DfgOperations};
use crate::graph_algos::connected_components;
use crate::graph_algos::is_vectorizable;
use crate::insn::TraceInstruction;
use crate::trace::TracePoint;

mod dfg;
mod graph_algos;
mod insn;
mod trace;

fn print_separator(s: &str) {
    let sep = "#".repeat(80);
    println!("\n{}\n\t{}\n{}\n", &sep, s, &sep);
}

fn main() {
    let args = env::args().collect::<Vec<_>>();

    let lines = fs::read_to_string(&args[1]).unwrap();

    let trace_points: Vec<TracePoint> = lines
        .lines()
        .map(|l| l.parse().unwrap_or_else(|_| panic!("Error parsing: {}", l)))
        .collect();

    print_separator("Trace points from PinTool");
    for tp in &trace_points {
        println!("{:?}", tp);
    }

    let insns = TraceInstruction::combine(trace_points);
    print_separator("Augmented same IP trace points to instructions");
    for ins in &insns {
        println!("{:?}", ins);
    }

    let trace_points = TraceInstruction::merge_instructions(insns);
    println!("parsing of trace done");
    print_separator("Converted instructions back to trace points");
    for tp in &trace_points {
        println!("{:?}", tp);
    }
    let mut graph = Dfg::from_trace(trace_points);
    print_separator("Graph creation done. Saving...");
    graph.save("out");
    connected_components(&mut graph);
    graph.save("reduced");
    print_separator("Analysis of strided memory accesses");
    is_vectorizable(&graph);
}
