use std::env;
use std::fs;

use crate::dfg::{Dfg, DfgOperations};
use crate::trace::TracePoint;

mod dfg;
mod trace;

fn main() {
    let args = env::args().collect::<Vec<_>>();

    let lines = fs::read_to_string(&args[1]).unwrap();

    let trace_points: Vec<TracePoint> = lines.lines().map(|l| l.parse().unwrap()).collect();
    println!("parsing of trace done");
    let graph = Dfg::from_trace(trace_points);
    println!("creation of graph done");
    graph.to_png("out");
    println!("export to png done");
}
