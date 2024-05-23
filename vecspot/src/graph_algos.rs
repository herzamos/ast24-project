use petgraph::{algo::kosaraju_scc, stable_graph::StableUnGraph};

use crate::dfg::{Dfg, Operand};

pub fn connected_components(dfg: &mut Dfg) {
    let graph = &mut dfg.graph;
    let undirected: StableUnGraph<Operand, String> = unsafe { std::mem::transmute(graph.clone()) };
    for cc in kosaraju_scc(&undirected) {
        println!("Connected component {{");
        let mut read = false;
        let mut write = false;
        for node in &cc {
            println!("\t{:?}", undirected[*node]);
            match &undirected[*node] {
                Operand::Memory(_) => {
                    let inc = graph
                        .edges_directed(*node, petgraph::Direction::Incoming)
                        .count();
                    let out = graph
                        .edges_directed(*node, petgraph::Direction::Outgoing)
                        .count();
                    if inc > 0 {
                        write = true;
                    }
                    if out > 0 {
                        read = true;
                    }
                }
                Operand::Register(_) => (),
            }
        }
        println!("}}");
        println!("W: {}, R: {}\n", write, read);
        if !(write && read) {
            for node in cc {
                graph.remove_node(node);
            }
        }
    }
}
