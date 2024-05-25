use std::collections::{hash_map::Entry, HashMap, HashSet};

use petgraph::{algo::kosaraju_scc, graph::NodeIndex, stable_graph::StableUnGraph};

use crate::dfg::{Dfg, Operand};

pub fn connected_components(dfg: &mut Dfg) {
    let graph = &mut dfg.graph;
    let undirected: StableUnGraph<Operand, String> = unsafe { std::mem::transmute(graph.clone()) };
    for cc in kosaraju_scc(&undirected) {
        println!("Connected component {{");
        let mut read = false;
        let mut write = false;
        for node in &cc {
            println!("READ  IP: {:?}", dfg.read_ip_map.get(node));
            println!("WRITE IP: {:?}", dfg.write_ip_map.get(node));
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

pub fn color_graph(dfg: &Dfg) {
    // let mut color_map = HashMap::new();
    let mem_writes = get_strided_accesses(dfg, false);

    for partition in mem_writes {
        let mut iter_nodes = partition;
        loop {
            // iter_ndoes = iter_nodes;
            todo!()
        }
    }
}

fn check_chain_equality(dfg: &Dfg, nodes: Vec<NodeIndex>) -> bool {
    // check if no nodes left
    if nodes.is_empty() {
        return true;
    }
    let mut ips = nodes.iter().map(|n| dfg.read_ip_map[n]);
    let mut operands = nodes.iter().map(|n| dfg.graph[*n].clone());
    let first_ip = ips.next().unwrap();
    let first_op = operands.next().unwrap();

    // check that the ips match
    if !ips.all(|i| i == first_ip) {
        return false;
    }

    todo!()
}

// struct NodeHelper {
//     ip: u64,
//     idx: NodeIndex,
//     addr
// }

fn get_strided_accesses(dfg: &Dfg, read: bool) -> Vec<Vec<(u64, NodeIndex, u64)>> {
    let hm = if read {
        &dfg.read_ip_map
    } else {
        &dfg.write_ip_map
    };
    let mem_accesses =
        dfg.graph
            .node_indices()
            .filter_map(|idx| match (&dfg.graph[idx], hm.get(&idx)) {
                (Operand::Memory(addr), Some(&ip)) => Some((ip, idx, *addr)),
                _ => None,
            });
    // Create a hashmap with all the mem_write operations at the same ip
    let mut mm_partitions: HashMap<u64, HashSet<(u64, NodeIndex, u64)>> = HashMap::new();
    for mm in mem_accesses {
        match mm_partitions.entry(mm.0) {
            Entry::Occupied(mut o) => {
                o.get_mut().insert(mm);
            }
            Entry::Vacant(v) => {
                v.insert(HashSet::new());
            }
        }
    }

    let mut v = vec![];
    for (ip, partition) in mm_partitions {
        let mut list = partition.into_iter().collect::<Vec<_>>();
        list.sort_by(|a, b| a.2.cmp(&b.2));
        let strides = list.iter().zip(list.iter().skip(1)).map(|(l, h)| h.2 - l.2);
        if strides.clone().max() == strides.clone().min() {
            println!("Stride is always the same for ip: {:x}!", ip);
            v.push(list);
        }
    }
    v
}
