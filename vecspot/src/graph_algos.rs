use std::{
    collections::{hash_map::Entry, HashMap},
    fs::File,
    io::Write,
};

use graphviz_rust::{cmd::Format, exec_dot};
use petgraph::{
    algo::kosaraju_scc,
    dot::Dot,
    graph::{DiGraph, NodeIndex},
    stable_graph::StableUnGraph,
    Direction::Outgoing,
};

use crate::dfg::{Dfg, Operand};

/// Removes every connected component that does not perform a memory access.
/// This is to remove parts of the `Dfg` that only influence the control flow
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

/// Checks if the `Dfg` is vectorizable given the subtrees resulting in memory writes
pub fn is_vectorizable(dfg: &Dfg) -> bool {
    // let mut color_map = HashMap::new();
    let mem_writes = get_strided_accesses(dfg, false);
    if mem_writes.is_empty() {
        println!("No strided memory accesses found. Probably not vectorizable");
        return false;
    }

    for (p, partition) in mem_writes.iter().enumerate() {
        println!("partition: {}", p);
        let trees = Box::new(
            partition
                .iter()
                .map(|sink| {
                    let t = Tree::from_graph(dfg, sink.1);
                    println!("Tree for 0x{:x} @ IP: 0x{:x}", sink.2, sink.0);
                    Box::new(t)
                })
                .collect::<Vec<_>>(),
        );
        println!("Analyzing trees in partition");
        if trees.windows(2).map(|ts| ts[0] == ts[1]).all(|p| p) {
            println!("Every tree in partition is the same -> vectorizable");
        } else {
            println!("This is not vectorizable! Big tragedy");
            return false;
        }
    }
    true
}

/// `Tree` data structure used to perform the comparison between different dataflows
/// to see if they can be vectorized
#[derive(Debug)]
struct Tree {
    t: DiGraph<u64, ()>,
    sources: Vec<NodeIndex>,
    sink_idx: NodeIndex,
}

impl Tree {
    /// Creates a `Tree` from a node in the `Dfg` that is a memory write operation
    pub fn from_graph(dfg: &Dfg, idx: NodeIndex) -> Self {
        let root = dfg.get_write_ip(idx).unwrap();
        let mut t = DiGraph::new();
        let tree_idx = t.add_node(root);
        let mut tree = Self {
            t,
            sources: vec![],
            sink_idx: tree_idx,
        };
        let next_idx = dfg
            .graph
            .neighbors_directed(idx, petgraph::Direction::Incoming)
            .next()
            .unwrap();
        tree.append_tree(dfg, next_idx, tree_idx);
        tree
    }

    /// Helper function to create a tree from a node in the `Dfg`
    fn append_tree(&mut self, dfg: &Dfg, graph_idx: NodeIndex, tree_iddx: NodeIndex) {
        let mut is_source = true;
        for next_graph_idx in dfg
            .graph
            .neighbors_directed(graph_idx, petgraph::Direction::Incoming)
        {
            is_source = false;
            let next_tree_idx = self.t.add_node(dfg.get_read_ip(graph_idx).unwrap());
            self.t.add_edge(tree_iddx, next_tree_idx, ());
            self.append_tree(dfg, next_graph_idx, next_tree_idx);
        }
        if is_source {
            self.sources.push(graph_idx);
        }
    }

    /// Saves the `Tree` to a png file
    pub fn save(&self, name: &str) {
        let png = exec_dot(
            format!("{:?}", Dot::with_config(&self.t, &[])),
            vec![Format::Png.into()],
        )
        .unwrap();
        File::create(format!("{}.png", name))
            .unwrap()
            .write_all(&png)
            .unwrap();
    }

    /// Helper function to implement the `PartialEq` and `Eq` trait for `Tree`.
    fn eq_subtree(&self, other: &Self, self_idx: NodeIndex, other_idx: NodeIndex) -> bool {
        let mut stack = vec![(self_idx, other_idx)];

        while let Some((self_idx, other_idx)) = stack.pop() {
            if self.t[self_idx] != other.t[other_idx] {
                return false;
            }

            let a_prev = self
                .t
                .neighbors_directed(self_idx, Outgoing)
                .collect::<Vec<_>>();
            let b_prev = other
                .t
                .neighbors_directed(other_idx, Outgoing)
                .collect::<Vec<_>>();

            if a_prev.len() != b_prev.len() {
                return false;
            }

            if a_prev.len() == 1 {
                stack.push((a_prev[0], b_prev[0]));
            } else if a_prev.len() == 2 {
                if self.t[a_prev[0]] == other.t[b_prev[0]] {
                    stack.push((a_prev[0], b_prev[0]));
                    stack.push((a_prev[1], b_prev[1]));
                } else {
                    stack.push((a_prev[0], b_prev[1]));
                    stack.push((a_prev[1], b_prev[0]));
                }
            }
        }

        true
    }
}

impl Eq for Tree {}
impl PartialEq for Tree {
    fn eq(&self, other: &Self) -> bool {
        self.eq_subtree(other, self.sink_idx, other.sink_idx)
    }
}

/// Returns all the memory accesses that are strided in the `Dfg`. They are partitioned into classes
/// with the same ip.
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
    let mut mm_partitions: HashMap<u64, Vec<(u64, NodeIndex, u64)>> = HashMap::new();
    for mm in mem_accesses {
        match mm_partitions.entry(mm.0) {
            Entry::Occupied(mut o) => {
                o.get_mut().push(mm);
            }
            Entry::Vacant(v) => {
                v.insert(vec![mm]);
            }
        }
    }

    let mut v = vec![];
    for (ip, list) in mm_partitions {
        let mut addrs = list.iter().map(|e| e.2).collect::<Vec<_>>();
        if let Some(stride) = addrs_strided(&mut addrs) {
            println!("Stride({}) is always the same for ip: {:x}!", stride, ip);
            v.push(list);
        }
    }
    v
}

/// Returns the stride of the address is possible to determine
fn addrs_strided(addrs: &mut [u64]) -> Option<u64> {
    addrs.sort();
    let mut strides = addrs.iter().zip(addrs.iter().skip(1)).map(|(l, h)| h - l);
    if strides.clone().max() == strides.clone().min() {
        strides.next().or(Some(0))
    } else {
        None
    }
}
