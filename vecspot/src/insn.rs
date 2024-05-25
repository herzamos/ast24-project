use crate::trace::{TraceBinOp, TraceMemOp, TraceMemOpType, TraceOperation, TracePoint};

/// Due to some issues with operations like `add %rcx, 0x8(%rdx, %rax)` resulting in
/// `*invalid*` registers we resolve the issue by combining `TracePoint`s with the same
/// ip into a `TraceInstruction`. This will then be turned into a `TracePoint` for
/// the dataflow graph creation.
#[derive(Debug, Default)]
pub struct TraceInstruction {
    ip: u64,
    read: Option<TraceMemOp>,
    binop: Option<TraceBinOp>,
    write: Option<TraceMemOp>,
}

impl TraceInstruction {
    fn add_memop(&mut self, memop: &TraceMemOp) -> bool {
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

    /// Turns a vector of `TraceInstruction`s into a vector of `TracePoint`s to be converted
    /// into the dataflow graph
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

    /// Turns a vector of `TracePoint`s into a vector of the more expressive `TraceInstruction`.
    pub fn combine(trace_points: Vec<TracePoint>) -> Vec<TraceInstruction> {
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
