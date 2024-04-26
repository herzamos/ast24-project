import angr
from angr.block import CapstoneInsn
import capstone
import pyvex

trace = [None]

def trace_memory_access(state: angr.SimState):
    # Function to be called on memory read/write
    #print(f"Memory access at {state.inspect.mapped_address}, size {state.inspect.mem_length}")
    block: angr.Block = state.block(num_inst=1)

    # If already appended don't add again
    if trace[-1] != (state.regs, block):
        trace.append((state.regs, block))
    
    # print(state.regs._rax)
    # instr: CapstoneInsn = block.capstone.insns[0]
    # vex = block.vex
    # print("@" * 60)
    # print(instr)
    # print("#" * 40)
    # vex.pp()
    # print("$" * 20, "eval", "$" * 20)
    # for stmt in vex.statements:
    #     # Use this maybe stmt.replace_expression()
    #     if isinstance(stmt, pyvex.IRStmt.Put):
    #         print(stmt)
    #         a: pyvex.IRStmt.Put = stmt
    #         print(a.offset)
    #         print(a.data)

        # print(stmt)
    # print(block.capstone.insns[0])

def dataflow_analysis(binary_path):
    project = angr.Project(binary_path, load_options={'auto_load_libs': False})

    entry_state = project.factory.entry_state()

    # Hook memory events
    entry_state.inspect.b('mem_write', when=angr.BP_BEFORE, action=trace_memory_access)
    entry_state.inspect.b('reg_write', when=angr.BP_BEFORE, action=trace_memory_access)

    simgr = project.factory.simgr(entry_state)

    def handle_state(state):
        print(f"Reached deadend at address 0x{hex(state.addr)}")

    simgr.run()
    for a in simgr.deadended:
        handle_state(a)

dataflow_analysis("add")

    # print(state.registers.load("rax"))
print("Length of the trace in pyvex blocks: ", len(trace))
state, block = trace[-25]
instr: CapstoneInsn = block.capstone.insns[0]
block: angr.Block = block
vex = block.vex
print("@" * 60)
print(instr)
print("#" * 40)
vex.pp()

for stmt in vex.statements:
    if isinstance(stmt, pyvex.IRStmt.Put):
        print(stmt)
        t6 = pyvex.IRExpr.RdTmp(6)
        t6p = pyvex.IRExpr.Const(pyvex.IRExpr.U8(16))
        stmt.replace_expression({t6: t6p})

        print(stmt)