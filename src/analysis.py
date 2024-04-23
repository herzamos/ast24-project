import angr
from angr.block import CapstoneInsn
import capstone
import pyvex

trace = [None]

def trace_memory_access(state: angr.SimState):
    # Function to be called on memory read/write
    #print(f"Memory access at {state.inspect.mapped_address}, size {state.inspect.mem_length}")
    block: angr.Block = state.block(num_inst=1)
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
    # Load the binary
    project = angr.Project(binary_path, load_options={'auto_load_libs': False})
    # project.hook_symbol("main",)

    # Entry state for the analysis
    entry_state = project.factory.entry_state()

    # Hook memory events
    # entry_state.inspect.b('mem_read', when=angr.BP_BEFORE, action=trace_memory_access)
    entry_state.inspect.b('mem_write', when=angr.BP_BEFORE, action=trace_memory_access)
    # entry_state.inspect.b('reg_read', when=angr.BP_BEFORE, action=trace_memory_access)
    entry_state.inspect.b('reg_write', when=angr.BP_BEFORE, action=trace_memory_access)

    # Setup a simulation manager
    simgr = project.factory.simgr(entry_state)

    # Define a simple function to handle the state of each deadend
    def handle_state(state):
        print(f"Reached deadend at address {state.addr}")
        # Optionally, here you could analyze state further or dump state data

    # Run the analysis and apply the handler function to each deadend
    simgr.run()
    for a in simgr.deadended:
        handle_state(a)

dataflow_analysis("test")

    # print(state.registers.load("rax"))
print(len(trace))
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
        t0 = pyvex.IRExpr.RdTmp(0)
        t0p = pyvex.IRExpr.Const(pyvex.IRExpr.U8(16))
        stmt.replace_expression({t0: t0p})

        print(stmt)

