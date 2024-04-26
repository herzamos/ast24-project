

import angr
import claripy

def trace_memory_to_register_movements(binary_path):
    project = angr.Project(binary_path, load_options={'auto_load_libs': False})

    state = project.factory.entry_state()
    simgr = project.factory.simulation_manager(state)

    last_mem_read = {}

    # Trace every memory read, and put the last access into the last_mem_read dictionary
    # When tracing register reads, check whether we are loading from this memory address
    def trace_mem_read(state):
        if state.inspect.mem_read_address is not None:
            # Store the address and data size of the read
            address = state.solver.eval(state.inspect.mem_read_address)
            value = state.solver.eval(state.inspect.mem_read_expr)
            print(f"{hex(state.addr)}: MEM READ @ {hex(address)} -> {value}")
            size = state.inspect.mem_read_length
            last_mem_read[state.addr] = (address, size)

    # Trace every register write and combine with information from last_mem_read
    def trace_reg_write(state):
        reg_offset = state.solver.eval(state.inspect.reg_write_offset)
        reg_name = state.arch.register_names[reg_offset]
        value = state.solver.eval(state.inspect.reg_write_expr)
        if reg_name != 'rip' and "cc" not in reg_name:
            print(f"{hex(state.addr)}: REG WRITE {reg_name} <- {value}")

    def trace_reg_read(state):
        # if state.inspect.reg_write_offset is None or state.addr not in last_mem_read:
        #     print("xdd")
        #     pass
        
        # print("A")
        reg_offset = state.solver.eval(state.inspect.reg_read_offset)
        print("CANE", reg_offset)
        reg_name = state.arch.register_names[reg_offset]
        # if reg_name != 'rip':
        print(f"{hex(state.addr)}: reading from {reg_name}")

    def trace_tmp_write(state):
        pass
    
    def trace_tmp_read(state):
        tmp_offset = state.solver.eval(state.inspect.tmp_read_num)
        # reg_name = state.arch.register_names[reg_offset]
        # if reg_name != 'rip':
        print(f"{hex(state.addr)}: reading from t{tmp_offset}: {state.inspect.tmp_read_expr}")

        # if state.inspect.reg_write_offset is not None and state.addr in last_mem_read:
        #     reg_offset = state.solver.eval(state.inspect.reg_write_offset)
        #     print("reg offset", reg_offset)
        #     reg_name = state.arch.register_names[state.inspect.reg_write_offset]
        #     print(reg_name)
        #     mem_address, size = last_mem_read[state.addr]
        #     print(f"Data moved from memory {mem_address} to register {reg_name}")

    state.inspect.b('mem_read', when=angr.BP_AFTER, action=trace_mem_read)
    # state.inspect.b('reg_read', when=angr.BP_BEFORE, action=trace_reg_read)
    state.inspect.b('reg_write', when=angr.BP_BEFORE, action=trace_reg_write)

    # state.inspect.b("tmp_read", when=angr.BP_AFTER, action=trace_tmp_read)

    def handle_state(state):
        print(f"Reached deadend at address 0x{hex(state.addr)}")

    simgr.run()
    for a in simgr.deadended:
        handle_state(a)

    print("\nAccess dictionary")
    for r in last_mem_read:
        address, size = last_mem_read[r]
        print(hex(r), ": ", hex(address), ", size: ", size)

binary_path = 'ass'
trace_memory_to_register_movements(binary_path)