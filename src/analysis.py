import angr

def trace_memory_access(state):
    # Function to be called on memory read/write
    #print(f"Memory access at {state.inspect.mapped_address}, size {state.inspect.mem_length}")
    print(state)

def dataflow_analysis(binary_path):
    # Load the binary
    project = angr.Project(binary_path, load_options={'auto_load_libs': False})
    # project.hook_symbol("main",)

    # Entry state for the analysis
    entry_state = project.factory.entry_state()

    # Hook memory events
    entry_state.inspect.b('mem_read', when=angr.BP_BEFORE, action=trace_memory_access)
    entry_state.inspect.b('mem_write', when=angr.BP_BEFORE, action=trace_memory_access)

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
