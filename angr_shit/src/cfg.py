import angr
import networkx as nx
import matplotlib.pyplot as plt

proj = angr.Project("test", load_options={"auto_load_libs": False})

cfg = proj.analyses.CFGFast()

main_f = cfg.kb.functions.function(name="main")

for node in cfg.graph.nodes():
    if node.function_address == main_f.addr:
        print(f"Basic Block: {hex(node.addr)}, ends at {hex(node.addr + node.size)}")



def draw_cfg(cfg, name='main'):
    # Find the main function and get its blocks
    main_function = cfg.kb.functions.function(name=name)
    main_blocks = [node for node in cfg.graph.nodes() if node.function_address == main_function.addr]

    # Create a subgraph containing only the nodes within the main function
    subgraph = cfg.graph.subgraph(main_blocks)

    # Use the Kamada-Kawai layout for better visualization of complex graphs
    pos = nx.kamada_kawai_layout(subgraph)  # This layout tries to spread nodes evenly

    # Draw the nodes
    nx.draw_networkx_nodes(subgraph, pos, node_size=700, node_color='skyblue')

    # Draw the edges
    nx.draw_networkx_edges(subgraph, pos, arrowstyle='->', arrowsize=20, edge_color='gray')

    # Draw labels on the nodes
    nx.draw_networkx_labels(subgraph, pos, font_size=8, font_color='darkred')

    # Optionally, draw edge labels to show more information about transitions
    edge_labels = {(u.addr, v.addr): f"{u.addr}->{v.addr}" for u, v in subgraph.edges()}
    nx.draw_networkx_edge_labels(subgraph, pos, edge_labels=edge_labels, font_color='green')

    # Show the plot
    plt.title('CFG of Main Function')
    plt.show()

draw_cfg(cfg)
