import angr
import networkx as nx
import matplotlib.pyplot as plt

binary_path = 'ass'
project = angr.Project(binary_path, load_options={'auto_load_libs': False})

cfg = project.analyses.CFG()
vfg = project.analyses.VFG(cfg)

nx_graph = nx.DiGraph()
for node in vfg._nodes:
    nx_graph.add_node(node)
    for successor in vfg.successors(node):
        nx_graph.add_edge(node, successor)

plt.figure(figsize=(10, 10))
nx.draw(nx_graph, with_labels=True, font_weight='bold')
plt.show()