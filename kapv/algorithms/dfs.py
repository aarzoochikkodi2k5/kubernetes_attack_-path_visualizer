# algorithms/dfs.py

import networkx as nx
from typing import List, Dict

def detect_cycles(G: nx.DiGraph) -> Dict:
    """
    DFS-based cycle detection using Johnson's algorithm (via NetworkX).

    Why Johnson's and not simple DFS?
    Simple DFS finds IF cycles exist. Johnson's finds ALL elementary cycles
    in O((n+e)(c+1)) time — essential for enumerating every privilege loop.

    Cycles in a Kubernetes RBAC graph represent mutual admin grants where
    Service-A can escalate to Service-B which can escalate back — 
    this doubles the effective blast radius of any node in the cycle.
    """
    all_cycles = list(nx.simple_cycles(G))

    annotated = []
    for cycle in all_cycles:
        risk_nodes = [
            G.nodes[n].get("risk_score", G.nodes[n].get("risk", 0))
            for n in cycle
        ]
        misconfig_edges = sum(
            1 for i in range(len(cycle))
            for u, v in [(cycle[i], cycle[(i+1) % len(cycle)])]
            if G.has_edge(u, v) and G.edges[u, v].get("misconfig", False)
        )
        annotated.append({
            "cycle":              cycle,
            "length":             len(cycle),
            "max_node_risk":      max(risk_nodes),
            "avg_node_risk":      round(sum(risk_nodes)/len(risk_nodes), 2),
            "misconfig_edges":    misconfig_edges,
            "severity":           "CRITICAL" if max(risk_nodes) >= 8 else "HIGH",
        })

    # Sort by danger (most risky first)
    annotated.sort(key=lambda x: x["max_node_risk"], reverse=True)

    return {
        "total_cycles": len(annotated),
        "cycles":       annotated,
    }