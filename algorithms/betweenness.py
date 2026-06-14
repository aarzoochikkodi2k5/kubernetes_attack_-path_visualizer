# algorithms/betweenness.py

import networkx as nx
from typing import Dict

def attack_betweenness(G: nx.DiGraph) -> Dict:
    """
    Betweenness Centrality: for each node v, counts what fraction of all 
    shortest paths between all pairs (s, t) pass through v.

    Security Interpretation:
    A node with high betweenness is a structural BRIDGE in the attack graph.
    Patching it doesn't just stop ONE attack path — it interrupts ALL paths 
    that must route through that node, making it the highest-leverage 
    remediation target.

    Difference from PageRank:
    - PageRank: "How many attack SOURCES can reach me?"
    - Betweenness: "How many attack SOURCE→TARGET paths MUST pass through me?"
    
    For a security team with limited patch budget, betweenness is the 
    better metric for prioritising remediation.

    Uses Brandes' algorithm: O(VE) for unweighted, O(VE + V²logV) weighted.
    """
    bc = nx.betweenness_centrality(G, weight="weight", normalized=True)

    # Also compute edge betweenness — identifies critical TRUST RELATIONSHIPS
    ebc = nx.edge_betweenness_centrality(G, weight="weight", normalized=True)

    top_nodes = sorted(bc.items(), key=lambda x: x[1], reverse=True)[:10]
    top_edges = sorted(ebc.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "node_betweenness": bc,
        "edge_betweenness": ebc,
        "top_bottleneck_nodes": [
            {
                "node":       n,
                "centrality": round(c, 6),
                "type":       G.nodes[n].get("type", "?"),
            }
            for n, c in top_nodes
        ],
        "top_bottleneck_edges": [
            {
                "edge":       f"{u} → {v}",
                "centrality": round(c, 6),
                "rel":        G.edges[u,v].get("relationship", G.edges[u,v].get("rel","?")),
            }
            for (u,v), c in top_edges
        ],
    }