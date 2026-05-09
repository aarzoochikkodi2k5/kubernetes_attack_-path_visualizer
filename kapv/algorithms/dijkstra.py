# algorithms/dijkstra.py

import networkx as nx
from typing import List, Optional, Dict

def shortest_attack_path(G: nx.DiGraph, source: str, target: str) -> Dict:
    """
    Dijkstra's algorithm using edge 'weight' (exploitability cost).
    Lower weight = attacker can traverse more easily.

    NetworkX's dijkstra_path uses the 'weight' attribute by default.
    We augment the result with per-hop metadata and a total risk score.

    Risk score = sum of (edge_cvss * node_risk) per hop — composite metric.
    """
    try:
        path = nx.dijkstra_path(G, source, target, weight="weight")
        cost = nx.dijkstra_path_length(G, source, target, weight="weight")
    except nx.NetworkXNoPath:
        return {"found": False, "source": source, "target": target}
    except nx.NodeNotFound as e:
        raise ValueError(str(e))

    # Annotate each hop
    hops = []
    total_risk = 0.0
    for i in range(len(path) - 1):
        u, v = path[i], path[i+1]
        edge  = G.edges[u, v]
        n_risk = G.nodes[v].get("risk_score", G.nodes[v].get("risk", 0))
        cvss   = edge.get("cvss", 0.0)
        hop_risk = (cvss + n_risk) / 2  # normalised hop risk
        total_risk += hop_risk

        hops.append({
            "from":          u,
            "to":            v,
            "relationship":  edge.get("relationship", edge.get("rel", "?")),
            "edge_weight":   edge.get("weight"),
            "cvss":          cvss,
            "misconfig":     edge.get("misconfig", False),
            "node_risk":     n_risk,
            "cves":          G.nodes[v].get("cves", []),
        })

    severity = (
        "CRITICAL" if total_risk >= 30 else
        "HIGH"     if total_risk >= 20 else
        "MEDIUM"   if total_risk >= 10 else "LOW"
    )

    return {
        "found":       True,
        "source":      source,
        "target":      target,
        "path":        path,
        "hops":        hops,
        "hop_count":   len(path) - 1,
        "dijkstra_cost": round(cost, 3),
        "total_risk":  round(total_risk, 2),
        "severity":    severity,
    }