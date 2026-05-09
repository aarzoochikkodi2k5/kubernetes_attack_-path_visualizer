# algorithms/astar.py

import networkx as nx
import heapq
from typing import Dict, Callable

def heuristic(G: nx.DiGraph, node: str, target: str) -> float:
    """
    Admissible heuristic: estimated remaining cost to reach target.
    
    We use the node's risk_score as a proxy — higher risk nodes are
    "closer" to the crown jewel in attacker-relevance space.
    
    h(n) must never OVERESTIMATE the true cost (admissibility condition).
    Since minimum edge weight in our graph is 0.5, and risk scores are
    bounded by 10, we divide by 10 to keep h(n) ≤ true cost.
    
    In a real cluster, you could use namespace distance, RBAC hop count,
    or a learned embedding distance (GNN approach — see below).
    """
    target_risk = G.nodes[target].get("risk_score", G.nodes[target].get("risk", 5.0))
    node_risk   = G.nodes[node].get("risk_score",   G.nodes[node].get("risk",   5.0))
    # Closer in risk score = heuristically closer in attack graph
    return abs(target_risk - node_risk) / 10.0


def astar_attack_path(G: nx.DiGraph, source: str, target: str) -> Dict:
    """
    A* on the attack graph.
    
    g(n) = actual cost from source to n (sum of edge weights)
    h(n) = heuristic estimate from n to target
    f(n) = g(n) + h(n)  ← what the priority queue sorts by
    
    Contrast with Dijkstra: Dijkstra uses only g(n).
    On a 10,000-node cluster graph, A* can be 5-10x faster than Dijkstra
    because it doesn't waste time exploring nodes far from the target.
    
    Security insight: this models a SMART attacker who picks the highest
    value target and navigates toward it efficiently, not randomly.
    """
    if source not in G or target not in G:
        return {"found": False, "reason": "Node not in graph"}

    # Priority queue: (f_score, node, path, g_score)
    h0 = heuristic(G, source, target)
    pq = [(h0, 0.0, source, [source])]
    visited = {}

    while pq:
        f, g, current, path = heapq.heappop(pq)

        if current == target:
            # Annotate path with hop metadata
            hops = []
            total_risk = 0.0
            for i in range(len(path) - 1):
                u, v = path[i], path[i+1]
                edge = G.edges[u, v]
                n_risk = G.nodes[v].get("risk_score", G.nodes[v].get("risk", 0))
                cvss   = edge.get("cvss", 0.0)
                total_risk += (cvss + n_risk) / 2
                hops.append({
                    "from": u, "to": v,
                    "relationship": edge.get("relationship", edge.get("rel", "?")),
                    "edge_weight":  edge.get("weight"),
                    "cvss": cvss, "node_risk": n_risk,
                    "misconfig": edge.get("misconfig", False),
                    "cves": G.nodes[v].get("cves", []),
                })
            severity = (
                "CRITICAL" if total_risk >= 30 else
                "HIGH"     if total_risk >= 20 else
                "MEDIUM"   if total_risk >= 10 else "LOW"
            )
            return {
                "found": True, "algorithm": "A*",
                "source": source, "target": target,
                "path": path, "hops": hops,
                "hop_count": len(path) - 1,
                "g_cost": round(g, 3),         # actual path cost
                "total_risk": round(total_risk, 2),
                "severity": severity,
            }

        if current in visited and visited[current] <= g:
            continue
        visited[current] = g

        for neighbor in G.successors(current):
            edge_w = G.edges[current, neighbor].get("weight", 1.0)
            new_g  = g + edge_w
            new_h  = heuristic(G, neighbor, target)
            new_f  = new_g + new_h
            heapq.heappush(pq, (new_f, new_g, neighbor, path + [neighbor]))

    return {"found": False, "source": source, "target": target}