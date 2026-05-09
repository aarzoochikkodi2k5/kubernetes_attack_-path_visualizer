# algorithms/bfs.py

from collections import deque
from typing import Dict, Set
import networkx as nx

def blast_radius(G: nx.DiGraph, source: str, max_hops: int = 3) -> Dict:
    """
    BFS from a compromised node.
    Returns all reachable nodes within max_hops, grouped by hop distance.

    Why BFS and not DFS here?
    BFS is level-order — it gives you EXACT hop distances, which maps
    perfectly to "how many lateral moves does an attacker need?".
    DFS would give reachability but not minimum hop distance.
    """
    if source not in G:
        raise ValueError(f"Node '{source}' not in graph.")

    visited: Dict[str, int] = {source: 0}   # node → hop_count
    queue = deque([(source, 0)])
    danger_zone: Dict[int, list] = {}

    while queue:
        node, hop = queue.popleft()

        if hop >= max_hops:
            continue

        for neighbor in G.successors(node):
            if neighbor not in visited:
                new_hop = hop + 1
                visited[neighbor] = new_hop
                danger_zone.setdefault(new_hop, []).append({
                    "node":       neighbor,
                    "type":       G.nodes[neighbor].get("entity_type", G.nodes[neighbor].get("type")),
                    "risk_score": G.nodes[neighbor].get("risk_score",  G.nodes[neighbor].get("risk")),
                    "edge_data":  G.edges[node, neighbor],
                })
                queue.append((neighbor, new_hop))

    return {
        "source":     source,
        "max_hops":   max_hops,
        "total_reach": len(visited) - 1,   # exclude source itself
        "danger_zone": danger_zone,
    }