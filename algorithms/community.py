# algorithms/community.py

import networkx as nx
from typing import Dict, List
import community as community_louvain  # pip install python-louvain

def detect_attack_communities(G: nx.DiGraph) -> Dict:
    """
    Louvain Community Detection (modularity maximisation).

    INSIGHT: Kubernetes best practice is namespace isolation — separate 
    workloads into pods that CANNOT reach each other. Louvain finds natural 
    "communities" (clusters of highly-interconnected nodes). 

    Security Application:
    If two nodes in DIFFERENT namespaces land in the SAME community, 
    there is a hidden cross-namespace trust relationship that VIOLATES the 
    principle of least privilege — a misconfiguration that no RBAC reviewer 
    would spot manually.

    Algorithm: Greedy modularity maximisation.
    Time complexity: O(n log n) — fast even on large clusters.
    """
    # Louvain requires undirected graph — we use the underlying structure
    UG = G.to_undirected()

    # Assign weights so high-risk edges attract community membership
    for u, v, d in UG.edges(data=True):
        d["weight"] = d.get("cvss", 0) + 1  # +1 to avoid zero weights

    partition = community_louvain.best_partition(UG, weight="weight")

    # Group nodes by community
    communities: Dict[int, List[str]] = {}
    for node, comm_id in partition.items():
        communities.setdefault(comm_id, []).append(node)

    # Detect cross-namespace communities (security violation)
    violations = []
    for comm_id, members in communities.items():
        namespaces = set(G.nodes[n].get("namespace", "?") for n in members)
        if len(namespaces) > 1:
            violations.append({
                "community_id":  comm_id,
                "members":       members,
                "namespaces":    list(namespaces),
                "violation":     "Cross-namespace trust — violates least privilege",
            })

    return {
        "num_communities": len(communities),
        "partition":       partition,
        "communities":     communities,
        "cross_namespace_violations": violations,
    }