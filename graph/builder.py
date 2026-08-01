import networkx as nx
from typing import Dict, Any
from graph.schema import NodeData, EdgeData, EntityType, RelationshipType
from ingestion.mock_loader import load_mock_cluster

class ClusterGraph:
    """
    Wraps a NetworkX DiGraph with typed node/edge metadata.
    The graph is a Directed Weighted Multigraph — edges carry
    exploitability weights so Dijkstra can find the "cheapest" path.
    Lower weight = easier to exploit = higher danger.
    """

    def __init__(self):
        self.G: nx.DiGraph = nx.DiGraph()
        self.crown_jewels = []
        self.entry_points  = []

    def build_from_mock(self) -> None:
        data = load_mock_cluster()
        self._load_nodes(data["nodes"])
        self._load_edges(data["edges"])
        self.crown_jewels = [n for n, d in self.G.nodes(data=True) if d.get("crown")]
        self.entry_points  = [n for n, d in self.G.nodes(data=True) if d.get("entry")]

    def _load_nodes(self, nodes):
        for n in nodes:
            self.G.add_node(
                n["id"],
                entity_type = n["type"],
                namespace   = n["namespace"],
                risk_score  = n["risk"],
                crown       = n.get("crown", False),
                entry       = n.get("entry", False),
                cves        = n.get("cves", []),
            )

    def _load_edges(self, edges):
        for e in edges:
            self.G.add_edge(
                e["src"], e["dst"],
                relationship = e["rel"],
                weight       = e["weight"],
                cvss         = e.get("cvss", 0.0),
                misconfig    = e.get("misconfig", False),
            )

    def summary(self) -> Dict[str, Any]:
        return {
            "nodes":        self.G.number_of_nodes(),
            "edges":        self.G.number_of_edges(),
            "crown_jewels": self.crown_jewels,
            "entry_points": self.entry_points,
        }
