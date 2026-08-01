import json
import time
import os
from datetime import datetime


def save_snapshot(graph_data):
    """
    graph_data is the dict your main.py already produces.
    We just extract and save the key metrics.
    """
    snapshot = {
        "timestamp":          datetime.now().isoformat(),
        "unix_time":          time.time(),
        "total_nodes":        graph_data["node_count"],
        "total_edges":        graph_data["edge_count"],
        "attack_paths_count": len(graph_data["attack_paths"]),
        "privilege_cycles":   len(graph_data["cycles"]),
        "monte_carlo_risk":   graph_data["monte_carlo_score"],
        "pagerank_scores":    graph_data["pagerank"],
        "attack_paths":       graph_data["attack_paths"],
        "misconfigs":         graph_data["misconfigs"],
    }

    os.makedirs("snapshots", exist_ok=True)
    filename = f"snapshots/snapshot_{int(time.time())}.json"
    with open(filename, "w") as f:
        json.dump(snapshot, f, indent=2)

    print(f"  [Snapshot saved] → {filename}")
    return snapshot
