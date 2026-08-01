import time
import sys
import os
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from temporal.snapshot   import save_snapshot
from temporal.comparator import compare_snapshots
from temporal.database   import init_database, store_in_db

from graph.builder       import ClusterGraph
from algorithms.dijkstra import shortest_attack_path
from algorithms.dfs      import detect_cycles
from algorithms.pagerank import security_pagerank
from algorithms.monte_carlo import monte_carlo_attack


def run_full_scan():
    cg = ClusterGraph()
    cg.build_from_mock()
    G = cg.G

    crown_jewels = cg.crown_jewels
    entry_points = cg.entry_points

    all_paths = []
    for ep in entry_points:
        for cj in crown_jewels:
            result = shortest_attack_path(G, ep, cj)
            if result.get("found"):
                all_paths.append(result["path"])

    cycle_result = detect_cycles(G)
    pr_result    = security_pagerank(G)
    mc_result    = monte_carlo_attack(G, entry_points[0], crown_jewels)

    misconfigs = [
        (u, v)
        for u, v, d in G.edges(data=True)
        if d.get("misconfig", False)
    ]

    mc_scores = [
        v["compromise_probability"]
        for v in mc_result.get("crown_jewel_risk", {}).values()
        if isinstance(v, dict) and "compromise_probability" in v
    ]
    max_mc = max(mc_scores) if mc_scores else 0.0

    return {
        "node_count":      G.number_of_nodes(),
        "edge_count":      G.number_of_edges(),
        "attack_paths":    all_paths,
        "cycles":          cycle_result.get("cycles", []),
        "monte_carlo_score": max_mc,
        "pagerank":        pr_result.get("pagerank_scores", {}),
        "misconfigs":      misconfigs,
    }


def print_alert_box(changes):
    print("\n" + "!" * 55)
    print("  🚨 SECURITY ALERT DETECTED")
    print("!" * 55)
    for alert in changes["alerts"]:
        lvl = alert["level"]
        msg = alert["message"]
        icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","INFO":"🟢"}.get(lvl,"·")
        print(f"  {icon} [{lvl}] {msg}")
    print("!" * 55 + "\n")


def temporal_monitor(interval=30):
    print("=" * 55)
    print("  KAPV Temporal Monitor v1.0")
    print("=" * 55)

    conn              = init_database()
    previous_snapshot = None
    scan_count        = 0

    while True:
        scan_count += 1
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[Scan #{scan_count}] {now}")

        try:
            graph_data       = run_full_scan()
            current_snapshot = save_snapshot(graph_data)

            if previous_snapshot is not None:
                changes = compare_snapshots(previous_snapshot,
                                            current_snapshot)
                store_in_db(conn, current_snapshot, changes)

                if changes["is_dangerous"]:
                    print_alert_box(changes)
                else:
                    risk  = current_snapshot["monte_carlo_risk"]
                    paths = current_snapshot["attack_paths_count"]
                    cyc   = current_snapshot["privilege_cycles"]
                    print(f"  ✅ STABLE | Risk: {risk*100:.1f}%"
                          f" | Paths: {paths} | Cycles: {cyc}")
                    if changes["alerts"]:
                        for a in changes["alerts"]:
                            print(f"     [{a['level']}] {a['message']}")
            else:
                print(f"  📸 Baseline snapshot saved.")
                print(f"     Nodes: {current_snapshot['total_nodes']}"
                      f" | Edges: {current_snapshot['total_edges']}"
                      f" | Paths: {current_snapshot['attack_paths_count']}")
                store_in_db(conn, current_snapshot, {"risk_delta": 0.0, "is_dangerous": False, "alerts": []})

            previous_snapshot = current_snapshot

        except Exception as e:
            print(f"  ❌ Scan failed: {e}")

        print(f"  ⏱  Next scan in {interval}s...")
        time.sleep(interval)


if __name__ == "__main__":
    temporal_monitor(interval=30)
