# main.py

import argparse
import sys
import json

from graph.builder import ClusterGraph
from algorithms.bfs        import blast_radius
from algorithms.dijkstra   import shortest_attack_path
from algorithms.dfs        import detect_cycles
from algorithms.pagerank   import security_pagerank
from algorithms.betweenness import attack_betweenness
from algorithms.community   import detect_attack_communities
from ai.risk_predictor     import train_risk_model, extract_node_features
from ai.anomaly_detector   import detect_anomalous_nodes
from ai.temporal_analyzer  import forecast_node_risk
from reporting.kill_chain  import generate_report


def parse_args():
    parser = argparse.ArgumentParser(
        description="KAPV — Kubernetes Attack Path Visualizer"
    )
    parser.add_argument("--source",  default="lb-frontend",  help="Entry point node ID")
    parser.add_argument("--target",  default="db-production", help="Crown jewel node ID")
    parser.add_argument("--hops",    type=int, default=3,    help="Max hops for BFS")
    parser.add_argument("--mock",    action="store_true",    help="Use mock cluster data")
    parser.add_argument("--output",  default=None,           help="Save report to file")
    parser.add_argument("--json",    action="store_true",    help="Output raw JSON")
    return parser.parse_args()


def main():
    args = parse_args()

    print("[*] Building cluster graph...")
    cg = ClusterGraph()
    cg.build_from_mock()   # swap with build_from_kubectl() for live cluster
    G  = cg.G
    summary = cg.summary()

    print(f"[*] Graph: {summary['nodes']} nodes, {summary['edges']} edges")
    print(f"[*] Crown jewels : {summary['crown_jewels']}")
    print(f"[*] Entry points : {summary['entry_points']}")

    # ── 1. BFS Blast Radius ────────────────────────────────────────────────
    print("[*] Running BFS blast radius analysis...")
    blast_results = []
    for ep in summary["entry_points"][:3]:  # limit for demo
        blast_results.append(blast_radius(G, ep, max_hops=args.hops))

    # ── 2. Dijkstra Attack Paths ───────────────────────────────────────────
    print("[*] Running Dijkstra shortest attack path analysis...")
    attack_paths = []
    for ep in summary["entry_points"]:
        for cj in summary["crown_jewels"]:
            result = shortest_attack_path(G, ep, cj)
            attack_paths.append(result)

    # ── 3. DFS Cycle Detection ────────────────────────────────────────────
    print("[*] Running DFS cycle detection...")
    cycle_results = detect_cycles(G)

    # ── 4. PageRank Critical Node ─────────────────────────────────────────
    print("[*] Running Security PageRank...")
    pagerank_results = security_pagerank(G)

    # ── 5. Betweenness ────────────────────────────────────────────────────
    print("[*] Running betweenness centrality analysis...")
    betweenness_results = attack_betweenness(G)

    # ── 6. Community Detection ────────────────────────────────────────────
    print("[*] Running Louvain community detection...")
    try:
        community_results = detect_attack_communities(G)
    except Exception as e:
        community_results = {"num_communities": 0, "cross_namespace_violations": [], "error": str(e)}

    # ── 7. AI Risk Prediction ─────────────────────────────────────────────
    print("[*] Training AI risk prediction model (XGBoost)...")
    ai_predictions = train_risk_model(G)

    # ── 8. Anomaly Detection ──────────────────────────────────────────────
    print("[*] Running Isolation Forest anomaly detection...")
    X, node_ids, _ = extract_node_features(G)
    anomaly_results = detect_anomalous_nodes(G, X, node_ids)

    # ── 9. Temporal Forecasting (simulated history) ───────────────────────
    print("[*] Running temporal risk forecasting...")
    # Simulate 5 days of historical data with slight upward trends
    import random
    risk_history = {}
    for node in G.nodes():
        base = G.nodes[node].get("risk_score", G.nodes[node].get("risk", 3.0))
        history = [round(base + random.gauss(0, 0.3) + i * 0.15, 2) for i in range(5)]
        risk_history[node] = history
    temporal_results = forecast_node_risk(risk_history, forecast_days=7)

    # ── Generate Report ───────────────────────────────────────────────────
    print("[*] Generating Kill Chain Report...")
    report = generate_report(
        graph_summary       = summary,
        blast_results       = blast_results,
        attack_paths        = [ap for ap in attack_paths if ap.get("found")],
        cycle_results       = cycle_results,
        pagerank_results    = pagerank_results,
        betweenness_results = betweenness_results,
        community_results   = community_results,
        ai_predictions      = ai_predictions,
        anomaly_results     = anomaly_results,
        temporal_results    = temporal_results,
    )

    if args.json:
        output = {
            "summary":      summary,
            "attack_paths": attack_paths,
            "cycles":       cycle_results,
            "pagerank":     pagerank_results,
        }
        print(json.dumps(output, indent=2, default=str))
    else:
        print(report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"[✓] Report saved to {args.output}")


if __name__ == "__main__":
    main()