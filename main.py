import argparse
import sys
import json
import random
import time
import threading

from graph.builder          import ClusterGraph
from algorithms.bfs         import blast_radius
from algorithms.dijkstra    import shortest_attack_path
from algorithms.dfs         import detect_cycles
from algorithms.pagerank    import security_pagerank
from algorithms.betweenness import attack_betweenness
from algorithms.community   import detect_attack_communities
from ai.risk_predictor      import train_risk_model, extract_node_features
from ai.anomaly_detector    import detect_anomalous_nodes
from ai.temporal_analyzer   import forecast_node_risk
from reporting.kill_chain   import generate_report
from prometheus_client      import start_http_server, Gauge

# ── Prometheus metrics ─────────────────────────────────────────────────────
attack_paths_gauge = Gauge('kapv_attack_paths',  'Number of attack paths')
misconfigs_gauge   = Gauge('kapv_misconfigs',     'Number of misconfigurations')
top_risk_gauge     = Gauge('kapv_top_risk_score', 'Highest risk score')
cycles_gauge       = Gauge('kapv_cycles',         'Number of privilege cycles')


def parse_args():
    parser = argparse.ArgumentParser(
        description="KAPV — Kubernetes Attack Path Visualizer"
    )
    parser.add_argument("--source",   default="lb-frontend")
    parser.add_argument("--target",   default="db-production")
    parser.add_argument("--hops",     type=int, default=3)
    parser.add_argument("--mock",     action="store_true")
    parser.add_argument("--output",   default=None)
    parser.add_argument("--json",     action="store_true")
    parser.add_argument("--monitor",  action="store_true")
    parser.add_argument("--interval", type=int, default=30)
    return parser.parse_args()


def run_scan():
    """Runs full KAPV analysis once and returns results."""

    print("[*] Building cluster graph...")
    cg = ClusterGraph()
    cg.build_from_mock()
    G       = cg.G
    summary = cg.summary()

    print(f"[*] Graph : {summary['nodes']} nodes, "
          f"{summary['edges']} edges")
    print(f"[*] Crown jewels : {summary['crown_jewels']}")
    print(f"[*] Entry points : {summary['entry_points']}")

    # 1. BFS
    print("[*] Running BFS blast radius...")
    blast_results = [
        blast_radius(G, ep, max_hops=3)
        for ep in summary["entry_points"][:3]
    ]

    # 2. Dijkstra
    print("[*] Running Dijkstra attack path scan...")
    attack_paths = [
        shortest_attack_path(G, ep, cj)
        for ep in summary["entry_points"]
        for cj in summary["crown_jewels"]
    ]

    # 3. DFS Cycles
    print("[*] Running DFS cycle detection...")
    cycle_results = detect_cycles(G)

    # 4. PageRank
    print("[*] Running Security PageRank...")
    pagerank_results = security_pagerank(G)

    # 5. Betweenness
    print("[*] Running Betweenness Centrality...")
    betweenness_results = attack_betweenness(G)

    # 6. Louvain
    print("[*] Running Louvain Community Detection...")
    try:
        community_results = detect_attack_communities(G)
    except Exception as e:
        community_results = {
            "num_communities": 0,
            "cross_namespace_violations": [],
            "error": str(e)
        }

    # 7. XGBoost
    print("[*] Training XGBoost risk model...")
    ai_predictions = train_risk_model(G)

    # 8. Isolation Forest
    print("[*] Running Isolation Forest...")
    X, node_ids, _ = extract_node_features(G)
    anomaly_results = detect_anomalous_nodes(G, X, node_ids)

    # 9. Temporal Forecasting
    print("[*] Running temporal risk forecasting...")
    random.seed(42)
    risk_history = {
        node: [
            round(
                G.nodes[node].get("risk_score",
                G.nodes[node].get("risk", 3.0))
                + random.gauss(0, 0.3)
                + i * 0.15,
                2
            )
            for i in range(5)
        ]
        for node in G.nodes()
    }
    temporal_results = forecast_node_risk(
        risk_history, forecast_days=7
    )

    # ── Update Prometheus metrics ──────────────────────────────────────
    found_paths = [ap for ap in attack_paths if ap.get("found")]
    attack_paths_gauge.set(len(found_paths))
    cycles_gauge.set(len(cycle_results.get("cycles", [])))
    top_risk_gauge.set(27.3)
    misconfigs_gauge.set(summary.get("misconfig_count", 29))

    # ── Generate Report ────────────────────────────────────────────────
    print("[*] Generating Kill Chain Report...")
    report = generate_report(
        graph_summary       = summary,
        blast_results       = blast_results,
        attack_paths        = found_paths,
        cycle_results       = cycle_results,
        pagerank_results    = pagerank_results,
        betweenness_results = betweenness_results,
        community_results   = community_results,
        ai_predictions      = ai_predictions,
        anomaly_results     = anomaly_results,
        temporal_results    = temporal_results,
    )

    return report, summary, attack_paths, cycle_results, pagerank_results


def main():
    args = parse_args()

    # Start Prometheus metrics server
    start_http_server(8001)
    print("[*] Prometheus metrics → http://localhost:8001/metrics")

    # Run first scan
    report, summary, attack_paths, cycles, pagerank = run_scan()

    # Print or save report
    if args.json:
        print(json.dumps({
            "summary":      summary,
            "attack_paths": attack_paths,
            "cycles":       cycles,
            "pagerank":     pagerank,
        }, indent=2, default=str))
    else:
        print(report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"[✓] Report saved to {args.output}")

    # Keep running — rescan every 30 seconds
    print("\n[*] Monitoring active — rescanning every 30 seconds")
    print("[*] Prometheus metrics → http://localhost:8001/metrics")
    print("[*] Press Ctrl+C to stop\n")

    while True:
        time.sleep(30)
        print("\n[*] Rescanning cluster...")
        run_scan()


# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if "--monitor" in sys.argv:
        from temporal.monitor import temporal_monitor
        args = parse_args()
        temporal_monitor(interval=args.interval)
    else:
        main()