# reporting/kill_chain.py

from typing import Dict, List
import textwrap
from datetime import datetime


SEVERITY_COLORS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "CLEAR":    "✅",
}

def generate_report(
    graph_summary:      Dict,
    blast_results:      List[Dict],
    attack_paths:       List[Dict],
    cycle_results:      Dict,
    pagerank_results:   Dict,
    betweenness_results:Dict,
    community_results:  Dict,
    ai_predictions:     Dict,
    anomaly_results:    Dict,
    temporal_results:   Dict = None,
) -> str:

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = []
    sep  = "═" * 72
    sep2 = "─" * 72

    def h1(title):  lines.append(f"\n{sep}\n  {title}\n{sep}")
    def h2(title):  lines.append(f"\n  {sep2}\n  {title}\n  {sep2}")
    def ln(text=""):lines.append(f"  {text}")

    # ── Header ────────────────────────────────────────────────────────────
    h1("⚔  KUBERNETES ATTACK PATH VISUALIZER  ⚔")
    ln(f"  Report Generated : {ts}")
    ln(f"  Cluster Nodes    : {graph_summary['nodes']}")
    ln(f"  Cluster Edges    : {graph_summary['edges']}")
    ln(f"  Crown Jewels     : {', '.join(graph_summary['crown_jewels'])}")
    ln(f"  Entry Points     : {', '.join(graph_summary['entry_points'])}")

    # ── Section 1: Attack Paths ───────────────────────────────────────────
    h1("SECTION 1 — ATTACK PATH ANALYSIS (Dijkstra's Algorithm)")
    for ap in attack_paths:
        if not ap.get("found"):
            ln(f"✅  No path: {ap['source']} → {ap['target']}")
            continue

        icon = SEVERITY_COLORS.get(ap["severity"], "⚠")
        ln(f"\n{icon} {ap['severity']} — Attack Path Detected")
        ln(f"   Source → Target : {ap['source']} → {ap['target']}")
        ln(f"   Total Hops      : {ap['hop_count']}")
        ln(f"   Path Risk Score : {ap['total_risk']} ({ap['severity']})")
        ln(f"   Dijkstra Cost   : {ap['dijkstra_cost']}")
        ln()
        ln("   Kill Chain:")
        for i, hop in enumerate(ap["hops"]):
            cves = f"  ← {', '.join(hop['cves'])}" if hop["cves"] else ""
            misc = "  ⚠ MISCONFIGURED" if hop["misconfig"] else ""
            ln(f"   {'  ' * i}[{i+1}] {hop['from']}")
            ln(f"   {'  ' * i}     └─[{hop['relationship'].upper()} | CVSS:{hop['cvss']}]{misc}")
            ln(f"   {'  ' * i}        → {hop['to']}{cves}")
        ln()

    # ── Section 2: Blast Radius ───────────────────────────────────────────
    h1("SECTION 2 — BLAST RADIUS (BFS)")
    for br in blast_results:
        ln(f"\n🔥  Blast Radius from: '{br['source']}'")
        ln(f"    Reachable nodes within {br['max_hops']} hops: {br['total_reach']}")
        for hop_n, nodes in br["danger_zone"].items():
            ln(f"\n    Hop {hop_n}:")
            for n in nodes:
                icon = "💀" if n["risk_score"] >= 8 else "⚠" if n["risk_score"] >= 5 else "·"
                ln(f"      {icon} {n['node']} [{n['type']}] risk={n['risk_score']}")

    # ── Section 3: Cycles ─────────────────────────────────────────────────
    h1("SECTION 3 — CIRCULAR PERMISSION DETECTION (DFS / Johnson's)")
    ln(f"Total cycles found: {cycle_results['total_cycles']}")
    for c in cycle_results["cycles"]:
        icon = SEVERITY_COLORS.get(c["severity"], "⚠")
        cycle_str = " ↔ ".join(c["cycle"]) + f" ↔ {c['cycle'][0]}"
        ln(f"\n{icon} Cycle (len={c['length']}, max_risk={c['max_node_risk']})")
        ln(f"    {cycle_str}")
        ln(f"    Misconfigured edges in cycle: {c['misconfig_edges']}")

    # ── Section 4: Critical Node (PageRank) ───────────────────────────────
    h1("SECTION 4 — CRITICAL NODE IDENTIFICATION (Security PageRank)")
    ln("Top 10 nodes by Security PageRank (personalized by risk score):")
    ln()
    ln(f"  {'Rank':<5} {'Node':<30} {'Type':<20} {'PR Score':<12} {'Risk'}")
    ln(f"  {'-'*5} {'-'*30} {'-'*20} {'-'*12} {'-'*6}")
    for i, entry in enumerate(pagerank_results["top_10_critical"]):
        ln(f"  {i+1:<5} {entry['node']:<30} {entry['type']:<20} {entry['score']:<12} {entry['risk_score']}")

    ln()
    top = pagerank_results["top_10_critical"][0]
    ln(f"  ✅ RECOMMENDATION: Removing permission binding '{top['node']}'")
    ln(f"     would maximally reduce attack surface (PageRank = {top['score']})")

    # ── Section 5: Betweenness ────────────────────────────────────────────
    h1("SECTION 5 — BOTTLENECK ANALYSIS (Betweenness Centrality)")
    ln("Nodes that sit on the most attack paths (highest betweenness):")
    for entry in betweenness_results["top_bottleneck_nodes"][:5]:
        ln(f"  · {entry['node']:<30} centrality={entry['centrality']}")
    ln()
    ln("Most critical TRUST RELATIONSHIPS (edge betweenness):")
    for entry in betweenness_results["top_bottleneck_edges"][:5]:
        ln(f"  · {entry['edge']:<40} [{entry['rel']}]  centrality={entry['centrality']}")

    # ── Section 6: Communities ────────────────────────────────────────────
    h1("SECTION 6 — ATTACK SURFACE SEGMENTATION (Louvain Communities)")
    ln(f"Detected {community_results['num_communities']} trust communities.")
    violations = community_results.get("cross_namespace_violations", [])
    if violations:
        ln(f"\n🔴 Cross-namespace violations found: {len(violations)}")
        for v in violations:
            ln(f"\n  Community #{v['community_id']}:")
            ln(f"    Members:    {', '.join(v['members'])}")
            ln(f"    Namespaces: {', '.join(v['namespaces'])}")
            ln(f"    Issue:      {v['violation']}")
    else:
        ln("  ✅ No cross-namespace violations detected.")

    # ── Section 7: AI Risk Predictions ───────────────────────────────────
    h1("SECTION 7 — AI RISK PREDICTION (XGBoost — Predictive)")
    ln(f"Model CV F1 Score: {ai_predictions.get('cv_f1_mean', 'N/A')}")
    ln()
    ln("Feature Importances (what drives predicted risk):")
    if "feature_importances" in ai_predictions:
        sorted_fi = sorted(ai_predictions["feature_importances"].items(), key=lambda x: x[1], reverse=True)
        for feat, imp in sorted_fi[:6]:
            bar = "█" * int(imp * 40)
            ln(f"  {feat:<25} {bar} {imp:.4f}")
    ln()
    ln("Top Predicted High-Risk Nodes:")
    for node, info in ai_predictions.get("top_predicted_risks", [])[:8]:
        alert = "🔴" if info["predicted_risk_proba"] > 0.7 else "🟠"
        ln(f"  {alert} {node:<30} predicted_risk={info['predicted_risk_proba']}")

    # ── Section 8: Anomaly Detection ──────────────────────────────────────
    h1("SECTION 8 — ANOMALY DETECTION (Isolation Forest — Reactive)")
    ln(f"Anomalous nodes detected: {anomaly_results['anomaly_count']}")
    ln()
    for node, info in anomaly_results.get("top_anomalies", []):
        ln(f"  ⚠  {node:<30} anomaly_score={info['anomaly_score']}")

    # ── Section 9: Temporal ───────────────────────────────────────────────
    if temporal_results:
        h1("SECTION 9 — TEMPORAL ANALYSIS (Predictive Drift Detection)")
        at_risk = temporal_results.get("at_risk_nodes", [])
        ln(f"Nodes forecast to reach HIGH RISK in {temporal_results.get('forecast_days',7)} days:")
        for node in at_risk:
            f = temporal_results["forecasts"][node]
            ln(f"  🔴 {node:<30} current={f['current_risk']} → projected={f['projected_risk']} [{f['trend']}]")
        if not at_risk:
            ln("  ✅ No nodes forecast to exceed risk threshold.")

    # ── Footer ────────────────────────────────────────────────────────────
    h1("END OF REPORT")
    ln("KAPV — Kubernetes Attack Path Visualizer")
    ln("Algorithms: BFS · Dijkstra · DFS · PageRank · Betweenness · Louvain")
    ln("AI/ML:      XGBoost (predictive) · Isolation Forest (reactive) · LinReg (temporal)")
    ln()

    return "\n".join(lines)