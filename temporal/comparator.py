def compare_snapshots(old_snap, new_snap):
    """
    Compare two snapshots.
    Returns a changes dict with all alerts.
    """
    changes = {
        "timestamp":    new_snap["timestamp"],
        "alerts":       [],
        "risk_delta":   0.0,
        "is_dangerous": False
    }

    old_risk   = old_snap["monte_carlo_risk"]
    new_risk   = new_snap["monte_carlo_risk"]
    risk_delta = new_risk - old_risk
    changes["risk_delta"] = round(risk_delta, 4)

    if risk_delta > 0.05:
        changes["alerts"].append({
            "level":   "CRITICAL",
            "message": f"Compromise probability rose {risk_delta*100:.1f}%"
                       f" ({old_risk*100:.0f}% → {new_risk*100:.0f}%)"
        })
        changes["is_dangerous"] = True

    old_paths = set(str(p) for p in old_snap["attack_paths"])
    new_paths = set(str(p) for p in new_snap["attack_paths"])
    added     = new_paths - old_paths
    removed   = old_paths - new_paths

    if added:
        changes["alerts"].append({
            "level":   "CRITICAL",
            "message": f"{len(added)} new attack path(s) appeared",
            "details": list(added)
        })
        changes["is_dangerous"] = True

    if removed:
        changes["alerts"].append({
            "level":   "INFO",
            "message": f"{len(removed)} attack path(s) eliminated"
        })

    old_pr = old_snap.get("pagerank_scores", {})
    new_pr = new_snap.get("pagerank_scores", {})

    for node, new_score in new_pr.items():
        old_score = old_pr.get(node, 0.0)
        increase  = new_score - old_score
        if increase > 0.02:
            changes["alerts"].append({
                "level":   "HIGH",
                "message": f"Node '{node}' PageRank jumped"
                           f" {old_score:.4f} → {new_score:.4f}"
                           f" — more attack paths now route through it"
            })

    old_cyc = old_snap["privilege_cycles"]
    new_cyc = new_snap["privilege_cycles"]

    if new_cyc > old_cyc:
        changes["alerts"].append({
            "level":   "CRITICAL",
            "message": f"{new_cyc - old_cyc} new privilege cycle(s) detected!"
        })
        changes["is_dangerous"] = True

    old_mc = len(old_snap.get("misconfigs", []))
    new_mc = len(new_snap.get("misconfigs", []))
    if new_mc > old_mc:
        changes["alerts"].append({
            "level":   "MEDIUM",
            "message": f"{new_mc - old_mc} new misconfiguration(s) found"
        })

    return changes
