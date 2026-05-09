# algorithms/monte_carlo.py

"""
Monte Carlo simulation of attack propagation.

Classical graph algorithms give DETERMINISTIC answers:
"This path EXISTS with cost X."

Reality is PROBABILISTIC:
- CVE exploitation succeeds with probability p (not 100%)
- Defenders may detect lateral movement mid-chain
- Network segmentation may intermittently block traversal

Monte Carlo models this uncertainty by simulating 10,000 attack
attempts and computing:
- Probability of successfully reaching each crown jewel
- Expected number of hops before detection
- Confidence intervals on path risk scores

This converts the tool from a static analyser to a
RISK QUANTIFICATION engine — giving security teams
"there is a 73% chance an attacker reaching pod-frontend
can compromise db-production within 4 hops."

That number is what a CISO actually wants to see.
"""

import networkx as nx
import numpy as np
from typing import Dict, List
from collections import defaultdict


def _edge_exploit_probability(edge_data: Dict) -> float:
    """
    Convert edge metadata to a traversal success probability.
    
    CVSS 9-10  → 90% success probability
    CVSS 7-8.9 → 70%
    CVSS 4-6.9 → 50%
    CVSS 0-3.9 → 30%
    misconfig  → +15% bonus
    """
    cvss = edge_data.get("cvss", 0.0)
    base = (
        0.90 if cvss >= 9.0 else
        0.70 if cvss >= 7.0 else
        0.50 if cvss >= 4.0 else 0.30
    )
    if edge_data.get("misconfig", False):
        base = min(base + 0.15, 0.99)
    return base


def monte_carlo_attack(
    G: nx.DiGraph,
    source: str,
    crown_jewels: List[str],
    num_simulations: int = 10_000,
    max_hops: int = 8,
    detection_prob: float = 0.05,   # 5% chance per hop of being detected
) -> Dict:
    """
    Run N simulated attack attempts from source.
    Each simulation:
      1. Start at source
      2. At each hop, choose a random successor
      3. Traverse the edge with probability p (exploit success)
      4. With probability detection_prob, attacker is caught (path fails)
      5. Stop when crown jewel is reached OR max_hops exceeded OR caught
    
    Output: per-crown-jewel compromise probability with 95% CI.
    """
    rng = np.random.default_rng(42)

    reach_counts    = defaultdict(int)   # crown jewel → times reached
    hop_counts      = defaultdict(list)  # crown jewel → hops taken
    path_samples    = defaultdict(list)  # crown jewel → sample paths
    detection_count = 0

    for sim in range(num_simulations):
        current = source
        path    = [current]
        reached = False

        for hop in range(max_hops):
            # Detection check
            if rng.random() < detection_prob:
                detection_count += 1
                break

            successors = list(G.successors(current))
            if not successors:
                break

            # Weighted random walk — prefer low-weight (easy) edges
            weights = np.array([
                1.0 / (G.edges[current, nb].get("weight", 1.0) + 0.1)
                for nb in successors
            ])
            weights /= weights.sum()
            next_node = rng.choice(successors, p=weights)

            # Attempt exploitation
            edge_data = G.edges[current, next_node]
            p_exploit = _edge_exploit_probability(edge_data)

            if rng.random() > p_exploit:
                break   # Exploit failed

            current = next_node
            path.append(current)

            if current in crown_jewels:
                reach_counts[current] += 1
                hop_counts[current].append(hop + 1)
                if len(path_samples[current]) < 5:
                    path_samples[current].append(path.copy())
                reached = True
                break

    results = {}
    for cj in crown_jewels:
        count = reach_counts[cj]
        prob  = count / num_simulations
        hops  = hop_counts[cj]

        # 95% Wilson confidence interval
        z     = 1.96
        denom = 1 + z**2 / num_simulations
        centre = (prob + z**2 / (2 * num_simulations)) / denom
        margin = z * np.sqrt(prob * (1-prob) / num_simulations + z**2 / (4 * num_simulations**2)) / denom

        results[cj] = {
            "compromise_probability":   round(prob, 4),
            "ci_lower":                 round(max(0, centre - margin), 4),
            "ci_upper":                 round(min(1, centre + margin), 4),
            "simulations":              num_simulations,
            "avg_hops_to_compromise":   round(np.mean(hops), 2) if hops else None,
            "min_hops":                 min(hops) if hops else None,
            "sample_paths":             path_samples[cj][:3],
            "severity": (
                "CRITICAL" if prob >= 0.6 else
                "HIGH"     if prob >= 0.3 else
                "MEDIUM"   if prob >= 0.1 else "LOW"
            ),
        }

    return {
        "source":            source,
        "num_simulations":   num_simulations,
        "detection_rate":    round(detection_count / num_simulations, 4),
        "crown_jewel_risk":  results,
    }