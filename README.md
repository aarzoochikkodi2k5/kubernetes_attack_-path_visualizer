# Kubernetes Attack Path Visualizer (KAPV)

A graph-based security analysis tool that models Kubernetes RBAC
configurations as a directed weighted graph and automatically discovers
multi-hop privilege escalation paths, cycles, and critical nodes.

---

## Project Structure

```text
kubernetes_attack_path_visualizer/
├── ai/               # XGBoost + Isolation Forest anomaly detection
├── algorithms/       # BFS, Dijkstra, A*, DFS, PageRank,
│                     # Betweenness, Louvain, Monte Carlo
├── graph/            # Graph builder from cluster JSON
├── ingestion/        # Cluster data ingestion layer
├── kapv/             # Dashboard HTML + result analysis PPT
├── reporting/        # Kill chain report generator
├── main.py           # Entry point — runs full analysis
├── mock_cluster.json # 100-node synthetic K8s cluster dataset
└── dashboard.html    # Interactive D3.js visualization
```

---

## What It Does

| Algorithm | Output |
|-----------|--------|
| BFS | Blast radius from each entry point |
| Dijkstra | All attack paths (12×6 = 72 pairs) |
| A* | Fastest targeted single-pair query |
| DFS / Johnson's | Privilege escalation cycles |
| Security PageRank | Critical node ranking |
| Betweenness Centrality | Structural bottleneck nodes |
| Louvain | Cross-namespace community detection |
| Monte Carlo | Compromise probability per crown jewel |
| XGBoost | Predictive high-risk node scoring |
| Isolation Forest | Unsupervised anomaly detection |

---

## Dataset — mock_cluster.json

| Property | Value |
|----------|-------|
| Nodes | 100 |
| Edges | 144 |
| Entry points | 12 (LoadBalancers + Users) |
| Crown jewels | 6 (Databases + Master secrets) |
| Namespaces | 15 |
| Misconfigs | 29 |

---

## Key Results

| Metric | Result |
|--------|--------|
| Attack paths found | 6 (2 Critical · 2 High · 2 Medium) |
| Highest risk path | lb-admin → pod-admin-panel → sa-admin → clusterrole-admin → db-production (4 hops · score 27.3) |
| Privilege cycles | 3 (7 nodes affected) |
| Max blast radius | 18 nodes (lb-admin · 3 hops) |
| Compromise probability | 81% for db-production (Monte Carlo · 10k sims) |
| Top PageRank node | clusterrole-admin (0.0921) → removing 2 bindings eliminates 4/6 paths |

---

## How to Run

### 1. Clone the repo
```bash
git clone https://github.com/aarzoochikkodi2k5/kubernetes_attack_-path_visualizer.git
cd kubernetes_attack_-path_visualizer
```

### 2. Install dependencies
```bash
pip install networkx flask numpy scikit-learn xgboost
```

### 3. Run the analyzer
```bash
python main.py
```

### 4. Open the dashboard
```bash
python -m http.server 8000
# Open: http://localhost:8000/dashboard.html
```

---

## Dashboard Features

- **Overview** — cluster metrics, top attack paths, severity charts
- **Attack Paths** — all 6 paths with hop chain visualization
- **Graph Viz** — D3.js force-directed graph (100 nodes · 144 edges)
- **Critical Nodes** — PageRank · Betweenness · Louvain tabs
- **Monte Carlo** — compromise probability per crown jewel
- **AI / ML** — XGBoost predictions · Isolation Forest anomalies
- **Real-time Monitoring** — 30s rescan · live alert feed

---

## Tech Stack

| Layer | Tool |
|-------|------|
| Language | Python 3 |
| Graph library | NetworkX |
| Visualization | D3.js · Chart.js · HTML5/CSS3 |
| AI / ML | XGBoost · Scikit-learn (Isolation Forest) |
| Data format | JSON |

---

## Base Paper Comparison

| Metric | Base Paper (Sheyner et al. 2002) | KAPV |
|--------|----------------------------------|------|
| Attack paths detected | 2/6 (33%) | 6/6 (100%) |
| Analysis time | ~180 min | ~3 min |
| Multi-hop detection | ✗ | ✓ Up to 7 hops |
| Privilege cycles | ✗ | ✓ 3 detected |
| Algorithms | 1 (DFS only) | 8 + 2 ML |
| Probabilistic risk | ✗ | ✓ Monte Carlo 81% |
| Visualization | Text report | Interactive dashboard |

---

## Academic References

1. Sheyner et al. — *Automated Generation and Analysis of Attack Graphs*  
   IEEE S&P 2002 · https://ieeexplore.ieee.org/document/1004358

2. NSA/CISA — *Kubernetes Hardening Guide v1.2*  
   https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF

---

## Author

**Aarzoo Chikkodi**  
3rd Year B.Tech CSE · KLE Technological University, Hubli  
Minor Project · Nokia Hackathon Problem Statement
