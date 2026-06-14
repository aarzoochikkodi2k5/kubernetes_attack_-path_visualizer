# ai/gnn_embeddings.py

"""
Graph Neural Network (GNN) — specifically GraphSAGE — for learning
node embeddings that capture BOTH structural position AND feature context.

WHY GNNs OVER CLASSICAL ML:
- XGBoost treats nodes independently (bag of features)
- GNN propagates information across the graph: "what are my neighbors like?"
- A node surrounded by high-risk nodes gets a high-risk embedding
  EVEN IF its own features look benign — this is multi-hop awareness

GRAPHSAGE (Hamilton et al., 2017):
  h_v^k = σ(W · CONCAT(h_v^(k-1), AGGREGATE({h_u^(k-1) : u ∈ N(v)})))

Where:
  h_v^k  = embedding of node v at layer k
  N(v)   = neighbors of v
  AGGREGATE = mean/max/LSTM pooling over neighbor embeddings
  σ      = non-linear activation (ReLU)

In security terms: after K layers, each node's embedding encodes
information from its K-hop neighborhood — exactly matching the
"multi-hop attack path" threat model.

Downstream tasks:
1. Node classification: is this node likely compromised?
2. Link prediction: will a new trust relationship appear between u and v?
3. Similarity search: find all nodes structurally similar to a known
   compromised node (zero-shot threat hunting)
"""

import numpy as np
import networkx as nx
from typing import Dict, List, Optional, Tuple

def manual_graphsage(
    G: nx.DiGraph,
    feature_matrix: np.ndarray,
    node_ids: List[str],
    num_layers: int = 2,
    embedding_dim: int = 16,
    seed: Optional[int] = None,
) -> Dict[str, np.ndarray]:
    """
    Pure NumPy implementation of GraphSAGE mean aggregator.
    No PyTorch/TF required — runs anywhere Python runs.
    
    This is the inference-only version (no training loop).
    In production: train with node2vec or full PyTorch Geometric.
    """
    np.random.seed(seed)
    n_features = feature_matrix.shape[1]

    # Random weight matrices per layer (untrained — for structure only)
    # In production: train these with a classification objective
    W = [
        np.random.randn(
            (n_features if i == 0 else embedding_dim) * 2,
            embedding_dim
        ) * 0.1
        for i in range(num_layers)
    ]

    node_index = {n: i for i, n in enumerate(node_ids)}
    H = feature_matrix.copy().astype(float)

    # Normalise features
    H = (H - H.mean(axis=0)) / (H.std(axis=0) + 1e-8)

    for layer in range(num_layers):
        H_new = np.zeros((len(node_ids), embedding_dim))
        for node in G.nodes():
            if node not in node_index:
                continue
            idx = node_index[node]

            # Aggregate neighbor embeddings (mean pooling)
            neighbors = list(G.predecessors(node)) + list(G.successors(node))
            neighbor_idxs = [node_index[nb] for nb in neighbors if nb in node_index]

            if neighbor_idxs:
                neighbor_h = H[neighbor_idxs].mean(axis=0)
            else:
                neighbor_h = np.zeros(H.shape[1])

            # Concatenate self + neighbor
            self_h = H[idx]
            # Pad/truncate to match concat size
            if layer == 0:
                concat = np.concatenate([self_h, neighbor_h])
            else:
                s_pad = self_h if len(self_h) == embedding_dim else np.resize(self_h, embedding_dim)
                n_pad = neighbor_h if len(neighbor_h) == embedding_dim else np.resize(neighbor_h, embedding_dim)
                concat = np.concatenate([s_pad, n_pad])

            # Linear transform + ReLU
            H_new[idx] = np.maximum(0, concat @ W[layer])

        H = H_new

    embeddings = {node_ids[i]: H[i] for i in range(len(node_ids))}
    return embeddings


def find_similar_nodes(
    embeddings: Dict[str, np.ndarray],
    query_node: str,
    top_k: int = 5,
) -> List[Dict]:
    """
    Cosine similarity search over GNN embeddings.
    
    Use case: "Find all nodes structurally similar to this known
    compromised pod" — zero-shot threat hunting without any labels.
    """
    if query_node not in embeddings:
        return []

    q_vec = embeddings[query_node]
    q_norm = np.linalg.norm(q_vec) + 1e-8

    similarities = []
    for node, vec in embeddings.items():
        if node == query_node:
            continue
        cos_sim = np.dot(q_vec, vec) / (q_norm * np.linalg.norm(vec) + 1e-8)
        similarities.append({"node": node, "similarity": round(float(cos_sim), 4)})

    return sorted(similarities, key=lambda x: x["similarity"], reverse=True)[:top_k]


def link_prediction(
    G: nx.DiGraph,
    embeddings: Dict[str, np.ndarray],
    threshold: float = 0.85,
) -> List[Dict]:
    """
    Predict likely FUTURE trust relationships (new edges) using
    Hadamard product of node embedding pairs.
    
    Security interpretation: this predicts which new RBAC bindings or
    service account assignments are LIKELY to appear based on current 
    cluster structure — allowing pre-emptive hardening before the 
    misconfiguration is even made.
    
    This is genuinely PREDICTIVE security — not reactive.
    """
    nodes = list(embeddings.keys())
    predicted_links = []

    for i, u in enumerate(nodes):
        for v in nodes[i+1:]:
            if G.has_edge(u, v):
                continue  # already exists

            # Hadamard product similarity
            h_prod = embeddings[u] * embeddings[v]
            score = float(np.linalg.norm(h_prod) / (
                np.linalg.norm(embeddings[u]) * np.linalg.norm(embeddings[v]) + 1e-8
            ))

            if score >= threshold:
                predicted_links.append({
                    "from": u, "to": v,
                    "predicted_trust_score": round(score, 4),
                    "warning": "Potential future trust relationship — harden now",
                })

    return sorted(predicted_links, key=lambda x: x["predicted_trust_score"], reverse=True)[:10]