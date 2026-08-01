import json
import os

MOCK_CLUSTER_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'mock_cluster.json')
)


def load_mock_cluster():
    if os.path.exists(MOCK_CLUSTER_FILE):
        try:
            with open(MOCK_CLUSTER_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict) and 'nodes' in data and 'edges' in data:
                print(f"[+] Reloaded mock cluster from {MOCK_CLUSTER_FILE}")
                return data
        except Exception:
            pass
    raise FileNotFoundError(f"Could not load mock cluster from {MOCK_CLUSTER_FILE}")


MOCK_CLUSTER = load_mock_cluster()
