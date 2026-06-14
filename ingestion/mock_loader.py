# data/mock_cluster.json  (store this as a Python dict in mock_loader.py for simplicity)

MOCK_CLUSTER = {
    "nodes": [
        # ── Entry Points ──────────────────────────────────────
        {"id": "lb-frontend",      "type": "LoadBalancer",   "namespace": "default",  "risk": 7.5, "entry": True,  "crown": False, "cves": ["CVE-2024-1234"]},
        {"id": "user-dev1",        "type": "User",           "namespace": "default",  "risk": 4.0, "entry": True,  "crown": False, "cves": []},
        {"id": "user-dev2",        "type": "User",           "namespace": "staging",  "risk": 3.5, "entry": True,  "crown": False, "cves": []},
        {"id": "user-ci-bot",      "type": "User",           "namespace": "ci",       "risk": 6.0, "entry": True,  "crown": False, "cves": ["CVE-2024-5678"]},

        # ── Pods ──────────────────────────────────────────────
        {"id": "pod-frontend",     "type": "Pod",            "namespace": "default",  "risk": 7.5, "entry": False, "crown": False, "cves": ["CVE-2024-1234"]},
        {"id": "pod-backend",      "type": "Pod",            "namespace": "default",  "risk": 5.0, "entry": False, "crown": False, "cves": []},
        {"id": "pod-worker",       "type": "Pod",            "namespace": "default",  "risk": 4.5, "entry": False, "crown": False, "cves": []},
        {"id": "pod-logger",       "type": "Pod",            "namespace": "logging",  "risk": 3.0, "entry": False, "crown": False, "cves": []},
        {"id": "pod-ci-runner",    "type": "Pod",            "namespace": "ci",       "risk": 8.0, "entry": False, "crown": False, "cves": ["CVE-2024-5678","CVE-2023-9999"]},
        {"id": "pod-monitor",      "type": "Pod",            "namespace": "monitoring","risk": 4.0,"entry": False, "crown": False, "cves": []},

        # ── ServiceAccounts ───────────────────────────────────
        {"id": "sa-frontend",      "type": "ServiceAccount", "namespace": "default",  "risk": 5.0, "entry": False, "crown": False, "cves": []},
        {"id": "sa-backend",       "type": "ServiceAccount", "namespace": "default",  "risk": 6.0, "entry": False, "crown": False, "cves": []},
        {"id": "sa-worker",        "type": "ServiceAccount", "namespace": "default",  "risk": 4.0, "entry": False, "crown": False, "cves": []},
        {"id": "sa-ci",            "type": "ServiceAccount", "namespace": "ci",       "risk": 9.0, "entry": False, "crown": False, "cves": []},
        {"id": "sa-logger",        "type": "ServiceAccount", "namespace": "logging",  "risk": 3.5, "entry": False, "crown": False, "cves": []},
        {"id": "sa-monitor",       "type": "ServiceAccount", "namespace": "monitoring","risk": 4.5,"entry": False, "crown": False, "cves": []},

        # ── Roles ─────────────────────────────────────────────
        {"id": "role-secret-reader","type": "Role",          "namespace": "default",  "risk": 7.0, "entry": False, "crown": False, "cves": []},
        {"id": "role-pod-exec",    "type": "Role",           "namespace": "default",  "risk": 8.5, "entry": False, "crown": False, "cves": []},
        {"id": "role-log-reader",  "type": "Role",           "namespace": "logging",  "risk": 3.0, "entry": False, "crown": False, "cves": []},
        {"id": "clusterrole-admin","type": "ClusterRole",    "namespace": "cluster",  "risk": 10.0,"entry": False, "crown": False, "cves": []},
        {"id": "clusterrole-view", "type": "ClusterRole",    "namespace": "cluster",  "risk": 2.0, "entry": False, "crown": False, "cves": []},
        {"id": "role-ci-deploy",   "type": "Role",           "namespace": "ci",       "risk": 8.0, "entry": False, "crown": False, "cves": []},

        # ── Secrets ───────────────────────────────────────────
        {"id": "secret-db-creds",  "type": "Secret",         "namespace": "default",  "risk": 9.5, "entry": False, "crown": False, "cves": []},
        {"id": "secret-api-key",   "type": "Secret",         "namespace": "default",  "risk": 8.0, "entry": False, "crown": False, "cves": []},
        {"id": "secret-tls-cert",  "type": "Secret",         "namespace": "default",  "risk": 6.0, "entry": False, "crown": False, "cves": []},
        {"id": "secret-ci-token",  "type": "Secret",         "namespace": "ci",       "risk": 9.0, "entry": False, "crown": False, "cves": []},

        # ── ConfigMaps ────────────────────────────────────────
        {"id": "cm-app-config",    "type": "ConfigMap",      "namespace": "default",  "risk": 2.0, "entry": False, "crown": False, "cves": []},
        {"id": "cm-db-config",     "type": "ConfigMap",      "namespace": "default",  "risk": 5.5, "entry": False, "crown": False, "cves": []},

        # ── Crown Jewels ──────────────────────────────────────
        {"id": "db-production",    "type": "Database",       "namespace": "database", "risk": 10.0,"entry": False, "crown": True,  "cves": []},
        {"id": "db-analytics",     "type": "Database",       "namespace": "database", "risk": 8.5, "entry": False, "crown": True,  "cves": []},
        {"id": "secret-master-key","type": "Secret",         "namespace": "kube-system","risk":10.0,"entry":False,  "crown": True,  "cves": []},
    ],

    "edges": [
        # Attack Path 1: lb-frontend → pod-frontend → sa-frontend → role-secret-reader → secret-db-creds → db-production
        {"src": "lb-frontend",      "dst": "pod-frontend",      "rel": "exposes",    "weight": 2.5, "cvss": 7.5, "misconfig": True},
        {"src": "pod-frontend",     "dst": "sa-frontend",       "rel": "uses",       "weight": 1.0, "cvss": 0.0, "misconfig": False},
        {"src": "sa-frontend",      "dst": "role-secret-reader","rel": "bound_to",   "weight": 1.0, "cvss": 0.0, "misconfig": True},
        {"src": "role-secret-reader","dst":"secret-db-creds",   "rel": "can_read",   "weight": 1.5, "cvss": 0.0, "misconfig": False},
        {"src": "secret-db-creds",  "dst": "db-production",     "rel": "can_read",   "weight": 1.0, "cvss": 0.0, "misconfig": False},

        # Attack Path 2: user-dev1 → pod-backend → sa-backend → role-pod-exec → pod-ci-runner → sa-ci → secret-ci-token → db-production
        {"src": "user-dev1",        "dst": "pod-backend",       "rel": "uses",       "weight": 3.0, "cvss": 4.0, "misconfig": False},
        {"src": "pod-backend",      "dst": "sa-backend",        "rel": "uses",       "weight": 1.0, "cvss": 0.0, "misconfig": False},
        {"src": "sa-backend",       "dst": "role-pod-exec",     "rel": "bound_to",   "weight": 1.0, "cvss": 0.0, "misconfig": True},
        {"src": "role-pod-exec",    "dst": "pod-ci-runner",     "rel": "can_exec",   "weight": 0.5, "cvss": 8.5, "misconfig": True},
        {"src": "pod-ci-runner",    "dst": "sa-ci",             "rel": "uses",       "weight": 1.0, "cvss": 0.0, "misconfig": False},
        {"src": "sa-ci",            "dst": "secret-ci-token",   "rel": "mounts",     "weight": 1.0, "cvss": 0.0, "misconfig": False},
        {"src": "secret-ci-token",  "dst": "db-production",     "rel": "can_read",   "weight": 1.0, "cvss": 0.0, "misconfig": False},

        # Attack Path 3: user-ci-bot → pod-ci-runner → sa-ci → clusterrole-admin → secret-master-key
        {"src": "user-ci-bot",      "dst": "pod-ci-runner",     "rel": "uses",       "weight": 2.0, "cvss": 6.0, "misconfig": False},
        {"src": "sa-ci",            "dst": "clusterrole-admin", "rel": "bound_to",   "weight": 0.5, "cvss": 0.0, "misconfig": True},
        {"src": "clusterrole-admin","dst": "secret-master-key", "rel": "can_read",   "weight": 1.0, "cvss": 0.0, "misconfig": False},

        # Attack Path 4: user-dev2 → pod-worker → sa-worker → cm-db-config → db-analytics
        {"src": "user-dev2",        "dst": "pod-worker",        "rel": "uses",       "weight": 2.0, "cvss": 3.5, "misconfig": False},
        {"src": "pod-worker",       "dst": "sa-worker",         "rel": "uses",       "weight": 1.0, "cvss": 0.0, "misconfig": False},
        {"src": "sa-worker",        "dst": "cm-db-config",      "rel": "can_read",   "weight": 2.0, "cvss": 0.0, "misconfig": False},
        {"src": "cm-db-config",     "dst": "db-analytics",      "rel": "can_read",   "weight": 1.5, "cvss": 5.5, "misconfig": True},

        # Circular permission (cycle): sa-backend ↔ sa-frontend via roles
        {"src": "sa-frontend",      "dst": "role-pod-exec",     "rel": "bound_to",   "weight": 2.0, "cvss": 0.0, "misconfig": True},
        {"src": "role-pod-exec",    "dst": "sa-backend",        "rel": "impersonates","weight": 1.5,"cvss": 0.0, "misconfig": True},

        # Additional edges for graph density
        {"src": "pod-logger",       "dst": "sa-logger",         "rel": "uses",       "weight": 1.0, "cvss": 0.0, "misconfig": False},
        {"src": "sa-logger",        "dst": "role-log-reader",   "rel": "bound_to",   "weight": 1.0, "cvss": 0.0, "misconfig": False},
        {"src": "pod-monitor",      "dst": "sa-monitor",        "rel": "uses",       "weight": 1.0, "cvss": 0.0, "misconfig": False},
        {"src": "sa-monitor",       "dst": "clusterrole-view",  "rel": "bound_to",   "weight": 1.0, "cvss": 0.0, "misconfig": False},
        {"src": "pod-frontend",     "dst": "secret-tls-cert",   "rel": "mounts",     "weight": 1.0, "cvss": 0.0, "misconfig": False},
        {"src": "pod-backend",      "dst": "secret-api-key",    "rel": "mounts",     "weight": 1.0, "cvss": 0.0, "misconfig": False},
        {"src": "pod-backend",      "dst": "cm-app-config",     "rel": "can_read",   "weight": 1.0, "cvss": 0.0, "misconfig": False},
        {"src": "role-ci-deploy",   "dst": "pod-ci-runner",     "rel": "can_exec",   "weight": 0.5, "cvss": 8.0, "misconfig": True},
        {"src": "sa-ci",            "dst": "role-ci-deploy",    "rel": "bound_to",   "weight": 1.0, "cvss": 0.0, "misconfig": False},
        {"src": "secret-api-key",   "dst": "db-analytics",      "rel": "can_read",   "weight": 1.5, "cvss": 8.0, "misconfig": False},
    ]
}