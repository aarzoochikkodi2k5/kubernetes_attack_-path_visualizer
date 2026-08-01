import sqlite3
import json

DB_PATH = "kapv_timeline.db"


def init_database():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS snapshots (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT,
            risk_score    REAL,
            attack_paths  INTEGER,
            cycles        INTEGER,
            nodes         INTEGER,
            edges         INTEGER,
            risk_delta    REAL,
            is_dangerous  INTEGER,
            alerts        TEXT
        )
    ''')
    conn.commit()
    print(f"  [DB ready] → {DB_PATH}")
    return conn


def store_in_db(conn, snapshot, changes):
    conn.execute('''
        INSERT INTO snapshots
        (timestamp, risk_score, attack_paths, cycles,
         nodes, edges, risk_delta, is_dangerous, alerts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        snapshot["timestamp"],
        snapshot["monte_carlo_risk"],
        snapshot["attack_paths_count"],
        snapshot["privilege_cycles"],
        snapshot["total_nodes"],
        snapshot["total_edges"],
        changes["risk_delta"],
        1 if changes["is_dangerous"] else 0,
        json.dumps(changes["alerts"])
    ))
    conn.commit()


def fetch_last_n(conn, n=50):
    cur = conn.execute(
        'SELECT * FROM snapshots ORDER BY id DESC LIMIT ?', (n,)
    )
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in reversed(rows)]
