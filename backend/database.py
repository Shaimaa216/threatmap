from contextlib import contextmanager
from pathlib import Path
import sqlite3

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "threatmap.db"

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                country TEXT,
                city TEXT,
                isp TEXT,
                asn TEXT,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_ip ON analyses(ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_timestamp ON analyses(timestamp)")
        conn.commit()

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def save_analysis(record: dict):
    with get_db() as conn:
        conn.execute("""
            INSERT INTO analyses
            (ip, timestamp, country, city, isp, asn, risk_score, risk_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record["ip"], record["timestamp"], record.get("country"),
            record.get("city"), record.get("isp"), record.get("asn"),
            record["risk_score"], record["risk_level"]
        ))

def recent_analyses(limit: int = 20):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM analyses ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

def all_analyses(limit: int = 500):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM analyses ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

def clear_history():
    with get_db() as conn:
        conn.execute("DELETE FROM analyses")
