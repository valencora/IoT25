import sqlite3
import threading
from pathlib import Path
from datetime import datetime, timedelta, UTC

DB_PATH = Path(__file__).parent / "iot25.db"

_local = threading.local()


def get_db() -> sqlite3.Connection:
    """Return a thread-local reusable SQLite connection."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return conn


def init_db() -> None:
    """Create all tables, indices, and default settings if they don't exist."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            mac         TEXT NOT NULL UNIQUE,
            ip          TEXT,
            hostname    TEXT,
            vendor      TEXT,
            device_type TEXT,
            status      TEXT DEFAULT 'active',
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS device_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id   INTEGER NOT NULL REFERENCES devices(id),
            event_type  TEXT NOT NULL,
            old_value   TEXT,
            new_value   TEXT,
            timestamp   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id        INTEGER REFERENCES devices(id),
            type             TEXT NOT NULL,
            severity         TEXT NOT NULL,
            message          TEXT NOT NULL,
            technical_detail TEXT,   -- JSON
            metadata         TEXT,   -- JSON
            recommendations  TEXT,   -- JSON
            timestamp        TEXT NOT NULL,
            acknowledged     INTEGER NOT NULL DEFAULT 0,
            resolved         INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS traffic_flows (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id   INTEGER REFERENCES devices(id),
            src_ip      TEXT NOT NULL,
            dst_ip      TEXT NOT NULL,
            src_port    INTEGER,
            dst_port    INTEGER,
            protocol    TEXT,
            bytes_sent  INTEGER DEFAULT 0,
            packets     INTEGER DEFAULT 0,
            duration_ms INTEGER DEFAULT 0,
            timestamp   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS dns_queries (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id    INTEGER REFERENCES devices(id),
            domain       TEXT NOT NULL,
            record_type  TEXT,
            timestamp    TEXT NOT NULL,
            is_suspicious INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS tls_fingerprints (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id  INTEGER REFERENCES devices(id),
            ja3_hash   TEXT NOT NULL,
            ja3_string TEXT,
            dst_ip     TEXT,
            dst_port   INTEGER,
            timestamp  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS training_metadata (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id     INTEGER NOT NULL REFERENCES devices(id),
            training_date TEXT NOT NULL,
            n_samples     INTEGER NOT NULL DEFAULT 0,
            feature_names TEXT,  -- JSON
            status        TEXT NOT NULL DEFAULT 'pending'
        );

        CREATE TABLE IF NOT EXISTS settings (
            key        TEXT PRIMARY KEY,
            value      TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        -- Indices: device_id
        CREATE INDEX IF NOT EXISTS idx_device_events_device_id    ON device_events(device_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_device_id           ON alerts(device_id);
        CREATE INDEX IF NOT EXISTS idx_traffic_flows_device_id    ON traffic_flows(device_id);
        CREATE INDEX IF NOT EXISTS idx_dns_queries_device_id      ON dns_queries(device_id);
        CREATE INDEX IF NOT EXISTS idx_tls_fingerprints_device_id ON tls_fingerprints(device_id);
        CREATE INDEX IF NOT EXISTS idx_training_metadata_device_id ON training_metadata(device_id);

        -- Indices: timestamp
        CREATE INDEX IF NOT EXISTS idx_device_events_timestamp    ON device_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp           ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_traffic_flows_timestamp    ON traffic_flows(timestamp);
        CREATE INDEX IF NOT EXISTS idx_dns_queries_timestamp      ON dns_queries(timestamp);
        CREATE INDEX IF NOT EXISTS idx_tls_fingerprints_timestamp ON tls_fingerprints(timestamp);

        -- Indices: ip
        CREATE INDEX IF NOT EXISTS idx_devices_ip           ON devices(ip);
        CREATE INDEX IF NOT EXISTS idx_traffic_flows_src_ip ON traffic_flows(src_ip);
        CREATE INDEX IF NOT EXISTS idx_traffic_flows_dst_ip ON traffic_flows(dst_ip);
    """)

    _insert_default_settings(cursor)
    conn.commit()


def _insert_default_settings(cursor: sqlite3.Cursor) -> None:
    now = datetime.now(UTC).isoformat()
    defaults = [
        ("iforest_contamination", "0.05"),
        ("lof_contamination",     "0.05"),
        ("kitsune_threshold",     "0.1"),
        ("alert_level_min",       "warning"),
        ("notifications_enabled", "false"),
    ]
    cursor.executemany(
        "INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
        [(k, v, now) for k, v in defaults],
    )


def cleanup_old_data(days: int = 30) -> dict[str, int]:
    """
    Delete traffic_flows and dns_queries older than `days` days.
    Returns a dict with the number of rows deleted per table.
    """
    conn = get_db()
    cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()

    cur = conn.execute(
        "DELETE FROM traffic_flows WHERE timestamp < ?", (cutoff,)
    )
    flows_deleted = cur.rowcount

    cur = conn.execute(
        "DELETE FROM dns_queries WHERE timestamp < ?", (cutoff,)
    )
    dns_deleted = cur.rowcount

    conn.commit()
    return {"traffic_flows": flows_deleted, "dns_queries": dns_deleted}


if __name__ == "__main__":
    init_db()
    print(f"Database initialised at {DB_PATH}")
    conn = get_db()
    tables = [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
    ]
    print("Tables:", tables)
    settings = conn.execute("SELECT key, value FROM settings").fetchall()
    print("Default settings:")
    for row in settings:
        print(f"  {row['key']} = {row['value']}")
