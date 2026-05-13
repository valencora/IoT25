import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, UTC
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)

# Capture backend on OpenWrt: tcpdump (subprocess) feeding scapy as a passive
# pcap parser. Replaces ScapyCollector, which froze OpenWrt by forcing the NIC
# into promiscuous mode. Tcpdump itself runs with -p for the same reason.
TCPDUMP_ENABLED = True

from alert_manager import create_alert, get_active_alerts
from database import DB_PATH, get_db, init_db
from device_discovery import DeviceDiscovery
from traffic_capture import TrafficCollector, TrafficSimulator

if TCPDUMP_ENABLED:
    from tcpdump_capture import TcpdumpCapture, is_tcpdump_available
    if is_tcpdump_available() is None:
        logging.getLogger(__name__).error(
            "tcpdump not installed — passive capture disabled. "
            "Install on OpenWrt with: opkg install tcpdump"
        )

_discovery = DeviceDiscovery(interval=30, offline_threshold=2)
_collector = TrafficCollector()
# SIMULATE_TRAFFIC=1  → synthetic flows every 30 s (no router needed)
_simulator = TrafficSimulator(interval=30) if os.getenv("SIMULATE_TRAFFIC") == "1" else None
# CAPTURE_INTERFACE=wlo1 → real pcap capture on that NIC (needs root / CAP_NET_RAW).
# Defaults to "any" so tcpdump captures across all interfaces by default.
_capture_iface = os.getenv("CAPTURE_INTERFACE", "any")
_tcpdump = TcpdumpCapture(_capture_iface) if TCPDUMP_ENABLED else None


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    _discovery.start()
    _collector.start()
    if _simulator:
        _simulator.start()
    if _tcpdump:
        _tcpdump.start()
    yield
    _discovery.stop()
    _collector.stop()
    if _simulator:
        _simulator.stop()
    if _tcpdump:
        _tcpdump.stop()


app = FastAPI(title="IoT25", lifespan=lifespan)

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/devices")
def list_devices():
    conn = get_db()
    rows = conn.execute(
        """
        SELECT id, mac, ip, hostname, vendor, device_type, status, last_seen
        FROM devices
        ORDER BY last_seen DESC
        """
    ).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/alerts")
def list_alerts(
    severity: str | None = None,
    device_id: int | None = None,
    acknowledged: bool | None = None,
    limit: int = 100,
):
    conn = get_db()
    query = "SELECT * FROM alerts WHERE 1=1"
    params: list = []
    if severity is not None:
        query += " AND severity = ?"
        params.append(severity)
    if device_id is not None:
        query += " AND device_id = ?"
        params.append(device_id)
    if acknowledged is not None:
        query += " AND acknowledged = ?"
        params.append(int(acknowledged))
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/alerts/active")
def active_alerts():
    return get_active_alerts()


@app.post("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int):
    conn = get_db()
    if conn.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
    conn.commit()
    return {"ok": True}


@app.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int):
    conn = get_db()
    if conn.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    conn.execute("UPDATE alerts SET resolved = 1 WHERE id = ?", (alert_id,))
    conn.commit()
    return {"ok": True}


@app.get("/api/devices/{mac}/history")
def device_history(mac: str):
    conn = get_db()
    device = conn.execute(
        "SELECT id FROM devices WHERE mac = ?", (mac,)
    ).fetchone()
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    rows = conn.execute(
        """
        SELECT id, event_type, old_value, new_value, timestamp
        FROM device_events
        WHERE device_id = ?
        ORDER BY timestamp DESC
        """,
        (device["id"],),
    ).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/devices/{device_id}/traffic")
def device_traffic(device_id: int):
    conn = get_db()
    if conn.execute("SELECT id FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Device not found")
    rows = conn.execute(
        """
        SELECT id, src_ip, dst_ip, src_port, dst_port,
               protocol, bytes_sent, packets, duration_ms, timestamp
        FROM traffic_flows
        WHERE device_id = ?
        ORDER BY timestamp DESC
        LIMIT 100
        """,
        (device_id,),
    ).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/devices/{device_id}/dns")
def device_dns(device_id: int, limit: int = 50, offset: int = 0):
    conn = get_db()
    if conn.execute("SELECT id FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Device not found")
    rows = conn.execute(
        """
        SELECT id, domain, record_type, timestamp, is_suspicious
        FROM dns_queries
        WHERE device_id = ?
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
        """,
        (device_id, limit, offset),
    ).fetchall()
    total = conn.execute(
        "SELECT COUNT(*) FROM dns_queries WHERE device_id = ?", (device_id,)
    ).fetchone()[0]
    return {"total": total, "offset": offset, "limit": limit, "items": [dict(r) for r in rows]}


@app.get("/api/devices/{device_id}/tls")
def device_tls(device_id: int, limit: int = 50, offset: int = 0):
    conn = get_db()
    if conn.execute("SELECT id FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Device not found")
    rows = conn.execute(
        """
        SELECT id, ja3_hash, ja3_string, dst_ip, dst_port, timestamp
        FROM tls_fingerprints
        WHERE device_id = ?
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
        """,
        (device_id, limit, offset),
    ).fetchall()
    total = conn.execute(
        "SELECT COUNT(*) FROM tls_fingerprints WHERE device_id = ?", (device_id,)
    ).fetchone()[0]
    return {"total": total, "offset": offset, "limit": limit, "items": [dict(r) for r in rows]}


@app.get("/api/dns/suspicious")
def suspicious_dns(limit: int = 100, offset: int = 0):
    conn = get_db()
    rows = conn.execute(
        """
        SELECT dq.id, dq.device_id, dq.domain, dq.record_type, dq.timestamp,
               d.ip, d.mac, d.hostname
        FROM dns_queries dq
        LEFT JOIN devices d ON d.id = dq.device_id
        WHERE dq.is_suspicious = 1
        ORDER BY dq.timestamp DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    ).fetchall()
    total = conn.execute(
        "SELECT COUNT(*) FROM dns_queries WHERE is_suspicious = 1"
    ).fetchone()[0]
    return {"total": total, "offset": offset, "limit": limit, "items": [dict(r) for r in rows]}


@app.get("/api/stats")
def stats():
    conn = get_db()
    today_start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

    total_devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    active_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0"
    ).fetchone()[0]
    flows_today = conn.execute(
        "SELECT COUNT(*) FROM traffic_flows WHERE timestamp >= ?", (today_start,)
    ).fetchone()[0]
    db_size_mb = round(DB_PATH.stat().st_size / 1_048_576, 3) if DB_PATH.exists() else 0.0

    return {
        "total_devices": total_devices,
        "active_alerts": active_alerts,
        "flows_today": flows_today,
        "db_size_mb": db_size_mb,
    }
