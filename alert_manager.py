import json
import logging
from datetime import datetime, timedelta, UTC

from database import get_db

logger = logging.getLogger(__name__)


def create_alert(
    device_id: int,
    alert_type: str,
    severity: str,
    message: str,
    technical_detail: dict | None = None,
    event_time: datetime | None = None,
) -> int | None:
    """
    Insert an alert. Returns the new id, or None if a duplicate exists in the
    last 10 minutes for the same device_id + alert_type pair.

    event_time — fecha/hora del evento que disparó la alerta (p.ej. window_start
                 en anomalías). Si se omite, se usa datetime.now(UTC).
                 El campo ``timestamp`` de la alerta refleja esta fecha, mientras
                 que ``created_at`` siempre registra el momento de inserción en BD.
                 El anti-duplicados usa ``created_at`` para no verse afectado por
                 alertas de eventos pasados.
    """
    conn = get_db()
    now = datetime.now(UTC)
    cutoff = (now - timedelta(minutes=10)).isoformat()

    # Anti-duplicados basado en created_at (hora de registro), no en timestamp
    # (hora del evento), para que alertas de ventanas antiguas no bloqueen el
    # deduplicador de los próximos 10 minutos.
    duplicate = conn.execute(
        """
        SELECT id FROM alerts
        WHERE device_id = ? AND type = ?
          AND (created_at >= ? OR (created_at IS NULL AND timestamp >= ?))
        LIMIT 1
        """,
        (device_id, alert_type, cutoff, cutoff),
    ).fetchone()

    if duplicate:
        logger.debug(
            "Alert skipped (duplicate within 10 min) device_id=%s type=%s",
            device_id, alert_type,
        )
        return None

    now_iso        = now.isoformat()
    timestamp_val  = event_time.isoformat() if event_time else now_iso
    detail_json    = json.dumps(technical_detail) if technical_detail else None

    cur = conn.execute(
        """
        INSERT INTO alerts
            (device_id, type, severity, message, technical_detail, timestamp, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (device_id, alert_type, severity, message, detail_json, timestamp_val, now_iso),
    )
    conn.commit()
    logger.info(
        "Alert created id=%d type=%s severity=%s device_id=%s event_time=%s",
        cur.lastrowid, alert_type, severity, device_id,
        event_time.isoformat() if event_time else "now",
    )
    return cur.lastrowid


def get_active_alerts() -> list[dict]:
    """Return unacknowledged alerts ordered by severity (critical first) then created_at desc."""
    conn = get_db()
    rows = conn.execute(
        """
        SELECT id, device_id, type, severity, message, technical_detail,
               timestamp, created_at, acknowledged, resolved, category
        FROM alerts
        WHERE acknowledged = 0
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 0
                WHEN 'high'     THEN 1
                WHEN 'medium'   THEN 2
                WHEN 'low'      THEN 3
                ELSE 4
            END,
            COALESCE(created_at, timestamp) DESC
        """
    ).fetchall()
    return [dict(row) for row in rows]
