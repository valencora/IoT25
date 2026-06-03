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
) -> int | None:
    """
    Insert an alert. Returns the new id, or None if a duplicate exists in the
    last 10 minutes for the same device_id + alert_type pair.
    """
    conn = get_db()
    cutoff = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()

    duplicate = conn.execute(
        """
        SELECT id FROM alerts
        WHERE device_id = ? AND type = ? AND timestamp >= ?
        LIMIT 1
        """,
        (device_id, alert_type, cutoff),
    ).fetchone()

    if duplicate:
        logger.debug(
            "Alert skipped (duplicate within 10 min) device_id=%s type=%s",
            device_id, alert_type,
        )
        return None

    now = datetime.now(UTC).isoformat()
    detail_json = json.dumps(technical_detail) if technical_detail else None

    cur = conn.execute(
        """
        INSERT INTO alerts (device_id, type, severity, message, technical_detail, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (device_id, alert_type, severity, message, detail_json, now),
    )
    conn.commit()
    logger.info(
        "Alert created id=%d type=%s severity=%s device_id=%s",
        cur.lastrowid, alert_type, severity, device_id,
    )
    return cur.lastrowid


def get_active_alerts() -> list[dict]:
    """Return unacknowledged alerts ordered by severity (critical first) then timestamp desc."""
    conn = get_db()
    rows = conn.execute(
        """
        SELECT id, device_id, type, severity, message, technical_detail,
               timestamp, acknowledged, resolved, category
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
            timestamp DESC
        """
    ).fetchall()
    return [dict(row) for row in rows]
