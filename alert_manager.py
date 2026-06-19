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
    dedup_key: str | None = None,
    recommendation: str | None = None,
) -> int | None:
    """
    Inserta una alerta y devuelve el nuevo id, o None si es duplicado.

    Hay dos modos de deduplicación según si se provee ``dedup_key``:

    1. Deduplicación por clave permanente (dedup_key != None):
       Si ya existe cualquier alerta con ese dedup_key, se descarta.
       Útil para anomalías por ventana: mismo window_start → misma clave
       → nunca se duplica, sin importar cuántas veces corra el scanner.

    2. Deduplicación por tiempo (dedup_key is None, comportamiento original):
       Si existe una alerta con mismo device_id + type en los últimos 10 min,
       se descarta. Usado por alertas de dispositivo nuevo, DNS, TLS, etc.

    event_time — fecha/hora del evento (p.ej. window_start en anomalías).
                 Si se omite, se usa datetime.now(UTC).
                 ``timestamp`` refleja el evento; ``created_at`` siempre = now.
    """
    conn = get_db()
    now = datetime.now(UTC)

    if dedup_key is not None:
        # Modo 1: deduplicación permanente por clave de ventana.
        existing = conn.execute(
            "SELECT id FROM alerts WHERE dedup_key = ? LIMIT 1",
            (dedup_key,),
        ).fetchone()
        if existing:
            logger.debug(
                "Alert skipped (dedup_key exists) device_id=%s type=%s key=%s",
                device_id, alert_type, dedup_key,
            )
            return None
    else:
        # Modo 2: deduplicación por tiempo (alertas no-anomalía).
        cutoff = (now - timedelta(minutes=10)).isoformat()
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

    now_iso       = now.isoformat()
    timestamp_val = event_time.isoformat() if event_time else now_iso
    detail_json   = json.dumps(technical_detail) if technical_detail else None

    cur = conn.execute(
        """
        INSERT INTO alerts
            (device_id, type, severity, message, technical_detail,
             timestamp, created_at, dedup_key, recommendations)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (device_id, alert_type, severity, message, detail_json,
         timestamp_val, now_iso, dedup_key, recommendation),
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
               timestamp, created_at, acknowledged, resolved, category, recommendations
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
