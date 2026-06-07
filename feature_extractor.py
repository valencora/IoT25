"""
feature_extractor.py — Paso 9: extracción de features por ventana de tiempo
y estado de baseline por dispositivo.

Agrupa los flujos de cada dispositivo en ventanas fijas de WINDOW_SECONDS
(por defecto 5 min = 300 s) y calcula un vector de comportamiento por ventana.
Solo usa librería estándar de Python; no requiere dependencias externas.

Por qué estas features
──────────────────────
  n_flows           Intensidad de actividad: un IoT en reposo tiene muy pocos
                    flujos; un bot DDoS/scanner los dispara.
  bytes_total       Volumen enviado total; DDoS y exfiltración generan picos.
  bytes_mean        Tamaño medio por flujo; escaneos SYN tienen 0 bytes,
                    descargas tienen valores muy altos.
  packets_total     Complementa bytes (distingue muchos-paquetes-chicos de
                    pocos-paquetes-grandes).
  packets_mean      Media de paquetes por flujo; útil junto con bytes_mean.
  n_dst_ips         Fan-out a IPs destino; escaneos horizontales (Mirai) lo
                    elevan dramáticamente.
  n_dst_ports       Diversidad de puertos destino; escaneos verticales
                    (port-scan) lo elevan.
  duration_mean_ms  Duración media; flujos S0 (sin respuesta) → 0 ms,
                    comunicación real → segundos.
  pct_tcp           Fracción TCP; algunos malware usan TCP exclusivamente.
  pct_udp           Fracción UDP; DNS, NTP y DDoS amplification lo usan.
  pct_other         Fracción de otros protocolos (ICMP, GRE, etc.).

Umbral de baseline
──────────────────
  DEFAULT_MIN_WINDOWS = 10  (≈ 50 min de captura continua)
  Se puede sobreescribir con settings['baseline_min_windows'] en la base.
  Con el Amazon Echo (~5.4 h → ~65 ventanas de 5 min) el Echo alcanza
  el umbral; los 23 devices-ruido con <5 flujos quedan en 'pending'.
"""

import ipaddress
import json
import logging
from collections import defaultdict
from datetime import datetime, UTC
from sqlite3 import Connection

from database import get_db

logger = logging.getLogger(__name__)

# ── Configuración ────────────────────────────────────────────────────────────

WINDOW_SECONDS: int = 300   # tamaño de ventana en segundos (5 min)

# IPs que nunca corresponden a un dispositivo IoT vigilable: se marcan
# con status='excluded' y no entran en el cálculo de baseline.
_EXCLUDED_NETWORKS: list = [
    ipaddress.ip_network("0.0.0.0/8"),         # this-network / no asignada
    ipaddress.ip_network("255.255.255.255/32"), # broadcast limitado
    ipaddress.ip_network("169.254.0.0/16"),     # IPv4 link-local (APIPA)
    ipaddress.ip_network("224.0.0.0/4"),        # IPv4 multicast
    ipaddress.ip_network("::/128"),             # IPv6 no especificada
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
    ipaddress.ip_network("ff00::/8"),           # IPv6 multicast
]

DEFAULT_MIN_WINDOWS: int = 10
# Mínimo de ventanas para que un dispositivo alcance status='ready'.
# ≈ 50 min de observación continua con al menos 1 flujo por ventana.
# Leído de settings['baseline_min_windows'] si la clave existe.

_SETTING_KEY = "baseline_min_windows"

FEATURE_NAMES: list[str] = [
    "n_flows",
    "bytes_total",
    "bytes_mean",
    "packets_total",
    "packets_mean",
    "n_dst_ips",
    "n_dst_ports",
    "duration_mean_ms",
    "pct_tcp",
    "pct_udp",
    "pct_other",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_excluded_ip(ip: str | None) -> bool:
    """
    Devuelve True si la IP corresponde a una dirección especial que no debe
    incluirse en el baseline IoT: no asignada, broadcast, link-local IPv4/IPv6
    o multicast.  Las IPs privadas rutables (192.168.x.x, 10.x, 172.16-31.x)
    devuelven False — son candidatas legítimas a baseline.
    """
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _EXCLUDED_NETWORKS)
    except ValueError:
        return True   # no parseable → excluir por precaución


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _get_min_windows(conn: Connection) -> int:
    row = conn.execute(
        "SELECT value FROM settings WHERE key = ?", (_SETTING_KEY,)
    ).fetchone()
    if row:
        try:
            return int(row[0])
        except (ValueError, TypeError):
            pass
    return DEFAULT_MIN_WINDOWS


def _ts_to_epoch(ts_str: str) -> float | None:
    """Convierte timestamp ISO 8601 a epoch float. Devuelve None si falla."""
    try:
        return datetime.fromisoformat(ts_str).timestamp()
    except (ValueError, TypeError):
        return None


# ── Feature extraction ────────────────────────────────────────────────────────

def extract_features(
    device_id: int,
    conn: Connection | None = None,
    since: str | None = None,
    until: str | None = None,
    window_seconds: int = WINDOW_SECONDS,
    benign_only: bool = False,
) -> list[dict]:
    """
    Calcula un vector de features por ventana de tiempo para el dispositivo.

    Parámetros
    ----------
    device_id      : ID del dispositivo en la tabla devices.
    conn           : Conexión SQLite (usa get_db() si es None).
    since / until  : Filtros opcionales de rango (ISO 8601 UTC).
    window_seconds : Duración de cada ventana en segundos.
    benign_only    : Si True, excluye flujos con label='Malicious'.
                     Pasa `label IS NULL OR label = 'Benign'`, lo que
                     incluye todos los flujos de producción (sin label)
                     y solo los etiquetados como benignos en datasets IoT-23.
                     Debe usarse siempre en el contexto de entrenamiento para
                     evitar que flujos maliciosos contaminen el baseline.

    Retorna
    -------
    Lista de dicts ordenada por tiempo:
        [
          {
            "window_start": "2018-09-21T11:25:00+00:00",
            "window_epoch": 1537526700,
            "features": {
              "n_flows": 12,
              "bytes_total": 4096,
              ...
            }
          },
          ...
        ]
    """
    if conn is None:
        conn = get_db()

    query = """
        SELECT bytes_sent, packets, duration_ms, dst_ip, dst_port, protocol, timestamp
        FROM traffic_flows
        WHERE device_id = ?
    """
    params: list = [device_id]
    if benign_only:
        query += " AND (label IS NULL OR label = 'Benign')"
    if since:
        query += " AND timestamp >= ?"
        params.append(since)
    if until:
        query += " AND timestamp <= ?"
        params.append(until)
    query += " ORDER BY timestamp ASC"

    rows = conn.execute(query, params).fetchall()
    if not rows:
        return []

    # Agrupar filas por ventana temporal
    buckets: dict[int, list] = defaultdict(list)
    for row in rows:
        epoch = _ts_to_epoch(row["timestamp"] if hasattr(row, "__getitem__") else row[6])
        if epoch is None:
            continue
        key = int(epoch // window_seconds) * window_seconds
        buckets[key].append(row)

    # Calcular features por ventana
    result = []
    for w_epoch in sorted(buckets.keys()):
        flows = buckets[w_epoch]
        n = len(flows)

        bytes_list   = [row["bytes_sent"]   or 0 for row in flows]
        pkts_list    = [row["packets"]      or 0 for row in flows]
        dur_list     = [row["duration_ms"]  or 0 for row in flows]
        dst_ips      = {row["dst_ip"]   for row in flows if row["dst_ip"]}
        dst_ports    = {row["dst_port"] for row in flows if row["dst_port"] is not None}
        protos       = [str(row["protocol"] or "").lower() for row in flows]

        n_tcp   = sum(1 for p in protos if p == "tcp")
        n_udp   = sum(1 for p in protos if p == "udp")
        n_other = n - n_tcp - n_udp

        features: dict[str, float | int] = {
            "n_flows":          n,
            "bytes_total":      sum(bytes_list),
            "bytes_mean":       round(_mean(bytes_list), 2),
            "packets_total":    sum(pkts_list),
            "packets_mean":     round(_mean(pkts_list), 2),
            "n_dst_ips":        len(dst_ips),
            "n_dst_ports":      len(dst_ports),
            "duration_mean_ms": round(_mean(dur_list), 2),
            "pct_tcp":          round(n_tcp   / n, 4),
            "pct_udp":          round(n_udp   / n, 4),
            "pct_other":        round(n_other / n, 4),
        }

        window_iso = datetime.fromtimestamp(w_epoch, tz=UTC).isoformat()
        result.append({
            "window_start": window_iso,
            "window_epoch": w_epoch,
            "features": features,
        })

    return result


# ── Baseline status ───────────────────────────────────────────────────────────

def update_baseline_status(device_id: int, conn: Connection | None = None) -> dict:
    """
    Computa el número de ventanas de features para device_id y actualiza
    training_metadata. Retorna el estado resultante.

    status posibles
    ---------------
    'excluded' — IP especial (link-local, broadcast, multicast, 0.0.0.0);
                 no es un dispositivo IoT vigilable.
    'pending'  — IP válida pero aún no alcanzó el umbral mínimo de ventanas.
    'ready'    — IP válida con suficientes ventanas para entrenar el baseline.
    """
    if conn is None:
        conn = get_db()

    now_iso   = datetime.now(UTC).isoformat()
    feat_json = json.dumps(FEATURE_NAMES)

    # ── Comprobar si la IP del dispositivo es una dirección especial ──────────
    row = conn.execute("SELECT ip FROM devices WHERE id = ?", (device_id,)).fetchone()
    device_ip = row["ip"] if row else None

    if _is_excluded_ip(device_ip):
        status    = "excluded"
        n_windows = 0
    else:
        windows     = extract_features(device_id, conn=conn)
        n_windows   = len(windows)
        min_windows = _get_min_windows(conn)
        status      = "ready" if n_windows >= min_windows else "pending"

    # ── Upsert en training_metadata ───────────────────────────────────────────
    existing = conn.execute(
        "SELECT id FROM training_metadata WHERE device_id = ?", (device_id,)
    ).fetchone()

    if existing:
        conn.execute(
            """
            UPDATE training_metadata
               SET training_date = ?, n_samples = ?, feature_names = ?, status = ?
             WHERE device_id = ?
            """,
            (now_iso, n_windows, feat_json, status, device_id),
        )
    else:
        conn.execute(
            """
            INSERT INTO training_metadata
                (device_id, training_date, n_samples, feature_names, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (device_id, now_iso, n_windows, feat_json, status),
        )

    conn.commit()
    logger.debug(
        "baseline status updated device_id=%d ip=%s n_windows=%d status=%s",
        device_id, device_ip, n_windows, status,
    )
    return {"device_id": device_id, "n_windows": n_windows, "status": status}


def refresh_all_baselines(conn: Connection | None = None) -> list[dict]:
    """
    Actualiza training_metadata para todos los dispositivos registrados.
    Llamado por los endpoints de entrenamiento para mantener el estado al día.
    """
    if conn is None:
        conn = get_db()
    device_ids = [row[0] for row in conn.execute("SELECT id FROM devices")]
    return [update_baseline_status(did, conn=conn) for did in device_ids]
