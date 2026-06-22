"""
anomaly_detector.py — Paso 10: detección de anomalías con Isolation Forest.

Usa river.anomaly.HalfSpaceTrees, la versión online/incremental del
Isolation Forest.  Compatible con OpenWrt/musl/aarch64 sin necesidad de
ruedas de scikit-learn.

Diseño
──────
- Un modelo por dispositivo, guardado en models/iforest_<device_id>.pkl.
- Solo se entrena si training_metadata.status = 'ready' (paso 9).
- Umbral derivado empíricamente del propio baseline:
    threshold = percentil(1 - contamination) de los scores de entrenamiento
    p. ej. contamination=0.05 → percentil 95 → el 5% más alto del baseline
    se considera potencialmente anómalo (falsos positivos de referencia).
- score_one() de river devuelve [0, 1]; más alto = más anómalo.

Ajuste del modelo (HalfSpaceTrees)
────────────────────────────────────
  n_trees=25   : más árboles → estimación más estable del score.
  height=8     : profundidad del árbol; controla la granularidad.
  window_size  : = nº de ventanas de entrenamiento, para que toda la
                 captura baseline quepa en una sola ventana deslizante.

El modelo NO usa scikit-learn ni numpy; solo river y pickle de la stdlib.
"""

import logging
import pickle
import threading
from datetime import datetime, UTC, timedelta, timezone
from pathlib import Path
from sqlite3 import Connection

from river import anomaly

from alert_manager import create_alert
from database import get_db
from email_notifier import send_alert_email
from feature_extractor import FEATURE_NAMES, extract_features

logger = logging.getLogger(__name__)

# ── Rutas y constantes ────────────────────────────────────────────────────────

MODELS_DIR = Path(__file__).parent / "models"

_CONTAMINATION_KEY = "iforest_contamination"
_DEFAULT_CONTAMINATION = 0.05


def _model_path(device_id: int) -> Path:
    return MODELS_DIR / f"iforest_{device_id}.pkl"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_contamination(conn: Connection) -> float:
    """Lee iforest_contamination de settings; usa 0.05 si no existe."""
    row = conn.execute(
        "SELECT value FROM settings WHERE key = ?", (_CONTAMINATION_KEY,)
    ).fetchone()
    if row:
        try:
            return float(row[0])
        except (ValueError, TypeError):
            pass
    return _DEFAULT_CONTAMINATION


def _save_model(device_id: int, payload: dict) -> None:
    """
    Persiste el modelo y su metadata en models/iforest_<device_id>.pkl.
    payload = {
        'model':        HalfSpaceTrees,
        'threshold':    float,
        'trained_at':   str ISO 8601,
        'n_samples':    int,
        'contamination': float,
    }
    """
    MODELS_DIR.mkdir(exist_ok=True)
    with open(_model_path(device_id), "wb") as fh:
        pickle.dump(payload, fh)


def _load_model(device_id: int) -> dict | None:
    """Carga el modelo desde disco. Devuelve None si no existe."""
    path = _model_path(device_id)
    if not path.exists():
        return None
    with open(path, "rb") as fh:
        return pickle.load(fh)


def _percentile(values: list[float], p: float) -> float:
    """
    Percentil p ∈ [0, 1] de una lista de valores (interpolación lineal).
    No depende de numpy.
    """
    if not values:
        return 0.0
    sorted_v = sorted(values)
    idx_f = p * (len(sorted_v) - 1)
    lo = int(idx_f)
    hi = min(lo + 1, len(sorted_v) - 1)
    frac = idx_f - lo
    return sorted_v[lo] + frac * (sorted_v[hi] - sorted_v[lo])


# ── Normalización min-max ─────────────────────────────────────────────────────

def _build_normalizer(feature_dicts: list[dict]) -> dict[str, tuple[float, float]]:
    """
    Calcula el rango [min, max] de cada feature sobre el conjunto de
    entrenamiento. Se persiste junto con el modelo para aplicar la misma
    transformación en scoring.
    """
    normalizer: dict[str, tuple[float, float]] = {}
    for fname in FEATURE_NAMES:
        vals = [fd[fname] for fd in feature_dicts]
        normalizer[fname] = (min(vals), max(vals))
    return normalizer


def _normalize(fd: dict, normalizer: dict[str, tuple[float, float]]) -> dict:
    """
    Aplica normalización min-max a [0, 1] usando los rangos del entrenamiento.
    - Si el rango es 0 (feature constante en training), fija el valor en 0.5
      para no introducir NaN y mantener la feature "neutral" en el modelo.
    - En scoring: valores fuera del rango de entrenamiento se clampean a
      [0, 1] para que HalfSpaceTrees los identifique como casos extremos
      (score alto) sin colapsar el modelo.
    """
    result: dict[str, float] = {}
    for fname in FEATURE_NAMES:
        mn, mx = normalizer[fname]
        rng = mx - mn
        if rng == 0.0:
            result[fname] = 0.5
        else:
            raw = fd[fname]
            result[fname] = max(0.0, min(1.0, (raw - mn) / rng))
    return result


# ── Entrenamiento ─────────────────────────────────────────────────────────────

def train_device(device_id: int, conn: Connection | None = None) -> dict:
    """
    Entrena un HalfSpaceTrees con las ventanas baseline del dispositivo.

    Flujo
    -----
    1. Verifica que training_metadata.status sea 'ready' o 'trained'
       (si no, devuelve ok=False con la razón).
    2. Obtiene las ventanas de features via extract_features().
    3. Construye el modelo con window_size = nº de ventanas (todas caben
       en una sola ventana deslizante → el modelo no descarta muestras).
    4. Primera pasada: learn_one() con cada ventana (construye el modelo).
    5. Segunda pasada: score_one() para derivar el umbral empírico como
       percentil (1 - contamination) de los scores de entrenamiento.
    6. Persiste modelo + umbral en models/iforest_<device_id>.pkl.
    7. Actualiza training_metadata.status → 'trained'.

    Retorna dict con el resultado (ok, n_samples, threshold, etc.).
    """
    if conn is None:
        conn = get_db()

    # ── 1. Verificar estado ───────────────────────────────────────────────────
    row = conn.execute(
        "SELECT status, n_samples FROM training_metadata WHERE device_id = ?",
        (device_id,),
    ).fetchone()

    if row is None:
        return {
            "device_id": device_id,
            "ok": False,
            "reason": "sin entrada en training_metadata — ejecutá /api/training/status primero",
        }

    if row["status"] not in ("ready", "trained"):
        return {
            "device_id": device_id,
            "ok": False,
            "reason": (
                f"status='{row['status']}' — "
                "se requiere 'ready' o 'trained' (re-entrenar)"
            ),
        }

    # ── 2. Obtener ventanas de features (solo flujos benignos/sin label) ─────
    # benign_only=True excluye flujos label='Malicious' de datasets IoT-23.
    # En producción todos los flujos tienen label=NULL → ninguno se descarta.
    windows = extract_features(device_id, conn=conn, benign_only=True)
    if not windows:
        return {
            "device_id": device_id,
            "ok": False,
            "reason": "sin ventanas de features (o todos los flujos son Malicious)",
        }

    feature_dicts = [w["features"] for w in windows]
    contamination = _get_contamination(conn)

    # ── 3. Normalización min-max ──────────────────────────────────────────────
    # HalfSpaceTrees NO es invariante a escala: sin normalizar, bytes_total
    # (rango ≈10^6) dominaría los cortes y features como pct_tcp (rango ≈0.5)
    # serían casi invisibles para el modelo.
    # Normalizamos a [0,1] usando los rangos del propio baseline de entrenamiento.
    normalizer = _build_normalizer(feature_dicts)
    norm_dicts  = [_normalize(fd, normalizer) for fd in feature_dicts]

    # ── 4. Construir modelo ───────────────────────────────────────────────────
    # window_size = exactamente el nº de ventanas de entrenamiento.
    # Importante: si window_size > n_muestras, HalfSpaceTrees devuelve
    # scores 0.0 porque nunca llena su ventana de referencia → umbral=0
    # → modelo inútil.  Usar len() exacto garantiza que todo el baseline
    # quepa en una sola ventana de calibración.
    model = anomaly.HalfSpaceTrees(
        n_trees=25,
        height=8,
        window_size=len(norm_dicts),
        seed=42,
    )

    # ── 5. Primera pasada: aprender ───────────────────────────────────────────
    for nd in norm_dicts:
        model.learn_one(nd)

    # ── 6. Segunda pasada: derivar umbral empírico ────────────────────────────
    # Puntuamos los datos de entrenamiento. El umbral es el percentil
    # (1 - contamination): las ventanas con score por encima se consideran
    # anómalas.  Sobre el baseline benigno este percentil captura los "peores"
    # 5% de ventanas normales (falsos positivos aceptados).
    train_scores = [model.score_one(nd) for nd in norm_dicts]
    threshold = _percentile(train_scores, 1.0 - contamination)

    now_iso = datetime.now(UTC).isoformat()
    n_train_anomalies = sum(1 for s in train_scores if s > threshold)

    # ── 7. Persistir ──────────────────────────────────────────────────────────
    payload = {
        "model":        model,
        "normalizer":   normalizer,
        "threshold":    threshold,
        "trained_at":   now_iso,
        "n_samples":    len(feature_dicts),
        "contamination": contamination,
    }
    _save_model(device_id, payload)

    # ── 8. Actualizar training_metadata ───────────────────────────────────────
    conn.execute(
        """
        UPDATE training_metadata
           SET status = 'trained', training_date = ?, n_samples = ?
         WHERE device_id = ?
        """,
        (now_iso, len(feature_dicts), device_id),
    )
    conn.commit()

    logger.info(
        "IForest trained device_id=%d n_samples=%d threshold=%.4f "
        "n_train_anomalies=%d contamination=%.3f",
        device_id, len(feature_dicts), threshold,
        n_train_anomalies, contamination,
    )

    return {
        "device_id":         device_id,
        "ok":                True,
        "n_samples":         len(feature_dicts),
        "threshold":         round(threshold, 6),
        "contamination":     contamination,
        "trained_at":        now_iso,
        "n_train_anomalies": n_train_anomalies,
        "model_path":        str(_model_path(device_id)),
    }


def train_all_ready(conn: Connection | None = None) -> list[dict]:
    """
    Entrena todos los dispositivos con status = 'ready' en training_metadata.
    Ignora los 'excluded', 'pending' y los ya 'trained' (no re-entrena).
    Retorna lista de resultados de train_device().
    """
    if conn is None:
        conn = get_db()
    rows = conn.execute(
        "SELECT device_id FROM training_metadata WHERE status = 'ready'"
    ).fetchall()
    results = [train_device(row["device_id"], conn=conn) for row in rows]
    logger.info(
        "train_all_ready: %d entrenados, %d fallidos",
        sum(1 for r in results if r.get("ok")),
        sum(1 for r in results if not r.get("ok")),
    )
    return results


# ── Scoring ───────────────────────────────────────────────────────────────────

def score_window(device_id: int, features_dict: dict) -> dict | None:
    """
    Carga el modelo del dispositivo y puntúa una ventana de features.
    Aplica la misma normalización min-max usada en el entrenamiento.

    Retorna
    -------
    {
        "score":      float,   # [0, 1]; más alto = más anómalo
        "threshold":  float,   # umbral derivado en el entrenamiento
        "is_anomaly": bool,    # score > threshold
    }
    o None si no hay modelo entrenado para ese dispositivo.
    """
    payload = _load_model(device_id)
    if payload is None:
        return None
    norm = _normalize(features_dict, payload["normalizer"])
    score = payload["model"].score_one(norm)
    threshold = payload["threshold"]
    return {
        "score":      round(score, 6),
        "threshold":  round(threshold, 6),
        "is_anomaly": score > threshold,
    }


def score_all_windows(device_id: int, conn: Connection | None = None) -> dict:
    """
    Calcula las ventanas de features del dispositivo y puntúa cada una.
    Aplica la normalización del entrenamiento antes de pasarlas al modelo.

    Retorna
    -------
    {
        "device_id":    int,
        "n_windows":    int,
        "n_anomalies":  int,
        "threshold":    float,
        "contamination": float,
        "model_trained_at": str,
        "windows": [
            {
                "window_start": str,
                "features":     dict,   # valores crudos (sin normalizar)
                "score":        float,
                "is_anomaly":   bool,
            },
            ...
        ]
    }
    O un dict con "error" si no hay modelo entrenado.
    """
    if conn is None:
        conn = get_db()

    payload = _load_model(device_id)
    if payload is None:
        return {
            "device_id": device_id,
            "error": "sin modelo entrenado — ejecutá POST /api/devices/{id}/train primero",
        }

    windows   = extract_features(device_id, conn=conn)
    threshold = payload["threshold"]
    model     = payload["model"]
    norm_fn   = lambda fd: _normalize(fd, payload["normalizer"])

    scored = []
    for w in windows:
        s = model.score_one(norm_fn(w["features"]))
        scored.append({
            "window_start": w["window_start"],
            "features":     w["features"],    # crudos, para legibilidad
            "score":        round(s, 6),
            "is_anomaly":   s > threshold,
        })

    n_anomalies = sum(1 for w in scored if w["is_anomaly"])
    return {
        "device_id":        device_id,
        "n_windows":        len(scored),
        "n_anomalies":      n_anomalies,
        "threshold":        round(threshold, 6),
        "contamination":    payload["contamination"],
        "model_trained_at": payload["trained_at"],
        "windows":          scored,
    }


# ── Generación de alertas desde anomalías ────────────────────────────────────

# Mensajes en lenguaje cotidiano por feature y dirección de desviación.
# Tupla: (mensaje si el valor es ALTO/FUERA-POR-ARRIBA, mensaje si es BAJO/FUERA-POR-ABAJO)
# None indica que esa dirección no es una señal de alarma relevante.
_FEAT_THREAT_MSG: dict[str, tuple[str | None, str | None]] = {
    "n_dst_ips": (
        "se conectó a muchos más destinos de lo habitual, lo que puede indicar"
        " un escaneo de red o propagación a otros equipos",
        "se comunicó de forma sostenida con un único destino"
        " (posible servidor de control remoto)",
    ),
    "n_dst_ports": (
        "accedió a un gran número de puertos distintos, algo típico de un"
        " escaneo de puertos o de un intento de intrusión",
        None,
    ),
    "bytes_total": (
        "transfirió un volumen de datos muy superior a lo habitual,"
        " lo que puede indicar exfiltración de información",
        None,
    ),
    "bytes_mean": (
        "cada conexión movió muchos más datos de lo normal",
        None,
    ),
    "packets_total": (
        "generó una cantidad de paquetes muy superior a lo habitual,"
        " señal de actividad de red elevada o posible ataque de denegación de servicio",
        None,
    ),
    "packets_mean": (
        "los flujos de tráfico individuales fueron mucho más voluminosos de lo normal",
        None,
    ),
    "n_flows": (
        "generó muchas más conexiones de lo habitual,"
        " indicativo de actividad de red anormalmente elevada",
        None,
    ),
    "duration_mean_ms": (
        "mantuvo conexiones activas durante mucho más tiempo de lo normal,"
        " algo típico de conexiones persistentes a servidores externos",
        None,
    ),
    "pct_udp": (
        "cambió drásticamente el tipo de tráfico que genera hacia UDP,"
        " inusual para este dispositivo y común en ataques de amplificación o tunelización",
        None,
    ),
    "pct_other": (
        "utilizó protocolos de red poco habituales para este dispositivo",
        None,
    ),
    "pct_tcp": (
        "cambió el tipo de tráfico predominante hacia TCP,"
        " algo inusual para el comportamiento habitual de este dispositivo",
        None,
    ),
}

# Recomendaciones de acción por feature y dirección de desviación.
# Tupla: (acción si el valor es ALTO, acción si es BAJO)
# None indica que esa dirección no amerita recomendación específica.
_FEAT_ACTION: dict[str, tuple[str | None, str | None]] = {
    "n_dst_ips": (
        "Revisá si el dispositivo debería estar contactando tantas direcciones distintas. "
        "Si no reconocés esta actividad, desconectalo de la red y verificá si tiene "
        "actualizaciones de seguridad pendientes.",
        "Revisá a qué dirección se está conectando el dispositivo de forma sostenida. "
        "Este patrón puede indicar comunicación con un servidor externo. "
        "Ante la duda, aislá el dispositivo y revisá su tráfico con un técnico.",
    ),
    "n_dst_ports": (
        "Revisá si el dispositivo debería estar accediendo a tantos puertos distintos. "
        "Si no reconocés esta actividad, desconectalo de la red y verificá si tiene "
        "actualizaciones de seguridad pendientes.",
        None,
    ),
    "bytes_total": (
        "Verificá si el dispositivo debería estar transfiriendo esta cantidad de datos. "
        "Si no reconocés la actividad, desconectalo de la red y revisá su configuración "
        "o consultá con un responsable de seguridad.",
        None,
    ),
    "bytes_mean": (
        "Verificá si el dispositivo debería estar moviendo tantos datos por conexión. "
        "Si no reconocés la actividad, desconectalo y revisá su configuración.",
        None,
    ),
    "packets_total": (
        "Verificá si el dispositivo debería estar generando tanto tráfico de red. "
        "Si no iniciaste ninguna actividad especial, desconectalo y revisá su estado.",
        None,
    ),
    "packets_mean": (
        "Revisá si el dispositivo está funcionando normalmente. "
        "Si el tráfico te parece inusual, verificá su configuración.",
        None,
    ),
    "n_flows": (
        "Revisá si el dispositivo debería estar generando tantas conexiones de red. "
        "Si no reconocés esta actividad, desconectalo y verificá su estado.",
        None,
    ),
    "duration_mean_ms": (
        "Revisá a qué servidor se está conectando el dispositivo durante tanto tiempo. "
        "Este patrón puede indicar una conexión persistente a un servidor externo. "
        "Ante la duda, aislá el dispositivo y verificá su tráfico con un técnico.",
        None,
    ),
    "pct_udp": (
        "El dispositivo cambió el tipo de tráfico que genera. Verificá si esto es esperado; "
        "si no, reiniciá el dispositivo y monitoreá si el comportamiento continúa.",
        None,
    ),
    "pct_other": (
        "El dispositivo está usando protocolos de red poco habituales. "
        "Verificá si fue modificado o actualizado recientemente.",
        None,
    ),
    "pct_tcp": (
        "El dispositivo cambió el tipo de tráfico que genera. Verificá si esto es esperado; "
        "si no, reiniciá el dispositivo y monitoreá si el comportamiento continúa.",
        None,
    ),
}

# Recomendación genérica cuando no hay feature específica identificada.
_ACTION_FALLBACK = (
    "Revisá la actividad reciente del dispositivo. Si no reconocés este comportamiento, "
    "considerá desconectarlo de la red temporalmente y consultá con un responsable de seguridad."
)


def _pick_recommendation(
    features: dict,
    normalizer: dict[str, tuple[float, float]],
) -> str:
    """
    Elige la recomendación de acción más relevante según la feature principal
    que disparó la anomalía. Sigue el mismo criterio de priorización que
    _build_anomaly_message (mayor desviación + peso de alarma).
    """
    top = _top_deviated_features(features, normalizer, top_n=5)
    for t in top:
        action_pair = _FEAT_ACTION.get(t["name"])
        if not action_pair:
            continue
        action = action_pair[0] if t["direction"] == "above" else action_pair[1]
        if action is not None:
            return action
    return _ACTION_FALLBACK


# Peso de alarma por feature: prioriza las más relevantes cuando hay empate.
_FEAT_ALARM_WEIGHT: dict[str, int] = {
    "n_dst_ips":     10,
    "n_dst_ports":    9,
    "bytes_total":    8,
    "n_flows":        7,
    "packets_total":  6,
    "duration_mean_ms": 5,
    "bytes_mean":     4,
    "pct_udp":        3,
    "pct_other":      3,
    "pct_tcp":        2,
    "packets_mean":   2,
}


def _top_deviated_features(
    features: dict,
    normalizer: dict[str, tuple[float, float]],
    top_n: int = 5,
) -> list[dict]:
    """
    Identifica las features más llamativas respecto al rango del baseline.

    Criterio (por orden de prioridad):
    1. Features FUERA del rango de entrenamiento (outside > 0): comportamiento
       nuevo que el modelo nunca vio en training.
    2. Features en el EXTREMO del rango (normalized >= 0.85 o <= 0.15):
       en el límite de lo observado, posible causa de anomalía combinatoria.

    En caso de empate, _FEAT_ALARM_WEIGHT prioriza las features más relevantes
    para la detección de amenazas (n_dst_ips > n_dst_ports > bytes > ...).

    Devuelve lista con:
      outside   — cuánto excede el rango [0,1] (>0 si está fuera)
      direction — "above" si el valor es alto, "below" si es bajo
    """
    items = []
    for fname, val in features.items():
        if fname not in normalizer:
            continue
        mn, mx = normalizer[fname]
        rng = mx - mn
        if rng == 0.0:
            continue
        normalized = (val - mn) / rng
        outside    = max(0.0, normalized - 1.0) + max(0.0, -normalized)
        extremeness = max(normalized, 1.0 - normalized)
        # Fuera del rango pesa 10×; extremo cercano dentro pesa 1×.
        # _FEAT_ALARM_WEIGHT actúa como desempate entre features con score similar.
        alarm_boost = _FEAT_ALARM_WEIGHT.get(fname, 1) * 0.001
        score = outside * 10.0 + max(0.0, extremeness - 0.85) + alarm_boost
        if score > alarm_boost:  # ignorar si solo tiene el boost sin desviación real
            items.append({
                "name":       fname,
                "val":        val,
                "mn":         mn,
                "mx":         mx,
                "normalized": normalized,
                "outside":    outside,
                "direction":  "above" if normalized >= 0.5 else "below",
                "score":      score,
            })
    return sorted(items, key=lambda x: x["score"], reverse=True)[:top_n]


def _build_anomaly_message(
    device_label: str,
    window_start: str | None,
    features: dict,
    normalizer: dict[str, tuple[float, float]],
    n_anomalies: int,
    n_windows: int,
    severity: str = "medium",
) -> str:
    """
    Construye un mensaje en lenguaje cotidiano para un usuario no técnico.

    - No incluye valores numéricos crudos: describe qué ocurrió, no cuánto.
    - Prioriza las 1-2 desviaciones más relevantes como señal de amenaza.
    - Omite features cuya baja no es indicativa de ataque (ej. pocos bytes).
    - Los datos exactos van en technical_detail para quien quiera el detalle.
    """
    ts_str = ""
    if window_start:
        try:
            dt_utc = datetime.fromisoformat(window_start.replace("Z", "+00:00"))
            # Convertir a hora local de Argentina (UTC-3).
            # Se usa offset fijo porque:
            #   a) Argentina no tiene horario de verano (IANA: America/Argentina/Buenos_Aires).
            #   b) zoneinfo requiere tzdata instalado, no disponible de forma garantizada en OpenWrt.
            _AR = timezone(timedelta(hours=-3))
            dt_ar = dt_utc.astimezone(_AR)
            ts_str = f" el {dt_ar.strftime('%d/%m/%Y')} a las {dt_ar.strftime('%H:%M')}"
        except Exception:
            pass

    severity_phrase = {
        "critical": "un comportamiento altamente anómalo",
        "high":     "un comportamiento inusual",
        "medium":   "actividad posiblemente inusual",
    }.get(severity, "un comportamiento inusual")

    period_ctx = f"{n_anomalies} de {n_windows} períodos de 5 min anómalos"
    intro = (
        f"El dispositivo {device_label} mostró {severity_phrase}{ts_str}"
        f" ({period_ctx})."
    )

    # Seleccionar las features más desviadas y filtrar a las alarming
    top = _top_deviated_features(features, normalizer, top_n=5)
    threat_phrases: list[str] = []
    for t in top:
        msg_pair = _FEAT_THREAT_MSG.get(t["name"])
        if not msg_pair:
            continue
        msg = msg_pair[0] if t["direction"] == "above" else msg_pair[1]
        if msg is None:
            continue  # esa dirección no es señal de alarma
        threat_phrases.append(msg)
        if len(threat_phrases) >= 2:
            break

    if not threat_phrases:
        return intro

    if len(threat_phrases) == 1:
        body = f" {threat_phrases[0][0].upper()}{threat_phrases[0][1:]}."
    else:
        body = (
            f" {threat_phrases[0][0].upper()}{threat_phrases[0][1:]};"
            f" además, {threat_phrases[1]}."
        )

    return intro + body


def _anomaly_severity(score: float, threshold: float) -> str:
    """
    Deriva la severidad a partir del exceso normalizado sobre el umbral.

    Criterio (exceso = (score - threshold) / (1 - threshold)):
      < 0.25  → "medium"   score apenas sobre el umbral
      0.25–0.60 → "high"   claramente anómalo
      >= 0.60  → "critical" score muy elevado
    """
    if threshold >= 1.0:
        return "high"
    excess = (score - threshold) / (1.0 - threshold)
    if excess < 0.25:
        return "medium"
    if excess < 0.60:
        return "high"
    return "critical"


def generate_anomaly_alerts(device_id: int, conn: Connection | None = None) -> int:
    """
    Puntúa todas las ventanas del dispositivo y crea UNA alerta por cada
    ventana anómala distinta, identificada por su window_start.

    Deduplicación permanente por ventana:
      dedup_key = "anomaly_iforest:{device_id}:{window_start}"
      Si ya existe una alerta con ese key, la ventana se salta (no importa
      cuándo fue ni cuántas veces vuelva a correr el scanner).
      Dos ventanas distintas → dos alertas. Misma ventana re-procesada → 0 nuevas.

    Las ventanas se procesan de mayor a menor score para que el log refleje
    las anomalías más graves primero.

    Retorna el número de alertas efectivamente insertadas en esta pasada.
    """
    if conn is None:
        conn = get_db()

    dev_row = conn.execute(
        "SELECT ip, hostname FROM devices WHERE id = ?", (device_id,)
    ).fetchone()
    if dev_row is None:
        logger.warning("generate_anomaly_alerts: device_id=%d no encontrado", device_id)
        return 0

    device_label = dev_row["hostname"] or dev_row["ip"] or f"dispositivo #{device_id}"

    result = score_all_windows(device_id, conn=conn)
    if "error" in result:
        logger.debug(
            "generate_anomaly_alerts: device_id=%d sin modelo — %s",
            device_id, result["error"],
        )
        return 0

    # Ordenar de mayor a menor score: la peor anomalía genera la alerta primero.
    anomalous = sorted(
        [w for w in result["windows"] if w["is_anomaly"]],
        key=lambda w: w["score"],
        reverse=True,
    )
    if not anomalous:
        return 0

    payload    = _load_model(device_id)
    normalizer = payload["normalizer"] if payload else {}
    threshold  = result["threshold"]

    n_created = 0
    for w in anomalous:
        severity = _anomaly_severity(w["score"], threshold)
        message  = _build_anomaly_message(
            device_label = device_label,
            window_start = w["window_start"],
            features     = w["features"],
            normalizer   = normalizer,
            n_anomalies  = result["n_anomalies"],
            n_windows    = result["n_windows"],
            severity     = severity,
        )
        # event_time = inicio de la ventana anómala (puede ser una fecha antigua).
        # create_alert la usa como timestamp del evento; created_at = now siempre.
        try:
            evt = datetime.fromisoformat(
                w["window_start"].replace("Z", "+00:00")
            ) if w.get("window_start") else None
        except (ValueError, AttributeError):
            evt = None

        recommendation = _pick_recommendation(w["features"], normalizer)

        alert_id = create_alert(
            device_id        = device_id,
            alert_type       = "anomaly_iforest",
            severity         = severity,
            message          = message,
            technical_detail = {
                "score":        w["score"],
                "threshold":    threshold,
                "window_start": w["window_start"],
                "features":     w["features"],
            },
            event_time       = evt,
            dedup_key        = f"anomaly_iforest:{device_id}:{w.get('window_start', '')}",
            recommendation   = recommendation,
        )
        if alert_id is not None:
            n_created += 1
            # Notificación por correo: best-effort, no interrumpe el flujo.
            send_alert_email({
                "device_id":       device_id,
                "device_label":    device_label,
                "type":            "anomaly_iforest",
                "severity":        severity,
                "message":         message,
                "recommendations": recommendation,
                "timestamp":       w.get("window_start"),
            })

    logger.info(
        "generate_anomaly_alerts: device_id=%d ventanas_anómalas=%d alertas_creadas=%d",
        device_id, len(anomalous), n_created,
    )
    return n_created


# ── Scanner periódico ─────────────────────────────────────────────────────────

class AnomalyScanner:
    """
    Hilo daemon que ejecuta generate_anomaly_alerts() para todos los
    dispositivos entrenados cada `interval` segundos.

    Sigue el mismo patrón que DeviceDiscovery: start/stop/scan_now más un
    bucle _run interrumpible via threading.Event.

    El intervalo por defecto (300 s = 5 min) coincide con el tamaño de la
    ventana de features: cada ciclo procesa las ventanas más recientes del
    tráfico capturado sin solaparse innecesariamente con el ciclo anterior.
    El anti-duplicados de create_alert (10 min) absorbe cualquier solapamiento.
    """

    def __init__(self, interval: int = 300) -> None:
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Lanza el hilo de escaneo en background. Idempotente si ya corre."""
        if self._thread and self._thread.is_alive():
            logger.warning("AnomalyScanner ya está corriendo.")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="AnomalyScanner",
            daemon=True,
        )
        self._thread.start()
        logger.info("AnomalyScanner iniciado | intervalo=%ds", self.interval)

    def stop(self) -> None:
        """Señala al hilo que se detenga y espera su finalización."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self.interval + 10)
        logger.info("AnomalyScanner detenido.")

    def scan_now(self) -> int:
        """Dispara un escaneo inmediato (bloqueante). Retorna alertas creadas."""
        return self._scan_all()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._scan_all()
            except Exception:
                logger.exception("Error inesperado en AnomalyScanner.")
            self._stop_event.wait(self.interval)

    def _scan_all(self) -> int:
        """Escanea todos los dispositivos trained y retorna alertas creadas."""
        conn = get_db()
        rows = conn.execute(
            "SELECT device_id FROM training_metadata WHERE status = 'trained'"
        ).fetchall()
        if not rows:
            return 0
        total = sum(generate_anomaly_alerts(r["device_id"], conn=conn) for r in rows)
        if total:
            logger.info("AnomalyScanner: %d alerta(s) generada(s) en este ciclo.", total)
        return total
