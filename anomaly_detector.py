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
from datetime import datetime, UTC
from pathlib import Path
from sqlite3 import Connection

from river import anomaly

from database import get_db
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
