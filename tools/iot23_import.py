#!/usr/bin/env python3
"""
iot23_import.py — Importa un conn.log.labeled del dataset IoT-23 (Stratosphere/CTU)
a la base SQLite del proyecto IoT25, en una base de PRUEBA separada.

Uso:
    python tools/iot23_import.py <conn.log.labeled> <output.db>

Ejemplo:
    python tools/iot23_import.py data/conn.log.labeled iot25_iot23.db

El archivo conn.log.labeled es la salida etiquetada de Zeek (Bro) del dataset IoT-23.
Cada fila de flujo se mapea a traffic_flows; las IPs de origen se registran como devices.
La base de salida es independiente de la base de producción (iot25.db).
"""

import re
import sys
import hashlib
from datetime import datetime, UTC
from pathlib import Path

# Agrega el directorio raíz al path para importar database.py
sys.path.insert(0, str(Path(__file__).parent.parent))
import database


# ---------------------------------------------------------------------------
# Helpers de parsing
# ---------------------------------------------------------------------------

def _make_synthetic_mac(ip: str) -> str:
    """MAC determinista a partir de una IP (prefijo aa:bb para identificar origen)."""
    h = hashlib.md5(ip.encode()).hexdigest()
    return ":".join(h[i : i + 2] for i in range(0, 12, 2))


def _zeek_val(raw: str, unset: str, empty: str):
    """Devuelve None si el campo es unset o empty (convención Zeek)."""
    return None if raw in (unset, empty) else raw


def _to_int(raw: str, unset: str, empty: str) -> int | None:
    v = _zeek_val(raw, unset, empty)
    if v is None:
        return None
    try:
        return int(float(v))
    except ValueError:
        return None


def _to_ms(raw: str, unset: str, empty: str) -> int:
    """Convierte duración en segundos (float string de Zeek) a milisegundos."""
    v = _zeek_val(raw, unset, empty)
    if v is None:
        return 0
    try:
        return int(float(v) * 1000)
    except ValueError:
        return 0


def _epoch_to_iso(raw: str) -> str:
    """Convierte timestamp Unix (float) a ISO 8601 UTC."""
    try:
        return datetime.fromtimestamp(float(raw), tz=UTC).isoformat()
    except (ValueError, TypeError):
        return datetime.now(UTC).isoformat()


def _parse_meta(filepath: Path) -> tuple[list[str], str, str, bool]:
    """
    Lee el bloque de comentarios (#...) y extrae dinámicamente:
    - lista de campos (línea #fields)
    - valor unset  (línea #unset_field, por defecto '-')
    - valor empty  (línea #empty_field, por defecto '(empty)')
    - honeypot_fmt: True si las columnas de etiqueta van separadas por espacios al final
      (formato IoT-23 Honeypot) en lugar de tabs (formato IoT-23 Malware estándar).

    Formato estándar (Malware):
        #fields  ...  tunnel_parents<TAB>label<TAB>det_label
        data:    ...  -<TAB>Benign<TAB>-

    Formato Honeypot:
        #fields  ...  tunnel_parents   label   detailed-label   (3 espacios)
        data:    ...  -   benign   -
    """
    fields: list[str] = []
    unset = "-"
    empty = "(empty)"
    honeypot_fmt = False
    with open(filepath, "r") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                raw_parts = line.split("\t")[1:]  # excluye '#fields'
                fields = []
                for part in raw_parts:
                    # Si algún token contiene 2+ espacios consecutivos, es un bloque
                    # de campos separados por espacios (formato Honeypot)
                    if "  " in part:
                        honeypot_fmt = True
                        fields.extend(
                            s for s in re.split(r" {2,}", part.strip()) if s
                        )
                    else:
                        fields.append(part)
            elif line.startswith("#unset_field"):
                unset = line.split("\t")[1]
            elif line.startswith("#empty_field"):
                empty = line.split("\t")[1]
            elif not line.startswith("#"):
                break
    if not fields:
        raise ValueError("No se encontró la línea #fields en el archivo.")
    return fields, unset, empty, honeypot_fmt


def _split_row(line: str, honeypot_fmt: bool, n_fields: int) -> list[str]:
    """
    Parsea una línea de datos manejando ambos formatos de IoT-23:
    - Estándar  : todo tab-separado → split simple por '\\t'.
    - Honeypot  : los últimos N campos (label + detailed-label) están
                  pegados al final como "tunnel_val   label_val   det_val"
                  separados por 2+ espacios dentro del último campo tab.

    Devuelve una lista de exactamente n_fields valores (o la que resulte).
    """
    parts = line.rstrip("\n").split("\t")
    if not honeypot_fmt or len(parts) >= n_fields:
        return parts
    # Expande el último campo tab, que contiene los campos extra separados por espacios
    *head, last = parts
    extra = re.split(r" {2,}", last.strip())
    return head + extra


# ---------------------------------------------------------------------------
# Lógica de base de datos
# ---------------------------------------------------------------------------

def _ensure_extra_columns(conn) -> None:
    """
    Agrega columnas label y detail_label a traffic_flows si no existen (idempotente).
    - label       : 'Benign' / 'Malicious'
    - detail_label: tipo de ataque del IoT-23 (p. ej. 'C&C', 'PartOfAHorizontalPortScan')
    """
    existing = {row[1] for row in conn.execute("PRAGMA table_info(traffic_flows)")}
    for col in ("label", "detail_label"):
        if col not in existing:
            conn.execute(f"ALTER TABLE traffic_flows ADD COLUMN {col} TEXT")
            print(f"  [DB] Columna '{col}' agregada a traffic_flows.")
        else:
            print(f"  [DB] Columna '{col}' ya existe en traffic_flows.")
    conn.commit()


def _upsert_devices(conn, orig_ips: set[str]) -> dict[str, int]:
    """
    Inserta un device por cada IP origen única.
    Devuelve un dict ip → device_id (sin tocar los ya existentes).
    """
    now = datetime.now(UTC).isoformat()
    ip_to_id: dict[str, int] = {}

    for ip in sorted(orig_ips):
        mac = _make_synthetic_mac(ip)
        row = conn.execute("SELECT id FROM devices WHERE mac = ?", (mac,)).fetchone()
        if row:
            ip_to_id[ip] = row[0]
        else:
            cur = conn.execute(
                """INSERT INTO devices
                       (mac, ip, hostname, vendor, device_type, status, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (mac, ip, f"iot23-{ip}", "IoT-23", "iot23", "active", now, now),
            )
            ip_to_id[ip] = cur.lastrowid

    conn.commit()
    return ip_to_id


# ---------------------------------------------------------------------------
# Importación principal
# ---------------------------------------------------------------------------

BATCH_SIZE = 500

INSERT_SQL = """
    INSERT INTO traffic_flows
        (device_id, src_ip, dst_ip, src_port, dst_port, protocol,
         bytes_sent, packets, duration_ms, timestamp, label, detail_label)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def import_conn_log(input_path: Path, output_db: Path) -> None:
    print(f"\n{'='*55}")
    print(f"  IoT-23 → IoT25 importer")
    print(f"  Fuente : {input_path}")
    print(f"  Salida : {output_db}")
    print(f"{'='*55}\n")

    # --- Inicializar base con el schema del proyecto ---
    database.DB_PATH = output_db
    # Asegura que no quede una conexión cacheada a otra base
    if hasattr(database._local, "conn"):
        database._local.conn.close()
        del database._local.conn

    database.init_db()
    conn = database.get_db()

    _ensure_extra_columns(conn)

    # --- Parsear header dinámicamente ---
    fields, unset_val, empty_val, honeypot_fmt = _parse_meta(input_path)
    fmt_name = "Honeypot (espacios)" if honeypot_fmt else "estándar (tabs)"
    print(f"  Formato detectado  : {fmt_name}")
    print(f"  Campos detectados ({len(fields)}): {', '.join(fields)}\n")

    # Índices de los campos usados
    try:
        fi = fields.index
        idx_ts       = fi("ts")
        idx_src_ip   = fi("id.orig_h")
        idx_src_port = fi("id.orig_p")
        idx_dst_ip   = fi("id.resp_h")
        idx_dst_port = fi("id.resp_p")
        idx_proto    = fi("proto")
        idx_duration = fi("duration")
        idx_bytes    = fi("orig_bytes")
        idx_pkts     = fi("orig_pkts")
        idx_label    = fi("label")
        # Campo de tipo de ataque: "det_label" en Malware, "detailed-label" en Honeypot
        try:
            idx_det_label = fi("det_label")
        except ValueError:
            idx_det_label = fi("detailed-label")
    except ValueError as e:
        sys.exit(f"Error: campo obligatorio no encontrado en #fields: {e}")

    # --- Pasada 1: recolectar IPs origen únicas ---
    print("  Escaneando IPs de origen...")
    orig_ips: set[str] = set()
    with open(input_path, "r") as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            parts = _split_row(line, honeypot_fmt, len(fields))
            if len(parts) > idx_src_ip:
                ip = parts[idx_src_ip]
                if ip and ip not in (unset_val, empty_val):
                    orig_ips.add(ip)

    ip_to_id = _upsert_devices(conn, orig_ips)
    n_devices = len(ip_to_id)
    print(f"  Dispositivos registrados: {n_devices}\n")

    # --- Pasada 2: importar flujos en lotes ---
    print("  Importando flujos...")
    batch: list[tuple] = []
    total_flows = 0
    skipped = 0
    label_counts: dict[str, int] = {}
    detail_counts: dict[str, int] = {}

    def flush(b: list) -> None:
        conn.executemany(INSERT_SQL, b)
        conn.commit()

    with open(input_path, "r") as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            parts = _split_row(line, honeypot_fmt, len(fields))
            if len(parts) < len(fields):
                skipped += 1
                continue

            src_ip = parts[idx_src_ip]
            if src_ip in (unset_val, empty_val):
                skipped += 1
                continue

            dst_ip = _zeek_val(parts[idx_dst_ip], unset_val, empty_val)
            if dst_ip is None:
                skipped += 1
                continue

            # Normalizar label a título: "benign"→"Benign", "Malicious"→"Malicious"
            raw_label = _zeek_val(parts[idx_label], unset_val, empty_val) or "Unknown"
            label = raw_label.capitalize()
            label_counts[label] = label_counts.get(label, 0) + 1

            det_label = _zeek_val(parts[idx_det_label], unset_val, empty_val)
            detail_counts[det_label or "-"] = detail_counts.get(det_label or "-", 0) + 1

            batch.append((
                ip_to_id.get(src_ip),                              # device_id
                src_ip,                                            # src_ip
                dst_ip,                                            # dst_ip
                _to_int(parts[idx_src_port], unset_val, empty_val),  # src_port
                _to_int(parts[idx_dst_port], unset_val, empty_val),  # dst_port
                _zeek_val(parts[idx_proto], unset_val, empty_val),   # protocol
                _to_int(parts[idx_bytes],   unset_val, empty_val) or 0,  # bytes_sent
                _to_int(parts[idx_pkts],    unset_val, empty_val) or 0,  # packets
                _to_ms(parts[idx_duration], unset_val, empty_val),   # duration_ms
                _epoch_to_iso(parts[idx_ts]),                      # timestamp
                label,                                             # label
                det_label,                                         # detail_label
            ))

            if len(batch) >= BATCH_SIZE:
                flush(batch)
                total_flows += len(batch)
                batch.clear()

    if batch:
        flush(batch)
        total_flows += len(batch)

    # --- Reporte final ---
    print(f"\n{'='*55}")
    print(f"  REPORTE DE IMPORTACIÓN")
    print(f"{'='*55}")
    print(f"  Flujos importados  : {total_flows:>10,}")
    print(f"  Flujos omitidos    : {skipped:>10,}")
    print(f"  Dispositivos       : {n_devices:>10,}")
    print(f"\n  Distribución por label:")
    for lbl, cnt in sorted(label_counts.items(), key=lambda x: -x[1]):
        pct = cnt / total_flows * 100 if total_flows else 0
        print(f"    {lbl:<30s}: {cnt:>8,}  ({pct:.1f}%)")
    print(f"\n  Distribución por detail_label (tipo de ataque):")
    for dlbl, cnt in sorted(detail_counts.items(), key=lambda x: -x[1]):
        pct = cnt / total_flows * 100 if total_flows else 0
        print(f"    {dlbl:<40s}: {cnt:>8,}  ({pct:.1f}%)")
    print(f"{'='*55}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(
            "Uso: python tools/iot23_import.py <conn.log.labeled> <output.db>\n"
            "Ejemplo: python tools/iot23_import.py data/conn.log.labeled iot25_iot23.db"
        )

    input_path = Path(sys.argv[1])
    output_db  = Path(sys.argv[2]).resolve()

    if not input_path.exists():
        sys.exit(f"Error: el archivo '{input_path}' no existe.")

    if output_db.samefile(database.DB_PATH) if output_db.exists() and database.DB_PATH.exists() else False:
        sys.exit("Error: la base de salida no puede ser la base de producción (iot25.db).")

    import_conn_log(input_path, output_db)


if __name__ == "__main__":
    main()
