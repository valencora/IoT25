"""
Passive TLS fingerprinting (JA3) for IoT25.

Sniffs TLS ClientHello records from packets captured by ScapyCollector,
computes the JA3 fingerprint (per https://github.com/salesforce/ja3) and
persists it to tls_fingerprints.

JA3 string format:
    SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
JA3 hash: MD5 of the JA3 string.

Identifies known clients against a local blacklist (ja3_blacklist.csv),
sourced from abuse.ch SSL Blacklist. Matches generate alerts via
alert_manager.create_alert(). To refresh the list call download_blacklist().

Activate by passing an interface name (same as CAPTURE_INTERFACE).
"""
import hashlib
import logging
import threading
import urllib.error
import urllib.request
from datetime import datetime, UTC
from pathlib import Path

from alert_manager import create_alert
from database import get_db

logger = logging.getLogger(__name__)

# GREASE values (RFC 8701) — clients inject these to detect ossified middleboxes.
# JA3 strips them so the fingerprint stays stable across handshakes.
_GREASE: frozenset[int] = frozenset({
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
})

_TLS_HANDSHAKE = 0x16     # TLS record content_type
_CLIENT_HELLO  = 0x01     # handshake_type
_EXT_SUPPORTED_GROUPS  = 10
_EXT_EC_POINT_FORMATS  = 11

_BLACKLIST_URL  = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
_BLACKLIST_PATH = Path(__file__).parent / "ja3_blacklist.csv"


# ── local JA3 blacklist ────────────────────────────────────────────────────────

_blacklist: dict[str, str] = {}
_blacklist_lock = threading.Lock()


def _load_blacklist() -> int:
    """Read ja3_blacklist.csv into the in-memory dict. Returns # of entries."""
    if not _BLACKLIST_PATH.exists():
        logger.info("JA3 blacklist not found at %s — identification disabled", _BLACKLIST_PATH)
        with _blacklist_lock:
            _blacklist.clear()
        return 0

    loaded: dict[str, str] = {}
    with _BLACKLIST_PATH.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("ja3_md5"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 4 and parts[0] and parts[3]:
                loaded[parts[0].lower()] = parts[3]   # hash -> reason

    with _blacklist_lock:
        _blacklist.clear()
        _blacklist.update(loaded)

    logger.info("Loaded %d JA3 blacklist entries from %s", len(loaded), _BLACKLIST_PATH.name)
    return len(loaded)


def _identify(ja3_hash: str) -> str | None:
    with _blacklist_lock:
        return _blacklist.get(ja3_hash)


def download_blacklist() -> int:
    """
    Refresh ja3_blacklist.csv from abuse.ch and reload it.
    Returns the number of entries loaded after refresh.
    """
    req = urllib.request.Request(_BLACKLIST_URL, headers={"User-Agent": "IoT25/0.1"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = resp.read()
    _BLACKLIST_PATH.write_bytes(data)
    logger.info("Downloaded JA3 blacklist (%d bytes)", len(data))
    return _load_blacklist()


# ── db helpers ─────────────────────────────────────────────────────────────────

def _lookup_device_id(conn, src_ip: str) -> int | None:
    row = conn.execute("SELECT id FROM devices WHERE ip = ?", (src_ip,)).fetchone()
    return row["id"] if row else None


def _save_fingerprint(
    device_id: int | None,
    ja3_hash: str,
    ja3_string: str,
    dst_ip: str,
    dst_port: int,
) -> None:
    conn = get_db()
    conn.execute(
        """
        INSERT INTO tls_fingerprints (device_id, ja3_hash, ja3_string, dst_ip, dst_port, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (device_id, ja3_hash, ja3_string, dst_ip, dst_port, datetime.now(UTC).isoformat()),
    )
    conn.commit()


# ── JA3 parser ─────────────────────────────────────────────────────────────────

def _filter_grease(values: list[int]) -> list[int]:
    return [v for v in values if v not in _GREASE]


def _parse_client_hello(record: bytes) -> tuple[int, list[int], list[int], list[int], list[int]] | None:
    """
    Parse the body of a TLS handshake record (the 4-byte handshake header
    plus the ClientHello body). Returns a tuple of
    (version, ciphers, extensions, curves, point_formats) or None.

    Single-segment ClientHellos only — TCP-fragmented handshakes are skipped.
    """
    if len(record) < 4 or record[0] != _CLIENT_HELLO:
        return None

    hs_len = int.from_bytes(record[1:4], "big")
    body = record[4:4 + hs_len]
    if len(body) < 38:                          # version(2) + random(32) + sid_len(1) + ...
        return None

    version = int.from_bytes(body[0:2], "big")
    idx = 2 + 32                                # skip legacy_version + random

    sid_len = body[idx]
    idx += 1 + sid_len
    if idx + 2 > len(body):
        return None

    cs_len = int.from_bytes(body[idx:idx + 2], "big")
    idx += 2
    if idx + cs_len > len(body) or cs_len % 2 != 0:
        return None
    ciphers = [
        int.from_bytes(body[idx + i:idx + i + 2], "big")
        for i in range(0, cs_len, 2)
    ]
    idx += cs_len

    if idx + 1 > len(body):
        return None
    cm_len = body[idx]
    idx += 1 + cm_len
    if idx + 2 > len(body):
        return version, ciphers, [], [], []     # no extensions present

    ext_total = int.from_bytes(body[idx:idx + 2], "big")
    idx += 2
    ext_end = min(idx + ext_total, len(body))

    extensions: list[int] = []
    curves: list[int] = []
    point_formats: list[int] = []

    while idx + 4 <= ext_end:
        ext_type = int.from_bytes(body[idx:idx + 2], "big")
        ext_len  = int.from_bytes(body[idx + 2:idx + 4], "big")
        idx += 4
        if idx + ext_len > ext_end:
            break
        ext_data = body[idx:idx + ext_len]
        idx += ext_len

        extensions.append(ext_type)

        if ext_type == _EXT_SUPPORTED_GROUPS and len(ext_data) >= 2:
            ec_len = int.from_bytes(ext_data[0:2], "big")
            if 2 + ec_len <= len(ext_data) and ec_len % 2 == 0:
                curves = [
                    int.from_bytes(ext_data[2 + i:2 + i + 2], "big")
                    for i in range(0, ec_len, 2)
                ]
        elif ext_type == _EXT_EC_POINT_FORMATS and len(ext_data) >= 1:
            pf_len = ext_data[0]
            if 1 + pf_len <= len(ext_data):
                point_formats = list(ext_data[1:1 + pf_len])

    return version, ciphers, extensions, curves, point_formats


def _compute_ja3(
    version: int,
    ciphers: list[int],
    extensions: list[int],
    curves: list[int],
    point_formats: list[int],
) -> tuple[str, str]:
    parts = [
        str(version),
        "-".join(str(c) for c in _filter_grease(ciphers)),
        "-".join(str(e) for e in _filter_grease(extensions)),
        "-".join(str(c) for c in _filter_grease(curves)),
        "-".join(str(p) for p in point_formats),
    ]
    ja3_str = ",".join(parts)
    ja3_hash = hashlib.md5(ja3_str.encode("utf-8")).hexdigest()
    return ja3_hash, ja3_str


# ── packet entry-point ─────────────────────────────────────────────────────────

def process_tls_packet(pkt) -> None:
    """
    Called by ScapyCollector for every captured packet.
    Detects TLS ClientHello records (any TCP port — 443, 8443, 993, etc.)
    and persists the JA3 fingerprint.
    """
    from scapy.layers.inet import IP, TCP

    try:
        if IP not in pkt or TCP not in pkt:
            return
        payload = bytes(pkt[TCP].payload)
        # TLS record header: content_type(1) + version(2) + length(2) = 5 bytes
        if len(payload) < 6 or payload[0] != _TLS_HANDSHAKE:
            return
        rec_len = int.from_bytes(payload[3:5], "big")
        record = payload[5:5 + rec_len]

        parsed = _parse_client_hello(record)
        if parsed is None:
            return

        ja3_hash, ja3_str = _compute_ja3(*parsed)

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        dst_port = pkt[TCP].dport

        conn = get_db()
        device_id = _lookup_device_id(conn, src_ip)
        _save_fingerprint(device_id, ja3_hash, ja3_str, dst_ip, dst_port)

        label = _identify(ja3_hash)
        if label:
            logger.warning(
                "Malicious JA3 match: %s = %s (src=%s -> %s:%d device_id=%s)",
                ja3_hash, label, src_ip, dst_ip, dst_port, device_id,
            )
            create_alert(
                device_id=device_id,
                alert_type="malicious_tls",
                severity="high",
                message=f"TLS fingerprint asociado a {label} ({dst_ip}:{dst_port})",
                technical_detail={
                    "ja3_hash": ja3_hash,
                    "label": label,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                },
            )
        else:
            logger.info(
                "TLS JA3: %s -> %s:%d hash=%s",
                src_ip, dst_ip, dst_port, ja3_hash,
            )

    except Exception as exc:
        logger.warning("TlsCapture: error processing packet: %s", exc)


class TlsCapture:
    """Stub kept for API compatibility — TLS is processed inside ScapyCollector."""

    def __init__(self, interface: str):
        pass

    def start(self) -> None:
        _load_blacklist()
        logger.info("TlsCapture: integrated into ScapyCollector")

    def stop(self) -> None:
        pass
