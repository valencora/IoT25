"""
device_discovery.py  –  US-01/US-02: Detección e identificación de dispositivos IoT.

Estrategia general
──────────────────
1. Detecta el rango de red local (ej. 192.168.1.0/24).
2. Cada `interval` segundos envía ARP requests broadcast al rango.
3. Por cada host que responde:
   - MAC nueva  → INSERT en `devices`, evento 'device_discovered'.
   - IP cambió  → UPDATE ip + last_seen,   evento 'ip_changed'.
   - Estaba offline → marcar 'active',      evento 'status_changed'.
   - Siempre    → UPDATE last_seen.
4. Dispositivos activos que no responden durante `offline_threshold` escaneos
   consecutivos son marcados status='offline'.
5. Todo corre en un hilo daemon; el hilo principal no se bloquea.

Requisitos
──────────
  pip install mac-vendor-lookup
  El barrido ARP se delega a `nmap` o `arp-scan` (binarios del sistema) vía
  subprocess. NO se usa Scapy: ponía la interfaz WiFi en modo promiscuo, lo
  que desestabilizaba el driver de OpenWrt y tiraba la red completa.
  Ejecutar con privilegios root (nmap/arp-scan necesitan root para el ARP sweep).
"""

import logging
import re
import shutil
import socket
import subprocess
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, UTC
from ipaddress import IPv4Interface

from alert_manager import create_alert
from database import get_db, init_db

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers de red
# ──────────────────────────────────────────────────────────────────────────────

def _detect_local_network() -> str:
    """
    Determina la red local abriendo un socket UDP sin datos para obtener la IP
    de la interfaz de salida, luego asume máscara /24 (válido para redes
    domésticas / laboratorio). Para máscaras distintas, pasar `network` manualmente.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        # Conectar a una dirección pública sin enviar nada: el SO elige la
        # interfaz correcta y expone la IP local en getsockname().
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]

    network = str(IPv4Interface(f"{local_ip}/24").network)
    logger.debug("Red local detectada: %s", network)
    return network


def _normalize_mac(mac: str) -> str:
    """Normaliza la MAC a minúsculas con ':'. Ej: 'AA-BB-CC-DD-EE-FF' → 'aa:bb:cc:dd:ee:ff'."""
    return mac.lower().replace("-", ":").replace(".", ":")


def _resolve_hostname(ip: str, timeout: float = 0.5) -> str | None:
    """
    Intenta resolver el hostname via reverse DNS (PTR record).
    Usa un timeout corto para no ralentizar el escaneo.
    Retorna None si la resolución falla.
    """
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old)


_mac_lookup = None


def _get_mac_lookup():
    global _mac_lookup
    if _mac_lookup is None:
        from mac_vendor_lookup import MacLookup  # type: ignore
        _mac_lookup = MacLookup()
    return _mac_lookup


def _lookup_vendor(mac: str) -> str | None:
    """
    Busca el fabricante del dispositivo por OUI usando mac-vendor-lookup.
    Retorna 'random_mac' si la MAC es localmente administrada (aleatorizada).
    """
    first_byte = int(mac.split(":")[0], 16)
    if first_byte & 0x02:
        return "random_mac"
    try:
        return _get_mac_lookup().lookup(mac)
    except Exception:
        return None


_DEVICE_TYPE_RULES: list[tuple[list[str], str]] = [
    (["camera", "cam", "hikvision", "dahua"], "camara"),
    (["samsung", "lg", " tv", "television"], "smart_tv"),
    (["tp-link", "netgear", "router"], "router"),
    (["arduino", "raspberry", "esp"], "sensor"),
]


def _infer_device_type(vendor: str | None, hostname: str | None) -> str:
    text = " ".join(filter(None, [vendor, hostname])).lower()
    for keywords, device_type in _DEVICE_TYPE_RULES:
        if any(kw in text for kw in keywords):
            return device_type
    return "desconocido"


def _scan_with_nmap(network: str, timeout: int) -> list[dict]:
    """
    Descubre hosts con `nmap -sn` (ping/ARP sweep) y parsea la salida XML.

    nmap abre la captura pcap con promisc=0, así que NO activa el modo
    promiscuo en la interfaz — a diferencia de Scapy, que congelaba el
    driver WiFi de OpenWrt.
    """
    result = subprocess.run(
        ["nmap", "-sn", "-n", "-oX", "-", network],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        logger.warning(
            "nmap terminó con código %d: %s", result.returncode, result.stderr.strip()
        )

    hosts: list[dict] = []
    root = ET.fromstring(result.stdout)
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = mac = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")

        # Sin MAC no podemos identificar el dispositivo (la IP cambia con DHCP).
        # El propio host que ejecuta el escaneo aparece sin MAC → se omite.
        if ip and mac:
            hosts.append({"ip": ip, "mac": _normalize_mac(mac)})

    return hosts


# Línea de arp-scan: "192.168.1.1<TAB>aa:bb:cc:dd:ee:ff<TAB>Vendor..."
_ARPSCAN_LINE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:]{17})")


def _scan_with_arpscan(network: str, timeout: int) -> list[dict]:
    """
    Descubre hosts con `arp-scan`. Las respuestas ARP son unicast a nuestra
    propia MAC, así que arp-scan no necesita modo promiscuo tampoco.
    """
    result = subprocess.run(
        ["arp-scan", "--retry=2", "--timeout=500", network],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        logger.warning(
            "arp-scan terminó con código %d: %s",
            result.returncode,
            result.stderr.strip(),
        )

    hosts: list[dict] = []
    for line in result.stdout.splitlines():
        m = _ARPSCAN_LINE.match(line)
        if m:
            ip, mac = m.group(1), m.group(2)
            hosts.append({"ip": ip, "mac": _normalize_mac(mac)})

    return hosts


def _arp_scan(network: str, timeout: int = 60) -> list[dict]:
    """
    Descubre los hosts activos de la red ejecutando una herramienta nativa
    del sistema vía subprocess, en lugar de Scapy.

    Motivo del cambio
    -----------------
    Scapy (srp/ARP) ponía la interfaz WiFi en modo promiscuo
    ("device phy0-sta0 entered promiscuous mode" en dmesg), lo que
    desestabilizaba el driver de OpenWrt y cortaba la red. `nmap -sn` y
    `arp-scan` hacen el mismo barrido ARP sin tocar el modo promiscuo.

    Prefiere nmap (abre pcap con promisc=0 de forma explícita); si no está
    instalado, usa arp-scan como alternativa.

    Parámetros
    ----------
    network : str
        Rango CIDR, ej. '192.168.1.0/24'.
    timeout : int
        Segundos máximos para el subprocess antes de abortar el escaneo.

    Retorna
    -------
    Lista de dicts con claves 'ip' y 'mac' por cada host que respondió.
    """
    if shutil.which("nmap"):
        scanner, scan_fn = "nmap", _scan_with_nmap
    elif shutil.which("arp-scan"):
        scanner, scan_fn = "arp-scan", _scan_with_arpscan
    else:
        logger.error(
            "No se encontró 'nmap' ni 'arp-scan' en PATH. "
            "Instalar uno en OpenWrt: opkg install nmap  (o)  opkg install arp-scan"
        )
        return []

    try:
        hosts = scan_fn(network, timeout)
        logger.debug("Escaneo vía %s: %d host(s).", scanner, len(hosts))
        return hosts
    except subprocess.TimeoutExpired:
        logger.error("El escaneo con %s superó el timeout de %ds.", scanner, timeout)
        return []
    except FileNotFoundError:
        logger.error("'%s' no está instalado o no es ejecutable.", scanner)
        return []
    except ET.ParseError:
        logger.exception("No se pudo parsear la salida XML de nmap.")
        return []
    except Exception:
        logger.exception("Error ejecutando el escaneo con %s.", scanner)
        return []


# ──────────────────────────────────────────────────────────────────────────────
# Persistencia en SQLite
# ──────────────────────────────────────────────────────────────────────────────

def _log_event(
    conn,
    device_id: int,
    event_type: str,
    old_value: str | None,
    new_value: str | None,
) -> None:
    """Inserta una fila en device_events para auditar cambios de estado."""
    conn.execute(
        """
        INSERT INTO device_events (device_id, event_type, old_value, new_value, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        (device_id, event_type, old_value, new_value, datetime.now(UTC).isoformat()),
    )


def _upsert_device(host: dict) -> tuple[int, bool]:
    """
    Inserta o actualiza un dispositivo en la tabla `devices` usando la MAC
    como identificador único (la IP puede cambiar).

    Lógica
    ------
    - MAC nueva  → INSERT con status='active', evento 'device_discovered'.
    - IP cambió  → UPDATE ip,                  evento 'ip_changed'.
    - Offline    → UPDATE status='active',      evento 'status_changed'.
    - Hostname   → UPDATE solo si antes era NULL y ahora lo tenemos.
    - Siempre    → UPDATE last_seen.

    Retorna (device_id, is_new): id del dispositivo y True si fue insertado ahora.
    """
    conn = get_db()
    now = datetime.now(UTC).isoformat()
    mac = host["mac"]
    ip = host["ip"]
    hostname = host.get("hostname")
    vendor = host.get("vendor")
    device_type = host.get("device_type", "desconocido")

    # Buscar si la MAC ya existe en la DB
    existing = conn.execute(
        "SELECT id, ip, hostname, vendor, status, device_type FROM devices WHERE mac = ?", (mac,)
    ).fetchone()

    is_new = False

    if existing is None:
        # ── Dispositivo nuevo ──────────────────────────────────────────────
        cur = conn.execute(
            """
            INSERT INTO devices (mac, ip, hostname, vendor, device_type, status, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
            """,
            (mac, ip, hostname, vendor, device_type, now, now),
        )
        device_id = cur.lastrowid
        is_new = True
        _log_event(conn, device_id, "device_discovered", None, f"ip={ip}")
        logger.info(
            "[NEW]  MAC=%s  IP=%-15s  hostname=%s  vendor=%s  type=%s",
            mac, ip, hostname, vendor, device_type,
        )

    else:
        # ── Dispositivo ya conocido ────────────────────────────────────────
        device_id = existing["id"]

        # Empezamos con last_seen siempre actualizado
        updates: dict[str, object] = {"last_seen": now}

        if existing["ip"] != ip:
            # La IP cambió (ej. DHCP reasignó)
            updates["ip"] = ip
            _log_event(conn, device_id, "ip_changed", existing["ip"], ip)
            logger.info("[IP]   MAC=%s  %s → %s", mac, existing["ip"], ip)

        if existing["status"] == "offline":
            # Reapareció un dispositivo que estaba marcado offline
            updates["status"] = "active"
            _log_event(conn, device_id, "came_online", "offline", "active")
            logger.info("[UP]   MAC=%s  IP=%-15s  volvió online", mac, ip)

        if hostname and not existing["hostname"]:
            updates["hostname"] = hostname

        if vendor and not existing["vendor"]:
            updates["vendor"] = vendor

        # Actualizar device_type si el existente es null o genérico y el nuevo es mejor
        if existing["device_type"] is None or (
            device_type != "desconocido" and existing["device_type"] == "desconocido"
        ):
            updates["device_type"] = device_type

        # Construir UPDATE dinámico; las claves vienen de nuestro propio código
        set_clause = ", ".join(f"{col} = ?" for col in updates)
        conn.execute(
            f"UPDATE devices SET {set_clause} WHERE id = ?",
            (*updates.values(), device_id),
        )

    conn.commit()
    return device_id, is_new


def _mark_offline(mac: str) -> None:
    """
    Marca un dispositivo como 'offline' si todavía no lo estaba
    y registra el evento en device_events.
    """
    conn = get_db()
    row = conn.execute(
        "SELECT id, status FROM devices WHERE mac = ?", (mac,)
    ).fetchone()

    if row and row["status"] != "offline":
        conn.execute("UPDATE devices SET status = 'offline' WHERE id = ?", (row["id"],))
        _log_event(conn, row["id"], "went_offline", "active", "offline")
        conn.commit()
        logger.warning("[DOWN] MAC=%s  sin respuesta → offline", mac)


# ──────────────────────────────────────────────────────────────────────────────
# Clase principal de descubrimiento
# ──────────────────────────────────────────────────────────────────────────────

class DeviceDiscovery:
    """
    Escanea la red local con ARP en un hilo daemon y sincroniza los dispositivos
    con la base de datos SQLite.

    Uso típico
    ----------
    >>> from device_discovery import DeviceDiscovery
    >>> disc = DeviceDiscovery(network="192.168.1.0/24", interval=60)
    >>> disc.start()   # no bloquea
    >>> disc.stop()    # detención limpia

    Parámetros
    ----------
    network : str | None
        Rango CIDR a escanear. Si es None, se detecta automáticamente.
    interval : int
        Segundos entre escaneos (defecto: 60).
    offline_threshold : int
        Número de escaneos consecutivos sin respuesta para marcar offline (defecto: 3).
    """

    def __init__(
        self,
        network: str | None = None,
        interval: int = 60,
        offline_threshold: int = 3,
    ) -> None:
        self.network = network or _detect_local_network()
        self.interval = interval
        self.offline_threshold = offline_threshold

        # MAC → contador de escaneos consecutivos sin respuesta
        # Solo se usa desde el hilo de escaneo: no requiere lock.
        self._miss_counts: dict[str, int] = {}

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ── Control del ciclo de vida ─────────────────────────────────────────────

    def start(self) -> None:
        """Lanza el hilo de escaneo en background. Idempotente si ya corre."""
        if self._thread and self._thread.is_alive():
            logger.warning("DeviceDiscovery ya está corriendo.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="DeviceDiscovery",
            daemon=True,  # Muere automáticamente cuando el proceso principal termina
        )
        self._thread.start()
        logger.info(
            "DeviceDiscovery iniciado | red=%s | intervalo=%ds | offline_threshold=%d",
            self.network,
            self.interval,
            self.offline_threshold,
        )

    def stop(self) -> None:
        """Señala al hilo que se detenga y espera su finalización."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self.interval + 10)
        logger.info("DeviceDiscovery detenido.")

    def scan_now(self) -> None:
        """
        Dispara un escaneo inmediato desde cualquier hilo (bloqueante).
        Útil para pruebas o para forzar un refresh sin esperar el intervalo.
        """
        self._scan_once()

    # ── Bucle interno ─────────────────────────────────────────────────────────

    def _run(self) -> None:
        """
        Bucle principal del hilo. Ejecuta un escaneo y luego espera `interval`
        segundos. El Event permite despertar anticipadamente al llamar stop().
        """
        while not self._stop_event.is_set():
            try:
                self._scan_once()
            except PermissionError:
                logger.error(
                    "Sin permisos para enviar paquetes ARP. "
                    "Ejecutar con sudo o asignar CAP_NET_RAW al proceso."
                )
            except Exception:
                logger.exception("Error inesperado en el ciclo de escaneo.")

            # Espera interrumpible: despierta si se llama stop()
            self._stop_event.wait(self.interval)

    def _scan_once(self) -> None:
        """
        Un ciclo completo de escaneo:

        1. ARP sweep → conjunto de hosts activos en la red.
        2. Enriquecer cada host con hostname (reverse DNS) y vendor (OUI).
        3. Upsert en DB + resetear miss_count de los que respondieron.
        4. Incrementar miss_count de los ausentes; si alcanza el threshold,
           marcar offline.
        """
        logger.info("── Escaneo ARP en %s ──", self.network)

        # ── 1. Escaneo ARP ────────────────────────────────────────────────────
        found_hosts = _arp_scan(self.network)
        found_macs = {h["mac"] for h in found_hosts}
        logger.info("%d host(s) respondieron al ARP.", len(found_hosts))

        # ── 2. Enriquecer con hostname, vendor y device_type ─────────────────
        for host in found_hosts:
            host["hostname"] = _resolve_hostname(host["ip"])
            host["vendor"] = _lookup_vendor(host["mac"])
            host["device_type"] = _infer_device_type(host["vendor"], host["hostname"])

        # ── 3. Persistir dispositivos activos ─────────────────────────────────
        for host in found_hosts:
            try:
                device_id, is_new = _upsert_device(host)
                self._miss_counts[host["mac"]] = 0  # Respondió → resetear contador
                if is_new:
                    hostname_label = host.get("hostname") or "desconocido"
                    create_alert(
                        device_id,
                        "new_device",
                        "medium",
                        f"Se conecto un nuevo dispositivo ({hostname_label}) con IP {host['ip']}."
                        " Verificá si lo reconocés.",
                    )
            except Exception:
                logger.exception("Error guardando dispositivo MAC=%s", host["mac"])

        # ── 4. Detectar ausentes entre los activos conocidos ──────────────────
        conn = get_db()
        active_rows = conn.execute(
            "SELECT mac FROM devices WHERE status != 'offline'"
        ).fetchall()

        for row in active_rows:
            mac = row["mac"]
            if mac in found_macs:
                continue  # Ya fue procesado en el paso 3

            self._miss_counts[mac] = self._miss_counts.get(mac, 0) + 1
            misses = self._miss_counts[mac]
            logger.debug(
                "MAC=%s ausente (%d/%d escaneos)", mac, misses, self.offline_threshold
            )

            if misses >= self.offline_threshold:
                _mark_offline(mac)
                # Resetear para no re-procesar en cada ciclo posterior
                self._miss_counts[mac] = 0

        conn = get_db()
        total_active = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE status != 'offline'"
        ).fetchone()[0]
        logger.info("Escaneo completo — activos en red: %d  |  activos en DB: %d", len(found_hosts), total_active)


# ──────────────────────────────────────────────────────────────────────────────
# Entry point para pruebas rápidas
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import time

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    init_db()

    disc = DeviceDiscovery(interval=60, offline_threshold=3)
    disc.start()

    print("Escaneando… Ctrl+C para detener.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        disc.stop()
