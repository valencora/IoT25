"""
NetFlow v5/v9 collector and traffic simulator for IoT25.

Real mode (NetFlow) : TrafficCollector listens on UDP 2055 and persists each flow.
Real mode (pcap)    : ScapyCollector sniffs a NIC directly, aggregates into flows.
Simul mode          : TrafficSimulator generates synthetic flows every N seconds.
"""
import ipaddress
import logging
import random
import socket
import threading
import time
from datetime import datetime, UTC

from netflow import parse_packet
from netflow.v9 import V9TemplateNotRecognized

from database import get_db
from dns_capture import process_dns_packet
from tls_capture import process_tls_packet

logger = logging.getLogger(__name__)

NETFLOW_PORT = 2055

_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP"}

# ── helpers ────────────────────────────────────────────────────────────────────

def _proto_name(proto_num: int) -> str:
    return _PROTO_NAMES.get(proto_num, str(proto_num))


def _lookup_device_id(conn, src_ip: str) -> int | None:
    row = conn.execute("SELECT id FROM devices WHERE ip = ?", (src_ip,)).fetchone()
    return row["id"] if row else None


def _save_flow(
    device_id: int | None,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    bytes_sent: int,
    packets: int,
    duration_ms: int,
) -> None:
    conn = get_db()
    now = datetime.now(UTC).isoformat()
    conn.execute(
        """
        INSERT INTO traffic_flows
            (device_id, src_ip, dst_ip, src_port, dst_port,
             protocol, bytes_sent, packets, duration_ms, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (device_id, src_ip, dst_ip, src_port, dst_port,
         protocol, bytes_sent, packets, duration_ms, now),
    )
    conn.commit()


# ── real collector ─────────────────────────────────────────────────────────────

class TrafficCollector:
    """Listens for NetFlow v5/v9 datagrams on UDP 2055 in a background thread."""

    def __init__(self, host: str = "0.0.0.0", port: int = NETFLOW_PORT):
        self._host = host
        self._port = port
        self._templates: dict = {}      # v9 template cache (shared across packets)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="netflow-collector", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)        # allows checking stop_event each second
            sock.bind((self._host, self._port))
        except OSError as exc:
            logger.error("Cannot bind NetFlow UDP %s:%d — %s", self._host, self._port, exc)
            return

        logger.info("NetFlow collector listening on udp/%d", self._port)
        while not self._stop_event.is_set():
            try:
                data, addr = sock.recvfrom(65535)
                self._process_packet(data, addr)
            except socket.timeout:
                continue
            except Exception as exc:
                logger.warning("Collector recv error: %s", exc)

        sock.close()
        logger.info("NetFlow collector stopped")

    def _process_packet(self, data: bytes, addr: tuple) -> None:
        try:
            packet = parse_packet(data, self._templates)
        except V9TemplateNotRecognized:
            # Normal on first v9 packet — template arrives before data
            logger.debug("V9 template not yet known from %s, buffering", addr[0])
            return
        except Exception as exc:
            logger.warning("Failed to parse NetFlow packet from %s: %s", addr[0], exc)
            return

        conn = get_db()
        saved = 0
        version = getattr(packet.header, "version", 0)

        for flow in packet.flows:
            try:
                d = flow.data

                if version == 5:
                    src_ip = str(ipaddress.ip_address(d["IPV4_SRC_ADDR"]))
                    dst_ip = str(ipaddress.ip_address(d["IPV4_DST_ADDR"]))
                    src_port  = d["SRC_PORT"]
                    dst_port  = d["DST_PORT"]
                    proto_num = d["PROTO"]
                    bytes_sent = d["IN_OCTETS"]
                    packets    = d["IN_PACKETS"]
                    duration_ms = max(0, d["LAST_SWITCHED"] - d["FIRST_SWITCHED"])
                else:
                    # v9: IPs already converted to strings by the library
                    src_ip = d.get("IPV4_SRC_ADDR", "0.0.0.0")
                    dst_ip = d.get("IPV4_DST_ADDR", "0.0.0.0")
                    src_port  = d.get("L4_SRC_PORT", 0)
                    dst_port  = d.get("L4_DST_PORT", 0)
                    proto_num = d.get("PROTOCOL", 0)
                    bytes_sent = d.get("IN_BYTES", 0)
                    packets    = d.get("IN_PKTS", 0)
                    duration_ms = max(
                        0, d.get("LAST_SWITCHED", 0) - d.get("FIRST_SWITCHED", 0)
                    )

                device_id = _lookup_device_id(conn, src_ip)
                _save_flow(
                    device_id, src_ip, dst_ip,
                    src_port, dst_port, _proto_name(proto_num),
                    bytes_sent, packets, duration_ms,
                )
                saved += 1

            except Exception as exc:
                logger.warning("Failed to process individual flow: %s", exc)

        if saved:
            logger.debug("Saved %d flow(s) from %s", saved, addr[0])


# ── traffic simulator ──────────────────────────────────────────────────────────

# Typical IoT destinations: cloud APIs, DNS, MQTT, NTP, HTTP
_SIM_DESTINATIONS = [
    ("8.8.8.8",          53,   "UDP"),   # Google DNS
    ("1.1.1.1",          53,   "UDP"),   # Cloudflare DNS
    ("192.168.1.1",      1883, "TCP"),   # MQTT broker (LAN)
    ("34.120.208.123",   443,  "TCP"),   # Cloud API (HTTPS)
    ("52.84.17.33",      443,  "TCP"),   # AWS endpoint
    ("142.250.64.14",    80,   "TCP"),   # HTTP
    ("172.217.14.206",   443,  "TCP"),   # Google services
    ("216.239.35.0",     123,  "UDP"),   # NTP
    ("192.168.1.255",    5353, "UDP"),   # mDNS multicast
]


def simulate_traffic(device_id: int) -> None:
    """
    Persist one synthetic traffic flow for *device_id*.
    Useful for unit tests or demos without a real router.
    """
    conn = get_db()
    row = conn.execute("SELECT ip FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None:
        logger.warning("simulate_traffic: device_id=%d not found", device_id)
        return

    src_ip = row["ip"] or f"192.168.1.{random.randint(2, 254)}"
    dst_ip, dst_port, protocol = random.choice(_SIM_DESTINATIONS)
    src_port   = random.randint(1024, 65535)
    bytes_sent = random.randint(64, 65536)
    packets    = max(1, bytes_sent // random.randint(64, 1500))
    duration_ms = random.randint(1, 30_000)

    _save_flow(
        device_id, src_ip, dst_ip,
        src_port, dst_port, protocol,
        bytes_sent, packets, duration_ms,
    )
    logger.debug(
        "Simulated flow device_id=%d %s:%d -> %s:%d %s %d B",
        device_id, src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent,
    )


class TrafficSimulator:
    """
    Generates fake traffic for every active device every *interval* seconds.
    Start this instead of (or alongside) TrafficCollector when no NetFlow
    router is available.
    """

    def __init__(self, interval: int = 30):
        self._interval = interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="traffic-simulator", daemon=True
        )
        self._thread.start()
        logger.info("Traffic simulator started (interval=%ds)", self._interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                conn = get_db()
                device_ids = [
                    row["id"]
                    for row in conn.execute(
                        "SELECT id FROM devices WHERE status = 'active'"
                    ).fetchall()
                ]
                flows_per_device = random.randint(1, 5)
                for device_id in device_ids:
                    for _ in range(flows_per_device):
                        simulate_traffic(device_id)
                if device_ids:
                    logger.info(
                        "Simulated %d flow(s) across %d active device(s)",
                        flows_per_device * len(device_ids),
                        len(device_ids),
                    )
            except Exception as exc:
                logger.warning("Simulator tick error: %s", exc)

            self._stop_event.wait(self._interval)


# ── scapy pcap collector ───────────────────────────────────────────────────────

class ScapyCollector:
    """
    Captures real traffic directly from a NIC using scapy.
    Aggregates individual packets into flows (by 5-tuple) and flushes
    them to traffic_flows every *flush_interval* seconds.

    Requires root or CAP_NET_RAW on the process.
    Activate via:  CAPTURE_INTERFACE=wlo1 uvicorn main:app ...
    """

    def __init__(self, interface: str, flush_interval: int = 10):
        self._iface = interface
        self._flush_interval = flush_interval
        # key: (src_ip, dst_ip, src_port, dst_port, protocol)
        # val: {"bytes": int, "packets": int, "first_ms": int, "last_ms": int}
        self._flows: dict = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._sniffer = None
        self._flush_thread: threading.Thread | None = None

    def start(self) -> None:
        from scapy.all import AsyncSniffer  # lazy import — scapy is slow to load

        self._stop_event.clear()
        try:
            self._sniffer = AsyncSniffer(
                iface=self._iface,
                prn=self._on_packet,
                filter="ip",    # BPF: skip non-IP (ARP, etc.)
                store=False,
            )
            self._sniffer.start()
        except Exception as exc:
            logger.error("ScapyCollector: cannot start sniffer on %s: %s", self._iface, exc)
            return

        self._flush_thread = threading.Thread(
            target=self._flush_loop, name="scapy-flush", daemon=True
        )
        self._flush_thread.start()
        logger.info("ScapyCollector started on interface %s (flush every %ds)",
                    self._iface, self._flush_interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        if self._flush_thread:
            self._flush_thread.join(timeout=5)
        self._flush_flows()   # save whatever is still buffered
        logger.info("ScapyCollector stopped")

    def _on_packet(self, pkt) -> None:
        from scapy.layers.inet import IP, TCP, UDP

        if IP not in pkt:
            return

        try:
            process_dns_packet(pkt)
        except Exception as exc:
            logger.warning("DNS processing error: %s", exc)

        try:
            process_tls_packet(pkt)
        except Exception as exc:
            logger.warning("TLS processing error: %s", exc)

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto_num = pkt[IP].proto
        pkt_bytes = len(pkt[IP])
        src_port = dst_port = 0

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        proto = _proto_name(proto_num)
        key = (src_ip, dst_ip, src_port, dst_port, proto)
        now_ms = int(time.time() * 1000)

        with self._lock:
            if key not in self._flows:
                self._flows[key] = {
                    "bytes": 0, "packets": 0,
                    "first_ms": now_ms, "last_ms": now_ms,
                }
            f = self._flows[key]
            f["bytes"] += pkt_bytes
            f["packets"] += 1
            f["last_ms"] = now_ms

    def _flush_loop(self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(self._flush_interval)
            self._flush_flows()

    def _flush_flows(self) -> None:
        with self._lock:
            snapshot = dict(self._flows)
            self._flows.clear()

        if not snapshot:
            return

        conn = get_db()
        for (src_ip, dst_ip, src_port, dst_port, protocol), data in snapshot.items():
            device_id = _lookup_device_id(conn, src_ip)
            duration_ms = max(0, data["last_ms"] - data["first_ms"])
            _save_flow(
                device_id, src_ip, dst_ip,
                src_port, dst_port, protocol,
                data["bytes"], data["packets"], duration_ms,
            )

        logger.info("ScapyCollector flushed %d real flow(s) from %s",
                    len(snapshot), self._iface)
