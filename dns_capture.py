"""
Passive DNS capture for IoT25.

Sniffs UDP port 53 traffic using scapy, extracts DNS queries from each
packet, persists them to dns_queries, and raises alerts for known-suspicious
domains.

Requires root or CAP_NET_RAW on the process.
Activate by passing an interface name (same as CAPTURE_INTERFACE).
"""
import logging
from datetime import datetime, UTC

from alert_manager import create_alert
from database import get_db

logger = logging.getLogger(__name__)

_QTYPE_NAMES: dict[int, str] = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
    64: "SVCB", 65: "HTTPS", 255: "ANY",
}

# Known-bad domains for IoT environments: mining pools, C&C infrastructure,
# dynamic-DNS providers abused by botnets, and anonymisation gateways.
SUSPICIOUS_DOMAINS: frozenset[str] = frozenset({
    # Crypto-mining pools
    "pool.minexmr.com",
    "xmr.pool.minergate.com",
    "coinhive.com",
    "xmrpool.eu",
    "mining.honeyminer.com",
    # C&C / botnet infrastructure
    "n3td3v.net",
    "botnet.cc",
    "ircserver.xyz",
    "cnc.irongate.cc",
    # Dynamic DNS abused by IoT botnets (Mirai variants, etc.)
    "duckdns.org",
    "no-ip.com",
    "ddns.net",
    "hopto.org",
    "zapto.org",
    # Tor / anonymisation gateways used by malware
    "tor2web.org",
    "onion.ws",
})


def _is_suspicious(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    if d in SUSPICIOUS_DOMAINS:
        return True
    for s in SUSPICIOUS_DOMAINS:
        if d.endswith("." + s):
            return True
    return False


def _lookup_device_id(conn, src_ip: str) -> int | None:
    row = conn.execute("SELECT id FROM devices WHERE ip = ?", (src_ip,)).fetchone()
    return row["id"] if row else None


def _save_dns_query(
    device_id: int | None,
    domain: str,
    record_type: str,
    is_suspicious: bool,
) -> None:
    conn = get_db()
    conn.execute(
        """
        INSERT INTO dns_queries (device_id, domain, record_type, timestamp, is_suspicious)
        VALUES (?, ?, ?, ?, ?)
        """,
        (device_id, domain, record_type, datetime.now(UTC).isoformat(), int(is_suspicious)),
    )
    conn.commit()


def process_dns_packet(pkt) -> None:
    """
    Called by ScapyCollector for every captured packet.
    Processes DNS queries (UDP/53) and persists them.
    """
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, UDP

    try:
        if IP not in pkt or UDP not in pkt or DNS not in pkt:
            return
        if pkt[UDP].dport != 53:
            return

        dns = pkt[DNS]
        if dns.qr != 0 or dns.qdcount == 0 or dns.qd is None:
            return

        # Recent scapy versions return a _DNSQRList for dns.qd instead of a
        # DNSQR with a .payload chain. Normalise both shapes to a plain list.
        qd = dns.qd
        questions = list(qd) if isinstance(qd, list) else [qd]

        src_ip = pkt[IP].src
        conn = get_db()
        device_id = _lookup_device_id(conn, src_ip)

        for qr in questions:
            if not isinstance(qr, DNSQR):
                continue
            domain = qr.qname.decode("utf-8", errors="replace").rstrip(".")
            record_type = _QTYPE_NAMES.get(qr.qtype, str(qr.qtype))
            suspicious = _is_suspicious(domain)

            _save_dns_query(device_id, domain, record_type, suspicious)
            logger.info("DNS query: %s -> %s (%s)", src_ip, domain, record_type)

            if suspicious:
                logger.warning(
                    "Suspicious DNS: %s -> %s (device_id=%s)",
                    src_ip, domain, device_id,
                )
                create_alert(
                    device_id=device_id,
                    alert_type="suspicious_dns",
                    severity="high",
                    message=f"Suspicious DNS query to {domain}",
                    technical_detail={
                        "src_ip": src_ip,
                        "domain": domain,
                        "record_type": record_type,
                    },
                )

    except Exception as exc:
        logger.warning("DnsCapture: error processing packet: %s", exc)


class DnsCapture:
    """Stub kept for API compatibility — DNS is processed inside ScapyCollector."""

    def __init__(self, interface: str):
        pass

    def start(self) -> None:
        logger.info("DnsCapture: integrated into ScapyCollector")

    def stop(self) -> None:
        pass
