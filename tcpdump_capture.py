"""
Passive packet capture for IoT25 on OpenWrt.

Spawns tcpdump as a subprocess and writes pcap to stdout in packet-buffered
mode (-U). The Python side uses scapy only as a *parser* over the pipe — no
AsyncSniffer, no promiscuous-mode setup — so the OpenWrt kernel freeze that
hit ScapyCollector does not occur. Tcpdump itself runs with -p
(no-promiscuous-mode) for the same reason.

Captures DNS (UDP/53) and TLS (TCP/443) and dispatches each packet to the
same process_dns_packet / process_tls_packet handlers ScapyCollector used,
so US-06 (DNS domains) and US-07 (JA3) keep producing the same data.
"""
import logging
import shutil
import subprocess
import threading

logger = logging.getLogger(__name__)

_TCPDUMP_BIN = "tcpdump"
_BPF = "port 53 or port 443"
_BACKOFF_MIN = 1.0
_BACKOFF_MAX = 30.0


def is_tcpdump_available() -> str | None:
    """Return the resolved tcpdump path, or None if not on PATH."""
    return shutil.which(_TCPDUMP_BIN)


class TcpdumpCapture:
    """
    Run tcpdump in a background supervisor thread and feed every captured
    packet to the DNS and TLS handlers. Auto-restarts tcpdump with backoff
    if the subprocess dies.
    """

    def __init__(self, interface: str = "any"):
        self.interface = interface
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._proc: subprocess.Popen | None = None

    def start(self) -> None:
        path = is_tcpdump_available()
        if path is None:
            logger.error(
                "tcpdump not found on PATH. Install with: opkg install tcpdump"
            )
            return

        try:
            from tls_capture import _load_blacklist
            _load_blacklist()
        except Exception as exc:
            logger.warning("TcpdumpCapture: could not preload JA3 blacklist: %s", exc)

        logger.info("TcpdumpCapture: starting on iface=%s (binary=%s)", self.interface, path)
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._supervisor_loop, name="tcpdump-supervisor", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        logger.info("TcpdumpCapture: stopping")
        self._stop_event.set()
        self._kill_proc()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _kill_proc(self) -> None:
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return
        try:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        except Exception as exc:
            logger.warning("TcpdumpCapture: error killing process: %s", exc)

    def _supervisor_loop(self) -> None:
        backoff = _BACKOFF_MIN
        while not self._stop_event.is_set():
            try:
                self._run_once()
                backoff = _BACKOFF_MIN
            except Exception as exc:
                logger.warning(
                    "TcpdumpCapture: capture loop died (%s) — restarting in %.1fs",
                    exc, backoff,
                )
            if self._stop_event.wait(backoff):
                break
            backoff = min(backoff * 2, _BACKOFF_MAX)
        logger.info("TcpdumpCapture: supervisor exited")

    def _run_once(self) -> None:
        # -p: don't set promisc (this is the whole reason we're not using scapy)
        # -U: packet-buffered → scapy sees each packet as it arrives, not after a buffer fill
        # -s 0: full snaplen (TLS ClientHello can exceed 1500 bytes after fragmentation; DNS fits easily)
        # -n: don't resolve names (would create its own DNS traffic + slow capture)
        # -w -: write raw pcap to stdout for scapy.PcapReader to consume
        cmd = [
            _TCPDUMP_BIN,
            "-i", self.interface,
            "-p", "-U", "-n", "-s", "0",
            "-w", "-",
            _BPF,
        ]
        logger.info("TcpdumpCapture: spawn: %s", " ".join(cmd))
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        threading.Thread(
            target=self._drain_stderr,
            args=(self._proc,),
            name="tcpdump-stderr",
            daemon=True,
        ).start()

        try:
            self._read_packets(self._proc.stdout)
        finally:
            self._kill_proc()

        rc = self._proc.returncode
        if rc is not None and rc != 0 and not self._stop_event.is_set():
            logger.warning("TcpdumpCapture: tcpdump exited with code %s", rc)

    def _read_packets(self, stream) -> None:
        from scapy.utils import PcapReader

        from dns_capture import process_dns_packet
        from tls_capture import process_tls_packet

        reader = PcapReader(stream)
        for pkt in reader:
            if self._stop_event.is_set():
                break
            try:
                process_dns_packet(pkt)
            except Exception as exc:
                logger.warning("TcpdumpCapture: dns handler error: %s", exc)
            try:
                process_tls_packet(pkt)
            except Exception as exc:
                logger.warning("TcpdumpCapture: tls handler error: %s", exc)

    def _drain_stderr(self, proc: subprocess.Popen) -> None:
        try:
            for line in iter(proc.stderr.readline, b""):
                text = line.decode("utf-8", errors="replace").rstrip()
                if text:
                    logger.info("tcpdump: %s", text)
        except Exception:
            pass
