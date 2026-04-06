"""
sniffer.py - Packet Sniffer Engine (Phase 1 + 2)
==================================================
Captures live network packets using Scapy, extracts key fields,
logs traffic samples to the database, and feeds each packet to
the Detection Engine for analysis.

How packet sniffing works (beginner explanation):
-------------------------------------------------
Your network card receives ALL packets on the network segment.
Scapy puts it into "promiscuous mode" so we can read them all.
Each packet has layers:
  Ethernet → IP → TCP/UDP/ICMP → Payload

We "peel" each layer to extract the fields we need.
"""

import logging
import threading
import time
import random
from datetime import datetime

# Suppress Scapy's IPv6 warning on startup
import logging as _logging
_logging.getLogger("scapy.runtime").setLevel(_logging.ERROR)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from database import insert_traffic_log
from detector import DetectionEngine

logger = logging.getLogger(__name__)

# Only log 1 in every N packets to the DB to avoid filling storage
TRAFFIC_LOG_SAMPLE_RATE = 10  # log every 10th packet


class PacketSniffer:
    """
    Captures network packets, parses them, and sends to the DetectionEngine.

    Usage:
        sniffer = PacketSniffer(interface="eth0", alert_callback=my_func)
        sniffer.start()   # starts sniffing in a background thread
        sniffer.stop()    # gracefully stops
    """

    def __init__(self, interface=None, alert_callback=None):
        """
        Args:
            interface      (str): Network interface to sniff on.
                                  None = auto-select (Scapy default).
            alert_callback (callable): Passed to DetectionEngine.
                                       Called when an alert fires.
        """
        self.interface      = interface
        self.alert_callback = alert_callback
        self.is_running     = False
        self._thread        = None
        self._packet_count  = 0   # Total packets seen this session
        self._sample_counter = 0  # Counter for DB sampling

        # Initialize the detection engine with our callback
        self.detector = DetectionEngine(alert_callback=alert_callback)

        logger.info(
            "PacketSniffer initialized | Interface: %s | Scapy: %s",
            interface or "auto", "available" if SCAPY_AVAILABLE else "NOT FOUND"
        )

    # ─────────────────────────────────────────────
    # START / STOP
    # ─────────────────────────────────────────────

    def start(self):
        """Start sniffing in a background daemon thread."""
        if self.is_running:
            logger.warning("Sniffer is already running.")
            return

        self.is_running = True

        if SCAPY_AVAILABLE:
            self._thread = threading.Thread(
                target  = self._sniff_loop,
                name    = "PacketSnifferThread",
                daemon  = True   # Thread dies when main program exits
            )
        else:
            # Scapy not available → use simulation mode for demo/testing
            logger.warning("Scapy not available — running in SIMULATION mode")
            self._thread = threading.Thread(
                target  = self._simulate_traffic,
                name    = "SimulatorThread",
                daemon  = True
            )

        self._thread.start()
        logger.info("Sniffer started (Thread: %s)", self._thread.name)

    def stop(self):
        """Signal the sniffer to stop."""
        self.is_running = False
        logger.info("Sniffer stop requested.")

    @property
    def packet_count(self):
        return self._packet_count

    # ─────────────────────────────────────────────
    # SCAPY SNIFF LOOP (Real mode)
    # ─────────────────────────────────────────────

    def _sniff_loop(self):
        """
        Main sniffing loop using Scapy.
        sniff() blocks until stop_filter returns True or an error occurs.
        """
        logger.info("Starting live packet capture on interface: %s",
                    self.interface or "default")
        try:
            sniff(
                iface       = self.interface,
                prn         = self._process_packet,   # callback per packet
                store       = False,                   # don't keep in memory
                stop_filter = lambda _: not self.is_running,
                filter      = "ip",                    # BPF filter: IP packets only
            )
        except PermissionError:
            logger.error(
                "❌ Permission denied! Run with sudo/admin to capture packets."
            )
        except Exception as e:
            logger.error("Sniffer error: %s", e)

    def _process_packet(self, packet):
        """
        Called by Scapy for EVERY captured packet.
        Extracts fields and routes to detection + logging.
        """
        try:
            packet_info = self._parse_packet(packet)
            if packet_info:
                self._packet_count += 1
                self._route_packet(packet_info)
        except Exception as e:
            logger.debug("Packet processing error: %s", e)

    def _parse_packet(self, packet) -> dict | None:
        """
        Extract relevant fields from a raw Scapy packet.

        Returns a dict or None if the packet isn't IP-based.
        """
        # Must have an IP layer — skip Ethernet-only or ARP etc.
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        info = {
            "src_ip":    ip_layer.src,
            "dst_ip":    ip_layer.dst,
            "src_port":  None,
            "dst_port":  None,
            "protocol":  "OTHER",
            "flags":     "",
            "size":      len(packet),
            "timestamp": datetime.now().isoformat(),
        }

        # ── TCP Layer ──
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            info["src_port"] = tcp.sport
            info["dst_port"] = tcp.dport
            info["protocol"] = "TCP"

            # Decode TCP flags to human-readable string
            # Flags are stored as a FlagValue object in Scapy
            flag_map = {
                0x001: "F",   # FIN
                0x002: "S",   # SYN
                0x004: "R",   # RST
                0x008: "P",   # PSH
                0x010: "A",   # ACK
                0x020: "U",   # URG
            }
            flags_str = ""
            for bit, char in flag_map.items():
                if tcp.flags & bit:
                    flags_str += char
            info["flags"] = flags_str

        # ── UDP Layer ──
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            info["src_port"] = udp.sport
            info["dst_port"] = udp.dport
            info["protocol"] = "UDP"

        # ── ICMP Layer ──
        elif packet.haslayer(ICMP):
            info["protocol"] = "ICMP"

        return info

    # ─────────────────────────────────────────────
    # SIMULATION MODE (for environments without root)
    # ─────────────────────────────────────────────

    def _simulate_traffic(self):
        """
        Generates synthetic network traffic for demonstration purposes.
        Simulates:
          - Normal HTTPS/HTTP browsing traffic
          - Occasional port scans (nmap-like)
          - Occasional SYN floods
          - Normal DNS queries
        """
        logger.info("🔬 Simulation mode: generating synthetic traffic")

        normal_ips = [
            "192.168.1.10", "192.168.1.20", "192.168.1.30",
            "10.0.0.5",     "10.0.0.15",
        ]
        attacker_ips = [
            "203.0.113.45",   # Test IP (RFC 5737 — safe to use in docs)
            "198.51.100.99",
            "192.0.2.1",
        ]
        common_ports = [80, 443, 53, 22, 3306, 8080, 8443, 25, 110, 143]

        scenario_counter = 0

        while self.is_running:
            scenario_counter += 1

            # ── Normal traffic (most of the time) ──
            for _ in range(random.randint(5, 15)):
                if not self.is_running:
                    break
                src = random.choice(normal_ips)
                dst = f"8.8.{random.randint(0,255)}.{random.randint(0,255)}"
                pkt = {
                    "src_ip":   src,
                    "dst_ip":   dst,
                    "src_port": random.randint(49152, 65535),
                    "dst_port": random.choice(common_ports),
                    "protocol": random.choice(["TCP", "UDP", "ICMP"]),
                    "flags":    random.choice(["SA", "A", "PA"]),
                    "size":     random.randint(64, 1500),
                    "timestamp": datetime.now().isoformat(),
                }
                self._route_packet(pkt)
                self._packet_count += 1

            # ── Every ~10 cycles: simulate a PORT SCAN ──
            if scenario_counter % 10 == 0:
                attacker = random.choice(attacker_ips)
                logger.info("🎭 Simulating port scan from %s", attacker)
                for port in range(20, 20 + random.randint(20, 40)):
                    if not self.is_running:
                        break
                    pkt = {
                        "src_ip":   attacker,
                        "dst_ip":   "192.168.1.1",
                        "src_port": random.randint(49152, 65535),
                        "dst_port": port,
                        "protocol": "TCP",
                        "flags":    "S",
                        "size":     60,
                        "timestamp": datetime.now().isoformat(),
                    }
                    self._route_packet(pkt)
                    self._packet_count += 1
                    time.sleep(0.05)

            # ── Every ~15 cycles: simulate a SYN FLOOD ──
            if scenario_counter % 15 == 0:
                attacker = random.choice(attacker_ips)
                logger.info("🎭 Simulating SYN flood from %s", attacker)
                for _ in range(random.randint(100, 150)):
                    if not self.is_running:
                        break
                    pkt = {
                        "src_ip":   attacker,
                        "dst_ip":   "192.168.1.100",
                        "src_port": random.randint(1024, 65535),
                        "dst_port": 80,
                        "protocol": "TCP",
                        "flags":    "S",
                        "size":     60,
                        "timestamp": datetime.now().isoformat(),
                    }
                    self._route_packet(pkt)
                    self._packet_count += 1

            # ── Every ~20 cycles: simulate ICMP flood ──
            if scenario_counter % 20 == 0:
                attacker = random.choice(attacker_ips)
                logger.info("🎭 Simulating ICMP flood from %s", attacker)
                for _ in range(random.randint(60, 80)):
                    if not self.is_running:
                        break
                    pkt = {
                        "src_ip":   attacker,
                        "dst_ip":   "192.168.1.1",
                        "src_port": None,
                        "dst_port": None,
                        "protocol": "ICMP",
                        "flags":    "",
                        "size":     84,
                        "timestamp": datetime.now().isoformat(),
                    }
                    self._route_packet(pkt)
                    self._packet_count += 1

            time.sleep(1)  # 1 second between simulation cycles

    # ─────────────────────────────────────────────
    # ROUTING (shared between real and simulated)
    # ─────────────────────────────────────────────

    def _route_packet(self, packet_info: dict):
        """
        Route a parsed packet to:
        1. The Detection Engine (every packet)
        2. The Database traffic_logs (sampled — 1 in N)
        """
        # Always run detection
        self.detector.analyze_packet(packet_info)

        # Sample logging to avoid DB bloat
        self._sample_counter += 1
        if self._sample_counter % TRAFFIC_LOG_SAMPLE_RATE == 0:
            insert_traffic_log(
                source_ip  = packet_info.get("src_ip", ""),
                dest_ip    = packet_info.get("dst_ip", ""),
                source_port= packet_info.get("src_port"),
                dest_port  = packet_info.get("dst_port"),
                protocol   = packet_info.get("protocol", ""),
                flags      = packet_info.get("flags", ""),
                size       = packet_info.get("size", 0),
            )
