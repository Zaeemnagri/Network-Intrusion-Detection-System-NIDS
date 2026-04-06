"""
detector.py - Attack Detection Engine
======================================
This module analyzes captured packets and detects various attack patterns.

How detection works (simple explanation):
- We keep a short "memory" (time window) of recent packets per IP
- If an IP sends too many of the same type of packet → ALERT!
- We use Python's collections.defaultdict and deque for efficiency

Detection Types:
1. PORT SCAN     - One IP hitting many different ports quickly
2. SYN FLOOD     - One IP sending huge numbers of TCP SYN packets
3. ICMP FLOOD    - One IP sending excessive ICMP (ping) packets
4. UDP FLOOD     - Massive UDP traffic from a single source
5. BLACKLIST HIT - Packet from a known-bad IP
"""

import logging
import time
from collections import defaultdict, deque
from datetime import datetime
from threading import Lock, Thread
import time

from database import insert_alert, add_to_blacklist, is_blacklisted

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# DETECTION THRESHOLDS
# (Tune these values for your environment)
# ─────────────────────────────────────────────
THRESHOLDS = {
    # Port scan: if one IP hits more than N unique ports within TIME_WINDOW seconds
    "PORT_SCAN_PORTS":      15,    # unique ports
    "PORT_SCAN_WINDOW":     10,    # seconds

    # SYN flood: more than N SYN packets from one IP within TIME_WINDOW seconds
    "SYN_FLOOD_COUNT":      100,   # SYN packets
    "SYN_FLOOD_WINDOW":     5,     # seconds

    # ICMP flood: more than N ping packets from one IP within TIME_WINDOW seconds
    "ICMP_FLOOD_COUNT":     50,
    "ICMP_FLOOD_WINDOW":    5,

    # UDP flood
    "UDP_FLOOD_COUNT":      500,
    "UDP_FLOOD_WINDOW":     5,

    # Auto-blacklist: if an IP triggers more than N alerts → auto-blacklist
    "AUTO_BLACKLIST_THRESHOLD": 5,
}


class DetectionEngine:
    """
    Core detection engine that maintains state per IP address.

    Each IP has:
    - A deque (double-ended queue) of recent SYN timestamps
    - A deque of recently targeted ports
    - A deque of recent ICMP/UDP timestamps
    - An alert counter (for auto-blacklisting)
    """

    def __init__(self, alert_callback=None):
        """
        Initialize the detection engine.

        Args:
            alert_callback: Optional function called when an alert fires.
                            Signature: callback(alert_dict)
                            Used to push real-time alerts to the web dashboard.
        """
        self.alert_callback = alert_callback
        self._lock = Lock()  # Thread safety — sniffer runs in its own thread

        # Per-IP tracking structures
        # defaultdict means: if a key doesn't exist, create it automatically
        self.syn_tracker   = defaultdict(lambda: deque())   # IP → [timestamps]
        self.port_tracker  = defaultdict(lambda: deque())   # IP → [(timestamp, port)]
        self.icmp_tracker  = defaultdict(lambda: deque())   # IP → [timestamps]
        self.udp_tracker   = defaultdict(lambda: deque())   # IP → [timestamps]

        # How many alerts each IP has triggered (for auto-blacklisting)
        self.alert_counter = defaultdict(int)

        # Cooldown: don't spam the same alert for the same IP
        # Structure: {(ip, alert_type): last_alert_timestamp}
        self.alert_cooldown = {}
        self.COOLDOWN_SECONDS = 30  # Don't repeat same alert within 30s

        # AI Anomaly Detection (Isolation Forest)
        self.ml_data_buffer = defaultdict(lambda: {"packets": 0, "ports": set(), "total_size": 0})
        self.ml_training_data = [] # Stores rows of [packet_count, unique_ports, avg_size]
        self.ml_start_time = time.time()
        self.ml_is_training = True
        self.ml_training_period = 60 # seconds
        self.ml_model = None

        logger.info("Detection Engine initialized with thresholds: %s", THRESHOLDS)

        # Start the ML background thread if sklearn is available
        if SKLEARN_AVAILABLE:
            self.ml_thread = Thread(target=self._ml_analysis_loop, daemon=True)
            self.ml_thread.start()
        else:
            logger.warning("scikit-learn not installed. AI Anomaly Detection disabled.")

    # ─────────────────────────────────────────────
    # MAIN ENTRY POINT
    # ─────────────────────────────────────────────

    def analyze_packet(self, packet_info: dict):
        """
        Main method — called for every captured packet.
        Routes to the appropriate detection checks.

        Args:
            packet_info (dict): Parsed packet data from sniffer.py
                Keys: src_ip, dst_ip, src_port, dst_port, protocol,
                      flags, size, timestamp
        """
        src_ip   = packet_info.get("src_ip")
        protocol = packet_info.get("protocol", "")
        flags    = packet_info.get("flags", "")
        dst_port = packet_info.get("dst_port")

        if not src_ip:
            return

        # Skip private/loopback analysis for localhost testing
        # (comment out this block if you want to detect local traffic)
        # if src_ip.startswith("127.") or src_ip == "::1":
        #     return

        with self._lock:
            # Feed data to the ML engine buffer
            if SKLEARN_AVAILABLE and src_ip:
                self.ml_data_buffer[src_ip]["packets"] += 1
                if dst_port:
                    self.ml_data_buffer[src_ip]["ports"].add(dst_port)
                self.ml_data_buffer[src_ip]["total_size"] += packet_info.get("size", 0)

            # 1. Check if IP is already blacklisted
            if is_blacklisted(src_ip):
                self._fire_alert(
                    source_ip   = src_ip,
                    dest_ip     = packet_info.get("dst_ip"),
                    alert_type  = "BLACKLISTED_IP",
                    severity    = "CRITICAL",
                    description = f"Traffic from blacklisted IP {src_ip}",
                )
                return  # No need for further checks

            # 2. TCP-specific detections
            if protocol == "TCP":
                if flags and "S" in flags and "A" not in flags:
                    # Pure SYN packet (not SYN-ACK) → potential SYN flood
                    self._check_syn_flood(src_ip, packet_info)

                if dst_port:
                    # Any TCP connection attempt → potential port scan
                    self._check_port_scan(src_ip, dst_port, packet_info)

            # 3. ICMP detections (ping flood)
            elif protocol == "ICMP":
                self._check_icmp_flood(src_ip, packet_info)

            # 4. UDP detections
            elif protocol == "UDP":
                self._check_udp_flood(src_ip, packet_info)

    # ─────────────────────────────────────────────
    # DETECTION METHODS
    # ─────────────────────────────────────────────

    def _check_syn_flood(self, src_ip: str, packet_info: dict):
        """
        SYN Flood Detection Logic:
        ---------------------------
        A SYN flood is a DoS attack where the attacker sends thousands of
        TCP SYN packets but never completes the handshake. This exhausts
        the server's connection table.

        Detection: Count SYN packets from a single IP within a time window.
        """
        now     = time.time()
        window  = THRESHOLDS["SYN_FLOOD_WINDOW"]
        limit   = THRESHOLDS["SYN_FLOOD_COUNT"]
        tracker = self.syn_tracker[src_ip]

        # Add current timestamp
        tracker.append(now)

        # Remove old entries outside the time window (sliding window)
        while tracker and (now - tracker[0]) > window:
            tracker.popleft()

        if len(tracker) >= limit:
            self._fire_alert(
                source_ip   = src_ip,
                dest_ip     = packet_info.get("dst_ip"),
                alert_type  = "SYN_FLOOD",
                severity    = "CRITICAL",
                description = (
                    f"SYN flood detected from {src_ip}: "
                    f"{len(tracker)} SYN packets in {window}s "
                    f"(threshold: {limit})"
                ),
                packet_count = len(tracker),
            )

    def _check_port_scan(self, src_ip: str, dst_port: int, packet_info: dict):
        """
        Port Scan Detection Logic:
        ---------------------------
        A port scanner (like nmap) rapidly connects to many different ports
        to find which services are running. This leaves a distinctive pattern:
        one source IP → many different destination ports in a short time.

        Detection: Track unique destination ports hit by each IP within a window.
        """
        now     = time.time()
        window  = THRESHOLDS["PORT_SCAN_WINDOW"]
        limit   = THRESHOLDS["PORT_SCAN_PORTS"]
        tracker = self.port_tracker[src_ip]

        # Store (timestamp, port) tuples
        tracker.append((now, dst_port))

        # Slide the window — remove old entries
        while tracker and (now - tracker[0][0]) > window:
            tracker.popleft()

        # Count UNIQUE ports in the window
        unique_ports = len(set(p for _, p in tracker))

        if unique_ports >= limit:
            ports_sample = sorted(set(p for _, p in tracker))[:10]
            self._fire_alert(
                source_ip   = src_ip,
                dest_ip     = packet_info.get("dst_ip"),
                alert_type  = "PORT_SCAN",
                severity    = "HIGH",
                description = (
                    f"Port scan detected from {src_ip}: "
                    f"{unique_ports} unique ports in {window}s. "
                    f"Sample ports: {ports_sample}"
                ),
                packet_count = len(tracker),
            )

    def _check_icmp_flood(self, src_ip: str, packet_info: dict):
        """
        ICMP Flood (Ping Flood) Detection:
        ------------------------------------
        Sending thousands of ICMP echo requests can overwhelm a target.
        Simple detection: count ICMP packets per IP per time window.
        """
        now     = time.time()
        window  = THRESHOLDS["ICMP_FLOOD_WINDOW"]
        limit   = THRESHOLDS["ICMP_FLOOD_COUNT"]
        tracker = self.icmp_tracker[src_ip]

        tracker.append(now)
        while tracker and (now - tracker[0]) > window:
            tracker.popleft()

        if len(tracker) >= limit:
            self._fire_alert(
                source_ip   = src_ip,
                dest_ip     = packet_info.get("dst_ip"),
                alert_type  = "ICMP_FLOOD",
                severity    = "HIGH",
                description = (
                    f"ICMP flood from {src_ip}: "
                    f"{len(tracker)} packets in {window}s "
                    f"(threshold: {limit})"
                ),
                packet_count = len(tracker),
            )

    def _check_udp_flood(self, src_ip: str, packet_info: dict):
        """
        UDP Flood Detection:
        ---------------------
        UDP floods send large volumes of UDP datagrams to random ports,
        forcing the target to process each one.
        """
        now     = time.time()
        window  = THRESHOLDS["UDP_FLOOD_WINDOW"]
        limit   = THRESHOLDS["UDP_FLOOD_COUNT"]
        tracker = self.udp_tracker[src_ip]

        tracker.append(now)
        while tracker and (now - tracker[0]) > window:
            tracker.popleft()

        if len(tracker) >= limit:
            self._fire_alert(
                source_ip   = src_ip,
                dest_ip     = packet_info.get("dst_ip"),
                alert_type  = "UDP_FLOOD",
                severity    = "HIGH",
                description = (
                    f"UDP flood from {src_ip}: "
                    f"{len(tracker)} packets in {window}s"
                ),
                packet_count = len(tracker),
            )

    # ─────────────────────────────────────────────
    # AI ANOMALY DETECTION (ISOLATION FOREST)
    # ─────────────────────────────────────────────

    def _ml_analysis_loop(self):
        """
        Background thread that wakes up every 5 seconds.
        Collects data for the first 60 seconds to train the Isolation Forest.
        After 60 seconds, it uses the trained model to predict anomalies.
        """
        logger.info("🧠 AI Engine started. Training for %d seconds...", self.ml_training_period)
        
        while True:
            time.sleep(5) # Analyze in 5-second windows
            
            with self._lock:
                current_data = self.ml_data_buffer.copy()
                self.ml_data_buffer.clear()
            
            if not current_data:
                continue
                
            elapsed_time = time.time() - self.ml_start_time
            
            # --- TRAINING PHASE ---
            if self.ml_is_training:
                for ip, stats in current_data.items():
                    avg_size = stats["total_size"] / stats["packets"] if stats["packets"] > 0 else 0
                    features = [stats["packets"], len(stats["ports"]), avg_size]
                    self.ml_training_data.append(features)
                
                # Check if training period is over
                if elapsed_time >= self.ml_training_period:
                    if len(self.ml_training_data) > 10: # Ensure we have minimum data
                        logger.info("🧠 Training phase complete. Fitting Isolation Forest on %d samples.", len(self.ml_training_data))
                        # contamination=0.01 means we expect ~1% of traffic to be anomalous
                        self.ml_model = IsolationForest(contamination=0.01, random_state=42)
                        self.ml_model.fit(self.ml_training_data)
                        self.ml_is_training = False
                        logger.info("🧠 AI Engine is now in ACTIVE DETECTION mode.")
                    else:
                        # Extend training time if not enough data
                        self.ml_start_time = time.time()
                        logger.warning("🧠 Not enough training data. Extending training phase.")
            
            # --- DETECTION PHASE ---
            else:
                for ip, stats in current_data.items():
                    avg_size = stats["total_size"] / stats["packets"] if stats["packets"] > 0 else 0
                    features = [stats["packets"], len(stats["ports"]), avg_size]
                    
                    # predict() returns 1 for inliers, -1 for anomalies
                    try:
                        prediction = self.ml_model.predict([features])[0]
                        if prediction == -1:
                            # It's an anomaly!
                            self._fire_alert(
                                source_ip   = ip,
                                dest_ip     = "Multiple/System",
                                alert_type  = "AI_ANOMALY",
                                severity    = "HIGH",
                                description = (
                                    f"AI detected abnormal behavior! "
                                    f"Stats: {stats['packets']} pkts, "
                                    f"{len(stats['ports'])} ports, "
                                    f"{int(avg_size)}b avg size"
                                ),
                                packet_count = stats["packets"],
                            )
                    except Exception as e:
                        logger.error("ML Prediction error: %s", e)

    # ─────────────────────────────────────────────
    # ALERT FIRING
    # ─────────────────────────────────────────────

    def _fire_alert(self, source_ip, alert_type, description,
                    dest_ip=None, severity="MEDIUM", packet_count=1):
        """
        Fire an alert: save to DB, call callback, check auto-blacklist.
        Uses a cooldown to avoid flooding the DB with the same alert.
        """
        cooldown_key = (source_ip, alert_type)
        now = time.time()

        # Check cooldown — don't repeat the same alert too soon
        last_fired = self.alert_cooldown.get(cooldown_key, 0)
        if (now - last_fired) < self.COOLDOWN_SECONDS:
            return  # Still in cooldown, skip

        # Update cooldown timer
        self.alert_cooldown[cooldown_key] = now

        # Log to terminal
        timestamp = datetime.now().strftime("%H:%M:%S")
        logger.warning(
            "[%s] 🚨 ALERT | Type: %-15s | Severity: %-8s | IP: %s",
            timestamp, alert_type, severity, source_ip
        )
        logger.warning("    ↳ %s", description)

        # Save to database
        insert_alert(
            source_ip    = source_ip,
            alert_type   = alert_type,
            description  = description,
            dest_ip      = dest_ip,
            severity     = severity,
            packet_count = packet_count,
        )

        # Increment alert counter for this IP
        self.alert_counter[source_ip] += 1

        # Auto-blacklist if threshold exceeded
        auto_threshold = THRESHOLDS["AUTO_BLACKLIST_THRESHOLD"]
        if self.alert_counter[source_ip] == auto_threshold:
            logger.warning(
                "⛔  Auto-blacklisting %s after %d alerts",
                source_ip, auto_threshold
            )
            add_to_blacklist(
                source_ip,
                reason     = f"Auto-blacklisted: {auto_threshold} alerts triggered",
                auto_added = True,
            )

        # Call real-time callback (pushes to dashboard via SocketIO)
        if self.alert_callback:
            alert_data = {
                "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip":    source_ip,
                "dest_ip":      dest_ip or "N/A",
                "alert_type":   alert_type,
                "severity":     severity,
                "description":  description,
                "packet_count": packet_count,
            }
            try:
                self.alert_callback(alert_data)
            except Exception as e:
                logger.error("Alert callback error: %s", e)

    # ─────────────────────────────────────────────
    # UTILITY
    # ─────────────────────────────────────────────

    def reset_ip_state(self, ip_address: str):
        """Clear all tracking data for a specific IP (e.g., after whitelisting)."""
        with self._lock:
            self.syn_tracker.pop(ip_address, None)
            self.port_tracker.pop(ip_address, None)
            self.icmp_tracker.pop(ip_address, None)
            self.udp_tracker.pop(ip_address, None)
            self.alert_counter.pop(ip_address, None)

    def get_ml_status(self):
        """Return the current status of the AI Engine."""
        if not SKLEARN_AVAILABLE:
            return {"status": "OFFLINE"}
            
        elapsed = time.time() - self.ml_start_time
        time_left = max(0, self.ml_training_period - elapsed)
        
        if self.ml_is_training:
            return {
                "status": "TRAINING",
                "time_left": int(time_left)
            }
        else:
            return {
                "status": "ACTIVE",
                "time_left": 0
            }

    def get_active_threats(self) -> dict:
        """
        Return a summary of currently tracked IPs and their packet counts.
        Useful for the dashboard's live threat view.
        """
        with self._lock:
            return {
                "syn_sources":  {ip: len(q) for ip, q in self.syn_tracker.items()  if q},
                "scan_sources": {ip: len(q) for ip, q in self.port_tracker.items() if q},
                "icmp_sources": {ip: len(q) for ip, q in self.icmp_tracker.items() if q},
                "udp_sources":  {ip: len(q) for ip, q in self.udp_tracker.items()  if q},
            }
