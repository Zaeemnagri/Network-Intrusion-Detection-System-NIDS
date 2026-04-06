"""
database.py - SQLite Database Handler
=====================================
Handles all database operations for the NIDS system.
Stores alerts, traffic logs, blacklisted IPs, and traffic statistics.
"""

import sqlite3
import os
import logging
from datetime import datetime

# Path to the SQLite database file
DB_PATH = os.path.join(os.path.dirname(__file__), "logs", "nids.db")

logger = logging.getLogger(__name__)


def get_connection():
    """
    Create and return a new database connection.
    Uses check_same_thread=False so Flask can use the same DB from multiple threads.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row  # Allows accessing columns by name (like a dict)
    return conn


def init_db():
    """
    Initialize the database by creating all required tables if they don't exist.
    Called once when the application starts.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    conn = get_connection()
    cursor = conn.cursor()

    # --- Alerts Table ---
    # Stores every detected attack/suspicious activity
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            source_ip   TEXT    NOT NULL,
            dest_ip     TEXT,
            alert_type  TEXT    NOT NULL,
            severity    TEXT    DEFAULT 'MEDIUM',
            description TEXT,
            packet_count INTEGER DEFAULT 1
        )
    """)

    # --- Traffic Logs Table ---
    # Stores a sample of raw packet metadata for analysis
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            source_ip   TEXT,
            dest_ip     TEXT,
            source_port INTEGER,
            dest_port   INTEGER,
            protocol    TEXT,
            flags       TEXT,
            size        INTEGER
        )
    """)

    # --- Blacklist Table ---
    # IPs that have been manually or automatically blocked
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address  TEXT    UNIQUE NOT NULL,
            reason      TEXT,
            added_at    TEXT    NOT NULL,
            auto_added  INTEGER DEFAULT 0
        )
    """)

    # --- Statistics Table ---
    # Aggregated per-minute traffic stats for the charts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_stats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            total_packets   INTEGER DEFAULT 0,
            tcp_packets     INTEGER DEFAULT 0,
            udp_packets     INTEGER DEFAULT 0,
            icmp_packets    INTEGER DEFAULT 0,
            alert_count     INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()
    logger.info("Database initialized at %s", DB_PATH)


def reset_db():
    """Drop all tables and recreate them to reset system data."""
    try:
        conn = get_connection()
        conn.execute("DROP TABLE IF EXISTS alerts")
        conn.execute("DROP TABLE IF EXISTS traffic_logs")
        conn.execute("DROP TABLE IF EXISTS blacklist")
        conn.execute("DROP TABLE IF EXISTS traffic_stats")
        conn.commit()
        conn.close()
        init_db()
        logger.info("Database reset successfully.")
    except Exception as e:
        logger.error("Failed to reset database: %s", e)


# ─────────────────────────────────────────────
# ALERT OPERATIONS
# ─────────────────────────────────────────────

def insert_alert(source_ip, alert_type, description, dest_ip=None,
                 severity="MEDIUM", packet_count=1):
    """
    Insert a new alert record into the database.

    Args:
        source_ip    (str): The attacker's IP address
        alert_type   (str): Type of attack (e.g., 'PORT_SCAN', 'SYN_FLOOD')
        description  (str): Human-readable description of the alert
        dest_ip      (str): Target IP (optional)
        severity     (str): 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'
        packet_count (int): Number of packets that triggered this alert
    """
    try:
        conn = get_connection()
        conn.execute("""
            INSERT INTO alerts (timestamp, source_ip, dest_ip, alert_type,
                                severity, description, packet_count)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
              source_ip, dest_ip, alert_type, severity, description, packet_count))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("Failed to insert alert: %s", e)


def get_alerts(limit=100, offset=0, severity_filter=None):
    """
    Retrieve alerts from the database, newest first.

    Args:
        limit          (int): Max number of rows to return
        offset         (int): For pagination
        severity_filter(str): Optional filter by severity level

    Returns:
        list of dicts
    """
    try:
        conn = get_connection()
        if severity_filter:
            rows = conn.execute("""
                SELECT * FROM alerts WHERE severity = ?
                ORDER BY id DESC LIMIT ? OFFSET ?
            """, (severity_filter, limit, offset)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM alerts ORDER BY id DESC LIMIT ? OFFSET ?
            """, (limit, offset)).fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error("Failed to fetch alerts: %s", e)
        return []


def get_alert_count():
    """Return total number of alerts in the database."""
    try:
        conn = get_connection()
        count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        conn.close()
        return count
    except Exception:
        return 0


def get_alerts_by_type():
    """
    Return alert counts grouped by alert_type.
    Used for the pie chart on the dashboard.
    """
    try:
        conn = get_connection()
        rows = conn.execute("""
            SELECT alert_type, COUNT(*) as count
            FROM alerts
            GROUP BY alert_type
            ORDER BY count DESC
        """).fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error("Failed to get alerts by type: %s", e)
        return []


def get_top_attackers(limit=10):
    """
    Return the top source IPs with the most alerts.
    Used for the 'Top Suspicious IPs' table.
    """
    try:
        conn = get_connection()
        rows = conn.execute("""
            SELECT source_ip, COUNT(*) as alert_count,
                   MAX(timestamp) as last_seen,
                   GROUP_CONCAT(DISTINCT alert_type) as attack_types
            FROM alerts
            GROUP BY source_ip
            ORDER BY alert_count DESC
            LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error("Failed to get top attackers: %s", e)
        return []


def get_recent_alerts_for_chart(minutes=60):
    """
    Return alert counts per minute for the last N minutes.
    Used for the time-series chart.
    """
    try:
        conn = get_connection()
        rows = conn.execute("""
            SELECT strftime('%Y-%m-%d %H:%M', timestamp) as minute,
                   COUNT(*) as count
            FROM alerts
            WHERE timestamp >= datetime('now', ? || ' minutes')
            GROUP BY minute
            ORDER BY minute ASC
        """, (f"-{minutes}",)).fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error("Failed to get chart data: %s", e)
        return []


# ─────────────────────────────────────────────
# TRAFFIC LOG OPERATIONS
# ─────────────────────────────────────────────

def insert_traffic_log(source_ip, dest_ip, source_port, dest_port,
                        protocol, flags="", size=0):
    """
    Insert a single packet's metadata into traffic_logs.
    We sample packets (not every single one) to avoid DB bloat.
    """
    try:
        conn = get_connection()
        conn.execute("""
            INSERT INTO traffic_logs
                (timestamp, source_ip, dest_ip, source_port, dest_port,
                 protocol, flags, size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
              source_ip, dest_ip, source_port, dest_port,
              protocol, flags, size))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("Failed to insert traffic log: %s", e)


def get_traffic_logs(limit=200):
    """Retrieve recent traffic logs, newest first."""
    try:
        conn = get_connection()
        rows = conn.execute("""
            SELECT * FROM traffic_logs ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error("Failed to fetch traffic logs: %s", e)
        return []


# ─────────────────────────────────────────────
# BLACKLIST OPERATIONS
# ─────────────────────────────────────────────

def add_to_blacklist(ip_address, reason="Manual block", auto_added=False):
    """
    Add an IP address to the blacklist.
    Uses INSERT OR IGNORE so duplicate IPs don't cause errors.
    """
    try:
        conn = get_connection()
        conn.execute("""
            INSERT OR IGNORE INTO blacklist (ip_address, reason, added_at, auto_added)
            VALUES (?, ?, ?, ?)
        """, (ip_address, reason,
              datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
              1 if auto_added else 0))
        conn.commit()
        conn.close()
        logger.info("IP %s added to blacklist. Reason: %s", ip_address, reason)
    except Exception as e:
        logger.error("Failed to add to blacklist: %s", e)


def remove_from_blacklist(ip_address):
    """Remove an IP address from the blacklist."""
    try:
        conn = get_connection()
        conn.execute("DELETE FROM blacklist WHERE ip_address = ?", (ip_address,))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("Failed to remove from blacklist: %s", e)


def get_blacklist():
    """Return all blacklisted IPs."""
    try:
        conn = get_connection()
        rows = conn.execute("""
            SELECT * FROM blacklist ORDER BY added_at DESC
        """).fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error("Failed to fetch blacklist: %s", e)
        return []


def is_blacklisted(ip_address):
    """Check if a given IP is in the blacklist. Returns True/False."""
    try:
        conn = get_connection()
        result = conn.execute(
            "SELECT 1 FROM blacklist WHERE ip_address = ?", (ip_address,)
        ).fetchone()
        conn.close()
        return result is not None
    except Exception:
        return False


# ─────────────────────────────────────────────
# STATISTICS OPERATIONS
# ─────────────────────────────────────────────

def get_dashboard_stats():
    """
    Return a summary dict of key stats for the dashboard header cards.
    """
    try:
        conn = get_connection()

        total_alerts   = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        critical_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'"
        ).fetchone()[0]
        unique_attackers = conn.execute(
            "SELECT COUNT(DISTINCT source_ip) FROM alerts"
        ).fetchone()[0]
        blacklisted     = conn.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0]
        total_packets   = conn.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()[0]

        # Alerts in last 24 hours
        recent_alerts = conn.execute("""
            SELECT COUNT(*) FROM alerts
            WHERE timestamp >= datetime('now', '-24 hours')
        """).fetchone()[0]

        conn.close()
        return {
            "total_alerts":      total_alerts,
            "critical_alerts":   critical_alerts,
            "unique_attackers":  unique_attackers,
            "blacklisted_ips":   blacklisted,
            "total_packets":     total_packets,
            "alerts_24h":        recent_alerts,
        }
    except Exception as e:
        logger.error("Failed to get dashboard stats: %s", e)
        return {}
