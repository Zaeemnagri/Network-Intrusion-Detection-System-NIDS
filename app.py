"""
app.py - Flask Web Application & Real-Time Dashboard
======================================================
This is the main entry point for the NIDS web interface.

Architecture:
  - Flask serves the HTML dashboard
  - Flask-SocketIO pushes real-time alerts to the browser
  - The PacketSniffer runs in a background thread
  - All data is stored/read from SQLite via database.py

Routes:
  GET  /              → Main dashboard page
  GET  /alerts        → Alerts table page
  GET  /traffic       → Traffic logs page
  GET  /blacklist     → Blacklist management page
  POST /blacklist/add → Add IP to blacklist
  POST /blacklist/remove → Remove IP from blacklist
  GET  /api/stats     → JSON: dashboard statistics
  GET  /api/alerts    → JSON: recent alerts
  GET  /api/chart     → JSON: chart data
  GET  /api/threats   → JSON: active threat summary
"""

import logging
import os
import sys
from datetime import datetime

from flask import Flask, render_template, jsonify, request, redirect, url_for, Response
from flask_socketio import SocketIO, emit

# Local modules
from database import (
    init_db, get_alerts, get_alert_count, get_alerts_by_type,
    get_top_attackers, get_recent_alerts_for_chart, get_traffic_logs,
    get_blacklist, add_to_blacklist, remove_from_blacklist,
    get_dashboard_stats, reset_db,
)
from sniffer import PacketSniffer

# ─────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/nids.log"),
    ]
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# FLASK + SOCKETIO SETUP
# ─────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = "nids-super-secret-key-change-in-production"

# SocketIO enables real-time WebSocket communication
# async_mode='threading' works with the standard threading model
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

# ─────────────────────────────────────────────
# ALERT CALLBACK (Real-Time Push)
# ─────────────────────────────────────────────

def on_alert_detected(alert_data: dict):
    """
    Called by the DetectionEngine when a new alert fires.
    Uses SocketIO to instantly push the alert to all connected browsers.
    The browser JavaScript listens for 'new_alert' events.
    """
    socketio.emit("new_alert", alert_data)
    logger.debug("Pushed alert to dashboard: %s", alert_data.get("alert_type"))

# ─────────────────────────────────────────────
# INITIALIZE SNIFFER
# ─────────────────────────────────────────────

sniffer = PacketSniffer(
    interface      = None,    # None = auto-detect. Set to "eth0", "wlan0", etc.
    alert_callback = on_alert_detected,
)

# ─────────────────────────────────────────────
# HTML PAGE ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def dashboard():
    """Main dashboard with stats cards and charts."""
    stats = get_dashboard_stats()
    return render_template(
        "dashboard.html",
        stats       = stats,
        active_page = "dashboard",
        now         = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        is_running  = sniffer.is_running,
        packet_count = sniffer.packet_count,
    )


@app.route("/alerts")
def alerts_page():
    """Full alerts table with pagination and filtering."""
    severity = request.args.get("severity", "")
    page     = int(request.args.get("page", 1))
    per_page = 50
    offset   = (page - 1) * per_page

    alerts      = get_alerts(limit=per_page, offset=offset,
                              severity_filter=severity or None)
    total_count = get_alert_count()
    total_pages = max(1, (total_count + per_page - 1) // per_page)

    return render_template(
        "alerts.html",
        alerts       = alerts,
        total_count  = total_count,
        page         = page,
        total_pages  = total_pages,
        severity     = severity,
        active_page  = "alerts",
    )


@app.route("/traffic")
def traffic_page():
    """Raw traffic logs page."""
    logs = get_traffic_logs(limit=200)
    return render_template(
        "traffic.html",
        logs        = logs,
        active_page = "traffic",
    )


@app.route("/blacklist")
def blacklist_page():
    """Blacklist management page."""
    blacklist    = get_blacklist()
    top_attackers = get_top_attackers(limit=10)
    return render_template(
        "blacklist.html",
        blacklist     = blacklist,
        top_attackers = top_attackers,
        active_page   = "blacklist",
    )


# ─────────────────────────────────────────────
# BLACKLIST ACTIONS
# ─────────────────────────────────────────────

@app.route("/blacklist/add", methods=["POST"])
def blacklist_add():
    ip     = request.form.get("ip_address", "").strip()
    reason = request.form.get("reason", "Manual block").strip()
    if ip:
        add_to_blacklist(ip, reason=reason, auto_added=False)
    return redirect(url_for("blacklist_page"))


@app.route("/blacklist/remove", methods=["POST"])
def blacklist_remove():
    ip = request.form.get("ip_address", "").strip()
    if ip:
        remove_from_blacklist(ip)
    return redirect(url_for("blacklist_page"))


# ─────────────────────────────────────────────
# JSON API ROUTES (used by JavaScript AJAX)
# ─────────────────────────────────────────────

@app.route("/api/reset", methods=["POST"])
def api_reset():
    """Reset the entire database."""
    reset_db()
    # Also clear the detector's state so it forgets past packet counts
    sniffer.detector.syn_tracker.clear()
    sniffer.detector.port_tracker.clear()
    sniffer.detector.icmp_tracker.clear()
    sniffer.detector.udp_tracker.clear()
    sniffer.detector.alert_counter.clear()
    sniffer.detector.alert_cooldown.clear()
    return jsonify({"status": "success"})


@app.route("/api/export/csv")
def api_export_csv():
    """Export all alerts as a CSV file."""
    alerts = get_alerts(limit=100000)
    
    # Build CSV string
    csv_data = "ID,Timestamp,SourceIP,DestIP,AttackType,Severity,Packets,Description\n"
    for a in alerts:
        # Simple CSV formatting. Remove commas and newlines from description
        desc = str(a.get("description", "")).replace('"', '""').replace('\n', ' ')
        csv_data += f'{a.get("id")},{a.get("timestamp")},{a.get("source_ip")},{a.get("dest_ip")},{a.get("alert_type")},{a.get("severity")},{a.get("packet_count")},"{desc}"\n'
        
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=alerts.csv"}
    )

@app.route("/api/stats")
def api_stats():
    """Return dashboard stats as JSON."""
    stats = get_dashboard_stats()
    stats["packet_count"] = sniffer.packet_count
    stats["is_running"]   = sniffer.is_running
    return jsonify(stats)


@app.route("/api/alerts")
def api_alerts():
    """Return recent alerts as JSON (for AJAX live updates)."""
    limit  = int(request.args.get("limit", 20))
    alerts = get_alerts(limit=limit)
    return jsonify(alerts)


@app.route("/api/chart/alerts-over-time")
def api_chart_alerts_over_time():
    """
    Return per-minute alert counts for the last 60 minutes.
    Used by Chart.js time-series graph.
    """
    data = get_recent_alerts_for_chart(minutes=60)
    return jsonify(data)


@app.route("/api/chart/alert-types")
def api_chart_alert_types():
    """Return alert counts grouped by type. Used by the pie chart."""
    data = get_alerts_by_type()
    return jsonify(data)


@app.route("/api/chart/top-attackers")
def api_chart_top_attackers():
    """Return top 10 source IPs by alert count."""
    data = get_top_attackers(limit=10)
    return jsonify(data)


@app.route("/api/threats")
def api_threats():
    """Return currently tracked active threats from the detection engine."""
    return jsonify(sniffer.detector.get_active_threats())


@app.route("/api/sniffer/status")
def api_sniffer_status():
    return jsonify({
        "is_running":   sniffer.is_running,
        "packet_count": sniffer.packet_count,
        "ml_info":      sniffer.detector.get_ml_status(),
    })


# ─────────────────────────────────────────────
# WEBSOCKET EVENTS
# ─────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    """Called when a browser connects via WebSocket."""
    logger.info("Dashboard client connected: %s", request.sid)
    # Send current stats immediately on connect
    emit("stats_update", get_dashboard_stats())


@socketio.on("disconnect")
def on_disconnect():
    logger.info("Dashboard client disconnected: %s", request.sid)


# ─────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  🛡️  NIDS - Network Intrusion Detection System")
    print("  Version 1.0 | Python + Flask + Scapy")
    print("="*60)

    # Step 1: Initialize the database (create tables if needed)
    print("[1/3] Initializing database...")
    init_db()
    print("      ✓ Database ready")

    # Step 2: Start the packet sniffer in background
    print("[2/3] Starting packet sniffer...")
    sniffer.start()
    print("      ✓ Sniffer running")

    # Step 3: Start the Flask web server
    print("[3/3] Starting web dashboard...")
    print("\n  🌐 Open your browser: http://localhost:5000")
    print("  📊 Dashboard:  http://localhost:5000/")
    print("  🚨 Alerts:     http://localhost:5000/alerts")
    print("  📡 Traffic:    http://localhost:5000/traffic")
    print("  ⛔ Blacklist:  http://localhost:5000/blacklist")
    print("\n  Press Ctrl+C to stop\n")
    print("="*60 + "\n")

    socketio.run(
        app,
        host      = "0.0.0.0",
        port      = 5000,
        debug     = False,   # Set True for development (auto-reloads)
        use_reloader = False, # Must be False when using background threads
    )
