<div align="center">
  <img src="static/favicon.png" alt="Logo" width="80" height="80">

  # 🛡️ NIDS — Network Intrusion Detection System
  
  **A production-quality, real-time Network Intrusion Detection System powered by Machine Learning, Packet Sniffing, and a Live Web Dashboard.**
</div>

---

## 📸 Features

- **Live Packet Capture**: Scapy-powered sniffer continuously captures and analyzes all incoming/outgoing network traffic.
- **Machine Learning Detection**: Uses `scikit-learn` Isolation Forest to detect unknown anomalies alongside heuristic threshold detection.
- **Attack Detection Engine**: Capable of detecting Advanced Port Scans, SYN Floods, ICMP Floods, and UDP Floods.
- **Real-Time Interactive Dashboard**: Built with Flask and WebSocket (SocketIO), alerts and threats are pushed directly to your browser instantly.
- **IP Geolocation Tracking**: Automatically pinpoints the geographical origin of threat actors.
- **SQLite Data Persistence**: All packets, alerts, and logs are durably saved to a local SQLite database (`nids.db`).
- **Data Export & Reset Controls**: Quickly export your threat intelligence reports to CSV formats or wipe the system with the 💣 Reset Data functionality.
- **Automated IP Blacklisting**: Automatically drops repeat offenders or manually blacklist specific IPs.
- **Simulation Mode**: Operates effectively without root/admin access by generating synthetic, realistic attacks for demonstration and learning.

## 🚀 Built With

- **Backend**: Python 3, Flask, Flask-SocketIO, Eventlet
- **Network Stack**: Scapy
- **Machine Learning**: Scikit-Learn, Pandas
- **Frontend**: HTML5, CSS3, JavaScript, Chart.js, JetBrains Mono Font
- **Database**: SQLite3

---

## ⚙️ Setup & Installation

### Option 1: Quick Setup (Recommended)
```bash
# Clone the repository
git clone https://github.com/yourusername/NIDS.git
cd NIDS

# Run the setup script
bash setup.sh
```

### Option 2: Manual Setup
```bash
# 1. Create a virtual environment
python3 -m venv venv

# 2. Activate it
source venv/bin/activate       # Linux/Mac
# or: venv\Scripts\activate    # Windows

# 3. Install required dependencies
pip install -r requirements.txt
# Alternatively: pip install flask flask-socketio eventlet scapy pandas scikit-learn
```

---

## 🏃 Running the Project

### Simulation Mode (Without Root - For Demo/Learning)
```bash
python3 app.py
```
> The application will run in simulation mode. The sniffer will automatically generate synthetic attack traffic so you can see all the charts and live alerts functioning.

### Live Mode (With Root - Captures Real Traffic)
```bash
sudo python3 app.py
```
> Requires administrator/root privileges because capturing raw network packets requires elevated permissions.

### Accessing the System
Once started, open your web browser and navigate to:
- **🎛️ Main Dashboard**: `http://localhost:5000`
- **🚨 Alerts Table**: `http://localhost:5000/alerts`
- **📡 Traffic Logs**: `http://localhost:5000/traffic`
- **⛔ Blacklist Info**: `http://localhost:5000/blacklist`

---

## 🧪 Testing Active Defenses (Live Mode)

*(Make sure you run `sudo python3 app.py` before doing this)*

**1. Port Scan (using Nmap)**
```bash
nmap -sS 192.168.1.1           # SYN scan - triggers PORT_SCAN
nmap -p 1-1000 192.168.1.1     # Range scan - triggers PORT_SCAN
```

**2. SYN Flood (using hping3)**
```bash
sudo hping3 -S --flood -p 80 192.168.1.1
```

**3. ICMP Flood**
```bash
sudo hping3 -1 --flood 192.168.1.1
```

---

## 🔧 Configuration Options

Edit `detector.py` to tune the heuristic and machine learning threshold configurations according to your network size:

```python
THRESHOLDS = {
    "PORT_SCAN_PORTS":  15,    # Unique ports to trigger alert
    "PORT_SCAN_WINDOW": 10,    # Time window in seconds
    "SYN_FLOOD_COUNT":  100,   # SYN packets to trigger alert
    "SYN_FLOOD_WINDOW": 5,     # Time window in seconds
    "AUTO_BLACKLIST_THRESHOLD": 5,  # Alerts before auto-block
}
```

To change the capturing interface, edit `app.py`:
```python
sniffer = PacketSniffer(
    interface = "eth0",    # Replace with 'wlan0', 'Wi-Fi' etc. None triggers auto-detect.
)
```

---

## 📡 API Endpoints 

| Endpoint | Description |
|----------|-------------|
| `GET /api/stats` | JSON object containing basic system dashboard statistics |
| `GET /api/alerts?limit=20` | Most recent security alerts |
| `GET /api/export/csv` | Download `.csv` dataset file of tracked alerts |
| `POST /api/reset` | Resets the live database structure |
| `GET /api/threats` | Active tracked threat IP instances |
| `GET /api/chart/...` | Historical traffic/attack endpoints used for dashboard rendering |

---

## 🤝 Contributing
Contributions, issues and feature requests are welcome. Feel free to check the issues page if you want to contribute.

## 📝 License
This project is open-source and available under the terms of the MIT License.
