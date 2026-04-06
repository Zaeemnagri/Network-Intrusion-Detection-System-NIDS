#!/bin/bash
# ═══════════════════════════════════════════════════
#  NIDS Setup Script
#  Run this once to install dependencies
# ═══════════════════════════════════════════════════

set -e  # Exit immediately if any command fails

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  NIDS — Network Intrusion Detection System   ║"
echo "║  Setup Script v1.0                           ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── Check Python version ──
PYTHON=$(which python3 || which python)
if [ -z "$PYTHON" ]; then
    echo "❌ Python 3 not found. Please install Python 3.9+"
    exit 1
fi
echo "✓ Python found: $($PYTHON --version)"

# ── Create virtual environment ──
if [ ! -d "venv" ]; then
    echo "→ Creating virtual environment..."
    $PYTHON -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# ── Activate venv ──
source venv/bin/activate 2>/dev/null || . venv/Scripts/activate 2>/dev/null || true

# ── Install dependencies ──
echo "→ Installing Python packages (this may take a minute)..."
pip install --quiet --upgrade pip
pip install --quiet flask flask-socketio eventlet scapy pandas scikit-learn

echo "✓ All packages installed"

# ── Create directories ──
mkdir -p logs static/css static/js templates
echo "✓ Directory structure ready"

echo ""
echo "═══════════════════════════════════════════════"
echo "  ✅ Setup complete!"
echo ""
echo "  To run the NIDS dashboard:"
echo ""
echo "    # Linux/Mac (requires root for live packet capture):"
echo "    sudo python3 app.py"
echo ""
echo "    # Without root (simulation mode — great for demo):"
echo "    python3 app.py"
echo ""
echo "  Then open: http://localhost:5000"
echo "═══════════════════════════════════════════════"
echo ""
