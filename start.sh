#!/usr/bin/env bash
# TailScan — First-time setup and launch script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo ""
echo "  ████████╗ █████╗ ██╗██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗"
echo "     ██╔══╝██╔══██╗██║██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║"
echo "     ██║   ███████║██║██║     ███████╗██║     ███████║██╔██╗ ██║"
echo "     ██║   ██╔══██║██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║"
echo "     ██║   ██║  ██║██║███████╗███████║╚██████╗██║  ██║██║ ╚████║"
echo "     ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
echo ""
echo "  TailScan — Tailscale Network Scanner"
echo ""

# ── Check .env ──────────────────────────────────────────────────────────────
if [ ! -f ".env" ]; then
    warn ".env not found. Copying .env.example → .env"
    cp .env.example .env
    echo ""
    echo "  ⚠  Please edit .env and fill in your Tailscale OAuth credentials:"
    echo "     - TS_CLIENT_ID"
    echo "     - TS_CLIENT_SECRET"
    echo "     - BASE_URL  (your Tailscale IP:8080)"
    echo ""
    echo "  Then run ./start.sh again."
    echo ""
    exit 1
fi

# Check if placeholders are still in .env
if grep -q "your_oauth_client_id" .env; then
    error ".env still has placeholder values. Edit .env before running start.sh."
fi

# ── Check tailscale ─────────────────────────────────────────────────────────
info "Checking Tailscale..."
if ! command -v tailscale &>/dev/null; then
    error "tailscale CLI not found. Install Tailscale first: https://tailscale.com/download"
fi
TS_IP=$(tailscale ip -4 2>/dev/null || echo "")
if [ -z "$TS_IP" ]; then
    warn "Could not detect Tailscale IP — is Tailscale connected?"
else
    info "Tailscale IP: $TS_IP"
fi

# ── Install nmap if missing ─────────────────────────────────────────────────
if ! command -v nmap &>/dev/null; then
    info "Installing nmap..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get install -y nmap
    elif command -v yum &>/dev/null; then
        sudo yum install -y nmap
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y nmap
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm nmap
    elif command -v brew &>/dev/null; then
        brew install nmap
    else
        warn "Could not install nmap automatically. Please install it manually."
    fi
else
    info "nmap is installed: $(nmap --version | head -1)"
fi

# ── Python check ────────────────────────────────────────────────────────────
info "Checking Python..."
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    error "Python 3 not found. Please install Python 3.10+"
fi

PY_VERSION=$($PYTHON --version 2>&1 | awk '{print $2}')
info "Python: $PY_VERSION"

# ── Virtual environment ──────────────────────────────────────────────────────
if [ ! -d "venv" ]; then
    info "Creating virtual environment..."
    $PYTHON -m venv venv
fi

info "Activating venv and installing dependencies..."
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
info "Dependencies installed."

# ── Launch ───────────────────────────────────────────────────────────────────
echo ""
info "Starting TailScan on port 8080..."
if [ -n "$TS_IP" ]; then
    info "Open in browser: http://${TS_IP}:8080"
fi
echo ""

exec python main.py
