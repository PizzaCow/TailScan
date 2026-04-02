#!/bin/bash
set -e

echo "=== TailScan Setup ==="

install_pkg() {
  local pkg=$1
  if command -v apt-get &>/dev/null; then
    sudo apt-get install -y "$pkg"
  elif command -v dnf &>/dev/null; then
    sudo dnf install -y "$pkg"
  elif command -v yum &>/dev/null; then
    sudo yum install -y "$pkg"
  else
    echo "WARNING: Could not install $pkg automatically. Install it manually."
  fi
}

# masscan — fast host discovery (needs root/raw sockets)
if ! command -v masscan &>/dev/null; then
  echo "Installing masscan..."
  install_pkg masscan
fi

# nmap — used for on-demand port scanning per device
if ! command -v nmap &>/dev/null; then
  echo "Installing nmap..."
  install_pkg nmap
fi

# Install Python deps
if ! command -v pip3 &>/dev/null; then
  echo "ERROR: pip3 not found. Install Python 3.11+ first."
  exit 1
fi

echo "Installing Python dependencies..."
pip3 install -r requirements.txt -q

# Check .env exists
if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    cp .env.example .env
    echo ""
    echo "✅ Created .env from .env.example"
    echo "👉 Edit .env and fill in your Tailscale OAuth credentials, then re-run ./start.sh"
    exit 0
  fi
fi

# Validate .env
if grep -q "your_client_id_here" .env 2>/dev/null; then
  echo "ERROR: .env not configured. Edit .env and fill in TAILSCALE_CLIENT_ID etc."
  exit 1
fi

echo "Starting TailScan on port 8080..."
echo "Access at: http://$(tailscale ip -4 2>/dev/null || echo '<tailscale-ip>'):8080"
echo ""

# Run (needs sudo for nmap raw sockets)
sudo python3 main.py
