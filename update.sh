#!/usr/bin/env bash
# TailScan — Update script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }

info "Pulling latest changes..."
git pull origin main

info "Updating dependencies..."
if [ -d "venv" ]; then
    source venv/bin/activate
    pip install -r requirements.txt -q
    info "Dependencies updated."
else
    warn "No venv found — run ./start.sh to set up first."
    exit 1
fi

# Restart systemd service if running
if systemctl is-active --quiet tailscan 2>/dev/null; then
    info "Restarting tailscan service..."
    sudo systemctl restart tailscan
    info "Service restarted."
    systemctl status tailscan --no-pager
else
    info "Update complete. Run ./start.sh (or restart the service) to apply changes."
fi
