#!/bin/bash
set -e

echo "=== TailScan Update ==="

# Pull latest
git pull origin main

# Update Python deps
pip3 install -r requirements.txt -q

# Restart service if running via systemd
if systemctl is-active --quiet tailscan 2>/dev/null; then
  echo "Restarting tailscan service..."
  sudo systemctl restart tailscan
  echo "✅ Done. Service restarted."
else
  echo "✅ Updated. Run ./start.sh to launch."
fi
