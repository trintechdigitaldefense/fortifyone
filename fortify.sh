#!/data/data/com.termux/files/usr/bin/bash
# FortifyOne Master Launcher
# Usage: bash fortify.sh

echo "╔════════════════════════════════════════╗"
echo "║       FortifyOne Audit Framework       ║"
echo "║   TrinTech Digital Defense - v1.0      ║"
echo "║   Optimized for Samsung A16 (4GB)      ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo "Available memory: $(free -h | grep Mem | awk '{print $4}')"
echo ""

# Navigate to fortifyone directory
cd /data/data/com.termux/files/home/fortifyone

# Launch the Python orchestrator
python main.py "$@"
