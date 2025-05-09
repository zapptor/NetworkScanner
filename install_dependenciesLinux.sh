#!/usr/bin/env bash
set -euo pipefail

error_exit() {
  echo >&2 "[ERROR] $1"
  exit 1
}

echo
echo ">>> Updating package list..."
sudo apt-get update -y

echo
echo ">>> Installing Python3 and pip3..."
sudo apt-get install -y python3 python3-pip
command -v python3   >/dev/null 2>&1 || error_exit "python3 failed to install"
command -v pip3      >/dev/null 2>&1 || error_exit "pip3 failed to install"

echo
echo ">>> Installing Nmap..."
sudo apt-get install -y nmap
command -v nmap      >/dev/null 2>&1 || error_exit "nmap failed to install"

echo
echo ">>> Installing libpcap-dev (Npcap equivalent)..."
sudo apt-get install -y libpcap-dev
dpkg -s libpcap-dev  >/dev/null 2>&1 || error_exit "libpcap-dev failed to install"

echo
echo ">>> Installing Python modules (scapy & python-nmap)..."
sudo apt-get install -y python3-scapy python3-nmap
# verify via dpkg
dpkg -s python3-scapy >/dev/null 2>&1 || error_exit "python3-scapy package missing"
dpkg -s python3-nmap >/dev/null 2>&1 || error_exit "python3-nmap package missing"
# verify via pip3
pip3 show scapy      >/dev/null 2>&1 || error_exit "scapy Python module not found"
pip3 show python-nmap>/dev/null 2>&1 || error_exit "python-nmap Python module not found"

# All good! Show banner
cat <<'EOF'

  ____   ___  _   _ _____ 
 |  _ \ / _ \| \ | | ____|
 | | | | | | |  \| |  _|  
 | |_| | |_| | |\  | |___ 
 |____/ \___/|_| \_|_____|

All dependencies have been installed successfully!

EOF

exit 0
