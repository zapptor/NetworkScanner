#!/bin/bash
set -e

echo "Updating package list..."
sudo apt-get update

echo "Installing Python3 and pip3..."
sudo apt-get install -y python3 python3-pip

echo "Installing Nmap..."
sudo apt-get install -y nmap

echo "Installing libpcap-dev (for packet capture support)..."
sudo apt-get install -y libpcap-dev

echo "Installing required Python modules (scapy and python-nmap)..."
sudo apt install -y python3-scapy python3-nmap

echo "All dependencies have been installed successfully."
