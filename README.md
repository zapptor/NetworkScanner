README.md
=========

Overview
--------
NETWORK SCANNER is a Python-based tool that enables you to perform network host discovery and TCP port scanning. It uses Scapy (for ARP, SYN, and full handshake scans) and Nmap (for banner grabbing when version detection is enabled). The tool also allows you to configure various scan parameters and default port sets via an interactive, text-based menu.

Features
--------
- **Active Host Scan**: Discover active hosts in a given network range using ARP requests.
- **TCP Port Scanner**:
  - **SYN Scan (Stealth Scan)**: Send SYN packets and wait for SYN/ACK responses, then send an ACK or reset (RST) packet without completing the full handshake.
  - **CONNECT Scan (Full TCP Handshake)**: Perform a complete TCP handshake to determine open TCP ports.
- **Banner Scanning**: (Optional, when version detection is enabled) Grab banners from target ports using Nmap.
- **Configurable Options**:
  - Set Timeout, Retries, Stealth Delay, Threads, and Verbose mode.
  - Choose default ports for scanning from preset options (Top 20, Top 100, Top 200, Top 1000).
- **Scan Cancellation**:
  - You can quickly cancel a running scan by pressing **CTRL+C**. When cancelled, the program will display any partial results obtained up to that point.


Installation Instructions
-------------------------
### Automated Installation Windows

1. Open PowerShell as Administrator.
2. Navigate to you downloads folder.
     ```
     cd "$env:USERPROFILE\Downloads"
     ```
3. Download the installation script
     ```
     wget -O InstallDependenciesWindows.ps1 https://raw.githubusercontent.com/zapptor/NetworkScanner/main/InstallDependenciesWindows.ps1
     ```
4. Run the installation script:
     ```
     powershell -ExecutionPolicy Bypass -File .\InstallDependenciesWindows.ps1
     ```
5. Download the scanner:
     ```
     wget -O NETWORK10TM.py https://raw.githubusercontent.com/zapptor/NetworkScanner/main/NETWORK10TM.py
     ```
6. How to run the scanner:
    - [Usage](https://github.com/zapptor/NetworkScanner/tree/main?tab=readme-ov-file#usage)
   
### Manuall Installation Windows
1. Download and install the following programs:
- [Python](https://www.python.org/downloads/)
- [nmap](https://nmap.org/download.html)
- [npcap]([https://www.winpcap.org/install/](https://npcap.com/#download))

2. Then, open CMD and install the remaining dependencies with:
    ```
    python get-pip.py
    ```
    ```
    pip install python-nmap
    ```
    ```
    pip install scapy
    ```
3. To confirm installation, run:
    ```
    python --version
    ```
    ```
    pip show scapy
    ```
    ```
    pip show python-nmap
    ```
    ```
    nmap --version
    ```
4. Open PowerShell as Administrator.
5. Navigate to you downloads folder.
     ```
     cd "$env:USERPROFILE\Downloads"
     ```
6. Download the scanner:
     ```
     wget -O NETWORK10TM.py https://raw.githubusercontent.com/zapptor/NetworkScanner/main/NETWORK10TM.py
     ```
7. How to run the scanner:
    - [Usage](https://github.com/zapptor/NetworkScanner/tree/main?tab=readme-ov-file#usage)

      
### Automated Installation Linux
1. Open you terminal and navigate to your Downloads folder.
     ```
     cd ~/Downloads
     ```
2. Download the installation script
     ```
     curl -o install_dependenciesLinux.sh https://raw.githubusercontent.com/zapptor/NetworkScanner/main/install_dependenciesLinux.sh
     ```
4. Make the script executable:
     ```
     chmod +x install_dependenciesLinux.sh
     ```
5. Run the script:
     ```
     sudo ./install_dependenciesLinux.sh
     ```
6. Download the scanner:
     ```
     curl -o NETWORK10TM.py https://raw.githubusercontent.com/zapptor/NetworkScanner/main/NETWORK10TM.py
     ```   
6. How to run the scanner:
    - [Usage](https://github.com/zapptor/NetworkScanner/tree/main?tab=readme-ov-file#usage)
      
### Manuall Installation Linux
1. Open a terminal and run:
     ```
     sudo apt update
     ```
     ```
     sudo apt install python3 python3-pip nmap
     ```
2. Then, install the required Python packages:
     ```
     sudo pip3 install python-nmap scapy
     ```
3. To confirm installation, run:
     ```
     python3 --version
     ```
     ```
     pip3 show scapy
     ```
     ```
     pip3 show python-nmap
     ```
     ```
     nmap --version
     ```
4. Download the scanner:
     ```
     curl -o NETWORK10TM.py https://raw.githubusercontent.com/zapptor/NetworkScanner/main/NETWORK10TM.py
     ```   
6. How to run the scanner:
    - [Usage](https://github.com/zapptor/NetworkScanner/tree/main?tab=readme-ov-file#usage)

Usage
-----
Run the tool by executing the main script from your terminal/powershell:
Navigate to the scanner directory and run the python file

  Windows(run Powershell as admin):
  ```
  python NETWORK10TM.py
  ```
  Linux:
  ```
  sudo python NETWORK10TM.py
  ```
The main menu will be displayed with options:

- **1. Scan for Active Hosts**  
  Prompts you to enter a network range or a single IP, then sends ARP requests to discover active IP addresses on that network.

- **2. TCP Port Scanner**  
  Opens a sub-menu where you can choose between:
  - **SYN Scan (Stealth Scan)** – Uses SYN packets to check for open ports while remaining stealthy.
  - **CONNECT Scan (Full TCP Handshake)** – Performs a full handshake to determine open TCP ports.
  - **Configurations** – Allows you to modify scan settings.

- **q. Quit**  
  Exit the program.

TCP Port Scanner Options and Configuration
--------------------------------------------
In the TCP Port Scanner menu you can perform scans using two methods:

- **SYN Scan (Stealth Scan):**
  - Sends SYN packets to target ports and listens for SYN/ACK responses.
  - When an open port is detected, a reset (RST) packet is sent to avoid completing the handshake.
- **CONNECT Scan (Full TCP Handshake):**
  - Uses Python’s socket module to establish a full TCP connection.
  - This mode is less stealthy but works even if administrative privileges aren’t available.

### Configuration Menu
Selecting “Configurations” from the TCP Port Scanner menu opens an interactive configuration menu. In this menu you can set:

- **Timeout:**  
  Duration (in seconds) to wait for responses during scans.
- **Retries:**  
  Number of times to retry a scan for a port in case of no response.
- **Stealth Delay:**  
  Delay between sending scan packets (useful when stealth is desired).
- **Threads:**  
  Number of concurrent scanning threads.
- **Verbose:**  
  Enable or disable extra output during scans.
- **Default Ports:**  
  Change the default port set used by the scanner. The available options (entered as key-value pairs) are:
  - `ports=20` (Top 20 ports)
  - `ports=100` (Top 100 ports)
  - `ports=200` (Top 200 ports)
  - `ports=1000` (Top 1000 ports)

  The currently chosen port set is displayed using a friendly label (e.g., “Top 100 ports”). To update it, type an entry like:  
  `ports=200`  
  in the configuration menu. The tool will then update its default port set accordingly.

**Resetting Configuration:**  
In the configurations menu, you can press **r** to reset all TCP scan parameters (including the default ports) to their default values.

General User Input Conventions
-------------------------------
- **b:** Return to the previous menu.
- **r:** Reset configuration settings (in the configuration menu).
- Input entries must adhere to the format `key=value` (e.g., `timeout=2`).

Version Detection
-----------------
When you perform a scan, you have the option to append version detection using `-vX` where **X** is a number from 0 (least aggressive) to 9 (most aggressive). When a valid version is provided, banner scanning is performed using Nmap to determine service details on discovered open ports.

Permissions
-----------
Note that some scan methods (especially those using Scapy for sending raw packets) may require administrative privileges.

License
-------
*ZAPPTOR*
