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
1. Download the `InstallDependenciesWindows.ps1` script.
2. Save the script in your downloads folder.
3. Open PowerShell as Administrator.
4. Navigate to the scripts directory:
     ```
     cd "$env:USERPROFILE\Downloads"
     ```
5. Run the script:
     ```
     .\InstallDependenciesWindows.ps1
     ```
6. If you encounter an error, run:
     ```
     powershell -ExecutionPolicy Bypass -File .\InstallDependenciesWindows.ps1
     ```

### Manuall Installation Windows
1. Download and install the following programs:
- [Python](https://www.python.org/downloads/)
- [nmap](https://nmap.org/download.html)
- [npcap](https://npcap.com/#download)

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

### Automated Installation Linux
1. Download the `install_dependenciesLinux.sh` script.
2. Open a terminal and navigate to the scripts directory.
3. Make the script executable:
     ```
     chmod +x install_dependenciesLinux.sh
     ```
4. Run the script:
     ```
     sudo ./install_dependenciesLinux.sh
     ```

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


Usage
-----
Run the tool by executing the main script from your console:
  Windows:
  `python NETWORK10TM.py`
  Linux:
  `sudo python NETWORK10TM.py`

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
