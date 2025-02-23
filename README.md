Network Scanner is a simple Python tool that helps you find devices on your network. It can:

Find Active Hosts: Discover which IP addresses are in use.
SYN Scan & Connect Scan: Check which TCP ports are open.
Banner Grabbing: Retrieve service information from open ports.
This tool makes it easy to see what's running on your network.

the code wil run on layer 2 if it can, so it avoids ids and
firewall. will fallback to layer 3 if external ip is detected


 INSTALLATION  GUIDE FOR THE NETWORKSCANNER TO RUN

--------------AUTOMATED INSTALLATION --------------

------------------FOR WINDOWS!!!!------------------


1. Download the InstallDependenciesWindows.ps1

2. Save the script in your downloads folder 
3. Open powershell as admin.

4. Navigate to the scripts directory (copy and run command under)

   cd "$env:USERPROFILE\Downloads"

5. run the script "YOU MIGHT GET AN ERROR"

   .\InstallDependenciesWindows.ps1

6. IF YOU GET AN ERROR run this command
   
   powershell -ExecutionPolicy Bypass -File .\InstallDependenciesWindows.ps1


---------------MANUAL INSTALLATION-----------------

------------------FOR WINDOWS!!!!------------------

1. Download these programs: Python, nmap, npcap

   https://www.python.org/downloads/

   https://nmap.org/download.html

   https://npcap.com/#download

2. open cmd and install the rest there with these commands:
   
   python get-pip.py
   
   pip install python-nmap

   pip install scapy

3. Commands to confirm installation:

   python --version

   pip show scapy

   pip show python-nmap

   nmap --version 


--------------AUTOMATED INSTALLATION --------------

---------------------FOR LINUX---------------------
1. Download the install_dependenciesLinux.sh
   
2. Go to the the scripts directory
   
3. make it executable by running this command
   
   chmod +x install_dependenciesLinux.sh

4. run the script
   
   ./install_dependenciesLinux.sh
