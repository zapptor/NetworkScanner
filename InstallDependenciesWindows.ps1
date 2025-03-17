# InstallDependencies.ps1

# 1. Check for Python:
Write-Output "Checking for Python..."
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Output "Python not found. Installing Python 3.12 via winget..."
    winget install --id Python.Python.3.12 -e
    Start-Sleep -Seconds 10
} else {
    Write-Output "Python is installed."
}

# 2. Verify pip is available (it usually comes with Python):
Write-Output "Verifying pip installation..."
$pip = Get-Command pip -ErrorAction SilentlyContinue
if (-not $pip) {
    Write-Output "pip not found. Installing pip using ensurepip..."
    python -m ensurepip
}

# 3. Check for Scapy:
Write-Output "Checking for Scapy..."
$scapyInfo = python -m pip show scapy 2>$null
if ([string]::IsNullOrEmpty($scapyInfo)) {
    Write-Output "Scapy not found. Installing Scapy..."
    python -m pip install scapy
} else {
    Write-Output "Scapy is already installed."
}

# 4. Check for python-nmap:
Write-Output "Checking for python-nmap..."
$pythonNmapInfo = python -m pip show python-nmap 2>$null
if ([string]::IsNullOrEmpty($pythonNmapInfo)) {
    Write-Output "python-nmap not found. Installing python-nmap..."
    python -m pip install python-nmap
} else {
    Write-Output "python-nmap is already installed."
}

<#
# 5. Check for Npcap:
Write-Output "Checking for Npcap..."
if (-not (Test-Path "C:\Windows\System32\wpcap.dll")) {
    Write-Output "Npcap not found. Installing Npcap via winget..."
    winget install --id Npcap.Npcap -e
    Start-Sleep -Seconds 10
} else {
    Write-Output "Npcap is already installed."
}
#>

# 5. Check for WinPcap:
Write-Output "Checking for WinPcap..."
if (-not (Test-Path "C:\Windows\System32\wpcap.dll")) {
    Write-Output "WinPcap not found. Installing WinPcap via winget..."
    winget install --id WinPcap.WinPcap -e
    Start-Sleep -Seconds 10
} else {
    Write-Output "WinPcap is already installed."
}

# 6. Check for Nmap:
Write-Output "Checking for Nmap..."
$nmap = Get-Command nmap -ErrorAction SilentlyContinue
if (-not $nmap) {
    Write-Output "Nmap not found. Installing Nmap via winget..."
    winget install --id Nmap.Nmap -e
    Start-Sleep -Seconds 10
} else {
    Write-Output "Nmap is already installed."
}

Write-Output "All dependencies are installed."
