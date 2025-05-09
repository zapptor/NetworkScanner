# InstallDependencies.ps1

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "This script requires Administrator privileges. Restarting as Administrator..."
    Start-Process powershell -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    exit
}

# Function to disable app execution aliases
function Disable-AppExecutionAlias {
    param (
        [string]$aliasName
    )
    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\$aliasName"
    if (Test-Path $registryPath) {
        Remove-Item -Path $registryPath -Recurse -Force
        Write-Output "Disabled app execution alias for $aliasName."
    }
}

# Function to refresh environment variables from registry
function Refresh-EnvironmentPath {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}

# 1. Check and Install Python
Write-Output "Checking for Python..."
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Output "Python not found. Installing Python 3.12 via winget..."
    Start-Process -Wait -FilePath winget -ArgumentList "install --id Python.Python.3.12 -e --silent"
    Write-Output "Python installed. Refreshing PATH..."
    Refresh-EnvironmentPath
    # Check if Python is now available
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        # Try adding common Python paths
        $possiblePaths = @(
            "${env:LocalAppData}\Programs\Python\Python312",
            "C:\Program Files\Python312",
            "C:\Program Files (x86)\Python312"
        )
        foreach ($path in $possiblePaths) {
            if (Test-Path $path) {
                $env:Path += ";$path;$path\Scripts"
                Write-Output "Added Python path: $path"
            }
        }
        # Verify again
        $python = Get-Command python -ErrorAction SilentlyContinue
        if (-not $python) {
            Write-Output "Failed to locate Python after installation. Exiting."
            exit 1
        }
    }
} else {
    $pythonPath = $python.Path
    Write-Output "Using Python from: $pythonPath"
    if ($pythonPath -like "*\WindowsApps\*") {
        Write-Output "Detected Microsoft Store Python stub. Disabling aliases..."
        Disable-AppExecutionAlias -aliasName "python.exe"
        Disable-AppExecutionAlias -aliasName "python3.exe"
        Write-Output "Installing Python 3.12 via winget..."
        Start-Process -Wait -FilePath winget -ArgumentList "install --id Python.Python.3.12 -e --silent"
        Write-Output "Python installed. Refreshing PATH..."
        Refresh-EnvironmentPath
        # Check again and add paths if needed
        $python = Get-Command python -ErrorAction SilentlyContinue
        if (-not $python) {
            $possiblePaths = @(
                "${env:LocalAppData}\Programs\Python\Python312",
                "C:\Program Files\Python312",
                "C:\Program Files (x86)\Python312"
            )
            foreach ($path in $possiblePaths) {
                if (Test-Path $path) {
                    $env:Path += ";$path;$path\Scripts"
                    Write-Output "Added Python path: $path"
                }
            }
            $python = Get-Command python -ErrorAction SilentlyContinue
            if (-not $python) {
                Write-Output "Python installation failed. Exiting."
                exit 1
            }
        }
    }
    # Verify Python functionality
    $pythonVersion = & $python.Path --version 2>$null
    if (-not $pythonVersion -or $pythonVersion -notmatch "Python \d+\.\d+\.\d+") {
        Write-Output "Python found but not functional. Reinstalling..."
        Start-Process -Wait -FilePath winget -ArgumentList "install --id Python.Python.3.12 -e --silent"
        Refresh-EnvironmentPath
        $python = Get-Command python -ErrorAction SilentlyContinue
        if (-not $python) {
            Write-Output "Python reinstallation failed. Exiting."
            exit 1
        }
    } else {
        Write-Output "Python is installed and functional. Version: $pythonVersion"
    }
}

# Update pythonPath after possible reinstall
$python = Get-Command python -ErrorAction SilentlyContinue
$pythonPath = $python.Path

# 2. Verify and Install pip
Write-Output "Verifying pip installation..."
$pip = Get-Command pip -ErrorAction SilentlyContinue
if (-not $pip) {
    Write-Output "pip not found. Installing pip using ensurepip..."
    & $pythonPath -m ensurepip --default-pip
    & $pythonPath -m pip install --upgrade pip
    Write-Output "pip installed successfully."
} else {
    Write-Output "pip is installed."
}

# 3. Install Scapy
Write-Output "Checking for Scapy..."
$scapyInfo = & $pythonPath -m pip show scapy 2>$null
if (-not $scapyInfo) {
    Write-Output "Scapy not found. Installing Scapy..."
    & $pythonPath -m pip install scapy
    Write-Output "Scapy installed successfully."
} else {
    Write-Output "Scapy is already installed."
}

# 4. Install python-nmap
Write-Output "Checking for python-nmap..."
$pythonNmapInfo = & $pythonPath -m pip show python-nmap 2>$null
if (-not $pythonNmapInfo) {
    Write-Output "python-nmap not found. Installing python-nmap..."
    & $pythonPath -m pip install python-nmap
    Write-Output "python-nmap installed successfully."
} else {
    Write-Output "python-nmap is already installed."
}

# 5. Install Npcap
Write-Output "Checking for Npcap..."
$npcapInstalled = winget list --id Npcap.Npcap -e 2>$null
if (-not $npcapInstalled) {
    Write-Output "Npcap not found. Installing Npcap via winget..."
    Start-Process -Wait -FilePath winget -ArgumentList "install --id Npcap.Npcap -e --silent"
    Start-Sleep -Seconds 5
    Write-Output "Npcap installed successfully."
} else {
    Write-Output "Npcap is already installed."
}

# 6. Install Nmap
Write-Output "Checking for Nmap..."
$nmap = Get-Command nmap -ErrorAction SilentlyContinue
if (-not $nmap) {
    Write-Output "Nmap not found. Installing Nmap via winget..."
    Start-Process -Wait -FilePath winget -ArgumentList "install --id Insecure.Nmap -e --silent"
    Refresh-EnvironmentPath
    # Check again and add path if needed
    $nmap = Get-Command nmap -ErrorAction SilentlyContinue
    if (-not $nmap) {
        $nmapPath = "C:\Program Files\Nmap"
        if (Test-Path $nmapPath) {
            $env:Path += ";$nmapPath"
            Write-Output "Added Nmap path: $nmapPath"
        }
        $nmap = Get-Command nmap -ErrorAction SilentlyContinue
        if (-not $nmap) {
            Write-Output "Nmap installation failed. Exiting."
            exit 1
        }
    }
    Write-Output "Nmap installed successfully."
} else {
    Write-Output "Nmap is already installed."
}

# Final verification
Write-Output "Verifying all dependencies..."
if ((Get-Command python -ErrorAction SilentlyContinue) -and 
    (Get-Command pip -ErrorAction SilentlyContinue) -and 
    (& $pythonPath -m pip show scapy 2>$null) -and 
    (& $pythonPath -m pip show python-nmap 2>$null) -and 
    (winget list --id Npcap.Npcap -e 2>$null) -and 
    (Get-Command nmap -ErrorAction SilentlyContinue)) {
    Write-Output "All dependencies are installed successfully. You're ready to go!"
} else {
    Write-Output "Some dependencies failed to install. Please check the output above for details."
}
