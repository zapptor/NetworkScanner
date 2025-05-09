# InstallDependencies.ps1


param(
    [switch]$Elevated
)

# Elevation handling: if not elevated, restart elevated with -Elevated switch and wait
if (-not $Elevated) {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "This script requires Administrator privileges. Restarting as Administrator..."
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'powershell.exe'
        $psi.Arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",'-Elevated')
        $psi.Verb    = 'runas'
        $process     = [System.Diagnostics.Process]::Start($psi)
        $process.WaitForExit()
        Clear-Host
        if ($process.ExitCode -eq 0) {
            function Show-Banner {
                param([string]$Text)
                $bannerLines = @(
                    "  ____   ___  _   _ _____ ",
                    " |  _ \ / _ \| \ | | ____|",
                    " | | | | | | |  \| |  _|  ",
                    " | |_| | |_| | |\  | |___ ",
                    " |____/ \___/|_| \_|_____|"
                )
                foreach ($line in $bannerLines) { Write-Host $line }
                Write-Host "`n$Text`n"
            }
            Show-Banner "All dependencies installed successfully, CLOSE POWERSHELL!"
        } else {
            Write-Host "Installation encountered errors, try running the script again or install manually."
        }
        exit $process.ExitCode
    }
}

# Helper functions
function Disable-AppExecutionAlias {
    param ([string]$aliasName)
    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\$aliasName"
    if (Test-Path $registryPath) {
        Remove-Item -Path $registryPath -Recurse -Force
        Write-Host "Disabled app execution alias for $aliasName."
    }
}

function Refresh-EnvironmentPath {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

function Invoke-WingetInstall {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'winget'
    # Join arguments for Windows PowerShell compatibility
    $psi.Arguments = $Arguments -join ' '
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($psi)
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        $err = $process.StandardError.ReadToEnd()
        Write-Error "winget install failed: $err"
        exit $process.ExitCode
    }
}

# -- Begin dependency checks and installs --

# 1. Check and Install Python
Write-Host "Checking for Python..."
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "Python not found. Installing Python 3.12 via winget..."
    Invoke-WingetInstall -Arguments @('install','--id','Python.Python.3.12','-e','--silent','--accept-source-agreements','--accept-package-agreements')
    Write-Host "Python installed. Refreshing PATH..."
    Refresh-EnvironmentPath
} else {
    Write-Host "Using Python from: $($python.Path)"
    if ($python.Path -like "*\WindowsApps\*") {
        Write-Host "Detected Microsoft Store stub. Disabling aliases and reinstalling..."
        Disable-AppExecutionAlias -aliasName "python.exe"
        Disable-AppExecutionAlias -aliasName "python3.exe"
        Invoke-WingetInstall -Arguments @('install','--id','Python.Python.3.12','-e','--silent','--accept-source-agreements','--accept-package-agreements')
        Refresh-EnvironmentPath
    }
    $version = (& python --version) -replace '\r',''
    if (-not $version -or $version -notmatch 'Python \d+\.\d+\.\d+') {
        Write-Host "Invalid Python version. Reinstalling..."
        Invoke-WingetInstall -Arguments @('install','--id','Python.Python.3.12','-e','--silent','--accept-source-agreements','--accept-package-agreements')
        Refresh-EnvironmentPath
    } else {
        Write-Host "Python is functional. $version"
    }
}

# 2. Verify and Install pip
Write-Host "Verifying pip..."
if (-not (Get-Command pip -ErrorAction SilentlyContinue)) {
    Write-Host "pip not found. Installing..."
    python -m ensurepip --default-pip
    python -m pip install --upgrade pip
    Write-Host "pip installed."
} else {
    Write-Host "pip is installed."
}

# 3. Install Scapy
Write-Host "Checking for Scapy..."
if (-not (python -m pip show scapy 2>$null)) {
    Write-Host "Installing Scapy..."
    python -m pip install scapy
    Write-Host "Scapy installed."
} else {
    Write-Host "Scapy is already installed."
}

# 4. Install python-nmap
Write-Host "Checking for python-nmap..."
if (-not (python -m pip show python-nmap 2>$null)) {
    Write-Host "Installing python-nmap..."
    python -m pip install python-nmap
    Write-Host "python-nmap installed."
} else {
    Write-Host "python-nmap is already installed."
}

# 5. Install Npcap
Write-Host "Checking for Npcap..."
$npcapInstalled = winget list --id Npcap.Npcap -e 2>$null
if (-not $npcapInstalled) {
    Write-Host "Npcap not found. Installing Npcap via winget..."
    Invoke-WingetInstall -Arguments @('install','--id','Npcap.Npcap','-e','--silent','--accept-source-agreements','--accept-package-agreements')
    Write-Host "Npcap installed."
} else {
    Write-Host "Npcap is already installed."
}

# 6. Install Nmap
Write-Host "Checking for Nmap..."
if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    Write-Host "Nmap not found. Installing Nmap via winget..."
    Invoke-WingetInstall -Arguments @('install','--id','Insecure.Nmap','-e','--silent','--accept-source-agreements','--accept-package-agreements')
    Refresh-EnvironmentPath
    Write-Host "Nmap installed."
} else {
    Write-Host "Nmap is already installed."
}

# Final verification and message
Write-Host "Verifying all dependencies..."
if ((Get-Command python -ErrorAction SilentlyContinue) -and (Get-Command pip -ErrorAction SilentlyContinue) -and (python -m pip show scapy 2>$null) -and (python -m pip show python-nmap 2>$null) -and (winget list --id Npcap.Npcap -e 2>$null) -and (Get-Command nmap -ErrorAction SilentlyContinue)) {
    Write-Host "All dependencies installed successfully."
    Write-Host "Done. Please close this PowerShell window when finished."
} else {
    Write-Host "Some installations failed. Please review above output."
}
