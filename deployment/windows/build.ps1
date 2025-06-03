# Build script for Rustaceans RMM Agent Windows deployment

param(
    [string]$BuildMode = "Release",
    [string]$OutputDir = "dist",
    [switch]$CreateInstaller
)

Write-Host "Building Rustaceans RMM Agent for Windows..." -ForegroundColor Green

# Clean previous builds
if (Test-Path $OutputDir) {
    Remove-Item -Path $OutputDir -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# Build the agent binary
Write-Host "Compiling agent binary..." -ForegroundColor Yellow
$env:CARGO_TARGET_DIR = "target"

try {
    if ($BuildMode -eq "Release") {
        cargo build --bin rmm-agent --release --manifest-path Cargo.toml.agent
        $binarySource = "target\release\rmm-agent.exe"
    } else {
        cargo build --bin rmm-agent --manifest-path Cargo.toml.agent
        $binarySource = "target\debug\rmm-agent.exe"
    }
    
    if (-not (Test-Path $binarySource)) {
        throw "Binary not found at expected location: $binarySource"
    }
    
    # Copy binary to output directory
    Copy-Item -Path $binarySource -Destination "$OutputDir\rmm-agent.exe"
    Write-Host "Binary copied to output directory" -ForegroundColor Green
}
catch {
    Write-Error "Failed to build agent binary: $($_.Exception.Message)"
    exit 1
}

# Copy deployment files
Write-Host "Copying deployment files..." -ForegroundColor Yellow
Copy-Item -Path "deployment\windows\install.ps1" -Destination "$OutputDir\install.ps1"
Copy-Item -Path "deployment\windows\*.wxs" -Destination $OutputDir -ErrorAction SilentlyContinue

# Create default configuration template
$configTemplate = @"
# Rustaceans RMM Agent Configuration
# Edit these values before installation

agent_id = "GENERATE_NEW_UUID"
server_url = "https://your-rmm-server.com:5000"
api_key = "YOUR_API_KEY_HERE"
heartbeat_interval = 60
scan_interval = 3600
run_as_service = true
log_level = "info"
data_directory = "C:\\ProgramData\\RustaceansRMM"
tls_verify_server = true
max_retry_attempts = 3
retry_delay_seconds = 30
"@

Set-Content -Path "$OutputDir\agent.toml.template" -Value $configTemplate -Encoding UTF8

# Create quick install script
$quickInstall = @"
@echo off
echo Rustaceans RMM Agent Quick Installer
echo.

set /p SERVER_URL="Enter RMM Server URL (e.g., https://rmm.company.com:5000): "
set /p API_KEY="Enter API Key: "

if "%SERVER_URL%"=="" (
    echo Server URL is required
    pause
    exit /b 1
)

if "%API_KEY%"=="" (
    echo API Key is required
    pause
    exit /b 1
)

echo.
echo Installing agent with:
echo Server: %SERVER_URL%
echo.

powershell.exe -ExecutionPolicy Bypass -File "install.ps1" -ServerUrl "%SERVER_URL%" -ApiKey "%API_KEY%"

pause
"@

Set-Content -Path "$OutputDir\quick-install.bat" -Value $quickInstall -Encoding ASCII

# Create README for deployment
$readme = @"
# Rustaceans RMM Agent Windows Deployment

## Files in this package:
- rmm-agent.exe         - The agent binary
- install.ps1          - PowerShell installation script
- quick-install.bat    - Interactive installer
- agent.toml.template  - Configuration template

## Installation Methods:

### Method 1: Quick Install (Interactive)
1. Run as Administrator: quick-install.bat
2. Enter your RMM server URL and API key when prompted

### Method 2: PowerShell Script
Run as Administrator:
```powershell
.\install.ps1 -ServerUrl "https://your-server:5000" -ApiKey "your-api-key"
```

### Method 3: Manual Installation
1. Copy rmm-agent.exe to C:\Program Files\RustaceansRMM\
2. Edit agent.toml.template and save as C:\ProgramData\RustaceansRMM\agent.toml
3. Install as Windows service:
   ```cmd
   sc create RustaceansRMMAgent binPath="C:\Program Files\RustaceansRMM\rmm-agent.exe --service" start=auto
   sc start RustaceansRMMAgent
   ```

## System Requirements:
- Windows 10/11 or Windows Server 2016+
- Administrator privileges for installation
- Network access to RMM server (HTTPS)
- Minimum 50MB disk space

## Uninstallation:
```powershell
Stop-Service RustaceansRMMAgent
sc delete RustaceansRMMAgent
Remove-Item "C:\Program Files\RustaceansRMM" -Recurse -Force
Remove-Item "C:\ProgramData\RustaceansRMM" -Recurse -Force
```

## Support:
Check the Windows Event Log (Application) for "RustaceansRMM" events
Log files are stored in: C:\ProgramData\RustaceansRMM\Logs\
"@

Set-Content -Path "$OutputDir\README.md" -Value $readme -Encoding UTF8

Write-Host "`nBuild completed successfully!" -ForegroundColor Green
Write-Host "Output directory: $OutputDir" -ForegroundColor Cyan
Write-Host "Package contents:" -ForegroundColor Cyan
Get-ChildItem -Path $OutputDir | ForEach-Object { Write-Host "  $($_.Name)" -ForegroundColor Gray }

if ($CreateInstaller) {
    Write-Host "`nCreating MSI installer..." -ForegroundColor Yellow
    # MSI creation would require WiX Toolset
    Write-Host "MSI installer creation requires WiX Toolset (not implemented in this demo)" -ForegroundColor Yellow
}

Write-Host "`nDeployment package ready for distribution!" -ForegroundColor Green