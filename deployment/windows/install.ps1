# Rustaceans RMM Agent Installation Script for Windows
# Run as Administrator

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerUrl,
    
    [Parameter(Mandatory=$true)]
    [string]$ApiKey,
    
    [string]$InstallPath = "C:\Program Files\RustaceansRMM",
    [string]$DataPath = "C:\ProgramData\RustaceansRMM",
    [string]$LogPath = "C:\ProgramData\RustaceansRMM\Logs",
    [switch]$SkipFirewall,
    [switch]$Quiet
)

# Check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

Write-Host "Installing Rustaceans RMM Agent..." -ForegroundColor Green

# Create directories
$directories = @($InstallPath, $DataPath, $LogPath)
foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "Created directory: $dir" -ForegroundColor Yellow
    }
}

# Download the latest agent binary
$agentUrl = "$ServerUrl/api/agents/download/windows"
$agentPath = Join-Path $InstallPath "rmm-agent.exe"

try {
    Write-Host "Downloading agent binary from $agentUrl..." -ForegroundColor Yellow
    
    # Create headers with API key
    $headers = @{
        "Authorization" = "Bearer $ApiKey"
        "User-Agent" = "RustaceansRMM-Installer/1.0"
    }
    
    Invoke-WebRequest -Uri $agentUrl -OutFile $agentPath -Headers $headers
    Write-Host "Agent binary downloaded successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to download agent binary: $($_.Exception.Message)"
    exit 1
}

# Generate agent configuration
$configPath = Join-Path $DataPath "agent.toml"
$agentId = [System.Guid]::NewGuid().ToString()

$configContent = @"
agent_id = "$agentId"
server_url = "$ServerUrl"
api_key = "$ApiKey"
heartbeat_interval = 60
scan_interval = 3600
run_as_service = true
log_level = "info"
data_directory = "$($DataPath.Replace('\', '\\'))"
tls_verify_server = true
max_retry_attempts = 3
retry_delay_seconds = 30
"@

Set-Content -Path $configPath -Value $configContent -Encoding UTF8
Write-Host "Configuration file created: $configPath" -ForegroundColor Green

# Install Windows service
try {
    Write-Host "Installing Windows service..." -ForegroundColor Yellow
    
    $serviceName = "RustaceansRMMAgent"
    $serviceDisplayName = "Rustaceans RMM Agent"
    $serviceDescription = "Security monitoring and management agent for Rustaceans RMM"
    
    # Stop and remove existing service if it exists
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Host "Stopping existing service..." -ForegroundColor Yellow
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $serviceName | Out-Null
        Start-Sleep -Seconds 2
    }
    
    # Create new service
    & sc.exe create $serviceName binPath= "`"$agentPath`" --service" DisplayName= $serviceDisplayName start= auto | Out-Null
    & sc.exe description $serviceName $serviceDescription | Out-Null
    
    Write-Host "Windows service installed successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to install Windows service: $($_.Exception.Message)"
    exit 1
}

# Start the service
try {
    Write-Host "Starting agent service..." -ForegroundColor Yellow
    Start-Service -Name $serviceName
    
    $service = Get-Service -Name $serviceName
    if ($service.Status -eq "Running") {
        Write-Host "Agent service is running" -ForegroundColor Green
    } else {
        Write-Warning "Service is not running. Check logs for issues."
    }
}
catch {
    Write-Warning "Failed to start service: $($_.Exception.Message)"
}

Write-Host "`nInstallation completed successfully!" -ForegroundColor Green
Write-Host "Agent ID: $agentId" -ForegroundColor Cyan
Write-Host "Service Name: $serviceName" -ForegroundColor Cyan
Write-Host "Install Path: $InstallPath" -ForegroundColor Cyan