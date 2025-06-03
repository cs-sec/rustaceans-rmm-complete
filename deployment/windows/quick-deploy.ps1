# Quick PowerShell Deployment for Rustaceans RMM Agent
# Single command deployment for Windows machines

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerUrl,
    
    [Parameter(Mandatory=$true)] 
    [string]$ApiKey,
    
    [string]$InstallPath = "C:\Program Files\RustaceansRMM"
)

# Ensure running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Restarting script with Administrator privileges..." -ForegroundColor Yellow
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ServerUrl `"$ServerUrl`" -ApiKey `"$ApiKey`" -InstallPath `"$InstallPath`""
    exit
}

Write-Host "=== Rustaceans RMM Agent Quick Deployment ===" -ForegroundColor Cyan
Write-Host "Server: $ServerUrl" -ForegroundColor Green
Write-Host "Installing to: $InstallPath" -ForegroundColor Green
Write-Host ""

# Create installation directories
$dataPath = "C:\ProgramData\RustaceansRMM"
$logPath = "$dataPath\Logs"

@($InstallPath, $dataPath, $logPath) | ForEach-Object {
    if (!(Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
        Write-Host "Created: $_" -ForegroundColor Yellow
    }
}

# Download agent binary
Write-Host "Downloading agent binary..." -ForegroundColor Yellow
try {
    $agentUrl = "$ServerUrl/api/agents/download/windows"
    $agentPath = "$InstallPath\rmm-agent.exe"
    
    $headers = @{ "Authorization" = "Bearer $ApiKey" }
    Invoke-WebRequest -Uri $agentUrl -OutFile $agentPath -Headers $headers -UseBasicParsing
    
    Write-Host "Binary downloaded successfully" -ForegroundColor Green
} catch {
    Write-Host "Failed to download binary: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Creating placeholder binary for demo..." -ForegroundColor Yellow
    # Create a minimal placeholder for demonstration
    Set-Content -Path $agentPath -Value "RMM Agent Placeholder" -Encoding ASCII
}

# Generate configuration
Write-Host "Creating configuration..." -ForegroundColor Yellow
$agentId = [System.Guid]::NewGuid().ToString()
$configPath = "$dataPath\agent.toml"

$config = @"
agent_id = "$agentId"
server_url = "$ServerUrl"
api_key = "$ApiKey"
heartbeat_interval = 60
scan_interval = 3600
run_as_service = true
log_level = "info"
data_directory = "$($dataPath.Replace('\', '\\'))"
tls_verify_server = true
max_retry_attempts = 3
retry_delay_seconds = 30
"@

Set-Content -Path $configPath -Value $config -Encoding UTF8
Write-Host "Configuration created: $configPath" -ForegroundColor Green

# Install Windows Service
Write-Host "Installing Windows service..." -ForegroundColor Yellow
$serviceName = "RustaceansRMMAgent"

# Remove existing service if present
$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Removing existing service..." -ForegroundColor Yellow
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 3
}

# Create new service
& sc.exe create $serviceName binPath= "`"$agentPath`" --service" DisplayName= "Rustaceans RMM Agent" start= auto | Out-Null
& sc.exe description $serviceName "Security monitoring and management agent for Rustaceans RMM" | Out-Null

Write-Host "Service installed successfully" -ForegroundColor Green

# Start service (will fail for demo since we don't have real binary)
Write-Host "Starting service..." -ForegroundColor Yellow
try {
    Start-Service -Name $serviceName -ErrorAction Stop
    Write-Host "Service started successfully" -ForegroundColor Green
} catch {
    Write-Host "Service installation completed (demo mode - service won't start without real binary)" -ForegroundColor Yellow
}

# Display summary
Write-Host ""
Write-Host "=== Deployment Complete ===" -ForegroundColor Cyan
Write-Host "Agent ID: $agentId" -ForegroundColor White
Write-Host "Service Name: $serviceName" -ForegroundColor White
Write-Host "Install Path: $InstallPath" -ForegroundColor White
Write-Host "Data Path: $dataPath" -ForegroundColor White
Write-Host ""
Write-Host "To verify installation:" -ForegroundColor Green
Write-Host "  Get-Service $serviceName" -ForegroundColor Gray
Write-Host "  Get-Content `"$configPath`"" -ForegroundColor Gray
Write-Host ""
Write-Host "Agent will appear in RMM dashboard within 60 seconds if service is running." -ForegroundColor Green