# Enterprise PowerShell Deployment Script for Rustaceans RMM
# Supports mass deployment across multiple Windows machines

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerUrl,
    
    [Parameter(Mandatory=$true)]
    [string]$ApiKey,
    
    [string]$ComputerListFile,
    [string[]]$ComputerNames,
    [string]$OUPath,
    [string]$InstallPath = "C:\Program Files\RustaceansRMM",
    [string]$LogFile = "deployment-log.txt",
    [switch]$TestConnection,
    [switch]$Parallel,
    [int]$ThrottleLimit = 10,
    [PSCredential]$Credential
)

# Import required modules
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# Initialize logging
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogFile -Value $logEntry
}

Write-Log "Starting enterprise deployment of Rustaceans RMM Agent"
Write-Log "Server URL: $ServerUrl"
Write-Log "Install Path: $InstallPath"

# Get target computers
$targetComputers = @()

if ($ComputerListFile -and (Test-Path $ComputerListFile)) {
    $targetComputers += Get-Content $ComputerListFile
    Write-Log "Loaded $(($targetComputers).Count) computers from file: $ComputerListFile"
}

if ($ComputerNames) {
    $targetComputers += $ComputerNames
    Write-Log "Added $($ComputerNames.Count) computers from parameter"
}

if ($OUPath) {
    try {
        $ouComputers = Get-ADComputer -Filter * -SearchBase $OUPath | Select-Object -ExpandProperty Name
        $targetComputers += $ouComputers
        Write-Log "Found $(($ouComputers).Count) computers in OU: $OUPath"
    }
    catch {
        Write-Log "Failed to query Active Directory: $($_.Exception.Message)" "ERROR"
    }
}

if ($targetComputers.Count -eq 0) {
    Write-Log "No target computers specified. Use -ComputerListFile, -ComputerNames, or -OUPath" "ERROR"
    exit 1
}

# Remove duplicates
$targetComputers = $targetComputers | Sort-Object | Get-Unique
Write-Log "Total unique target computers: $(($targetComputers).Count)"

# Test connectivity if requested
if ($TestConnection) {
    Write-Log "Testing connectivity to target computers..."
    $reachableComputers = @()
    
    foreach ($computer in $targetComputers) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            $reachableComputers += $computer
            Write-Log "✓ $computer is reachable"
        } else {
            Write-Log "✗ $computer is not reachable" "WARN"
        }
    }
    
    $targetComputers = $reachableComputers
    Write-Log "Reachable computers: $(($targetComputers).Count)"
}

# Define deployment script block
$deploymentScript = {
    param($ComputerName, $ServerUrl, $ApiKey, $InstallPath)
    
    $result = @{
        Computer = $ComputerName
        Success = $false
        Message = ""
        AgentId = ""
    }
    
    try {
        # Copy installation files to target computer
        $remotePath = "\\$ComputerName\C$\Temp\RustaceansRMM"
        
        if (-not (Test-Path $remotePath)) {
            New-Item -ItemType Directory -Path $remotePath -Force | Out-Null
        }
        
        # Copy files (assuming they're in current directory)
        Copy-Item -Path ".\install.ps1" -Destination $remotePath -Force
        Copy-Item -Path ".\rmm-agent.exe" -Destination $remotePath -Force
        
        # Execute installation remotely
        $installCommand = @"
PowerShell.exe -ExecutionPolicy Bypass -File "C:\Temp\RustaceansRMM\install.ps1" -ServerUrl "$ServerUrl" -ApiKey "$ApiKey" -InstallPath "$InstallPath"
"@
        
        $session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
        $output = Invoke-Command -Session $session -ScriptBlock {
            param($Command)
            & cmd.exe /c $Command
        } -ArgumentList $installCommand
        
        Remove-PSSession $session
        
        # Verify installation
        $service = Get-Service -ComputerName $ComputerName -Name "RustaceansRMMAgent" -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            $result.Success = $true
            $result.Message = "Agent installed and running successfully"
            
            # Try to extract agent ID from config
            $configPath = "\\$ComputerName\C$\ProgramData\RustaceansRMM\agent.toml"
            if (Test-Path $configPath) {
                $configContent = Get-Content $configPath
                $agentIdLine = $configContent | Where-Object { $_ -match 'agent_id = "(.*)"' }
                if ($agentIdLine) {
                    $result.AgentId = $matches[1]
                }
            }
        } else {
            $result.Message = "Installation completed but service is not running"
        }
        
        # Cleanup temp files
        Remove-Item -Path $remotePath -Recurse -Force -ErrorAction SilentlyContinue
        
    }
    catch {
        $result.Message = "Deployment failed: $($_.Exception.Message)"
    }
    
    return $result
}

# Execute deployment
Write-Log "Starting deployment to $(($targetComputers).Count) computers..."

$deploymentResults = @()

if ($Parallel) {
    Write-Log "Running parallel deployment with throttle limit: $ThrottleLimit"
    
    $deploymentResults = $targetComputers | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $params = @{
            ComputerName = $_
            ServerUrl = $using:ServerUrl
            ApiKey = $using:ApiKey
            InstallPath = $using:InstallPath
        }
        
        & $using:deploymentScript @params
    }
} else {
    Write-Log "Running sequential deployment"
    
    foreach ($computer in $targetComputers) {
        Write-Log "Deploying to: $computer"
        
        $params = @{
            ComputerName = $computer
            ServerUrl = $ServerUrl
            ApiKey = $ApiKey
            InstallPath = $InstallPath
        }
        
        $result = & $deploymentScript @params
        $deploymentResults += $result
        
        if ($result.Success) {
            Write-Log "✓ $computer - $($result.Message)" "SUCCESS"
        } else {
            Write-Log "✗ $computer - $($result.Message)" "ERROR"
        }
    }
}

# Generate deployment report
$successCount = ($deploymentResults | Where-Object { $_.Success }).Count
$failureCount = $deploymentResults.Count - $successCount

Write-Log "Deployment Summary:"
Write-Log "Total computers: $($deploymentResults.Count)"
Write-Log "Successful deployments: $successCount"
Write-Log "Failed deployments: $failureCount"

# Create detailed report
$reportPath = "deployment-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$deploymentResults | Export-Csv -Path $reportPath -NoTypeInformation

Write-Log "Detailed report saved to: $reportPath"

# Display failed deployments
if ($failureCount -gt 0) {
    Write-Log "Failed Deployments:" "ERROR"
    $deploymentResults | Where-Object { -not $_.Success } | ForEach-Object {
        Write-Log "  $($_.Computer): $($_.Message)" "ERROR"
    }
}

# Display successful agent IDs
$successfulDeployments = $deploymentResults | Where-Object { $_.Success -and $_.AgentId }
if ($successfulDeployments.Count -gt 0) {
    Write-Log "Successfully deployed Agent IDs:"
    $successfulDeployments | ForEach-Object {
        Write-Log "  $($_.Computer): $($_.AgentId)"
    }
}

Write-Log "Enterprise deployment completed"