# Rustaceans Security RMM Agent with Vulnerability Scanning
# Enterprise-ready Windows agent with comprehensive security monitoring

param(
    [string]$ServerUrl = "http://your-server-url:5000",
    [string]$AgentId = $null,
    [int]$HeartbeatInterval = 300,  # 5 minutes
    [int]$ScanInterval = 3600,      # 1 hour
    [switch]$InstallAsService = $false,
    [switch]$Debug = $false
)

# Configuration
$Global:ServerUrl = $ServerUrl
$Global:AgentId = if ($AgentId) { $AgentId } else { "$env:COMPUTERNAME-$(Get-Random -Maximum 9999)" }
$Global:HeartbeatInterval = $HeartbeatInterval
$Global:ScanInterval = $ScanInterval
$Global:LastScanTime = 0
$Global:Debug = $Debug

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    if ($Global:Debug) {
        Add-Content -Path "rmm-agent.log" -Value $LogMessage
    }
}

function Get-SystemInfo {
    try {
        $OS = Get-CimInstance Win32_OperatingSystem
        $Computer = Get-CimInstance Win32_ComputerSystem
        $Processor = Get-CimInstance Win32_Processor | Select-Object -First 1
        
        # Get network adapter with IP
        $NetworkAdapter = Get-CimInstance Win32_NetworkAdapterConfiguration | 
            Where-Object { $_.IPEnabled -eq $true -and $_.IPAddress -ne $null } | 
            Select-Object -First 1
        
        # Memory usage
        $TotalMemory = [math]::Round($OS.TotalVisibleMemorySize / 1MB, 2)
        $FreeMemory = [math]::Round($OS.FreePhysicalMemory / 1MB, 2)
        $MemoryUsage = [math]::Round((($TotalMemory - $FreeMemory) / $TotalMemory) * 100, 2)
        
        # CPU usage (approximate)
        $CpuUsage = [math]::Round((Get-Counter "\Processor(_Total)\% Processor Time").CounterSamples.CookedValue, 1)
        
        # Disk usage
        $SystemDrive = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive }
        $DiskUsage = if ($SystemDrive) { 
            [math]::Round((($SystemDrive.Size - $SystemDrive.FreeSpace) / $SystemDrive.Size) * 100, 2)
        } else { 0 }
        
        return @{
            hostname = $env:COMPUTERNAME
            ip_address = if ($NetworkAdapter.IPAddress) { $NetworkAdapter.IPAddress[0] } else { "Unknown" }
            os = $OS.Caption
            os_version = $OS.Version
            architecture = $OS.OSArchitecture
            total_memory_gb = $TotalMemory
            cpu_model = $Processor.Name
            agent_version = "2.0.0"
            cpu_usage = $CpuUsage
            memory_usage = $MemoryUsage
            disk_usage = $DiskUsage
        }
    } catch {
        Write-Log "Error getting system info: $_" "ERROR"
        return @{
            hostname = $env:COMPUTERNAME
            ip_address = "Unknown"
            os = "Windows"
            os_version = "Unknown"
            agent_version = "2.0.0"
            cpu_usage = 0
            memory_usage = 0
            disk_usage = 0
        }
    }
}

function Register-WithServer {
    try {
        $SystemInfo = Get-SystemInfo
        $RegistrationData = @{
            agent_id = $Global:AgentId
            system_info = $SystemInfo
        }
        
        $Body = $RegistrationData | ConvertTo-Json -Depth 3
        $Response = Invoke-RestMethod -Uri "$Global:ServerUrl/api/clients" -Method POST -Body $Body -ContentType "application/json" -TimeoutSec 30 -UseBasicParsing
        
        Write-Log "Successfully registered with server. Agent ID: $Global:AgentId"
        return $true
    } catch {
        Write-Log "Failed to register with server: $_" "ERROR"
        return $false
    }
}

function Send-Heartbeat {
    try {
        $SystemInfo = Get-SystemInfo
        $HeartbeatData = @{
            system_info = $SystemInfo
            timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        }
        
        $Body = $HeartbeatData | ConvertTo-Json -Depth 3
        $Response = Invoke-RestMethod -Uri "$Global:ServerUrl/api/clients/$Global:AgentId/heartbeat" -Method POST -Body $Body -ContentType "application/json" -TimeoutSec 10 -UseBasicParsing
        Write-Log "Heartbeat sent successfully"
        return $true
    } catch {
        Write-Log "Failed to send heartbeat: $_" "ERROR"
        return $false
    }
}

function Perform-VulnerabilityScans {
    Write-Log "Starting comprehensive vulnerability scan..."
    $findings = @()
    
    # 1. Windows Update Check
    try {
        $Updates = Get-WmiObject -Class Win32_QuickFixEngineering | Sort-Object InstalledOn -Descending | Select-Object -First 10
        $LastUpdate = $Updates | Select-Object -First 1
        $DaysSinceUpdate = if ($LastUpdate.InstalledOn) { ((Get-Date) - [DateTime]$LastUpdate.InstalledOn).Days } else { 999 }
        
        if ($DaysSinceUpdate -gt 30) {
            $findings += @{
                id = "outdated_patches"
                severity = "High"
                title = "System patches are outdated"
                description = "Last security update was $DaysSinceUpdate days ago. System may be vulnerable to known exploits."
                category = "System Updates"
                affected_component = "Windows OS"
                remediation = "Install latest Windows updates immediately"
                confidence = 0.9
            }
        } elseif ($DaysSinceUpdate -gt 7) {
            $findings += @{
                id = "recent_patches_available"
                severity = "Medium"
                title = "Recent patches available"
                description = "System updates are $DaysSinceUpdate days behind"
                category = "System Updates"
                affected_component = "Windows OS"
                remediation = "Install available Windows updates"
                confidence = 0.7
            }
        }
    } catch {
        $findings += @{
            id = "update_check_failed"
            severity = "Medium"
            title = "Unable to verify update status"
            description = "Could not check Windows update history - system may be missing critical patches"
            category = "System Updates"
            affected_component = "Windows Update Service"
            remediation = "Manually check Windows Update and verify service is running"
            confidence = 0.6
        }
    }
    
    # 2. Windows Defender Status
    try {
        $DefenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($DefenderStatus) {
            if (-not $DefenderStatus.RealTimeProtectionEnabled) {
                $findings += @{
                    id = "defender_realtime_disabled"
                    severity = "Critical"
                    title = "Windows Defender Real-time Protection Disabled"
                    description = "Real-time malware protection is turned off, leaving system vulnerable to threats"
                    category = "Antivirus"
                    affected_component = "Windows Defender"
                    remediation = "Enable real-time protection in Windows Security settings"
                    confidence = 1.0
                }
            }
            
            if (-not $DefenderStatus.OnAccessProtectionEnabled) {
                $findings += @{
                    id = "defender_onaccess_disabled"
                    severity = "High"
                    title = "Windows Defender On-Access Protection Disabled"
                    description = "File access scanning is disabled"
                    category = "Antivirus"
                    affected_component = "Windows Defender"
                    remediation = "Enable on-access protection in Windows Security"
                    confidence = 1.0
                }
            }
            
            $DaysSinceSignatureUpdate = ((Get-Date) - $DefenderStatus.AntivirusSignatureLastUpdated).Days
            if ($DaysSinceSignatureUpdate -gt 7) {
                $findings += @{
                    id = "defender_signatures_outdated"
                    severity = "High"
                    title = "Antivirus signatures outdated"
                    description = "Virus definitions are $DaysSinceSignatureUpdate days old - may not detect latest threats"
                    category = "Antivirus"
                    affected_component = "Windows Defender"
                    remediation = "Update virus definitions immediately"
                    confidence = 0.9
                }
            }
            
            if ($DefenderStatus.QuickScanAge -gt 7) {
                $findings += @{
                    id = "no_recent_scan"
                    severity = "Medium"
                    title = "No recent antivirus scan"
                    description = "Last quick scan was over 7 days ago"
                    category = "Antivirus"
                    affected_component = "Windows Defender"
                    remediation = "Run a full system antivirus scan"
                    confidence = 0.8
                }
            }
        } else {
            $findings += @{
                id = "defender_not_available"
                severity = "Critical"
                title = "Windows Defender not available or disabled"
                description = "Primary antivirus protection is not functioning"
                category = "Antivirus"
                affected_component = "Windows Defender"
                remediation = "Enable Windows Defender or install alternative antivirus"
                confidence = 0.9
            }
        }
    } catch {
        $findings += @{
            id = "defender_check_failed"
            severity = "Medium"
            title = "Unable to check antivirus status"
            description = "Could not verify Windows Defender configuration"
            category = "Antivirus"
            affected_component = "Windows Defender"
            remediation = "Manually verify Windows Security settings"
            confidence = 0.6
        }
    }
    
    # 3. Firewall Configuration
    try {
        $FirewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        if ($FirewallProfiles) {
            foreach ($Profile in $FirewallProfiles) {
                if ($Profile.Enabled -eq $false) {
                    $findings += @{
                        id = "firewall_disabled_$($Profile.Name)"
                        severity = "High"
                        title = "Windows Firewall disabled for $($Profile.Name) profile"
                        description = "Network firewall protection is disabled for $($Profile.Name) network profile"
                        category = "Network Security"
                        affected_component = "Windows Firewall"
                        remediation = "Enable Windows Firewall for the $($Profile.Name) profile"
                        confidence = 1.0
                    }
                }
            }
        } else {
            # Fallback for older systems
            $FirewallStatus = netsh advfirewall show allprofiles state 2>$null
            if ($FirewallStatus -match "State\s+OFF") {
                $findings += @{
                    id = "firewall_disabled"
                    severity = "High"
                    title = "Windows Firewall disabled"
                    description = "One or more firewall profiles are disabled"
                    category = "Network Security"
                    affected_component = "Windows Firewall"
                    remediation = "Enable Windows Firewall for all profiles"
                    confidence = 0.9
                }
            }
        }
    } catch {
        $findings += @{
            id = "firewall_check_failed"
            severity = "Low"
            title = "Unable to check firewall status"
            description = "Could not verify Windows Firewall configuration"
            category = "Network Security"
            affected_component = "Windows Firewall"
            remediation = "Manually check firewall settings in Windows Security"
            confidence = 0.5
        }
    }
    
    # 4. User Account Security
    try {
        $Users = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
        if ($Users) {
            foreach ($User in $Users) {
                if ($User.Name -eq "Administrator" -and $User.Enabled) {
                    $findings += @{
                        id = "admin_account_enabled"
                        severity = "Medium"
                        title = "Built-in Administrator account enabled"
                        description = "Default Administrator account is active and may be targeted by attackers"
                        category = "User Security"
                        affected_component = "User Accounts"
                        remediation = "Disable or rename the built-in Administrator account"
                        confidence = 0.8
                    }
                }
                
                if ($User.PasswordRequired -eq $false) {
                    $findings += @{
                        id = "no_password_required_$($User.Name)"
                        severity = "High"
                        title = "User account with no password requirement: $($User.Name)"
                        description = "Account can be accessed without password authentication"
                        category = "User Security"
                        affected_component = "User Accounts"
                        remediation = "Require password for user account $($User.Name)"
                        confidence = 1.0
                    }
                }
            }
        }
    } catch {
        # Try alternative method
        try {
            $NetUsers = net user 2>$null
            if ($NetUsers -match "Administrator") {
                $findings += @{
                    id = "admin_account_present"
                    severity = "Low"
                    title = "Administrator account detected"
                    description = "Built-in Administrator account is present on system"
                    category = "User Security"
                    affected_component = "User Accounts"
                    remediation = "Verify Administrator account is properly secured or disabled"
                    confidence = 0.5
                }
            }
        } catch {
            # Skip if both methods fail
        }
    }
    
    # 5. Network Share Security
    try {
        $Shares = Get-WmiObject Win32_Share | Where-Object { $_.Type -eq 0 -and $_.Name -notmatch '^[A-Z]\$$' }
        foreach ($Share in $Shares) {
            if ($Share.Name -notin @("ADMIN`$", "IPC`$", "C`$", "print`$")) {
                $findings += @{
                    id = "network_share_$($Share.Name)"
                    severity = "Medium"
                    title = "Network share detected: $($Share.Name)"
                    description = "Shared folder '$($Share.Name)' at '$($Share.Path)' may expose sensitive data"
                    category = "Network Security"
                    affected_component = "File Sharing"
                    remediation = "Review share permissions and necessity for '$($Share.Name)'"
                    confidence = 0.6
                }
            }
        }
    } catch {
        # Non-critical, skip
    }
    
    # 6. Service Security
    try {
        $RiskyServices = @{
            "Telnet" = "TlntSvr"
            "Remote Registry" = "RemoteRegistry"
            "Windows Remote Management" = "WinRM"
        }
        
        foreach ($ServiceName in $RiskyServices.Keys) {
            $ServiceKey = $RiskyServices[$ServiceName]
            $Service = Get-Service -Name $ServiceKey -ErrorAction SilentlyContinue
            if ($Service -and $Service.Status -eq "Running") {
                $findings += @{
                    id = "risky_service_$ServiceKey"
                    severity = "Medium"
                    title = "Potentially risky service running: $ServiceName"
                    description = "Service '$ServiceName' is running and may pose security risks"
                    category = "Service Security"
                    affected_component = $ServiceName
                    remediation = "Review necessity of '$ServiceName' service and disable if not required"
                    confidence = 0.7
                }
            }
        }
    } catch {
        # Non-critical, skip
    }
    
    # 7. Registry Security Check
    try {
        # Check for autorun entries in common locations
        $AutorunKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        
        $SuspiciousCount = 0
        foreach ($Key in $AutorunKeys) {
            if (Test-Path $Key) {
                $Entries = Get-ItemProperty $Key -ErrorAction SilentlyContinue
                if ($Entries) {
                    $EntryCount = ($Entries.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }).Count
                    $SuspiciousCount += $EntryCount
                }
            }
        }
        
        if ($SuspiciousCount -gt 5) {
            $findings += @{
                id = "excessive_autorun_entries"
                severity = "Medium"
                title = "Excessive startup programs detected"
                description = "Found $SuspiciousCount programs configured to start automatically"
                category = "System Configuration"
                affected_component = "Startup Programs"
                remediation = "Review and remove unnecessary startup programs"
                confidence = 0.6
            }
        }
    } catch {
        # Non-critical, skip
    }
    
    Write-Log "Vulnerability scan completed. Found $($findings.Count) security findings."
    return $findings
}

function Send-ScanResults {
    try {
        Write-Log "Performing comprehensive vulnerability scan..."
        $findings = Perform-VulnerabilityScans
        
        $ScanResults = @{
            agent_id = $Global:AgentId
            scan_type = "vulnerability"
            timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            scan_duration_ms = 15000
            findings_count = $findings.Count
            findings = $findings
        }
        
        $Body = $ScanResults | ConvertTo-Json -Depth 5
        $Response = Invoke-RestMethod -Uri "$Global:ServerUrl/api/scan-results" -Method POST -Body $Body -ContentType "application/json" -TimeoutSec 30 -UseBasicParsing
        Write-Log "Vulnerability scan completed: $($findings.Count) findings sent to server"
        return $true
    } catch {
        Write-Log "Failed to send scan results: $_" "ERROR"
        return $false
    }
}

function Install-AsService {
    Write-Log "Installing RMM Agent as Windows Service..."
    
    $ServiceScript = @"
# RMM Agent Service Wrapper
`$AgentScript = "$PSCommandPath"
`$Arguments = "-ServerUrl `"$Global:ServerUrl`" -AgentId `"$Global:AgentId`" -HeartbeatInterval $Global:HeartbeatInterval -ScanInterval $Global:ScanInterval"

while (`$true) {
    try {
        Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"`$AgentScript`" `$Arguments" -Wait -NoNewWindow
    } catch {
        Start-Sleep 60
    }
    Start-Sleep 30
}
"@
    
    $ServiceScriptPath = "$env:ProgramFiles\RustaceansRMM\agent-service.ps1"
    $ServiceDir = Split-Path $ServiceScriptPath -Parent
    
    if (-not (Test-Path $ServiceDir)) {
        New-Item -ItemType Directory -Path $ServiceDir -Force | Out-Null
    }
    
    $ServiceScript | Out-File -FilePath $ServiceScriptPath -Encoding UTF8
    
    # Create service using sc.exe
    $ServiceName = "RustaceansRMMAgent"
    $ServiceCommand = "powershell.exe -ExecutionPolicy Bypass -File `"$ServiceScriptPath`""
    
    sc.exe create $ServiceName binPath= "$ServiceCommand" start= auto DisplayName= "Rustaceans RMM Agent"
    sc.exe description $ServiceName "Rustaceans Security RMM monitoring agent"
    sc.exe start $ServiceName
    
    Write-Log "RMM Agent installed as service: $ServiceName"
}

# Main execution
Write-Log "Starting Rustaceans Security RMM Agent v2.0"
Write-Log "Server: $Global:ServerUrl"
Write-Log "Agent ID: $Global:AgentId"
Write-Log "Heartbeat Interval: $Global:HeartbeatInterval seconds"
Write-Log "Scan Interval: $Global:ScanInterval seconds"

if ($InstallAsService) {
    Install-AsService
    exit 0
}

# Registration
Write-Log "Attempting to register with server..."
$RegistrationAttempts = 0
while (-not (Register-WithServer) -and $RegistrationAttempts -lt 5) {
    $RegistrationAttempts++
    Write-Log "Registration attempt $RegistrationAttempts failed. Retrying in 10 seconds..."
    Start-Sleep 10
}

if ($RegistrationAttempts -eq 5) {
    Write-Log "Failed to register after 5 attempts. Exiting." "ERROR"
    exit 1
}

# Initial vulnerability scan
Write-Log "Performing initial vulnerability scan..."
Send-ScanResults

# Main monitoring loop
Write-Log "Starting monitoring loop..."
$Global:LastScanTime = [DateTimeOffset]::Now.ToUnixTimeSeconds()

while ($true) {
    try {
        # Send heartbeat
        Send-Heartbeat | Out-Null
        
        # Check if it's time for a vulnerability scan
        $CurrentTime = [DateTimeOffset]::Now.ToUnixTimeSeconds()
        if (($CurrentTime - $Global:LastScanTime) -ge $Global:ScanInterval) {
            Write-Log "Starting scheduled vulnerability scan..."
            Send-ScanResults | Out-Null
            $Global:LastScanTime = $CurrentTime
        }
        
        # Wait for next heartbeat
        Start-Sleep $Global:HeartbeatInterval
        
    } catch {
        Write-Log "Error in monitoring loop: $_" "ERROR"
        Start-Sleep 30
    }
}