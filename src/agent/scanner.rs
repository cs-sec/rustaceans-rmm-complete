use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use tracing::{info, warn, error};

use crate::config::AgentConfig;
use crate::system::SystemInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub scan_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub scan_type: String,
    pub findings: Vec<SecurityFinding>,
    pub system_info: SystemInfo,
    pub scan_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub cve_id: Option<String>,
    pub affected_component: String,
    pub remediation: String,
    pub confidence: f32,
}

pub struct SecurityScanner {
    config: AgentConfig,
}

impl SecurityScanner {
    pub fn new(config: AgentConfig) -> Self {
        Self { config }
    }

    pub async fn perform_comprehensive_scan(&mut self) -> Result<ScanResults> {
        let start_time = std::time::Instant::now();
        let scan_id = Uuid::new_v4();
        info!("Starting comprehensive security scan: {}", scan_id);

        let mut findings = Vec::new();
        
        // Perform different types of scans
        findings.extend(self.scan_installed_software().await?);
        findings.extend(self.scan_windows_updates().await?);
        findings.extend(self.scan_network_configuration().await?);
        findings.extend(self.scan_user_accounts().await?);
        findings.extend(self.scan_services().await?);

        let scan_duration = start_time.elapsed().as_millis() as u64;
        
        Ok(ScanResults {
            scan_id,
            timestamp: Utc::now(),
            scan_type: "comprehensive".to_string(),
            findings,
            system_info: SystemInfo::new(),
            scan_duration_ms: scan_duration,
        })
    }

    pub async fn scan_vulnerabilities(&mut self) -> Result<ScanResults> {
        let start_time = std::time::Instant::now();
        let scan_id = Uuid::new_v4();
        
        let mut findings = Vec::new();
        findings.extend(self.scan_installed_software().await?);
        findings.extend(self.scan_windows_updates().await?);

        let scan_duration = start_time.elapsed().as_millis() as u64;
        
        Ok(ScanResults {
            scan_id,
            timestamp: Utc::now(),
            scan_type: "vulnerability".to_string(),
            findings,
            system_info: SystemInfo::new(),
            scan_duration_ms: scan_duration,
        })
    }

    #[cfg(windows)]
    async fn scan_installed_software(&self) -> Result<Vec<SecurityFinding>> {
        use std::os::windows::process::CommandExt;
        
        let mut findings = Vec::new();
        
        // Query installed software via PowerShell
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | ConvertTo-Json"
            ])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
            .context("Failed to execute PowerShell command")?;

        if output.status.success() {
            let software_list: Vec<InstalledSoftware> = serde_json::from_slice(&output.stdout)
                .unwrap_or_default();

            for software in software_list {
                // Check for known vulnerable software versions
                if self.is_vulnerable_software(&software) {
                    findings.push(SecurityFinding {
                        id: format!("vuln_software_{}", software.name.replace(" ", "_")),
                        severity: "Medium".to_string(),
                        title: format!("Potentially vulnerable software: {}", software.name),
                        description: format!(
                            "Software {} version {} may contain security vulnerabilities",
                            software.name, software.version.unwrap_or_default()
                        ),
                        category: "Software Vulnerabilities".to_string(),
                        cve_id: None,
                        affected_component: software.name.clone(),
                        remediation: format!("Update {} to the latest version", software.name),
                        confidence: 0.7,
                    });
                }
            }
        }

        Ok(findings)
    }

    #[cfg(windows)]
    async fn scan_windows_updates(&self) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        
        // Check for available Windows updates
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "if (Get-Module -ListAvailable PSWindowsUpdate) { Get-WUList } else { Write-Output 'PSWindowsUpdate module not available' }"
            ])
            .output()
            .context("Failed to check Windows updates")?;

        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if !output_str.contains("PSWindowsUpdate module not available") && !output_str.trim().is_empty() {
                findings.push(SecurityFinding {
                    id: "windows_updates_available".to_string(),
                    severity: "High".to_string(),
                    title: "Windows updates available".to_string(),
                    description: "Security updates are available for Windows".to_string(),
                    category: "System Updates".to_string(),
                    cve_id: None,
                    affected_component: "Windows Operating System".to_string(),
                    remediation: "Install available Windows updates".to_string(),
                    confidence: 0.9,
                });
            }
        }

        Ok(findings)
    }

    #[cfg(windows)]
    async fn scan_network_configuration(&self) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        
        // Check firewall status
        let output = Command::new("netsh")
            .args(&["advfirewall", "show", "allprofiles", "state"])
            .output()
            .context("Failed to check firewall status")?;

        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.contains("State                                 OFF") {
                findings.push(SecurityFinding {
                    id: "firewall_disabled".to_string(),
                    severity: "High".to_string(),
                    title: "Windows Firewall disabled".to_string(),
                    description: "Windows Firewall is disabled on one or more profiles".to_string(),
                    category: "Network Security".to_string(),
                    cve_id: None,
                    affected_component: "Windows Firewall".to_string(),
                    remediation: "Enable Windows Firewall for all profiles".to_string(),
                    confidence: 1.0,
                });
            }
        }

        // Check for open ports
        let output = Command::new("netstat")
            .args(&["-an"])
            .output()
            .context("Failed to check open ports")?;

        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let suspicious_ports = ["23", "135", "445", "1433", "3389"];
            
            for port in suspicious_ports {
                if output_str.contains(&format!(":{}             ", port)) {
                    findings.push(SecurityFinding {
                        id: format!("open_port_{}", port),
                        severity: "Medium".to_string(),
                        title: format!("Potentially risky port {} is open", port),
                        description: format!("Port {} is listening and may pose security risks", port),
                        category: "Network Security".to_string(),
                        cve_id: None,
                        affected_component: format!("Network Port {}", port),
                        remediation: format!("Review necessity of port {} and secure if needed", port),
                        confidence: 0.6,
                    });
                }
            }
        }

        Ok(findings)
    }

    #[cfg(windows)]
    async fn scan_user_accounts(&self) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        
        // Check for accounts with no password expiration
        let output = Command::new("net")
            .args(&["user"])
            .output()
            .context("Failed to list user accounts")?;

        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            // Simple check for common weak accounts
            if output_str.contains("Administrator") {
                findings.push(SecurityFinding {
                    id: "admin_account_enabled".to_string(),
                    severity: "Medium".to_string(),
                    title: "Administrator account may be enabled".to_string(),
                    description: "The built-in Administrator account appears to be present".to_string(),
                    category: "User Account Security".to_string(),
                    cve_id: None,
                    affected_component: "Administrator Account".to_string(),
                    remediation: "Disable or rename the Administrator account if not needed".to_string(),
                    confidence: 0.5,
                });
            }
        }

        Ok(findings)
    }

    #[cfg(windows)]
    async fn scan_services(&self) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        
        // Check for risky services
        let risky_services = [
            ("Telnet", "TlntSvr"),
            ("Remote Registry", "RemoteRegistry"),
            ("Server Message Block 1.0", "mrxsmb10"),
        ];

        for (service_name, service_key) in risky_services {
            let output = Command::new("sc")
                .args(&["query", service_key])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    if output_str.contains("RUNNING") {
                        findings.push(SecurityFinding {
                            id: format!("risky_service_{}", service_key),
                            severity: "Medium".to_string(),
                            title: format!("Risky service running: {}", service_name),
                            description: format!("The {} service is running and may pose security risks", service_name),
                            category: "Service Security".to_string(),
                            cve_id: None,
                            affected_component: service_name.to_string(),
                            remediation: format!("Consider disabling {} if not required", service_name),
                            confidence: 0.8,
                        });
                    }
                }
            }
        }

        Ok(findings)
    }

    pub async fn scan_pii_exposure(&mut self) -> Result<ScanResults> {
        // Implementation for PII scanning would go here
        // This would scan for credit card numbers, SSNs, email addresses, etc.
        Ok(ScanResults {
            scan_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            scan_type: "pii".to_string(),
            findings: Vec::new(),
            system_info: SystemInfo::new(),
            scan_duration_ms: 0,
        })
    }

    pub async fn scan_misconfigurations(&mut self) -> Result<ScanResults> {
        // Implementation for configuration scanning would go here
        Ok(ScanResults {
            scan_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            scan_type: "configuration".to_string(),
            findings: Vec::new(),
            system_info: SystemInfo::new(),
            scan_duration_ms: 0,
        })
    }

    pub async fn apply_security_patch(&mut self, patch_id: &str, kb_article: &str) -> Result<()> {
        info!("Applying security patch: {} ({})", patch_id, kb_article);
        
        #[cfg(windows)]
        {
            // Use Windows Update PowerShell cmdlets to install specific updates
            let output = Command::new("powershell")
                .args(&[
                    "-Command",
                    &format!("Install-WindowsUpdate -KBArticleID {} -AcceptAll -AutoReboot", kb_article)
                ])
                .output()
                .context("Failed to install Windows update")?;

            if !output.status.success() {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow::anyhow!("Patch installation failed: {}", error_msg));
            }
        }

        info!("Patch {} applied successfully", patch_id);
        Ok(())
    }

    fn is_vulnerable_software(&self, software: &InstalledSoftware) -> bool {
        // Known vulnerable software patterns
        let vulnerable_patterns = [
            ("Adobe Flash Player", Some("32.0.0.0")), // Old Flash versions
            ("Java", Some("8.0.0")), // Old Java versions
            ("Google Chrome", Some("100.0.0")), // Very old Chrome
        ];

        for (pattern, max_version) in vulnerable_patterns {
            if software.name.contains(pattern) {
                if let (Some(installed_version), Some(max_safe)) = (&software.version, max_version) {
                    if installed_version < max_safe {
                        return true;
                    }
                }
            }
        }

        false
    }
}

#[derive(Debug, Deserialize)]
struct InstalledSoftware {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Version")]
    version: Option<String>,
    #[serde(rename = "Vendor")]
    vendor: Option<String>,
}

// Unix implementations would be similar but use different system commands
#[cfg(unix)]
impl SecurityScanner {
    async fn scan_installed_software(&self) -> Result<Vec<SecurityFinding>> {
        // Use dpkg, rpm, or pacman depending on the distribution
        Ok(Vec::new())
    }

    async fn scan_windows_updates(&self) -> Result<Vec<SecurityFinding>> {
        // Check for available system updates using package managers
        Ok(Vec::new())
    }

    async fn scan_network_configuration(&self) -> Result<Vec<SecurityFinding>> {
        // Use iptables, ufw, or firewalld to check firewall status
        Ok(Vec::new())
    }

    async fn scan_user_accounts(&self) -> Result<Vec<SecurityFinding>> {
        // Check /etc/passwd, /etc/shadow for weak configurations
        Ok(Vec::new())
    }

    async fn scan_services(&self) -> Result<Vec<SecurityFinding>> {
        // Use systemctl or service command to check running services
        Ok(Vec::new())
    }
}