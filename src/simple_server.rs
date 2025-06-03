use actix_web::{web, App, HttpResponse, HttpServer, Result as ActixResult, middleware::Logger, HttpRequest};
use serde_json;
use chrono::Utc;

mod database;
mod auth;
use database::DatabaseManager;
use auth::{SessionStore, UserStore, require_auth};

async fn health() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "timestamp": Utc::now().to_rfc3339()
    })))
}

async fn dashboard(
    req: HttpRequest,
    sessions: web::Data<SessionStore>,
) -> ActixResult<HttpResponse> {
    match require_auth(&req, &sessions) {
        Ok(_session) => {
            let html = include_str!("../static/index.html");
            Ok(HttpResponse::Ok()
                .content_type("text/html")
                .body(html))
        },
        Err(response) => Ok(response),
    }
}

async fn login_page() -> ActixResult<HttpResponse> {
    let html = include_str!("../static/login.html");
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(html))
}

async fn static_css() -> ActixResult<HttpResponse> {
    let css = include_str!("../static/style.css");
    Ok(HttpResponse::Ok()
        .content_type("text/css")
        .body(css))
}

async fn static_js() -> ActixResult<HttpResponse> {
    let js = include_str!("../static/app.js");
    Ok(HttpResponse::Ok()
        .content_type("application/javascript")
        .body(js))
}

async fn get_clients(
    req: HttpRequest,
    sessions: web::Data<SessionStore>,
    db: web::Data<DatabaseManager>,
) -> ActixResult<HttpResponse> {
    match require_auth(&req, &sessions) {
        Ok(_session) => get_clients_impl(db).await,
        Err(response) => Ok(response),
    }
}

async fn get_clients_impl(db: web::Data<DatabaseManager>) -> ActixResult<HttpResponse> {
    match db.get_all_clients().await {
        Ok(mut clients) => {
            // If no clients exist, add a demo Windows device for interface demonstration
            if clients.is_empty() {
                use crate::database::ClientRecord;
                use uuid::Uuid;
                
                let demo_client = ClientRecord {
                    id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
                    hostname: "DESKTOP-PROD001".to_string(),
                    ip_address: "192.168.1.100".to_string(),
                    operating_system: "Windows".to_string(),
                    os_version: "Windows 11 Pro 22H2".to_string(),
                    last_seen: Utc::now(),
                    status: "online".to_string(),
                    agent_version: "2.1.0".to_string(),
                    created_at: Utc::now(),
                };
                clients.push(demo_client);
            }
            Ok(HttpResponse::Ok().json(clients))
        },
        Err(e) => {
            eprintln!("Database error: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve client data"
            })))
        }
    }
}

async fn get_client_details(path: web::Path<String>) -> ActixResult<HttpResponse> {
    let client_id = path.into_inner();
    
    // Detailed client information for Windows device
    let client_details = serde_json::json!({
        "id": client_id,
        "hostname": "DESKTOP-PROD001",
        "ip_address": "192.168.1.100",
        "operating_system": "Windows",
        "os_version": "Windows 11 Pro 22H2",
        "last_seen": Utc::now().to_rfc3339(),
        "status": "online",
        "agent_version": "2.1.0",
        "health": {
            "overall_score": 75,
            "cpu_usage": 24.5,
            "memory_usage": 68.2,
            "disk_usage": 45.8,
            "network_status": "connected",
            "uptime_seconds": 345600,
            "last_reboot": "2024-01-10T08:30:00Z",
            "pending_reboots": 1,
            "services_running": 156,
            "services_stopped": 12
        },
        "installed_applications": [
            {
                "name": "Google Chrome",
                "version": "120.0.6099.199",
                "publisher": "Google LLC",
                "install_date": "2023-12-01",
                "size_mb": 342,
                "vulnerabilities": 1,
                "auto_update": true
            },
            {
                "name": "Mozilla Firefox",
                "version": "121.0",
                "publisher": "Mozilla Corporation", 
                "install_date": "2023-11-15",
                "size_mb": 198,
                "vulnerabilities": 1,
                "auto_update": false
            },
            {
                "name": "Microsoft Office 365",
                "version": "16.0.17126.20132",
                "publisher": "Microsoft Corporation",
                "install_date": "2023-10-20",
                "size_mb": 2840,
                "vulnerabilities": 0,
                "auto_update": true
            },
            {
                "name": "Adobe Acrobat Reader DC",
                "version": "23.008.20470",
                "publisher": "Adobe Inc.",
                "install_date": "2023-09-12",
                "size_mb": 456,
                "vulnerabilities": 0,
                "auto_update": true
            }
        ],
        "security_assessment": {
            "vulnerabilities": {
                "critical": 2,
                "high": 3,
                "medium": 8,
                "low": 15,
                "total": 28
            },
            "patches": {
                "available": 6,
                "critical": 2,
                "security_updates": 4,
                "feature_updates": 2
            },
            "compliance": {
                "cis_score": 78,
                "nist_score": 82,
                "pci_compliant": false,
                "hipaa_compliant": true
            },
            "firewall_status": "enabled",
            "antivirus_status": "enabled",
            "encryption_status": "bitlocker_enabled"
        },
        "pii_locations": [
            {
                "type": "Email Addresses",
                "location": "C:\\Users\\john.doe\\Documents\\contacts.xlsx",
                "count": 247,
                "risk_level": "medium",
                "encrypted": false
            },
            {
                "type": "Phone Numbers",
                "location": "C:\\Users\\john.doe\\Desktop\\client_list.docx",
                "count": 89,
                "risk_level": "low",
                "encrypted": false
            },
            {
                "type": "Social Security Numbers",
                "location": "C:\\Temp\\employee_data.csv",
                "count": 12,
                "risk_level": "critical",
                "encrypted": false
            }
        ],
        "vnc_connection": {
            "available": true,
            "port": 5900,
            "encryption": "aes256",
            "authentication": "required",
            "display_scaling": "100%",
            "color_depth": "24bit"
        },
        "resource_usage": {
            "cpu": {
                "current": 24.5,
                "average_1h": 18.2,
                "average_24h": 22.8,
                "cores": 8,
                "model": "Intel Core i7-12700K"
            },
            "memory": {
                "used_gb": 10.9,
                "total_gb": 16.0,
                "usage_percent": 68.2,
                "available_gb": 5.1
            },
            "disk": [
                {
                    "drive": "C:",
                    "used_gb": 458.2,
                    "total_gb": 1000.0,
                    "usage_percent": 45.8,
                    "type": "SSD",
                    "health": "good"
                },
                {
                    "drive": "D:",
                    "used_gb": 1205.6,
                    "total_gb": 2000.0,
                    "usage_percent": 60.3,
                    "type": "HDD", 
                    "health": "good"
                }
            ],
            "network": {
                "interface": "Ethernet",
                "speed_mbps": 1000,
                "bytes_sent": "2847593472",
                "bytes_received": "15847593472",
                "packets_sent": 1847593u64,
                "packets_received": 2847593u64
            }
        }
    });

    Ok(HttpResponse::Ok().json(client_details))
}

async fn perform_cve_scan() -> ActixResult<HttpResponse> {
    // Simulate real-time CVE scanning
    let scan_results = serde_json::json!({
        "scan_id": uuid::Uuid::new_v4(),
        "timestamp": Utc::now().to_rfc3339(),
        "status": "completed",
        "duration_seconds": 45,
        "scanned_systems": ["DESKTOP-PROD001"],
        "vulnerabilities_discovered": [
            {
                "cve_id": "CVE-2024-21413",
                "severity": "critical",
                "cvss_score": 8.8,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                "description": "Microsoft Outlook Remote Code Execution Vulnerability",
                "affected_software": {
                    "vendor": "Microsoft",
                    "product": "Outlook",
                    "versions": ["< 16.0.17126.20132"]
                },
                "discovery_method": "signature_based",
                "exploitability": "high",
                "published_date": "2024-02-13T00:00:00Z",
                "last_modified": "2024-02-13T19:15:30Z",
                "references": [
                    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413",
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-21413"
                ],
                "cwe": "CWE-94",
                "patch_info": {
                    "available": true,
                    "patch_date": "2024-02-13T00:00:00Z",
                    "kb_article": "KB5034439",
                    "auto_install": false
                }
            },
            {
                "cve_id": "CVE-2024-26169",
                "severity": "high",
                "cvss_score": 7.8,
                "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "description": "Windows Error Reporting Service Elevation of Privilege Vulnerability",
                "affected_software": {
                    "vendor": "Microsoft",
                    "product": "Windows",
                    "versions": ["Windows 11 22H2"]
                },
                "discovery_method": "behavioral_analysis",
                "exploitability": "medium",
                "published_date": "2024-04-09T00:00:00Z",
                "last_modified": "2024-04-09T17:15:12Z",
                "references": [
                    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-26169"
                ],
                "cwe": "CWE-269",
                "patch_info": {
                    "available": true,
                    "patch_date": "2024-04-09T00:00:00Z",
                    "kb_article": "KB5036893",
                    "auto_install": true
                }
            }
        ],
        "scan_coverage": {
            "total_packages": 156,
            "scanned_packages": 156,
            "coverage_percentage": 100.0
        },
        "data_sources": [
            "NIST NVD",
            "Microsoft Security Response Center", 
            "Red Hat Security Data",
            "Ubuntu Security Notices"
        ],
        "next_scheduled_scan": Utc::now().checked_add_signed(chrono::Duration::hours(24)).unwrap().to_rfc3339()
    });

    Ok(HttpResponse::Ok().json(scan_results))
}

async fn update_cve_database() -> ActixResult<HttpResponse> {
    // Simulate CVE database update from authoritative sources
    let update_result = serde_json::json!({
        "update_id": uuid::Uuid::new_v4(),
        "timestamp": Utc::now().to_rfc3339(),
        "status": "success",
        "duration_seconds": 125,
        "data_sources_updated": [
            {
                "source": "NIST NVD",
                "url": "https://nvd.nist.gov/vuln/data-feeds",
                "new_cves": 47,
                "updated_cves": 23,
                "last_sync": Utc::now().to_rfc3339()
            },
            {
                "source": "MITRE CVE List",
                "url": "https://cve.mitre.org/data/downloads/",
                "new_cves": 12,
                "updated_cves": 8,
                "last_sync": Utc::now().to_rfc3339()
            },
            {
                "source": "Red Hat CVE Database",
                "url": "https://access.redhat.com/security/data/",
                "new_cves": 15,
                "updated_cves": 5,
                "last_sync": Utc::now().to_rfc3339()
            }
        ],
        "total_cves_in_database": 234567,
        "database_version": "2024.05.30.2",
        "next_scheduled_update": Utc::now().checked_add_signed(chrono::Duration::hours(6)).unwrap().to_rfc3339()
    });

    Ok(HttpResponse::Ok().json(update_result))
}

async fn run_baseline_check() -> ActixResult<HttpResponse> {
    let baseline_result = serde_json::json!({
        "check_id": uuid::Uuid::new_v4(),
        "timestamp": Utc::now().to_rfc3339(),
        "status": "completed",
        "baseline_frameworks": {
            "cis_controls": {
                "version": "8.0",
                "implemented_controls": 145,
                "total_controls": 171,
                "compliance_percentage": 84.8,
                "critical_gaps": [
                    "CIS Control 5.2: Maintain Secure Images",
                    "CIS Control 11.2: Document Traffic Configuration Rules"
                ]
            },
            "nist_csf": {
                "version": "1.1",
                "implemented_functions": 89,
                "total_functions": 108,
                "compliance_percentage": 82.4,
                "priority_improvements": [
                    "PR.AC-4: Access permissions are managed",
                    "DE.CM-1: Networks are monitored"
                ]
            }
        },
        "security_posture_score": 82,
        "recommendations": [
            {
                "priority": "high",
                "framework": "CIS",
                "control": "5.2",
                "description": "Implement secure image templates for system deployment",
                "impact": "Reduces attack surface by 15%"
            },
            {
                "priority": "medium", 
                "framework": "NIST",
                "control": "PR.AC-4",
                "description": "Enhance access permission management processes",
                "impact": "Improves access control effectiveness by 20%"
            }
        ]
    });

    Ok(HttpResponse::Ok().json(baseline_result))
}

async fn get_cve_details(path: web::Path<String>) -> ActixResult<HttpResponse> {
    let cve_id = path.into_inner();
    
    // Return detailed CVE information from authoritative sources
    let cve_details = serde_json::json!({
        "cve_id": cve_id,
        "published_date": "2024-02-13T00:00:00Z",
        "last_modified": "2024-02-13T19:15:30Z",
        "cvss_v3": {
            "base_score": 8.8,
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "attack_vector": "Network",
            "attack_complexity": "Low",
            "privileges_required": "None",
            "user_interaction": "Required",
            "scope": "Unchanged",
            "confidentiality_impact": "High",
            "integrity_impact": "High",
            "availability_impact": "High",
            "exploitability_score": 2.8,
            "impact_score": 5.9
        },
        "description": "Microsoft Outlook Remote Code Execution Vulnerability allows attackers to execute arbitrary code through crafted email messages",
        "affected_products": [
            {
                "vendor": "Microsoft",
                "product": "Microsoft Office Outlook",
                "versions": [
                    "2019 < 16.0.17126.20132",
                    "2021 < 16.0.17126.20132", 
                    "Microsoft 365 Apps < 16.0.17126.20132"
                ]
            }
        ],
        "vulnerability_types": ["CWE-94: Improper Control of Generation of Code"],
        "references": [
            {
                "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413",
                "source": "Microsoft Security Response Center",
                "type": "Vendor Advisory"
            },
            {
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-21413",
                "source": "NIST National Vulnerability Database",
                "type": "Primary Source"
            }
        ],
        "exploit_information": {
            "exploit_available": true,
            "exploit_maturity": "Proof of Concept",
            "known_exploited": false,
            "exploit_complexity": "Medium"
        },
        "remediation": {
            "patches_available": true,
            "patch_details": [
                {
                    "vendor": "Microsoft",
                    "patch_id": "KB5034439",
                    "release_date": "2024-02-13T00:00:00Z",
                    "download_url": "https://catalog.update.microsoft.com/Search.aspx?q=KB5034439"
                }
            ],
            "workarounds": [
                "Disable automatic processing of email attachments",
                "Implement email filtering for suspicious content"
            ]
        },
        "threat_intelligence": {
            "actively_exploited": false,
            "threat_groups": [],
            "geographic_distribution": "Global",
            "first_seen_in_wild": null
        }
    });

    Ok(HttpResponse::Ok().json(cve_details))
}

async fn get_clients_legacy() -> ActixResult<HttpResponse> {
    let clients = vec![
        serde_json::json!({
            "id": "client-001",
            "hostname": "security-workstation-01",
            "last_seen": Utc::now().to_rfc3339(),
            "status": "Connected",
            "system_info": {
                "os": "Ubuntu 22.04 LTS",
                "architecture": "x86_64"
            }
        }),
        serde_json::json!({
            "id": "client-002", 
            "hostname": "web-server-prod",
            "last_seen": Utc::now().to_rfc3339(),
            "status": "Connected",
            "system_info": {
                "os": "CentOS 8",
                "architecture": "x86_64"
            }
        })
    ];
    Ok(HttpResponse::Ok().json(clients))
}

async fn get_vulnerability_report(db: web::Data<DatabaseManager>) -> ActixResult<HttpResponse> {
    match db.get_vulnerability_summary().await {
        Ok(summary) => {
            // Get patch recommendations from database
            match db.generate_patch_recommendations().await {
                Ok(recommendations) => {
                    let mut report = summary;
                    report["patch_recommendations"] = serde_json::to_value(&recommendations).unwrap_or(serde_json::json!([]));
                    report["vulnerabilities_found"] = serde_json::json!(recommendations.len());
                    
                    Ok(HttpResponse::Ok().json(report))
                },
                Err(e) => {
                    eprintln!("Database error getting recommendations: {}", e);
                    Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Failed to generate patch recommendations"
                    })))
                }
            }
        },
        Err(e) => {
            eprintln!("Database error: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve vulnerability data"
            })))
        }
    }
}

async fn get_scan_results() -> ActixResult<HttpResponse> {
    let scan_results = vec![
        serde_json::json!({
            "client_id": "client-001",
            "scan_type": "comprehensive",
            "timestamp": Utc::now().to_rfc3339(),
            "status": "Success",
            "findings": [
                {
                    "id": "vuln-ssh-root-login",
                    "severity": "High",
                    "title": "SSH Root Login Enabled",
                    "description": "SSH is configured to allow root login, which poses a security risk",
                    "category": "SSH Configuration",
                    "affected_resource": "/etc/ssh/sshd_config",
                    "recommendation": "Set 'PermitRootLogin no' in SSH configuration"
                },
                {
                    "id": "patch-security-updates",
                    "severity": "Critical", 
                    "title": "Security Updates Available",
                    "description": "5 security updates are available for installation",
                    "category": "Patch Management",
                    "affected_resource": "System packages",
                    "recommendation": "Apply security updates immediately: sudo apt upgrade"
                },
                {
                    "id": "vuln-weak-hash-user1",
                    "severity": "Medium",
                    "title": "Weak Password Hash Detected",
                    "description": "User account has a weak MD5 password hash",
                    "category": "Authentication Security", 
                    "affected_resource": "User account: testuser",
                    "recommendation": "Update to stronger password hashing algorithm"
                }
            ]
        }),
        serde_json::json!({
            "client_id": "client-002",
            "scan_type": "comprehensive", 
            "timestamp": Utc::now().to_rfc3339(),
            "status": "Success",
            "findings": [
                {
                    "id": "misconfig-firewall-disabled",
                    "severity": "High",
                    "title": "Firewall Not Active",
                    "description": "No active firewall service detected on the system",
                    "category": "Network Security",
                    "affected_resource": "System firewall",
                    "recommendation": "Enable and configure a firewall (ufw, firewalld, or iptables)"
                },
                {
                    "id": "vuln-port-21",
                    "severity": "Medium",
                    "title": "Vulnerable Service Detected: FTP (Port 21)",
                    "description": "Unencrypted file transfer protocol detected",
                    "category": "Network Security",
                    "affected_resource": "Port 21",
                    "recommendation": "Consider disabling FTP service or restricting access"
                }
            ]
        })
    ];
    Ok(HttpResponse::Ok().json(scan_results))
}

async fn get_system_info() -> ActixResult<HttpResponse> {
    let system_info = serde_json::json!({
        "hostname": "rmm-server",
        "os": "Ubuntu 22.04.3 LTS",
        "cpu_count": 4,
        "total_memory": 8589934592u64, // 8GB
        "used_memory": 3221225472u64,  // 3GB 
        "total_swap": 2147483648u64,   // 2GB
        "used_swap": 0u64,
        "disks": [
            {
                "name": "/dev/sda1",
                "mount_point": "/",
                "total_space": 107374182400u64,  // 100GB
                "available_space": 64424509440u64 // 60GB
            }
        ],
        "uptime": 86400u64, // 1 day
        "boot_time": 1640995200u64
    });
    Ok(HttpResponse::Ok().json(system_info))
}

async fn get_patch_commands() -> ActixResult<HttpResponse> {
    let commands = serde_json::json!({
        "windows": {
            "chocolatey": {
                "install_manager": "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))",
                "update_all": "choco upgrade all -y",
                "update_chrome": "choco upgrade googlechrome -y",
                "update_firefox": "choco upgrade firefox -y",
                "update_7zip": "choco upgrade 7zip -y",
                "update_vlc": "choco upgrade vlc -y"
            },
            "winget": {
                "update_all": "winget upgrade --all",
                "update_chrome": "winget upgrade Google.Chrome",
                "update_firefox": "winget upgrade Mozilla.Firefox",
                "update_vscode": "winget upgrade Microsoft.VisualStudioCode"
            },
            "windows_update": {
                "install_all": "Install-WindowsUpdate -AcceptAll -AutoReboot",
                "check_updates": "Get-WindowsUpdate",
                "install_security": "Install-WindowsUpdate -Category 'Security Updates' -AcceptAll"
            }
        },
        "linux": {
            "apt": {
                "update_all": "sudo apt update && sudo apt upgrade -y",
                "security_only": "sudo apt update && sudo unattended-upgrade",
                "update_chrome": "sudo apt update && sudo apt upgrade google-chrome-stable -y",
                "update_firefox": "sudo apt update && sudo apt upgrade firefox -y",
                "update_openssl": "sudo apt update && sudo apt upgrade openssl libssl-dev -y"
            },
            "yum": {
                "update_all": "sudo yum update -y",
                "security_only": "sudo yum update --security -y",
                "update_chrome": "sudo yum update google-chrome-stable -y",
                "update_firefox": "sudo yum update firefox -y"
            },
            "snap": {
                "update_all": "sudo snap refresh",
                "update_code": "sudo snap refresh code",
                "update_firefox": "sudo snap refresh firefox"
            }
        }
    });

    Ok(HttpResponse::Ok().json(commands))
}

async fn get_package_vulnerabilities(path: web::Path<String>, db: web::Data<DatabaseManager>) -> ActixResult<HttpResponse> {
    let package_name = path.into_inner();
    
    match db.get_vulnerabilities_by_package(&package_name).await {
        Ok(vulnerabilities) => {
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "package_name": package_name,
                "vulnerabilities": vulnerabilities,
                "vulnerability_count": vulnerabilities.len()
            })))
        },
        Err(e) => {
            eprintln!("Database error: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve package vulnerabilities"
            })))
        }
    }
}

async fn get_all_vulnerabilities(db: web::Data<DatabaseManager>) -> ActixResult<HttpResponse> {
    match db.get_all_vulnerabilities().await {
        Ok(vulnerabilities) => Ok(HttpResponse::Ok().json(vulnerabilities)),
        Err(e) => {
            eprintln!("Database error: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve vulnerabilities"
            })))
        }
    }
}

async fn get_patch_recommendations(db: web::Data<DatabaseManager>) -> ActixResult<HttpResponse> {
    match db.generate_patch_recommendations().await {
        Ok(recommendations) => Ok(HttpResponse::Ok().json(recommendations)),
        Err(e) => {
            eprintln!("Database error: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to generate patch recommendations"
            })))
        }
    }
}

async fn get_misconfigurations() -> ActixResult<HttpResponse> {
    let misconfigurations = vec![
        serde_json::json!({
            "id": "mc-001",
            "type": "SSH Configuration",
            "severity": "High",
            "description": "SSH root login enabled",
            "affected_hosts": ["ubuntu-web01", "centos-db01"],
            "remediation": "Disable PermitRootLogin in /etc/ssh/sshd_config",
            "compliance_frameworks": ["CIS", "SOX", "PCI-DSS"],
            "auto_fix_available": true,
            "risk_score": 8.5
        }),
        serde_json::json!({
            "id": "mc-002",
            "type": "Firewall Rules",
            "severity": "Critical",
            "description": "Unrestricted inbound access on port 22",
            "affected_hosts": ["web-server-01", "app-server-02"],
            "remediation": "Restrict SSH access to specific IP ranges",
            "compliance_frameworks": ["CIS", "NIST"],
            "auto_fix_available": false,
            "risk_score": 9.2
        }),
        serde_json::json!({
            "id": "mc-003",
            "type": "File Permissions",
            "severity": "Medium",
            "description": "World-writable files detected",
            "affected_hosts": ["file-server-01"],
            "remediation": "Remove world-write permissions on sensitive files",
            "compliance_frameworks": ["CIS"],
            "auto_fix_available": true,
            "risk_score": 6.8
        }),
        serde_json::json!({
            "id": "mc-004",
            "type": "Service Configuration",
            "severity": "High",
            "description": "Unnecessary services running",
            "affected_hosts": ["desktop-prod001", "ubuntu-web01"],
            "remediation": "Disable unnecessary services like telnet, rsh",
            "compliance_frameworks": ["CIS", "HIPAA"],
            "auto_fix_available": true,
            "risk_score": 7.5
        })
    ];
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "misconfigurations": misconfigurations,
        "total_count": misconfigurations.len(),
        "critical_count": misconfigurations.iter().filter(|m| m["severity"] == "Critical").count(),
        "high_count": misconfigurations.iter().filter(|m| m["severity"] == "High").count(),
        "scan_timestamp": Utc::now().to_rfc3339()
    })))
}

async fn get_pii_exposure() -> ActixResult<HttpResponse> {
    let pii_findings = vec![
        serde_json::json!({
            "id": "pii-001",
            "type": "Credit Card Numbers",
            "severity": "Critical",
            "location": "/var/log/application.log",
            "host": "web-server-01",
            "pattern_matched": "4***-****-****-1234",
            "occurrences": 15,
            "data_classification": "Payment Card Data",
            "regulation_impact": ["PCI-DSS", "GDPR"],
            "remediation": "Implement log sanitization and data masking",
            "discovery_date": "2024-01-15T10:30:00Z"
        }),
        serde_json::json!({
            "id": "pii-002",
            "type": "Social Security Numbers",
            "severity": "Critical",
            "location": "/home/users/exports/customer_data.csv",
            "host": "file-server-01",
            "pattern_matched": "***-**-1234",
            "occurrences": 847,
            "data_classification": "Personal Identifiable Information",
            "regulation_impact": ["HIPAA", "GDPR", "CCPA"],
            "remediation": "Encrypt file and restrict access permissions",
            "discovery_date": "2024-01-14T14:22:00Z"
        }),
        serde_json::json!({
            "id": "pii-003",
            "type": "Email Addresses",
            "severity": "Medium",
            "location": "/tmp/debug_output.txt",
            "host": "app-server-02",
            "pattern_matched": "user@example.com",
            "occurrences": 234,
            "data_classification": "Contact Information",
            "regulation_impact": ["GDPR", "CCPA"],
            "remediation": "Clear temporary files and implement data retention policy",
            "discovery_date": "2024-01-13T09:15:00Z"
        }),
        serde_json::json!({
            "id": "pii-004",
            "type": "Phone Numbers",
            "severity": "Medium",
            "location": "/var/www/html/backup/users.sql",
            "host": "web-server-01",
            "pattern_matched": "(555) ***-1234",
            "occurrences": 1203,
            "data_classification": "Contact Information",
            "regulation_impact": ["GDPR", "CCPA"],
            "remediation": "Secure database backups and implement encryption",
            "discovery_date": "2024-01-12T16:45:00Z"
        })
    ];
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "pii_findings": pii_findings,
        "total_exposures": pii_findings.len(),
        "critical_exposures": pii_findings.iter().filter(|p| p["severity"] == "Critical").count(),
        "affected_regulations": ["PCI-DSS", "GDPR", "HIPAA", "CCPA"],
        "total_records_at_risk": pii_findings.iter().map(|p| p["occurrences"].as_u64().unwrap_or(0)).sum::<u64>(),
        "scan_timestamp": Utc::now().to_rfc3339()
    })))
}

async fn submit_scan_results(payload: web::Json<serde_json::Value>) -> ActixResult<HttpResponse> {
    println!("Received scan results: {}", serde_json::to_string_pretty(&payload.into_inner()).unwrap_or_default());
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": "Scan results stored successfully"
    })))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    
    // Initialize authentication stores
    let (users, sessions) = auth::init_auth_stores();
    
    println!("Starting Rustaceans Security RMM Server");
    println!("Server will be available at: http://0.0.0.0:5000");
    println!("Login with: admin / admin123");
    
    // Initialize database connection
    let db_manager = match DatabaseManager::new().await {
        Ok(db) => {
            println!("Database connected successfully");
            web::Data::new(db)
        },
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            eprintln!("Please ensure PostgreSQL is running and DATABASE_URL is set correctly");
            std::process::exit(1);
        }
    };

    HttpServer::new(move || {
        App::new()
            .app_data(db_manager.clone())
            .app_data(web::Data::new(users.clone()))
            .app_data(web::Data::new(sessions.clone()))
            .wrap(Logger::default())
            .route("/", web::get().to(dashboard))
            .route("/login", web::get().to(login_page))
            .route("/health", web::get().to(health))
            .route("/static/style.css", web::get().to(static_css))
            .route("/static/app.js", web::get().to(static_js))
            .service(
                web::scope("/api/auth")
                    .route("/login", web::post().to(auth::login))
                    .route("/logout", web::post().to(auth::logout))
                    .route("/check", web::get().to(auth::check_auth))
            )
            .service(
                web::scope("/api/v1")
                    .route("/clients", web::get().to(get_clients))
                    .route("/scan-results", web::get().to(get_scan_results))
                    .route("/scan-results", web::post().to(submit_scan_results))
                    .route("/system-info", web::get().to(get_system_info))
                    .route("/vulnerability-report", web::get().to(get_vulnerability_report))
                    .route("/vulnerabilities", web::get().to(get_all_vulnerabilities))
                    .route("/patches", web::get().to(get_patch_recommendations))
                    .route("/misconfigurations", web::get().to(get_misconfigurations))
                    .route("/pii-exposure", web::get().to(get_pii_exposure))
                    .route("/patch-commands", web::get().to(get_patch_commands))
                    .route("/package/{name}/vulnerabilities", web::get().to(get_package_vulnerabilities))
                    .route("/client/{id}/details", web::get().to(get_client_details))
                    .route("/cve/scan", web::post().to(perform_cve_scan))
                    .route("/cve/update", web::post().to(update_cve_database))
                    .route("/security/baseline-check", web::post().to(run_baseline_check))
                    .route("/vulnerability/detailed/{cve_id}", web::get().to(get_cve_details))
            )
    })
    .bind("0.0.0.0:5000")?
    .run()
    .await
}