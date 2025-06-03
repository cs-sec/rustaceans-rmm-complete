use sqlx::{PgPool, Row};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VulnerabilityRecord {
    pub id: Uuid,
    pub cve_id: String,
    pub severity: String,
    pub description: String,
    pub affected_packages: Vec<String>,
    pub affected_versions: Vec<String>,
    pub fixed_versions: Vec<String>,
    pub published_date: DateTime<Utc>,
    pub patch_available: bool,
    pub patch_source: Option<String>,
    pub patch_command: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ClientRecord {
    pub id: Uuid,
    pub hostname: String,
    pub ip_address: String,
    pub operating_system: String,
    pub os_version: String,
    pub last_seen: DateTime<Utc>,
    pub status: String,
    pub agent_version: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScanResult {
    pub id: Uuid,
    pub client_id: Uuid,
    pub scan_type: String,
    pub findings: serde_json::Value,
    pub severity_summary: serde_json::Value,
    pub scan_duration: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchRecommendation {
    pub id: Uuid,
    pub client_id: Uuid,
    pub package_name: String,
    pub current_version: String,
    pub target_version: String,
    pub vulnerability_ids: Vec<String>,
    pub severity_level: String,
    pub update_command: String,
    pub requires_reboot: bool,
    pub estimated_downtime: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub struct DatabaseManager {
    pool: PgPool,
}

impl DatabaseManager {
    pub async fn new() -> Result<Self, sqlx::Error> {
        let database_url = env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set");
        
        let pool = PgPool::connect(&database_url).await?;
        
        let manager = Self { pool };
        manager.initialize_schema().await?;
        manager.seed_initial_data().await?;
        
        Ok(manager)
    }

    async fn initialize_schema(&self) -> Result<(), sqlx::Error> {
        // Create vulnerabilities table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                cve_id VARCHAR(50) UNIQUE NOT NULL,
                severity VARCHAR(20) NOT NULL,
                description TEXT NOT NULL,
                affected_packages TEXT[] NOT NULL,
                affected_versions TEXT[] NOT NULL,
                fixed_versions TEXT[] NOT NULL,
                published_date TIMESTAMPTZ NOT NULL,
                patch_available BOOLEAN NOT NULL DEFAULT false,
                patch_source VARCHAR(50),
                patch_command TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        "#).execute(&self.pool).await?;

        // Create clients table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS clients (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                hostname VARCHAR(255) NOT NULL UNIQUE,
                ip_address INET NOT NULL,
                operating_system VARCHAR(100) NOT NULL,
                os_version VARCHAR(100) NOT NULL,
                last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                status VARCHAR(50) NOT NULL DEFAULT 'active',
                agent_version VARCHAR(50) NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        "#).execute(&self.pool).await?;

        // Create scan_results table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS scan_results (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
                scan_type VARCHAR(100) NOT NULL,
                findings JSONB NOT NULL,
                severity_summary JSONB NOT NULL,
                scan_duration INTEGER NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        "#).execute(&self.pool).await?;

        // Create patch_recommendations table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS patch_recommendations (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
                package_name VARCHAR(255) NOT NULL,
                current_version VARCHAR(100) NOT NULL,
                target_version VARCHAR(100) NOT NULL,
                vulnerability_ids TEXT[] NOT NULL,
                severity_level VARCHAR(20) NOT NULL,
                update_command TEXT NOT NULL,
                requires_reboot BOOLEAN NOT NULL DEFAULT false,
                estimated_downtime VARCHAR(50),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        "#).execute(&self.pool).await?;

        // Create indexes for performance
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve_id)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_clients_hostname ON clients(hostname)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_results_client ON scan_results(client_id)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_results_created ON scan_results(created_at)")
            .execute(&self.pool).await?;

        Ok(())
    }

    async fn seed_initial_data(&self) -> Result<(), sqlx::Error> {
        // Check if data already exists
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vulnerabilities")
            .fetch_one(&self.pool).await?;
        
        if count > 0 {
            return Ok(()); // Data already seeded
        }

        // Insert real vulnerability data
        let vulnerabilities = vec![
            (
                "CVE-2024-0517",
                "High",
                "Out of bounds write in V8 in Google Chrome prior to 121.0.6167.85",
                vec!["google-chrome", "chromium"],
                vec!["< 121.0.6167.85"],
                vec!["121.0.6167.85", "121.0.6167.139"],
                "chocolatey",
                "choco upgrade googlechrome -y"
            ),
            (
                "CVE-2024-0741",
                "Critical",
                "Out of bounds write in ANGLE in Firefox before 122.0",
                vec!["firefox", "mozilla-firefox"],
                vec!["< 122.0"],
                vec!["122.0", "122.0.1"],
                "chocolatey",
                "choco upgrade firefox -y"
            ),
            (
                "CVE-2023-5678",
                "High",
                "Generating excessively long X9.42 DH keys or checking excessively long X9.42 DH keys or parameters may be very slow",
                vec!["openssl", "libssl-dev"],
                vec!["< 3.0.12", "< 1.1.1w"],
                vec!["3.0.12", "1.1.1w"],
                "apt",
                "sudo apt update && sudo apt upgrade openssl -y"
            ),
            (
                "CVE-2024-21334",
                "Critical",
                "Windows Authentication Elevation of Privilege Vulnerability",
                vec!["windows", "microsoft-windows"],
                vec!["Windows 10", "Windows 11", "Windows Server 2019"],
                vec!["KB5034441"],
                "windows-update",
                "Install-WindowsUpdate -AcceptAll -AutoReboot"
            ),
        ];

        for (cve_id, severity, description, packages, affected_versions, fixed_versions, patch_source, patch_command) in vulnerabilities {
            sqlx::query(r#"
                INSERT INTO vulnerabilities 
                (cve_id, severity, description, affected_packages, affected_versions, fixed_versions, published_date, patch_available, patch_source, patch_command)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (cve_id) DO NOTHING
            "#)
            .bind(cve_id)
            .bind(severity)
            .bind(description)
            .bind(packages)
            .bind(affected_versions)
            .bind(fixed_versions)
            .bind(Utc::now())
            .bind(true)
            .bind(patch_source)
            .bind(patch_command)
            .execute(&self.pool).await?;
        }

        // Insert sample clients
        let clients = vec![
            ("DESKTOP-PROD001", "192.168.1.100", "Windows", "10.0.19041", "2.1.0"),
            ("UBUNTU-WEB01", "192.168.1.101", "Linux", "Ubuntu 22.04", "2.1.0"),
            ("MACBOOK-DEV01", "192.168.1.102", "macOS", "13.2.1", "2.1.0"),
        ];

        for (hostname, ip, os, version, agent_version) in clients {
            sqlx::query(r#"
                INSERT INTO clients (hostname, ip_address, operating_system, os_version, agent_version, status)
                VALUES ($1, $2::inet, $3, $4, $5, 'active')
                ON CONFLICT (hostname) DO NOTHING
            "#)
            .bind(hostname)
            .bind(ip)
            .bind(os)
            .bind(version)
            .bind(agent_version)
            .execute(&self.pool).await?;
        }

        Ok(())
    }

    pub async fn get_all_vulnerabilities(&self) -> Result<Vec<VulnerabilityRecord>, sqlx::Error> {
        sqlx::query_as::<_, VulnerabilityRecord>(
            "SELECT * FROM vulnerabilities ORDER BY severity DESC, published_date DESC"
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_vulnerabilities_by_package(&self, package_name: &str) -> Result<Vec<VulnerabilityRecord>, sqlx::Error> {
        sqlx::query_as::<_, VulnerabilityRecord>(
            "SELECT * FROM vulnerabilities WHERE $1 = ANY(affected_packages)"
        )
        .bind(package_name)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_all_clients(&self) -> Result<Vec<ClientRecord>, sqlx::Error> {
        sqlx::query_as::<_, ClientRecord>(
            "SELECT * FROM clients ORDER BY last_seen DESC"
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn update_client_status(&self, client_id: Uuid, status: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE clients SET status = $1, last_seen = NOW() WHERE id = $2"
        )
        .bind(status)
        .bind(client_id)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }

    pub async fn insert_scan_result(&self, client_id: Uuid, scan_type: &str, findings: &serde_json::Value, severity_summary: &serde_json::Value, scan_duration: i32) -> Result<Uuid, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO scan_results (client_id, scan_type, findings, severity_summary, scan_duration) VALUES ($1, $2, $3, $4, $5) RETURNING id"
        )
        .bind(client_id)
        .bind(scan_type)
        .bind(findings)
        .bind(severity_summary)
        .bind(scan_duration)
        .fetch_one(&self.pool)
        .await?;

        Ok(result.get("id"))
    }

    pub async fn get_recent_scan_results(&self, limit: i64) -> Result<Vec<ScanResult>, sqlx::Error> {
        sqlx::query_as::<_, ScanResult>(
            "SELECT * FROM scan_results ORDER BY created_at DESC LIMIT $1"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn generate_patch_recommendations(&self) -> Result<Vec<PatchRecommendation>, sqlx::Error> {
        // This would normally analyze installed packages vs vulnerabilities
        // For now, return sample recommendations based on vulnerability data
        let vulnerabilities = self.get_all_vulnerabilities().await?;
        let clients = self.get_all_clients().await?;
        
        let mut recommendations = Vec::new();
        
        for client in clients.iter().take(1) { // Just first client for demo
            for vuln in vulnerabilities.iter().take(3) { // Top 3 vulnerabilities
                if !vuln.affected_packages.is_empty() {
                    let package_name = &vuln.affected_packages[0];
                    let target_version = vuln.fixed_versions.first()
                        .unwrap_or(&"latest".to_string()).clone();
                    
                    let recommendation = PatchRecommendation {
                        id: Uuid::new_v4(),
                        client_id: client.id,
                        package_name: package_name.clone(),
                        current_version: "vulnerable".to_string(),
                        target_version,
                        vulnerability_ids: vec![vuln.cve_id.clone()],
                        severity_level: vuln.severity.clone(),
                        update_command: vuln.patch_command.clone().unwrap_or_default(),
                        requires_reboot: package_name.contains("windows") || package_name.contains("kernel"),
                        estimated_downtime: if package_name.contains("windows") { 
                            Some("5-10 minutes".to_string()) 
                        } else { 
                            None 
                        },
                        created_at: Utc::now(),
                    };
                    
                    recommendations.push(recommendation);
                }
            }
        }
        
        Ok(recommendations)
    }

    pub async fn get_vulnerability_summary(&self) -> Result<serde_json::Value, sqlx::Error> {
        let total_vulns: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vulnerabilities")
            .fetch_one(&self.pool).await?;
        
        let critical_vulns: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'Critical'")
            .fetch_one(&self.pool).await?;
        
        let high_vulns: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'High'")
            .fetch_one(&self.pool).await?;
        
        let patch_available: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vulnerabilities WHERE patch_available = true")
            .fetch_one(&self.pool).await?;

        Ok(serde_json::json!({
            "total_vulnerabilities": total_vulns,
            "critical_patches": critical_vulns,
            "high_priority_patches": high_vulns,
            "patches_available": patch_available,
            "scan_timestamp": Utc::now().to_rfc3339()
        }))
    }
}