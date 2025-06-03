use anyhow::{Context, Result};
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::AgentConfig;
use crate::scanner::ScanResults;
use crate::system::SystemInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerCommand {
    RunScan { scan_type: String },
    ApplyPatch { patch_id: String, kb_article: String },
    UpdateAgent { version_url: String },
    GetSystemInfo,
    Shutdown,
}

#[derive(Debug, Serialize)]
struct AgentRegistration {
    agent_id: Uuid,
    hostname: String,
    operating_system: String,
    os_version: String,
    agent_version: String,
    system_info: SystemInfo,
}

#[derive(Debug, Serialize)]
struct HeartbeatData {
    agent_id: Uuid,
    timestamp: chrono::DateTime<chrono::Utc>,
    system_info: SystemInfo,
    status: String,
}

pub struct ServerConnection {
    client: Client,
    config: AgentConfig,
    command_receiver: Option<mpsc::Receiver<ServerCommand>>,
}

impl ServerConnection {
    pub async fn new(config: AgentConfig) -> Result<Self> {
        let mut client_builder = ClientBuilder::new()
            .timeout(Duration::from_secs(30))
            .user_agent(format!("RustaceansRMM-Agent/{}", env!("CARGO_PKG_VERSION")));

        // Configure TLS if specified
        if let Some(cert_path) = &config.tls_cert_path {
            let cert_content = std::fs::read(cert_path)
                .context("Failed to read TLS certificate")?;
            
            let cert = reqwest::Certificate::from_pem(&cert_content)
                .context("Failed to parse TLS certificate")?;
            
            client_builder = client_builder.add_root_certificate(cert);
        }

        if !config.tls_verify_server {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        let client = client_builder.build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            client,
            config,
            command_receiver: None,
        })
    }

    pub async fn register_agent(&mut self, system_info: &SystemInfo) -> Result<()> {
        let registration = AgentRegistration {
            agent_id: self.config.agent_id,
            hostname: system_info.hostname.clone(),
            operating_system: system_info.operating_system.clone(),
            os_version: system_info.os_version.clone(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            system_info: system_info.clone(),
        };

        let url = format!("{}/api/agents/register", self.config.server_url);
        
        for attempt in 1..=self.config.max_retry_attempts {
            match self.client
                .post(&url)
                .header("Authorization", format!("Bearer {}", self.config.api_key))
                .json(&registration)
                .send()
                .await
            {
                Ok(response) => {
                    if response.status().is_success() {
                        info!("Agent registered successfully");
                        return Ok(());
                    } else {
                        let status = response.status();
                        let error_text = response.text().await.unwrap_or_default();
                        warn!("Registration failed with status {}: {}", status, error_text);
                        
                        if status.is_client_error() {
                            return Err(anyhow::anyhow!("Registration failed: {} - {}", status, error_text));
                        }
                    }
                }
                Err(e) => {
                    warn!("Registration attempt {} failed: {}", attempt, e);
                }
            }

            if attempt < self.config.max_retry_attempts {
                tokio::time::sleep(Duration::from_secs(self.config.retry_delay_seconds)).await;
            }
        }

        Err(anyhow::anyhow!("Failed to register agent after {} attempts", self.config.max_retry_attempts))
    }

    pub async fn send_heartbeat(&self, system_info: &SystemInfo) -> Result<()> {
        let heartbeat = HeartbeatData {
            agent_id: self.config.agent_id,
            timestamp: chrono::Utc::now(),
            system_info: system_info.clone(),
            status: "active".to_string(),
        };

        let url = format!("{}/api/agents/{}/heartbeat", self.config.server_url, self.config.agent_id);
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .json(&heartbeat)
            .send()
            .await
            .context("Failed to send heartbeat")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Heartbeat failed: {} - {}", status, error_text));
        }

        Ok(())
    }

    pub async fn send_scan_results(&self, scan_results: ScanResults) -> Result<()> {
        let url = format!("{}/api/agents/{}/scan-results", self.config.server_url, self.config.agent_id);
        
        for attempt in 1..=self.config.max_retry_attempts {
            match self.client
                .post(&url)
                .header("Authorization", format!("Bearer {}", self.config.api_key))
                .json(&scan_results)
                .send()
                .await
            {
                Ok(response) => {
                    if response.status().is_success() {
                        info!("Scan results sent successfully");
                        return Ok(());
                    } else {
                        let status = response.status();
                        let error_text = response.text().await.unwrap_or_default();
                        warn!("Failed to send scan results: {} - {}", status, error_text);
                        
                        if status.is_client_error() {
                            return Err(anyhow::anyhow!("Scan upload failed: {} - {}", status, error_text));
                        }
                    }
                }
                Err(e) => {
                    warn!("Scan upload attempt {} failed: {}", attempt, e);
                }
            }

            if attempt < self.config.max_retry_attempts {
                tokio::time::sleep(Duration::from_secs(self.config.retry_delay_seconds)).await;
            }
        }

        Err(anyhow::anyhow!("Failed to send scan results after {} attempts", self.config.max_retry_attempts))
    }

    pub async fn receive_command(&mut self) -> Result<ServerCommand> {
        // Poll for commands from server
        let url = format!("{}/api/agents/{}/commands", self.config.server_url, self.config.agent_id);
        
        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .send()
            .await
            .context("Failed to poll for commands")?;

        if response.status().is_success() {
            let commands: Vec<ServerCommand> = response.json().await
                .context("Failed to parse server commands")?;
            
            if let Some(command) = commands.into_iter().next() {
                return Ok(command);
            }
        }

        // Return a timeout error if no commands available
        Err(anyhow::anyhow!("No commands available"))
    }

    pub async fn acknowledge_command(&self, command_id: Uuid, success: bool, message: Option<String>) -> Result<()> {
        #[derive(Serialize)]
        struct CommandAck {
            command_id: Uuid,
            agent_id: Uuid,
            success: bool,
            message: Option<String>,
            timestamp: chrono::DateTime<chrono::Utc>,
        }

        let ack = CommandAck {
            command_id,
            agent_id: self.config.agent_id,
            success,
            message,
            timestamp: chrono::Utc::now(),
        };

        let url = format!("{}/api/agents/{}/command-ack", self.config.server_url, self.config.agent_id);
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .json(&ack)
            .send()
            .await
            .context("Failed to acknowledge command")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Command acknowledgment failed: {} - {}", status, error_text));
        }

        Ok(())
    }

    pub async fn check_for_updates(&self) -> Result<Option<String>> {
        let url = format!("{}/api/agents/updates/check", self.config.server_url);
        
        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .query(&[("current_version", env!("CARGO_PKG_VERSION"))])
            .send()
            .await
            .context("Failed to check for updates")?;

        if response.status().is_success() {
            #[derive(Deserialize)]
            struct UpdateInfo {
                update_available: bool,
                latest_version: String,
                download_url: Option<String>,
            }

            let update_info: UpdateInfo = response.json().await
                .context("Failed to parse update information")?;
            
            if update_info.update_available {
                info!("Update available: {}", update_info.latest_version);
                return Ok(update_info.download_url);
            }
        }

        Ok(None)
    }
}