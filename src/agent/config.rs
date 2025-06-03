use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub agent_id: Uuid,
    pub server_url: String,
    pub api_key: String,
    pub heartbeat_interval: u64, // seconds
    pub scan_interval: u64,      // seconds
    pub run_as_service: bool,
    pub log_level: String,
    pub data_directory: PathBuf,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_verify_server: bool,
    pub max_retry_attempts: u32,
    pub retry_delay_seconds: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: Uuid::new_v4(),
            server_url: "https://localhost:5000".to_string(),
            api_key: String::new(),
            heartbeat_interval: 60,  // 1 minute
            scan_interval: 3600,     // 1 hour
            run_as_service: true,
            log_level: "info".to_string(),
            data_directory: get_default_data_dir(),
            tls_cert_path: None,
            tls_verify_server: true,
            max_retry_attempts: 3,
            retry_delay_seconds: 30,
        }
    }
}

impl AgentConfig {
    pub fn load() -> Result<Self> {
        let config_path = get_config_path();
        
        if config_path.exists() {
            let config_content = std::fs::read_to_string(&config_path)
                .context("Failed to read config file")?;
            
            let config: AgentConfig = toml::from_str(&config_content)
                .context("Failed to parse config file")?;
            
            Ok(config)
        } else {
            // Create default config file
            let default_config = Self::default();
            default_config.save()?;
            Ok(default_config)
        }
    }
    
    pub fn save(&self) -> Result<()> {
        let config_path = get_config_path();
        
        // Create config directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create config directory")?;
        }
        
        let config_content = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;
        
        std::fs::write(&config_path, config_content)
            .context("Failed to write config file")?;
        
        Ok(())
    }
}

#[cfg(windows)]
fn get_config_path() -> PathBuf {
    let mut path = std::env::var("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData"));
    path.push("RustaceansRMM");
    path.push("agent.toml");
    path
}

#[cfg(unix)]
fn get_config_path() -> PathBuf {
    PathBuf::from("/etc/rustaceans-rmm/agent.toml")
}

#[cfg(windows)]
fn get_default_data_dir() -> PathBuf {
    let mut path = std::env::var("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData"));
    path.push("RustaceansRMM");
    path.push("data");
    path
}

#[cfg(unix)]
fn get_default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/rustaceans-rmm")
}