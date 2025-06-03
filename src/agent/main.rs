use anyhow::{Context, Result};
use std::time::Duration;
use tokio::time;
use tracing::{error, info, warn};

mod config;
mod scanner;
mod service;
mod system;
mod communication;

use config::AgentConfig;
use scanner::SecurityScanner;
use service::ServiceManager;
use system::SystemInfo;
use communication::ServerConnection;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("rmm_agent=info")
        .init();

    info!("Starting Rustaceans RMM Agent v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = AgentConfig::load().context("Failed to load agent configuration")?;
    
    // Initialize service manager for platform-specific operations
    let service_manager = ServiceManager::new();
    
    // Check if running as service/daemon
    if config.run_as_service {
        info!("Running as system service");
        #[cfg(windows)]
        service_manager.run_service().await?;
        
        #[cfg(unix)]
        service_manager.daemonize().await?;
    } else {
        info!("Running in console mode");
        run_agent(config).await?;
    }

    Ok(())
}

async fn run_agent(config: AgentConfig) -> Result<()> {
    let mut server_connection = ServerConnection::new(config.clone()).await?;
    let mut scanner = SecurityScanner::new(config.clone());
    let system_info = SystemInfo::new();
    
    info!("Agent initialized successfully");
    info!("Server endpoint: {}", config.server_url);
    info!("Agent ID: {}", config.agent_id);

    // Register with server
    if let Err(e) = server_connection.register_agent(&system_info).await {
        error!("Failed to register with server: {}", e);
        return Err(e);
    }

    info!("Successfully registered with RMM server");

    let mut heartbeat_interval = time::interval(Duration::from_secs(config.heartbeat_interval));
    let mut scan_interval = time::interval(Duration::from_secs(config.scan_interval));

    loop {
        tokio::select! {
            _ = heartbeat_interval.tick() => {
                if let Err(e) = server_connection.send_heartbeat(&system_info).await {
                    warn!("Heartbeat failed: {}", e);
                }
            }
            
            _ = scan_interval.tick() => {
                info!("Starting security scan");
                match scanner.perform_comprehensive_scan().await {
                    Ok(scan_results) => {
                        info!("Scan completed: {} findings", scan_results.findings.len());
                        if let Err(e) = server_connection.send_scan_results(scan_results).await {
                            error!("Failed to send scan results: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Security scan failed: {}", e);
                    }
                }
            }

            // Listen for server commands
            command = server_connection.receive_command() => {
                match command {
                    Ok(cmd) => {
                        info!("Received command: {:?}", cmd);
                        if let Err(e) = handle_server_command(cmd, &mut scanner, &system_info).await {
                            error!("Failed to execute command: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("Command reception error: {}", e);
                    }
                }
            }
        }
    }
}

async fn handle_server_command(
    command: communication::ServerCommand,
    scanner: &mut SecurityScanner,
    system_info: &SystemInfo,
) -> Result<()> {
    use communication::ServerCommand;

    match command {
        ServerCommand::RunScan { scan_type } => {
            info!("Running {} scan as requested by server", scan_type);
            let results = match scan_type.as_str() {
                "vulnerability" => scanner.scan_vulnerabilities().await?,
                "pii" => scanner.scan_pii_exposure().await?,
                "configuration" => scanner.scan_misconfigurations().await?,
                _ => scanner.perform_comprehensive_scan().await?,
            };
            Ok(())
        }
        
        ServerCommand::ApplyPatch { patch_id, kb_article } => {
            info!("Applying patch: {} ({})", patch_id, kb_article);
            scanner.apply_security_patch(&patch_id, &kb_article).await?;
            Ok(())
        }
        
        ServerCommand::UpdateAgent { version_url } => {
            info!("Agent update requested: {}", version_url);
            warn!("Agent self-update not yet implemented");
            Ok(())
        }
        
        ServerCommand::GetSystemInfo => {
            info!("System information requested");
            Ok(())
        }
        
        ServerCommand::Shutdown => {
            info!("Shutdown command received");
            std::process::exit(0);
        }
    }
}