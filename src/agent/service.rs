use anyhow::{Context, Result};
use tracing::{info, error};

#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher, Result as ServiceResult,
};

pub struct ServiceManager;

impl ServiceManager {
    pub fn new() -> Self {
        Self
    }

    #[cfg(windows)]
    pub async fn run_service(&self) -> Result<()> {
        info!("Starting Windows service");
        
        // Register the service main function
        service_dispatcher::start("RustaceansRMMAgent", ffi_service_main)
            .context("Failed to start service dispatcher")?;
        
        Ok(())
    }

    #[cfg(unix)]
    pub async fn daemonize(&self) -> Result<()> {
        use daemonize::Daemonize;
        use std::fs::File;

        info!("Daemonizing process");

        let stdout = File::create("/var/log/rustaceans-rmm-agent.log")
            .context("Failed to create log file")?;
        let stderr = File::create("/var/log/rustaceans-rmm-agent.err")
            .context("Failed to create error log file")?;

        let daemonize = Daemonize::new()
            .pid_file("/var/run/rustaceans-rmm-agent.pid")
            .chown_pid_file(true)
            .working_directory("/var/lib/rustaceans-rmm")
            .user("rmm")
            .group("rmm")
            .stdout(stdout)
            .stderr(stderr)
            .privileged_action(|| "Executed before drop privileges");

        match daemonize.start() {
            Ok(_) => {
                info!("Daemon started successfully");
                Ok(())
            }
            Err(e) => {
                error!("Failed to daemonize: {}", e);
                Err(anyhow::anyhow!("Daemonization failed: {}", e))
            }
        }
    }

    pub async fn install_service(&self) -> Result<()> {
        #[cfg(windows)]
        {
            self.install_windows_service().await
        }

        #[cfg(unix)]
        {
            self.install_systemd_service().await
        }
    }

    pub async fn uninstall_service(&self) -> Result<()> {
        #[cfg(windows)]
        {
            self.uninstall_windows_service().await
        }

        #[cfg(unix)]
        {
            self.uninstall_systemd_service().await
        }
    }

    #[cfg(windows)]
    async fn install_windows_service(&self) -> Result<()> {
        use std::process::Command;
        use std::env;

        let exe_path = env::current_exe()
            .context("Failed to get current executable path")?;

        let output = Command::new("sc")
            .args(&[
                "create",
                "RustaceansRMMAgent",
                "binPath=",
                &format!("\"{}\" --service", exe_path.display()),
                "DisplayName=",
                "Rustaceans RMM Agent",
                "start=",
                "auto"
            ])
            .output()
            .context("Failed to create Windows service")?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Service installation failed: {}", error_msg));
        }

        info!("Windows service installed successfully");
        Ok(())
    }

    #[cfg(windows)]
    async fn uninstall_windows_service(&self) -> Result<()> {
        use std::process::Command;

        let output = Command::new("sc")
            .args(&["delete", "RustaceansRMMAgent"])
            .output()
            .context("Failed to delete Windows service")?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Service removal failed: {}", error_msg));
        }

        info!("Windows service uninstalled successfully");
        Ok(())
    }

    #[cfg(unix)]
    async fn install_systemd_service(&self) -> Result<()> {
        use std::env;
        
        let exe_path = env::current_exe()
            .context("Failed to get current executable path")?;

        let service_content = format!(
            r#"[Unit]
Description=Rustaceans RMM Agent
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart={}
Restart=always
RestartSec=10
User=rmm
Group=rmm
WorkingDirectory=/var/lib/rustaceans-rmm
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"#,
            exe_path.display()
        );

        std::fs::write("/etc/systemd/system/rustaceans-rmm-agent.service", service_content)
            .context("Failed to write systemd service file")?;

        // Reload systemd and enable the service
        let output = std::process::Command::new("systemctl")
            .args(&["daemon-reload"])
            .output()
            .context("Failed to reload systemd")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to reload systemd"));
        }

        let output = std::process::Command::new("systemctl")
            .args(&["enable", "rustaceans-rmm-agent.service"])
            .output()
            .context("Failed to enable service")?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to enable service: {}", error_msg));
        }

        info!("Systemd service installed successfully");
        Ok(())
    }

    #[cfg(unix)]
    async fn uninstall_systemd_service(&self) -> Result<()> {
        // Stop and disable the service
        let _ = std::process::Command::new("systemctl")
            .args(&["stop", "rustaceans-rmm-agent.service"])
            .output();

        let _ = std::process::Command::new("systemctl")
            .args(&["disable", "rustaceans-rmm-agent.service"])
            .output();

        // Remove service file
        let _ = std::fs::remove_file("/etc/systemd/system/rustaceans-rmm-agent.service");

        // Reload systemd
        let _ = std::process::Command::new("systemctl")
            .args(&["daemon-reload"])
            .output();

        info!("Systemd service uninstalled successfully");
        Ok(())
    }
}

#[cfg(windows)]
define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
fn service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service() {
        error!("Service failed: {}", e);
    }
}

#[cfg(windows)]
fn run_service() -> ServiceResult<()> {
    use std::sync::mpsc;
    use std::time::Duration;

    // Create a channel to communicate with the service control handler
    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    // Define the service control handler
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                shutdown_tx.send(()).unwrap();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register the service control handler
    let status_handle = service_control_handler::register("RustaceansRMMAgent", event_handler)?;

    // Set the service as running
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // Create a Tokio runtime for the async agent code
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    rt.block_on(async {
        // Load configuration and run the agent
        match crate::config::AgentConfig::load() {
            Ok(config) => {
                if let Err(e) = crate::run_agent(config).await {
                    error!("Agent runtime error: {}", e);
                }
            }
            Err(e) => {
                error!("Failed to load agent configuration: {}", e);
            }
        }
    });

    // Wait for the shutdown signal
    let _ = shutdown_rx.recv();

    // Set the service as stopped
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}