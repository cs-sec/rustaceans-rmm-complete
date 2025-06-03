use anyhow::Result;
use serde::{Deserialize, Serialize};
use sysinfo::{System, SystemExt, CpuExt, DiskExt, NetworkExt, ProcessExt};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub operating_system: String,
    pub os_version: String,
    pub architecture: String,
    pub cpu_info: CpuInfo,
    pub memory_info: MemoryInfo,
    pub disk_info: Vec<DiskInfo>,
    pub network_interfaces: Vec<NetworkInterface>,
    pub uptime: u64,
    pub running_processes: u32,
    pub installed_software: Vec<SoftwareInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    pub brand: String,
    pub cores: usize,
    pub frequency: u64,
    pub usage_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_kb: u64,
    pub available_kb: u64,
    pub used_kb: u64,
    pub usage_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    pub total_space: u64,
    pub available_space: u64,
    pub file_system: String,
    pub disk_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub mac_address: String,
    pub ip_addresses: Vec<String>,
    pub bytes_received: u64,
    pub bytes_transmitted: u64,
    pub is_up: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareInfo {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub install_date: Option<String>,
    pub install_location: Option<String>,
}

impl SystemInfo {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();

        let hostname = whoami::hostname();
        let operating_system = std::env::consts::OS.to_string();
        let architecture = std::env::consts::ARCH.to_string();

        // Get OS version
        let os_version = Self::get_os_version();

        // CPU information
        let cpu_info = if let Some(cpu) = sys.cpus().first() {
            CpuInfo {
                brand: cpu.brand().to_string(),
                cores: sys.cpus().len(),
                frequency: cpu.frequency(),
                usage_percent: sys.global_cpu_info().cpu_usage(),
            }
        } else {
            CpuInfo {
                brand: "Unknown".to_string(),
                cores: 0,
                frequency: 0,
                usage_percent: 0.0,
            }
        };

        // Memory information
        let total_memory = sys.total_memory();
        let available_memory = sys.available_memory();
        let used_memory = total_memory - available_memory;
        let memory_usage_percent = if total_memory > 0 {
            (used_memory as f32 / total_memory as f32) * 100.0
        } else {
            0.0
        };

        let memory_info = MemoryInfo {
            total_kb: total_memory,
            available_kb: available_memory,
            used_kb: used_memory,
            usage_percent: memory_usage_percent,
        };

        // Disk information
        let disk_info = sys.disks().iter().map(|disk| {
            DiskInfo {
                name: disk.name().to_string_lossy().to_string(),
                mount_point: disk.mount_point().to_string_lossy().to_string(),
                total_space: disk.total_space(),
                available_space: disk.available_space(),
                file_system: disk.file_system().to_string_lossy().to_string(),
                disk_type: format!("{:?}", disk.kind()),
            }
        }).collect();

        // Network interfaces
        let network_interfaces = sys.networks().iter().map(|(interface_name, data)| {
            NetworkInterface {
                name: interface_name.clone(),
                mac_address: data.mac_address().to_string(),
                ip_addresses: Vec::new(), // Would need additional logic to get IPs
                bytes_received: data.total_received(),
                bytes_transmitted: data.total_transmitted(),
                is_up: data.total_received() > 0 || data.total_transmitted() > 0,
            }
        }).collect();

        // System uptime
        let uptime = sys.uptime();

        // Running processes count
        let running_processes = sys.processes().len() as u32;

        // Installed software (platform-specific)
        let installed_software = Self::get_installed_software();

        SystemInfo {
            hostname,
            operating_system,
            os_version,
            architecture,
            cpu_info,
            memory_info,
            disk_info,
            network_interfaces,
            uptime,
            running_processes,
            installed_software,
        }
    }

    #[cfg(windows)]
    fn get_os_version() -> String {
        use std::process::Command;
        
        let output = Command::new("cmd")
            .args(&["/C", "ver"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let version_str = String::from_utf8_lossy(&output.stdout);
                if let Some(version_line) = version_str.lines().next() {
                    return version_line.trim().to_string();
                }
            }
        }

        // Fallback to reading registry
        match Self::read_windows_version_from_registry() {
            Ok(version) => version,
            Err(_) => "Windows (Unknown Version)".to_string(),
        }
    }

    #[cfg(windows)]
    fn read_windows_version_from_registry() -> Result<String> {
        use winapi::um::winreg::{RegOpenKeyExW, RegQueryValueExW, RegCloseKey, HKEY_LOCAL_MACHINE};
        use winapi::um::winnt::{KEY_READ, REG_SZ};
        use winapi::shared::minwindef::{HKEY, DWORD};
        use std::ptr;
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let subkey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        let subkey_wide: Vec<u16> = OsStr::new(subkey).encode_wide().chain(std::iter::once(0)).collect();
        
        let mut hkey: HKEY = ptr::null_mut();
        let result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey_wide.as_ptr(),
                0,
                KEY_READ,
                &mut hkey
            )
        };

        if result != 0 {
            return Err(anyhow::anyhow!("Failed to open registry key"));
        }

        let product_name = Self::read_registry_string(hkey, "ProductName")?;
        let current_version = Self::read_registry_string(hkey, "CurrentVersion")?;
        let current_build = Self::read_registry_string(hkey, "CurrentBuild")?;

        unsafe { RegCloseKey(hkey); }

        Ok(format!("{} {} (Build {})", product_name, current_version, current_build))
    }

    #[cfg(windows)]
    fn read_registry_string(hkey: winapi::shared::minwindef::HKEY, value_name: &str) -> Result<String> {
        use winapi::um::winreg::RegQueryValueExW;
        use winapi::um::winnt::REG_SZ;
        use winapi::shared::minwindef::DWORD;
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::ptr;

        let value_name_wide: Vec<u16> = OsStr::new(value_name).encode_wide().chain(std::iter::once(0)).collect();
        let mut buffer_size: DWORD = 0;
        let mut value_type: DWORD = 0;

        // First call to get buffer size
        let result = unsafe {
            RegQueryValueExW(
                hkey,
                value_name_wide.as_ptr(),
                ptr::null_mut(),
                &mut value_type,
                ptr::null_mut(),
                &mut buffer_size
            )
        };

        if result != 0 || value_type != REG_SZ {
            return Err(anyhow::anyhow!("Failed to query registry value size"));
        }

        let mut buffer: Vec<u16> = vec![0; (buffer_size / 2) as usize];
        let result = unsafe {
            RegQueryValueExW(
                hkey,
                value_name_wide.as_ptr(),
                ptr::null_mut(),
                &mut value_type,
                buffer.as_mut_ptr() as *mut u8,
                &mut buffer_size
            )
        };

        if result != 0 {
            return Err(anyhow::anyhow!("Failed to read registry value"));
        }

        // Remove null terminator and convert to string
        if let Some(null_pos) = buffer.iter().position(|&x| x == 0) {
            buffer.truncate(null_pos);
        }

        Ok(String::from_utf16_lossy(&buffer))
    }

    #[cfg(unix)]
    fn get_os_version() -> String {
        use std::process::Command;
        
        // Try to read from /etc/os-release
        if let Ok(contents) = std::fs::read_to_string("/etc/os-release") {
            let mut name = String::new();
            let mut version = String::new();
            
            for line in contents.lines() {
                if line.starts_with("NAME=") {
                    name = line[5..].trim_matches('"').to_string();
                } else if line.starts_with("VERSION=") {
                    version = line[8..].trim_matches('"').to_string();
                }
            }
            
            if !name.is_empty() {
                return if !version.is_empty() {
                    format!("{} {}", name, version)
                } else {
                    name
                };
            }
        }

        // Fallback to uname
        let output = Command::new("uname")
            .args(&["-sr"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout).trim().to_string();
            }
        }

        "Unix (Unknown Version)".to_string()
    }

    #[cfg(windows)]
    fn get_installed_software() -> Vec<SoftwareInfo> {
        use std::process::Command;
        
        let mut software_list = Vec::new();

        // Query installed software via WMI
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor, InstallDate | ConvertTo-Json"
            ])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                if let Ok(software_data) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                    if let Some(array) = software_data.as_array() {
                        for item in array {
                            let name = item.get("Name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Unknown")
                                .to_string();
                            
                            let version = item.get("Version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Unknown")
                                .to_string();
                            
                            let publisher = item.get("Vendor")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Unknown")
                                .to_string();
                            
                            let install_date = item.get("InstallDate")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());

                            software_list.push(SoftwareInfo {
                                name,
                                version,
                                publisher,
                                install_date,
                                install_location: None,
                            });
                        }
                    }
                }
            }
        }

        software_list
    }

    #[cfg(unix)]
    fn get_installed_software() -> Vec<SoftwareInfo> {
        use std::process::Command;
        
        let mut software_list = Vec::new();

        // Try dpkg first (Debian/Ubuntu)
        if let Ok(output) = Command::new("dpkg-query")
            .args(&["-W", "-f=${Package}\\t${Version}\\t${Maintainer}\\n"])
            .output()
        {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() >= 3 {
                        software_list.push(SoftwareInfo {
                            name: parts[0].to_string(),
                            version: parts[1].to_string(),
                            publisher: parts[2].to_string(),
                            install_date: None,
                            install_location: None,
                        });
                    }
                }
                return software_list;
            }
        }

        // Try rpm (Red Hat/CentOS/SUSE)
        if let Ok(output) = Command::new("rpm")
            .args(&["-qa", "--qf", "%{NAME}\\t%{VERSION}\\t%{VENDOR}\\n"])
            .output()
        {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() >= 3 {
                        software_list.push(SoftwareInfo {
                            name: parts[0].to_string(),
                            version: parts[1].to_string(),
                            publisher: parts[2].to_string(),
                            install_date: None,
                            install_location: None,
                        });
                    }
                }
            }
        }

        software_list
    }

    pub fn refresh(&mut self) {
        *self = Self::new();
    }
}