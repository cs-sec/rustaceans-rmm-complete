# Rustaceans Security RMM

A security-first Remote Monitoring and Management (RMM) tool built in Rust, focusing on comprehensive system security scanning and proactive vulnerability management.

## Features

- **Security-First Architecture**: Built with Rust for memory safety and performance
- **Comprehensive Vulnerability Scanning**: Real-time CVE database integration with NIST NVD
- **Advanced Authentication**: Session-based login system with secure password hashing
- **Multi-Platform Support**: Windows agents with Linux server deployment
- **Enterprise Ready**: PowerShell deployment scripts for mass Windows deployment
- **Real-Time Monitoring**: Live dashboard with security alerts and compliance reporting

## Quick Start

### Server Deployment (AWS Linux)

1. **Launch EC2 Instance** (t2.micro free tier eligible)
2. **Configure Security Group** to allow port 5000
3. **Run setup script**:
```bash
curl -sSL https://raw.githubusercontent.com/cs-sec/rustaceans-rmm/main/deployment/aws-linux-setup.sh | bash
```

### Windows Agent Deployment

Run as Administrator:
```powershell
PowerShell -ExecutionPolicy Bypass -File deployment/windows/quick-deploy.ps1 -ServerUrl "http://YOUR_EC2_IP:5000" -ApiKey "your-api-key"
```

### Access Security Console

Navigate to: `http://YOUR_EC2_IP:5000/login`

**Default Credentials:**
- Username: `admin`
- Password: `admin123`

## Architecture

```
AWS EC2 Linux Server (Port 5000)
    ↓ HTTPS Communication
Windows Agents (Service)
    ↓ Real-time Data
Security Console (Web Browser)
```

## Repository Structure

```
├── src/                    # Rust server source code
│   ├── simple_server.rs   # Main server application
│   ├── auth.rs           # Authentication system
│   ├── database.rs       # Database management
│   └── ...
├── static/               # Web dashboard files
│   ├── index.html       # Main dashboard
│   ├── login.html       # Login page
│   ├── app.js           # Frontend JavaScript
│   └── style.css        # Styling
├── deployment/
│   ├── windows/         # Windows deployment scripts
│   ├── server/          # Docker deployment
│   ├── aws/             # AWS-specific deployment
│   └── DEPLOYMENT_GUIDE.md
└── docs/                # Documentation
```

## Security Features

- **Encrypted Communication**: TLS/HTTPS for all agent-server communication
- **Session Management**: Secure cookie-based authentication with 8-hour expiration
- **Password Security**: bcrypt hashing with salt for credential storage
- **Access Control**: Role-based permissions for different user types
- **Audit Logging**: Comprehensive logging of all security events

## Deployment Options

### 1. Docker Deployment
```bash
cd deployment/server
docker-compose up -d
```

### 2. Native Linux Deployment
```bash
cargo build --release --bin simple-rmm-server
./target/release/simple-rmm-server
```

### 3. AWS EC2 Deployment
Follow the detailed guide in `deployment/aws-deployment-guide.md`

## Windows Agent Features

- **Windows Service Integration**: Runs as native Windows service
- **Security Scanning**: Vulnerability detection, patch management, PII scanning
- **System Monitoring**: CPU, memory, disk usage, and network monitoring
- **Automatic Updates**: Self-updating capability with server coordination
- **Event Logging**: Integration with Windows Event Log

## PowerShell Deployment

### Single Machine
```powershell
.\deployment\windows\quick-deploy.ps1 -ServerUrl "https://your-server:5000" -ApiKey "key"
```

### Enterprise Mass Deployment
```powershell
.\deployment\windows\deploy-enterprise.ps1 -ServerUrl "https://your-server:5000" -ApiKey "key" -ComputerListFile computers.txt
```

### Active Directory Integration
```powershell
.\deployment\windows\deploy-enterprise.ps1 -ServerUrl "https://your-server:5000" -ApiKey "key" -OUPath "OU=Workstations,DC=company,DC=com"
```

## Development

### Prerequisites
- Rust 1.70+
- PostgreSQL 12+
- Git

### Building
```bash
git clone https://github.com/cs-sec/rustaceans-rmm.git
cd rustaceans-rmm
cargo build --release
```

### Running Development Server
```bash
export DATABASE_URL="postgresql://user:pass@localhost/rmm_db"
cargo run --bin simple-rmm-server
```

## Configuration

### Environment Variables
- `DATABASE_URL`: PostgreSQL connection string
- `RUST_LOG`: Logging level (info, debug, warn, error)
- `BIND_ADDRESS`: Server bind address (default: 0.0.0.0:5000)

### Agent Configuration
```toml
# agent.toml
agent_id = "unique-agent-id"
server_url = "https://your-rmm-server:5000"
api_key = "your-api-key"
heartbeat_interval = 60
scan_interval = 3600
```

## Security Console Dashboard

- **Overview**: System health summary and critical alerts
- **Vulnerabilities**: CVE tracking with CVSS scoring
- **Patches**: Available updates and patch management
- **Misconfigurations**: Security setting violations
- **PII Exposure**: Data privacy compliance scanning
- **Clients**: Connected device management
- **Reports**: Compliance and security reporting

## Compliance Frameworks

Supports monitoring for:
- CIS Controls
- NIST Cybersecurity Framework
- SOX (Sarbanes-Oxley)
- PCI-DSS
- HIPAA
- GDPR

## Cost Estimation (AWS Free Tier)

- **EC2 t2.micro**: Free for 12 months
- **Storage (20GB)**: Within free tier limits
- **Data Transfer**: Minimal for agent communication
- **Estimated monthly cost after free tier**: ~$10-15

## Support & Troubleshooting

### Common Issues

1. **Agent not connecting**: Check Windows firewall and network connectivity
2. **Database connection errors**: Verify PostgreSQL service and credentials
3. **Login issues**: Ensure cookies are enabled and session hasn't expired

### Logs Location
- **Server**: Check systemd logs or console output
- **Windows Agent**: `C:\ProgramData\RustaceansRMM\Logs\`
- **Windows Events**: Application log, source "RustaceansRMM"

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Changelog

### v0.1.0
- Initial release with core RMM functionality
- Windows agent with security scanning
- Web-based security console
- PowerShell deployment scripts
- Authentication system
- AWS deployment support
