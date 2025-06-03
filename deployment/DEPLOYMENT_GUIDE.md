# Rustaceans RMM Deployment Guide

## Overview

This guide covers deploying the Rustaceans RMM system with both server and agent components on Windows environments.

## Architecture

### Server Components
- **RMM Server**: Rust application serving the web dashboard and API
- **PostgreSQL Database**: Stores vulnerability data, client information, and scan results
- **Web Interface**: HTML/CSS/JavaScript dashboard for monitoring and management

### Agent Components
- **Windows Agent**: Native Windows service for security scanning
- **Scanner Modules**: Vulnerability detection, patch management, PII scanning
- **Communication Layer**: Encrypted TLS communication with server

## Server Deployment

### Requirements
- Windows Server 2016+ or Linux server
- PostgreSQL 12+
- 4GB RAM minimum, 8GB recommended
- 50GB disk space minimum
- Network ports 5000 (HTTPS) and 5432 (PostgreSQL)

### Option 1: Docker Deployment (Recommended)

1. **Install Docker and Docker Compose**
```bash
# On Windows Server with Docker Desktop
# Or on Linux:
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
```

2. **Clone and Configure**
```bash
git clone <repository>
cd rustaceans-rmm/deployment/server
```

3. **Generate SSL Certificates**
```bash
# Create self-signed certificates for testing
openssl req -x509 -newkey rsa:4096 -keyout ssl/server.key -out ssl/server.crt -days 365 -nodes
```

4. **Deploy with Docker Compose**
```bash
docker-compose up -d
```

### Option 2: Native Windows Deployment

1. **Install PostgreSQL**
   - Download from https://www.postgresql.org/download/windows/
   - Create database: `rmm_db`
   - Create user: `rmm_user` with password

2. **Build Server Binary**
```powershell
cargo build --release --bin simple-rmm-server
```

3. **Configure Environment**
```powershell
$env:DATABASE_URL = "postgresql://rmm_user:password@localhost:5432/rmm_db"
```

4. **Run Server**
```powershell
.\target\release\simple-rmm-server.exe
```

5. **Install as Windows Service**
```powershell
sc create RustaceansRMMServer binPath="C:\Path\To\simple-rmm-server.exe" start=auto
sc start RustaceansRMMServer
```

## Agent Deployment

### Building the Agent

1. **Build Agent Binary**
```powershell
cd deployment/windows
.\build.ps1 -BuildMode Release
```

### Mass Deployment Options

#### Option 1: PowerShell Script Deployment
```powershell
# Copy install.ps1 to target machines
# Run on each machine as Administrator:
.\install.ps1 -ServerUrl "https://your-rmm-server:5000" -ApiKey "your-api-key"
```

#### Option 2: Group Policy Deployment
1. Create GPO for software installation
2. Package agent as MSI (requires WiX Toolset)
3. Deploy via Computer Configuration > Software Installation

#### Option 3: SCCM/Intune Deployment
1. Create application package with install.ps1
2. Configure detection rules for service existence
3. Deploy to device collections

### Agent Configuration

Create configuration template for mass deployment:

```toml
# agent.toml.template
agent_id = "GENERATE_NEW_UUID"  # Will be auto-generated
server_url = "https://rmm.company.com:5000"
api_key = "YOUR_DEPLOYMENT_API_KEY"
heartbeat_interval = 60
scan_interval = 3600
run_as_service = true
log_level = "info"
tls_verify_server = true
```

## Security Configuration

### TLS Certificates
- Use valid SSL certificates for production
- Distribute CA certificates to agents if using internal CA
- Configure certificate pinning for enhanced security

### API Key Management
- Generate unique API keys for different deployment groups
- Implement key rotation policies
- Use environment variables or secure storage for keys

### Network Security
- Configure firewalls to allow HTTPS (443/5000) outbound from agents
- Implement network segmentation for management traffic
- Use VPN or private networks where possible

## Monitoring and Maintenance

### Server Monitoring
- Monitor PostgreSQL database performance
- Check disk space for logs and database growth
- Monitor SSL certificate expiration

### Agent Health Monitoring
- Agents send heartbeats every 60 seconds
- Dashboard shows agent connectivity status
- Configure alerts for offline agents

### Log Management
- Server logs: `/app/logs/` (Docker) or local directory
- Agent logs: `C:\ProgramData\RustaceansRMM\Logs\`
- Windows Event Log entries under "RustaceansRMM" source

## Scaling Considerations

### High Availability
- Deploy multiple server instances behind load balancer
- Use PostgreSQL replication for database redundancy
- Implement health checks and automatic failover

### Performance Optimization
- Tune PostgreSQL for your workload
- Configure connection pooling
- Implement database indexing for large deployments

### Large Scale Deployment
- Use configuration management tools (Ansible, Puppet)
- Implement staged rollouts for agent updates
- Consider regional server deployments for global organizations

## Troubleshooting

### Common Agent Issues
1. **Service won't start**: Check configuration file syntax
2. **Can't connect to server**: Verify network connectivity and certificates
3. **High CPU usage**: Adjust scan intervals in configuration

### Common Server Issues
1. **Database connection errors**: Verify PostgreSQL service and credentials
2. **High memory usage**: Monitor client connections and query performance
3. **SSL/TLS errors**: Check certificate validity and configuration

### Diagnostic Commands

**Windows Agent Diagnostics:**
```powershell
# Check service status
Get-Service RustaceansRMMAgent

# View recent logs
Get-EventLog -LogName Application -Source "RustaceansRMM" -Newest 50

# Test network connectivity
Test-NetConnection your-rmm-server.com -Port 5000
```

**Server Diagnostics:**
```bash
# Check database connectivity
psql -h localhost -U rmm_user -d rmm_db -c "SELECT version();"

# Monitor server logs
tail -f /app/logs/rmm-server.log

# Check port binding
netstat -tlnp | grep 5000
```

## Support and Updates

### Agent Updates
- Agents can be configured for automatic updates
- Use staged deployment for testing updates
- Maintain rollback capability for problematic updates

### Server Updates
- Follow standard application update procedures
- Backup database before major updates
- Test updates in staging environment first

For additional support, consult the system logs and ensure all components have network connectivity to the RMM server.