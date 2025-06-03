# AWS Linux Deployment Guide for Rustaceans RMM

## Overview

This guide walks you through setting up the Rustaceans RMM server on an AWS EC2 Linux instance and connecting Windows computers as agents.

## Architecture

```
Internet
    ↓
AWS EC2 Linux Instance (Server)
    ↓ Port 5000 (HTTPS)
Windows Computer (Agent) ←→ Security Console (Your Browser)
```

## Step 1: AWS EC2 Setup

### Launch EC2 Instance
1. Launch Amazon Linux 2 or Ubuntu 20.04+ instance
2. Instance type: t2.micro (free tier eligible)
3. Storage: 20GB minimum
4. Create or use existing key pair

### Configure Security Group
Create inbound rules:
- SSH (22): Your IP address
- Custom TCP (5000): 0.0.0.0/0 (for security console access)
- HTTPS (443): 0.0.0.0/0 (optional, for SSL)

## Step 2: Server Installation

### Connect to your instance:
```bash
ssh -i your-key.pem ec2-user@your-instance-ip
```

### Run the setup script:
```bash
curl -sSL https://raw.githubusercontent.com/your-repo/rustaceans-rmm/main/deployment/aws-linux-setup.sh | bash
```

Or manually:
```bash
# Update system
sudo yum update -y
sudo yum install -y git curl postgresql-server postgresql-contrib

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Setup PostgreSQL
sudo postgresql-setup initdb
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Create database
sudo -u postgres createdb rmm_db
sudo -u postgres createuser -P rmm_user

# Clone and build (replace with your repository)
git clone https://github.com/your-repo/rustaceans-rmm.git
cd rustaceans-rmm
export DATABASE_URL="postgresql://rmm_user:password@localhost:5432/rmm_db"
cargo build --release --bin simple-rmm-server

# Start server
./target/release/simple-rmm-server
```

## Step 3: Access Security Console

### Get your server URL:
Your security console will be accessible at:
- **http://YOUR_EC2_PUBLIC_IP:5000**

Example: http://54.123.45.67:5000

### Console Features:
- Real-time security dashboard
- Vulnerability management
- Client monitoring
- Patch management
- Compliance reporting
- PII scanning results

## Step 4: Deploy Windows Agent

### On your Windows computer, run PowerShell as Administrator:

```powershell
# Download deployment script
Invoke-WebRequest -Uri "http://YOUR_EC2_IP:5000/deploy/quick-deploy.ps1" -OutFile "quick-deploy.ps1"

# Run deployment
.\quick-deploy.ps1 -ServerUrl "http://YOUR_EC2_IP:5000" -ApiKey "your-api-key"
```

### Alternative manual deployment:
```powershell
# Set your server details
$ServerUrl = "http://YOUR_EC2_IP:5000"
$ApiKey = "your-generated-api-key"

# Run the installer
PowerShell -ExecutionPolicy Bypass -File "install.ps1" -ServerUrl $ServerUrl -ApiKey $ApiKey
```

## Step 5: Verify Installation

### Check server status:
```bash
# On your EC2 instance
sudo systemctl status rustaceans-rmm
curl http://localhost:5000/health
```

### Check agent status:
```powershell
# On your Windows computer
Get-Service RustaceansRMMAgent
```

### View in console:
1. Open browser to http://YOUR_EC2_IP:5000
2. Navigate to "Clients" tab
3. Your Windows computer should appear within 60 seconds

## Access Points Summary

| Component | Access Method | URL/Location |
|-----------|---------------|--------------|
| Security Console | Web Browser | http://YOUR_EC2_IP:5000 |
| Server Management | SSH | ssh ec2-user@YOUR_EC2_IP |
| Agent Management | PowerShell | Local Windows machine |
| Database | PostgreSQL | localhost:5432 (on EC2) |

## Security Console Navigation

### Dashboard Tabs:
1. **Overview** - System health and summary
2. **Vulnerabilities** - CVE scanning results
3. **Patches** - Available updates
4. **Misconfigurations** - Security settings
5. **PII Exposure** - Data privacy scanning
6. **Clients** - Connected computers
7. **Reports** - Compliance and security reports

### Real-time Features:
- Live vulnerability feeds
- Automatic security scans
- Instant alerts for critical issues
- Remote system monitoring

## Troubleshooting

### Server not accessible:
1. Check AWS Security Group allows port 5000
2. Verify server is running: `sudo systemctl status rustaceans-rmm`
3. Check firewall: `sudo ufw status`

### Agent not connecting:
1. Verify Windows firewall allows outbound HTTPS
2. Check agent service: `Get-Service RustaceansRMMAgent`
3. Review agent logs: `C:\ProgramData\RustaceansRMM\Logs\`

### Console not loading:
1. Ensure you're using HTTP (not HTTPS) for basic setup
2. Try private IP if public IP doesn't work
3. Check browser console for JavaScript errors

## Cost Considerations

### AWS Free Tier:
- t2.micro instance: 750 hours/month free
- 20GB storage: Within free tier
- Data transfer: 1GB outbound free

### Ongoing costs (after free tier):
- t2.micro: ~$8.50/month
- Storage: ~$2/month for 20GB
- Data transfer: Minimal for agent communication

## Next Steps

1. Set up SSL certificate for production use
2. Configure automated backups
3. Deploy agents to additional Windows computers
4. Set up monitoring and alerting
5. Configure compliance reporting

The security console provides comprehensive visibility into all connected Windows computers from a single web interface accessible from anywhere with internet access.