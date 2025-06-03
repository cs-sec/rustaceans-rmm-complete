# Quick Start Guide

## 1. Clone to GitHub

```bash
git clone <your-new-repo-url>
cd rustaceans-rmm
```

## 2. AWS EC2 Setup (5 minutes)

### Launch Instance
- AMI: Amazon Linux 2 or Ubuntu 20.04+
- Instance: t2.micro (free tier)
- Security Group: Allow port 22 (SSH) and 5000 (RMM Console)

### Install Server
```bash
ssh -i your-key.pem ec2-user@YOUR_EC2_IP

# Run setup script
curl -sSL https://raw.githubusercontent.com/your-username/rustaceans-rmm/main/deployment/aws-linux-setup.sh | bash

# Build and start
cd rustaceans-rmm
cargo build --release --bin simple-rmm-server
./target/release/simple-rmm-server
```

## 3. Access Security Console

Navigate to: `http://YOUR_EC2_IP:5000/login`

Login with:
- Username: `admin`
- Password: `admin123`

## 4. Deploy Windows Agent

On your Windows machine, run as Administrator:

```powershell
# Download deployment script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/your-username/rustaceans-rmm/main/deployment/windows/quick-deploy.ps1" -OutFile "quick-deploy.ps1"

# Deploy agent
.\quick-deploy.ps1 -ServerUrl "http://YOUR_EC2_IP:5000" -ApiKey "demo-key-123"
```

## 5. Monitor Security

Your Windows machine will appear in the RMM console within 60 seconds, showing:
- Real-time vulnerability scans
- System health monitoring
- Security configuration analysis
- PII exposure detection

## That's it!

You now have a complete security monitoring system running on AWS with Windows agents reporting to your central dashboard.