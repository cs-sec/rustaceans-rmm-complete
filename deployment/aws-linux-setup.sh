#!/bin/bash
# AWS Linux Setup Script for Rustaceans RMM Server
# Run this on your AWS EC2 instance (Amazon Linux 2 or Ubuntu)

set -e

echo "=== Rustaceans RMM Server Setup for AWS Linux ==="
echo ""

# Update system
echo "Updating system packages..."
if command -v yum &> /dev/null; then
    sudo yum update -y
    sudo yum install -y git curl postgresql-server postgresql-contrib
elif command -v apt &> /dev/null; then
    sudo apt update && sudo apt upgrade -y
    sudo apt install -y git curl postgresql postgresql-contrib
fi

# Install Rust
echo "Installing Rust..."
if ! command -v cargo &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
    echo 'source ~/.cargo/env' >> ~/.bashrc
fi

# Setup PostgreSQL
echo "Setting up PostgreSQL..."
if command -v systemctl &> /dev/null; then
    sudo systemctl enable postgresql
    sudo systemctl start postgresql
fi

# Initialize database if needed
if [ ! -d "/var/lib/pgsql/data" ] && command -v postgresql-setup &> /dev/null; then
    sudo postgresql-setup initdb
fi

# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE rmm_db;
CREATE USER rmm_user WITH PASSWORD 'secure_rmm_password_123';
GRANT ALL PRIVILEGES ON DATABASE rmm_db TO rmm_user;
\q
EOF

echo "Database setup completed"

# Clone repository (assuming you have the code)
echo "Setting up application..."
if [ ! -d "rustaceans-rmm" ]; then
    # In real deployment, you'd clone from your repository
    echo "Note: In production, clone your repository here"
    echo "git clone https://github.com/yourcompany/rustaceans-rmm.git"
    echo "cd rustaceans-rmm"
fi

# Set environment variables
export DATABASE_URL="postgresql://rmm_user:secure_rmm_password_123@localhost:5432/rmm_db"
echo 'export DATABASE_URL="postgresql://rmm_user:secure_rmm_password_123@localhost:5432/rmm_db"' >> ~/.bashrc

# Build the server
echo "Building RMM server..."
cargo build --release --bin simple-rmm-server

# Create systemd service
echo "Creating systemd service..."
sudo tee /etc/systemd/system/rustaceans-rmm.service > /dev/null << EOF
[Unit]
Description=Rustaceans RMM Server
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME/rustaceans-rmm
Environment=DATABASE_URL=postgresql://rmm_user:secure_rmm_password_123@localhost:5432/rmm_db
Environment=RUST_LOG=info
Environment=BIND_ADDRESS=0.0.0.0:5000
ExecStart=$HOME/rustaceans-rmm/target/release/simple-rmm-server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable rustaceans-rmm
sudo systemctl start rustaceans-rmm

# Configure firewall
echo "Configuring firewall..."
if command -v ufw &> /dev/null; then
    sudo ufw allow 5000/tcp
    sudo ufw allow ssh
elif command -v firewall-cmd &> /dev/null; then
    sudo firewall-cmd --permanent --add-port=5000/tcp
    sudo firewall-cmd --reload
fi

# Get public IP
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)

echo ""
echo "=== Setup Complete ==="
echo "Server is running on port 5000"
echo ""
echo "Access URLs:"
echo "Public:  http://$PUBLIC_IP:5000"
echo "Private: http://$PRIVATE_IP:5000"
echo ""
echo "Security Console will be available at these URLs"
echo ""
echo "Next steps:"
echo "1. Configure AWS Security Group to allow port 5000"
echo "2. Use PowerShell deployment scripts to install agents on Windows machines"
echo "3. Access the security console from your browser"
echo ""
echo "Service status:"
sudo systemctl status rustaceans-rmm --no-pager -l
EOF