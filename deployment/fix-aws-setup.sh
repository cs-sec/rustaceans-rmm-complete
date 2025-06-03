#!/bin/bash
# Quick Fix Script for AWS RMM Setup Issues

set -e

echo "=== AWS RMM Setup Fix Script ==="

# Detect the actual distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "Detected: $NAME $VERSION_ID"
fi

# Check what we're running on
if grep -q "Amazon Linux" /etc/os-release 2>/dev/null; then
    echo "Amazon Linux detected - using yum and amazon-linux-extras"
    
    # Update system
    sudo yum update -y
    
    # Install PostgreSQL using amazon-linux-extras
    sudo amazon-linux-extras install -y postgresql14
    sudo yum install -y postgresql-server postgresql-contrib
    
    # Initialize and start PostgreSQL
    sudo postgresql-setup initdb
    sudo systemctl enable postgresql
    sudo systemctl start postgresql
    
elif command -v apt &> /dev/null; then
    echo "Ubuntu/Debian detected - using apt"
    
    sudo apt update
    sudo apt install -y postgresql postgresql-contrib build-essential pkg-config libssl-dev libpq-dev
    sudo systemctl enable postgresql
    sudo systemctl start postgresql
    
elif command -v yum &> /dev/null; then
    echo "RHEL/CentOS detected - using yum"
    
    sudo yum update -y
    sudo yum install -y postgresql-server postgresql-contrib
    sudo postgresql-setup initdb
    sudo systemctl enable postgresql
    sudo systemctl start postgresql
fi

# Wait for PostgreSQL to start
sleep 3

# Create database and user
echo "Creating database..."
sudo -u postgres psql << 'EOF'
CREATE DATABASE rmm_db;
CREATE USER rmm_user WITH ENCRYPTED PASSWORD 'secure_rmm_password_123';
GRANT ALL PRIVILEGES ON DATABASE rmm_db TO rmm_user;
ALTER USER rmm_user CREATEDB;
\q
EOF

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
fi

# Clone repository
if [ ! -d "SecurityRMM" ]; then
    echo "Cloning repository..."
    git clone https://github.com/cs-sec/SecurityRMM.git
fi

cd SecurityRMM

# Set environment variable
export DATABASE_URL="postgresql://rmm_user:secure_rmm_password_123@localhost:5432/rmm_db"
echo 'export DATABASE_URL="postgresql://rmm_user:secure_rmm_password_123@localhost:5432/rmm_db"' >> ~/.bashrc

# Build the server
echo "Building RMM server..."
cargo build --release --bin simple-rmm-server

# Get public IP
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "localhost")

echo ""
echo "=== Setup Complete ==="
echo "Start server: ./target/release/simple-rmm-server"
echo "Access console: http://$PUBLIC_IP:5000/login"
echo "Username: admin"
echo "Password: admin123"
echo ""
echo "Remember to configure AWS Security Group to allow port 5000"