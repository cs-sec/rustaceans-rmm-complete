#!/bin/bash
# AWS RMM Setup Without Git Authentication Issues

set -e

echo "=== AWS RMM Setup (No Git Required) ==="

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "Detected: $NAME $VERSION_ID"
fi

# Install PostgreSQL based on distribution
if grep -q "Amazon Linux" /etc/os-release 2>/dev/null; then
    echo "Setting up PostgreSQL on Amazon Linux..."
    sudo yum update -y
    sudo amazon-linux-extras install -y postgresql14
    sudo yum install -y postgresql-server postgresql-contrib gcc openssl-devel
    sudo postgresql-setup initdb
    sudo systemctl enable postgresql
    sudo systemctl start postgresql
    
elif command -v apt &> /dev/null; then
    echo "Setting up PostgreSQL on Ubuntu/Debian..."
    sudo apt update
    sudo apt install -y postgresql postgresql-contrib build-essential pkg-config libssl-dev libpq-dev gcc
    sudo systemctl enable postgresql
    sudo systemctl start postgresql
    
elif command -v yum &> /dev/null; then
    echo "Setting up PostgreSQL on RHEL/CentOS..."
    sudo yum update -y
    sudo yum install -y postgresql-server postgresql-contrib gcc openssl-devel
    sudo postgresql-setup initdb
    sudo systemctl enable postgresql
    sudo systemctl start postgresql
fi

# Wait for PostgreSQL to start
sleep 5

# Create database and user
echo "Creating database..."
sudo -u postgres psql << 'EOF'
CREATE DATABASE rmm_db;
CREATE USER rmm_user WITH ENCRYPTED PASSWORD 'secure_rmm_password_123';
GRANT ALL PRIVILEGES ON DATABASE rmm_db TO rmm_user;
ALTER USER rmm_user CREATEDB;
\q
EOF

# Install Rust
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
    echo 'source ~/.cargo/env' >> ~/.bashrc
fi

# Download source code directly without git
echo "Downloading RMM source code..."
mkdir -p SecurityRMM
cd SecurityRMM

# Download individual files from GitHub
curl -sSL https://raw.githubusercontent.com/cs-sec/SecurityRMM/main/Cargo.toml -o Cargo.toml
mkdir -p src static deployment/windows

# Download Rust source files
curl -sSL https://raw.githubusercontent.com/cs-sec/SecurityRMM/main/src/simple_server.rs -o src/simple_server.rs
curl -sSL https://raw.githubusercontent.com/cs-sec/SecurityRMM/main/src/auth.rs -o src/auth.rs
curl -sSL https://raw.githubusercontent.com/cs-sec/SecurityRMM/main/src/database.rs -o src/database.rs

# Download web files
curl -sSL https://raw.githubusercontent.com/cs-sec/SecurityRMM/main/static/index.html -o static/index.html
curl -sSL https://raw.githubusercontent.com/cs-sec/SecurityRMM/main/static/login.html -o static/login.html
curl -sSL https://raw.githubusercontent.com/cs-sec/SecurityRMM/main/static/app.js -o static/app.js
curl -sSL https://raw.githubusercontent.com/cs-sec/SecurityRMM/main/static/style.css -o static/style.css

# Set environment variable
export DATABASE_URL="postgresql://rmm_user:secure_rmm_password_123@localhost:5432/rmm_db"
echo 'export DATABASE_URL="postgresql://rmm_user:secure_rmm_password_123@localhost:5432/rmm_db"' >> ~/.bashrc

# Build the server
echo "Building RMM server..."
source ~/.cargo/env
cargo build --release --bin simple-rmm-server

# Get public IP
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "localhost")

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Start server with:"
echo "  ./target/release/simple-rmm-server"
echo ""
echo "Access console at:"
echo "  http://$PUBLIC_IP:5000/login"
echo ""
echo "Login credentials:"
echo "  Username: admin"
echo "  Password: admin123"
echo ""
echo "Remember to configure AWS Security Group to allow port 5000"
echo ""
echo "To start server now: ./target/release/simple-rmm-server"