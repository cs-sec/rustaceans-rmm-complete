#!/bin/bash
# Quick AWS Setup for Rustaceans RMM Server

echo "=== Quick AWS Linux Setup ==="

# Install dependencies
sudo yum update -y
sudo yum install -y postgresql-server postgresql-contrib

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env

# Setup PostgreSQL
sudo postgresql-setup initdb
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Create database
sudo -u postgres psql << EOF
CREATE DATABASE rmm_db;
CREATE USER rmm_user WITH PASSWORD 'rmm_secure_2024';
GRANT ALL PRIVILEGES ON DATABASE rmm_db TO rmm_user;
\q
EOF

# Set environment
export DATABASE_URL="postgresql://rmm_user:rmm_secure_2024@localhost:5432/rmm_db"
echo 'export DATABASE_URL="postgresql://rmm_user:rmm_secure_2024@localhost:5432/rmm_db"' >> ~/.bashrc

# Get public IP for display
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

echo ""
echo "Setup complete!"
echo "Build and run your server, then access console at:"
echo "http://$PUBLIC_IP:5000"
echo ""
echo "Remember to configure AWS Security Group to allow port 5000"