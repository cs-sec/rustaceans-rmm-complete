#!/bin/bash
# Upgrade to Full RMM Console from GitHub Repository

set -e

echo "=== Upgrading to Full RMM Console from GitHub ==="

# Stop current server
pkill simple-rmm-server 2>/dev/null || true
sleep 2

cd SecurityRMM

# Backup current files
mkdir -p backup
cp -r src static backup/ 2>/dev/null || true

# Download complete RMM implementation from your repository
echo "Downloading complete RMM implementation..."

# Download main configuration
curl -sSL https://raw.githubusercontent.com/cs-sec/rustaceans-rmm-complete/main/Cargo.toml -o Cargo.toml

# Download Rust source files
mkdir -p src
curl -sSL https://raw.githubusercontent.com/cs-sec/rustaceans-rmm-complete/main/src/simple_server.rs -o src/simple_server.rs
curl -sSL https://raw.githubusercontent.com/cs-sec/rustaceans-rmm-complete/main/src/auth.rs -o src/auth.rs
curl -sSL https://raw.githubusercontent.com/cs-sec/rustaceans-rmm-complete/main/src/database.rs -o src/database.rs

# Download complete web interface
curl -sSL https://raw.githubusercontent.com/cs-sec/rustaceans-rmm-complete/main/static/index.html -o static/index.html
curl -sSL https://raw.githubusercontent.com/cs-sec/rustaceans-rmm-complete/main/static/login.html -o static/login.html
curl -sSL https://raw.githubusercontent.com/cs-sec/rustaceans-rmm-complete/main/static/app.js -o static/app.js
curl -sSL https://raw.githubusercontent.com/cs-sec/rustaceans-rmm-complete/main/static/style.css -o static/style.css

echo "Files downloaded successfully!"

# Rebuild with complete features
echo "Building complete RMM server..."
source ~/.cargo/env 2>/dev/null || export PATH="$HOME/.cargo/bin:$PATH"
cargo build --release --bin simple-rmm-server

PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "localhost")

echo ""
echo "=== Complete RMM Console Ready ==="
echo ""
echo "Start server: ./target/release/simple-rmm-server"
echo "Access at: http://$PUBLIC_IP:5000/login"
echo ""
echo "Complete features now available:"
echo "- Full security dashboard with real-time monitoring"
echo "- Comprehensive vulnerability scanning and CVE tracking"
echo "- Advanced client management and device monitoring"
echo "- Security scan results and patch management"
echo "- PII exposure detection and compliance reporting"
echo "- Real-time security alerts and health indicators"
echo ""
echo "Ready for Windows agent deployment with PowerShell scripts!"
EOF