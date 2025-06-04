#!/bin/bash

# Clean EC2 Update Script - Fixes corrupted files and updates from GitHub

echo "=== Clean EC2 Update Script ==="

# Navigate to project directory
cd /home/ubuntu/SecurityRMM || {
    echo "Creating fresh SecurityRMM directory..."
    cd /home/ubuntu
    rm -rf SecurityRMM
    mkdir SecurityRMM
    cd SecurityRMM
}

# Clean any corrupted files
echo "Cleaning corrupted files..."
rm -f src/simple_server.rs
rm -f static/app.js
rm -f static/index.html
rm -f Cargo.toml

# Create directories
mkdir -p src static deployment/windows

# Download clean files from GitHub
echo "Downloading clean files from GitHub..."

# Download Cargo.toml (simple version without database)
cat > Cargo.toml << 'EOF'
[package]
name = "simple-rmm-server"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "simple-rmm-server"
path = "src/simple_server.rs"

[dependencies]
actix-web = "4.4"
actix-files = "0.6"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1.0", features = ["full"] }
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1.0", features = ["serde", "v4"] }
anyhow = "1.0"
env_logger = "0.10"
sha2 = "0.10"
hex = "0.4"
EOF

# Download auth.rs
curl -sSL https://raw.githubusercontent.com/cs-sec/rustaceans-rmm-complete/main/src/auth.rs > src/auth.rs

# Download simple_server.rs
curl -sSL https://raw.githubusercontent.com/cs-sec/rustaceans-rmm-complete/main/src/simple_server.rs > src/simple_server.rs

# Download static files
curl -sSL https://raw.githubusercontent.com/cs-sec/rustaceans-rmm-complete/main/static/index.html > static/index.html
curl -sSL https://raw.githubusercontent.com/cs-sec/rustaceans-rmm-complete/main/static/style.css > static/style.css
curl -sSL https://raw.githubusercontent.com/cs-sec/rustaceans-rmm-complete/main/static/app.js > static/app.js

# Download Windows agent
curl -sSL https://raw.githubusercontent.com/cs-sec/rustaceans-rmm-complete/main/deployment/windows/rmm-agent-with-scanning.ps1 > deployment/windows/rmm-agent-with-scanning.ps1

# Remove any database references that might cause compilation errors
echo "Cleaning database references..."
if [ -f src/simple_server.rs ]; then
    sed -i '/mod database;/d' src/simple_server.rs
    sed -i '/mod vulnerability_db;/d' src/simple_server.rs
    sed -i '/use database::/d' src/simple_server.rs
    sed -i '/DatabaseManager/d' src/simple_server.rs
    sed -i '/sqlx::/d' src/simple_server.rs
    sed -i '/PgPool/d' src/simple_server.rs
fi

# Clean and build
echo "Building project..."
cargo clean
cargo build --bin simple-rmm-server

if [ $? -eq 0 ]; then
    echo ""
    echo "=== SUCCESS: EC2 Updated Successfully! ==="
    echo ""
    echo "To start the server:"
    echo "  cargo run --bin simple-rmm-server"
    echo ""
    echo "Server will be available at: http://your-ec2-ip:5000"
    echo "Login: admin / admin123"
    echo ""
    echo "Features:"
    echo "✓ Real-time vulnerability scanning"
    echo "✓ Windows agent support"
    echo "✓ Security monitoring dashboard"
    echo "✓ No database dependencies"
    echo ""
else
    echo ""
    echo "=== Build Failed ==="
    echo "Checking for remaining issues..."
    
    # Show any compilation errors
    cargo build --bin simple-rmm-server 2>&1 | head -20
    
    echo ""
    echo "Manual fix may be required. Check the error output above."
fi
EOF

chmod +x deployment/clean-update-ec2.sh
