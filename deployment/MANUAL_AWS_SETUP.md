# Manual AWS Setup Guide

## Step 1: Install Dependencies

### For Ubuntu/Debian:
```bash
sudo apt update
sudo apt install -y git curl postgresql postgresql-contrib build-essential pkg-config libssl-dev libpq-dev
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### For Amazon Linux 2:
```bash
sudo yum update -y
sudo amazon-linux-extras enable postgresql14
sudo yum install -y git curl postgresql-server postgresql-contrib postgresql-devel gcc openssl-devel
sudo postgresql-setup initdb
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### For CentOS/RHEL:
```bash
sudo yum update -y
sudo yum install -y git curl postgresql-server postgresql-contrib postgresql-devel gcc openssl-devel
sudo postgresql-setup initdb
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

## Step 2: Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
```

## Step 3: Setup Database
```bash
# Create database and user
sudo -u postgres psql -c "CREATE DATABASE rmm_db;"
sudo -u postgres psql -c "CREATE USER rmm_user WITH PASSWORD 'secure_rmm_password_123';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE rmm_db TO rmm_user;"
sudo -u postgres psql -c "ALTER USER rmm_user CREATEDB;"
```

## Step 4: Clone and Build
```bash
git clone https://github.com/cs-sec/SecurityRMM.git
cd SecurityRMM
export DATABASE_URL="postgresql://rmm_user:secure_rmm_password_123@localhost:5432/rmm_db"
echo 'export DATABASE_URL="postgresql://rmm_user:secure_rmm_password_123@localhost:5432/rmm_db"' >> ~/.bashrc
cargo build --release --bin simple-rmm-server
```

## Step 5: Run Server
```bash
./target/release/simple-rmm-server
```

## Step 6: Configure Firewall
```bash
# For Ubuntu with ufw
sudo ufw allow 5000/tcp
sudo ufw allow ssh

# For systems with firewalld
sudo firewall-cmd --permanent --add-port=5000/tcp
sudo firewall-cmd --reload
```

## Step 7: Access Console
Navigate to: `http://YOUR_EC2_PUBLIC_IP:5000/login`

Login with:
- Username: admin
- Password: admin123

## Troubleshooting

### If PostgreSQL fails to start:
```bash
sudo systemctl status postgresql
sudo journalctl -u postgresql
```

### If Rust compilation fails:
```bash
# Install additional dependencies
sudo yum install -y gcc-c++ cmake
# or for Ubuntu:
sudo apt install -y build-essential cmake
```

### Check your EC2 public IP:
```bash
curl http://169.254.169.254/latest/meta-data/public-ipv4
```