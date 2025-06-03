#!/bin/bash
# Standalone AWS RMM Setup - No GitHub Required

set -e

echo "=== Standalone AWS RMM Setup ==="

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

# Create project structure
echo "Creating RMM project..."
mkdir -p SecurityRMM/{src,static}
cd SecurityRMM

# Create Cargo.toml
cat > Cargo.toml << 'EOF'
[package]
name = "rustaceans-security-rmm"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1.0", features = ["full"] }
actix-web = "4.4"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
chrono = { version = "0.4", features = ["serde"] }
env_logger = "0.10"
sqlx = { version = "0.7", features = ["runtime-tokio-rustls", "postgres", "chrono", "uuid"] }
uuid = { version = "1.0", features = ["v4", "serde"] }
bcrypt = "0.15"

[[bin]]
name = "simple-rmm-server"
path = "src/simple_server.rs"
EOF

# Create basic main server file
cat > src/simple_server.rs << 'EOF'
use actix_web::{web, App, HttpResponse, HttpServer, Result as ActixResult, middleware::Logger, HttpRequest};
use serde_json;
use chrono::Utc;

mod auth;
use auth::{SessionStore, require_auth};

async fn health() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "timestamp": Utc::now().to_rfc3339()
    })))
}

async fn dashboard(
    req: HttpRequest,
    sessions: web::Data<SessionStore>,
) -> ActixResult<HttpResponse> {
    match require_auth(&req, &sessions) {
        Ok(_session) => {
            let html = include_str!("../static/index.html");
            Ok(HttpResponse::Ok()
                .content_type("text/html")
                .body(html))
        },
        Err(response) => Ok(response),
    }
}

async fn login_page() -> ActixResult<HttpResponse> {
    let html = include_str!("../static/login.html");
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(html))
}

async fn static_css() -> ActixResult<HttpResponse> {
    let css = include_str!("../static/style.css");
    Ok(HttpResponse::Ok()
        .content_type("text/css")
        .body(css))
}

async fn static_js() -> ActixResult<HttpResponse> {
    let js = include_str!("../static/app.js");
    Ok(HttpResponse::Ok()
        .content_type("application/javascript")
        .body(js))
}

async fn get_demo_data() -> ActixResult<HttpResponse> {
    let demo_data = serde_json::json!({
        "status": "success",
        "message": "RMM Server is running! Upload your files to GitHub and use the full deployment.",
        "timestamp": Utc::now().to_rfc3339()
    });
    Ok(HttpResponse::Ok().json(demo_data))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    
    let (users, sessions) = auth::init_auth_stores();
    
    println!("Starting Rustaceans Security RMM Server (Standalone Mode)");
    println!("Server will be available at: http://0.0.0.0:5000");
    println!("Login with: admin / admin123");
    println!("");
    println!("Note: This is standalone mode. Upload files to GitHub for full functionality.");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(users.clone()))
            .app_data(web::Data::new(sessions.clone()))
            .wrap(Logger::default())
            .route("/", web::get().to(dashboard))
            .route("/login", web::get().to(login_page))
            .route("/health", web::get().to(health))
            .route("/static/style.css", web::get().to(static_css))
            .route("/static/app.js", web::get().to(static_js))
            .service(
                web::scope("/api/auth")
                    .route("/login", web::post().to(auth::login))
                    .route("/logout", web::post().to(auth::logout))
                    .route("/check", web::get().to(auth::check_auth))
            )
            .service(
                web::scope("/api/v1")
                    .route("/demo", web::get().to(get_demo_data))
            )
    })
    .bind("0.0.0.0:5000")?
    .run()
    .await
}
EOF

# Create minimal auth module
cat > src/auth.rs << 'EOF'
use actix_web::{web, HttpRequest, HttpResponse, Result as ActixResult, cookie::Cookie};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use bcrypt::{hash, verify, DEFAULT_COST};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub role: String,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub username: String,
    pub role: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub message: String,
    pub user: Option<UserInfo>,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub username: String,
    pub role: String,
}

pub type SessionStore = Arc<Mutex<HashMap<String, Session>>>;
pub type UserStore = Arc<Mutex<HashMap<String, User>>>;

pub fn init_auth_stores() -> (UserStore, SessionStore) {
    let users = Arc::new(Mutex::new(HashMap::new()));
    let sessions = Arc::new(Mutex::new(HashMap::new()));
    
    let admin = User {
        id: Uuid::new_v4(),
        username: "admin".to_string(),
        password_hash: hash("admin123", DEFAULT_COST).expect("Failed to hash password"),
        role: "administrator".to_string(),
    };
    users.lock().unwrap().insert(admin.username.clone(), admin);
    
    (users, sessions)
}

pub fn require_auth(req: &HttpRequest, sessions: &SessionStore) -> Result<Session, HttpResponse> {
    if let Some(session_id) = req.cookie("rmm_session").map(|c| c.value().to_string()) {
        let sessions_guard = sessions.lock().unwrap();
        if let Some(session) = sessions_guard.get(&session_id) {
            if session.expires_at > Utc::now() {
                return Ok(session.clone());
            }
        }
    }
    
    Err(HttpResponse::Found()
        .append_header(("Location", "/login"))
        .finish())
}

pub async fn login(
    login_req: web::Json<LoginRequest>,
    users: web::Data<UserStore>,
    sessions: web::Data<SessionStore>,
) -> ActixResult<HttpResponse> {
    let users_guard = users.lock().unwrap();
    
    if let Some(user) = users_guard.get(&login_req.username) {
        if verify(&login_req.password, &user.password_hash).unwrap_or(false) {
            let session = Session {
                id: Uuid::new_v4().to_string(),
                username: user.username.clone(),
                role: user.role.clone(),
                expires_at: Utc::now() + Duration::hours(8),
            };
            let session_id = session.id.clone();
            
            sessions.lock().unwrap().insert(session_id.clone(), session);
            
            let cookie = Cookie::build("rmm_session", session_id)
                .path("/")
                .http_only(true)
                .max_age(actix_web::cookie::time::Duration::hours(8))
                .finish();
            
            return Ok(HttpResponse::Ok()
                .cookie(cookie)
                .json(LoginResponse {
                    success: true,
                    message: "Login successful".to_string(),
                    user: Some(UserInfo {
                        username: user.username.clone(),
                        role: user.role.clone(),
                    }),
                }));
        }
    }
    
    Ok(HttpResponse::Unauthorized().json(LoginResponse {
        success: false,
        message: "Invalid username or password".to_string(),
        user: None,
    }))
}

pub async fn logout(
    req: HttpRequest,
    sessions: web::Data<SessionStore>,
) -> ActixResult<HttpResponse> {
    if let Some(session_id) = req.cookie("rmm_session").map(|c| c.value().to_string()) {
        sessions.lock().unwrap().remove(&session_id);
    }
    
    let cookie = Cookie::build("rmm_session", "")
        .path("/")
        .max_age(actix_web::cookie::time::Duration::seconds(0))
        .finish();
    
    Ok(HttpResponse::Ok()
        .cookie(cookie)
        .json(serde_json::json!({"success": true, "message": "Logged out successfully"})))
}

pub async fn check_auth(
    req: HttpRequest,
    sessions: web::Data<SessionStore>,
) -> ActixResult<HttpResponse> {
    match require_auth(&req, &sessions) {
        Ok(session) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "authenticated": true,
            "user": {
                "username": session.username,
                "role": session.role
            }
        }))),
        Err(_) => Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "authenticated": false,
            "message": "Not authenticated"
        }))),
    }
}
EOF

# Create basic HTML files
cat > static/login.html << 'EOF'
<!DOCTYPE html>
<html><head><title>RMM Login</title><style>
body{font-family:Arial;background:#2c3e50;color:white;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.login{background:white;color:#333;padding:2rem;border-radius:8px;width:300px}
.login h1{text-align:center;margin-bottom:1rem}
.form-group{margin-bottom:1rem}
label{display:block;margin-bottom:0.5rem}
input{width:100%;padding:0.5rem;border:1px solid #ddd;border-radius:4px}
button{width:100%;padding:0.5rem;background:#3498db;color:white;border:none;border-radius:4px;cursor:pointer}
button:hover{background:#2980b9}
.error{color:red;margin-top:0.5rem;display:none}
</style></head><body>
<div class="login">
<h1>RMM Login</h1>
<form id="loginForm">
<div class="form-group">
<label>Username:</label><input type="text" id="username" value="admin" required>
</div>
<div class="form-group">
<label>Password:</label><input type="password" id="password" value="admin123" required>
</div>
<button type="submit">Login</button>
<div id="error" class="error"></div>
</form>
</div>
<script>
document.getElementById('loginForm').onsubmit = async function(e) {
    e.preventDefault();
    const resp = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            username: document.getElementById('username').value,
            password: document.getElementById('password').value
        })
    });
    const result = await resp.json();
    if (result.success) {
        window.location.href = '/';
    } else {
        document.getElementById('error').style.display = 'block';
        document.getElementById('error').textContent = result.message;
    }
};
</script>
</body></html>
EOF

cat > static/index.html << 'EOF'
<!DOCTYPE html>
<html><head><title>RMM Dashboard</title><style>
body{font-family:Arial;margin:0;background:#f5f5f5}
.header{background:#2c3e50;color:white;padding:1rem;display:flex;justify-content:space-between;align-items:center}
.main{padding:2rem}
.card{background:white;padding:1.5rem;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1);margin-bottom:1rem}
.btn{padding:0.5rem 1rem;background:#3498db;color:white;border:none;border-radius:4px;cursor:pointer}
.btn:hover{background:#2980b9}
</style></head><body>
<div class="header">
<h1>Security RMM Dashboard</h1>
<button onclick="logout()" class="btn">Logout</button>
</div>
<div class="main">
<div class="card">
<h2>Standalone Mode Active</h2>
<p>Your RMM server is running! This is a basic version.</p>
<p>To get full functionality:</p>
<ol>
<li>Upload all files to your GitHub repository</li>
<li>Run the full deployment script</li>
<li>Deploy Windows agents</li>
</ol>
</div>
</div>
<script>
async function logout() {
    await fetch('/api/auth/logout', {method: 'POST'});
    window.location.href = '/login';
}
</script>
</body></html>
EOF

cat > static/style.css << 'EOF'
/* Basic CSS for standalone mode */
EOF

cat > static/app.js << 'EOF'
/* Basic JS for standalone mode */
EOF

# Set environment variable
export DATABASE_URL="postgresql://rmm_user:secure_rmm_password_123@localhost:5432/rmm_db"
echo 'export DATABASE_URL="postgresql://rmm_user:secure_rmm_password_123@localhost:5432/rmm_db"' >> ~/.bashrc

# Build the server
echo "Building standalone RMM server..."
source ~/.cargo/env
cargo build --release --bin simple-rmm-server

# Get public IP
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "localhost")

echo ""
echo "=== Standalone Setup Complete ==="
echo ""
echo "Start server with:"
echo "  ./target/release/simple-rmm-server"
echo ""
echo "Access at: http://$PUBLIC_IP:5000/login"
echo "Username: admin"
echo "Password: admin123"
echo ""
echo "This is standalone mode. Upload files to GitHub for full RMM functionality."
EOF