#!/bin/bash

# Clean Simple RMM Server Setup - File-based vulnerability scanning
# This creates a working RMM server without database dependencies

echo "=== Clean Simple RMM Server Setup ==="

# Create fresh project directory
rm -rf SecurityRMM 2>/dev/null
mkdir -p SecurityRMM/src SecurityRMM/static SecurityRMM/deployment/windows
cd SecurityRMM

# Create simple Cargo.toml without database dependencies
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

# Create auth.rs
cat > src/auth.rs << 'EOF'
use actix_web::{web, HttpRequest, HttpResponse, Result as ActixResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use sha2::{Sha256, Digest};

pub type UserStore = Arc<Mutex<HashMap<String, User>>>;
pub type SessionStore = Arc<Mutex<HashMap<String, Session>>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password_hash: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: Uuid,
    pub username: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

pub fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn init_auth_stores() -> (UserStore, SessionStore) {
    let users = Arc::new(Mutex::new(HashMap::new()));
    let sessions = Arc::new(Mutex::new(HashMap::new()));
    
    // Add default admin user
    let admin_user = User {
        username: "admin".to_string(),
        password_hash: hash_password("admin123"),
        role: "admin".to_string(),
    };
    
    users.lock().unwrap().insert("admin".to_string(), admin_user);
    
    (users, sessions)
}

pub async fn login(
    login_req: web::Json<LoginRequest>,
    users: web::Data<UserStore>,
    sessions: web::Data<SessionStore>,
) -> ActixResult<HttpResponse> {
    let password_hash = hash_password(&login_req.password);
    
    let users_guard = users.lock().unwrap();
    if let Some(user) = users_guard.get(&login_req.username) {
        if user.password_hash == password_hash {
            let session_id = Uuid::new_v4().to_string();
            let session = Session {
                id: session_id.clone(),
                user_id: Uuid::new_v4(),
                username: user.username.clone(),
                created_at: Utc::now(),
            };
            
            sessions.lock().unwrap().insert(session_id.clone(), session);
            
            let cookie = format!("session_id={}; Path=/; HttpOnly", session_id);
            return Ok(HttpResponse::Ok()
                .append_header(("Set-Cookie", cookie))
                .json(serde_json::json!({
                    "success": true,
                    "message": "Login successful",
                    "user": {
                        "username": user.username,
                        "role": user.role
                    }
                })));
        }
    }
    
    Ok(HttpResponse::Unauthorized().json(serde_json::json!({
        "success": false,
        "message": "Invalid credentials"
    })))
}

pub async fn logout(
    req: HttpRequest,
    sessions: web::Data<SessionStore>,
) -> ActixResult<HttpResponse> {
    if let Some(cookie_header) = req.headers().get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie in cookie_str.split(';') {
                let parts: Vec<&str> = cookie.trim().split('=').collect();
                if parts.len() == 2 && parts[0] == "session_id" {
                    sessions.lock().unwrap().remove(parts[1]);
                    break;
                }
            }
        }
    }
    
    Ok(HttpResponse::Ok()
        .append_header(("Set-Cookie", "session_id=; Path=/; HttpOnly; Max-Age=0"))
        .json(serde_json::json!({
            "success": true,
            "message": "Logged out successfully"
        })))
}

pub async fn check_auth(
    req: HttpRequest,
    sessions: web::Data<SessionStore>,
) -> ActixResult<HttpResponse> {
    match require_auth(&req, &sessions).await {
        Ok(session) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "authenticated": true,
            "user": {
                "username": session.username
            }
        }))),
        Err(_) => Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "authenticated": false
        })))
    }
}

pub async fn require_auth(
    req: &HttpRequest,
    sessions: &SessionStore,
) -> Result<Session, HttpResponse> {
    if let Some(cookie_header) = req.headers().get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie in cookie_str.split(';') {
                let parts: Vec<&str> = cookie.trim().split('=').collect();
                if parts.len() == 2 && parts[0] == "session_id" {
                    let sessions_guard = sessions.lock().unwrap();
                    if let Some(session) = sessions_guard.get(parts[1]) {
                        return Ok(session.clone());
                    }
                }
            }
        }
    }
    
    Err(HttpResponse::Found()
        .append_header(("Location", "/login"))
        .finish())
}
EOF

# Create simple_server.rs with vulnerability scanning
cat > src/simple_server.rs << 'EOF'
use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse, Result as ActixResult, middleware::Logger};
use serde_json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::Utc;

mod auth;
use auth::{SessionStore, require_auth};

type AgentStore = Arc<Mutex<HashMap<String, serde_json::Value>>>;
type VulnerabilityStore = Arc<Mutex<HashMap<String, serde_json::Value>>>;

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
    match require_auth(&req, &sessions).await {
        Ok(_) => {
            let html = include_str!("../static/index.html");
            Ok(HttpResponse::Ok().content_type("text/html").body(html))
        },
        Err(response) => Ok(response),
    }
}

async fn login_page() -> ActixResult<HttpResponse> {
    let html = include_str!("../static/login.html");
    Ok(HttpResponse::Ok().content_type("text/html").body(html))
}

async fn static_css() -> ActixResult<HttpResponse> {
    let css = include_str!("../static/style.css");
    Ok(HttpResponse::Ok().content_type("text/css").body(css))
}

async fn static_js() -> ActixResult<HttpResponse> {
    let js = include_str!("../static/app.js");
    Ok(HttpResponse::Ok().content_type("application/javascript").body(js))
}

async fn get_clients(
    req: HttpRequest,
    sessions: web::Data<SessionStore>,
    agents: web::Data<AgentStore>,
) -> ActixResult<HttpResponse> {
    match require_auth(&req, &sessions).await {
        Ok(_session) => {
            let agents_guard = agents.lock().unwrap();
            let clients: Vec<serde_json::Value> = agents_guard.values().cloned().collect();
            Ok(HttpResponse::Ok().json(clients))
        },
        Err(response) => Ok(response),
    }
}

async fn get_vulnerabilities(
    req: HttpRequest,
    sessions: web::Data<SessionStore>,
    vulnerability_store: web::Data<VulnerabilityStore>,
) -> ActixResult<HttpResponse> {
    match require_auth(&req, &sessions).await {
        Ok(_session) => {
            let vuln_guard = vulnerability_store.lock().unwrap();
            let vulnerabilities: Vec<serde_json::Value> = vuln_guard.values().cloned().collect();
            Ok(HttpResponse::Ok().json(vulnerabilities))
        },
        Err(response) => Ok(response),
    }
}

async fn get_scan_results(
    req: HttpRequest,
    sessions: web::Data<SessionStore>,
) -> ActixResult<HttpResponse> {
    match require_auth(&req, &sessions).await {
        Ok(_session) => {
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "scan_results": []
            })))
        },
        Err(response) => Ok(response),
    }
}

async fn register_agent(
    agent_data: web::Json<serde_json::Value>,
    agents: web::Data<AgentStore>,
) -> ActixResult<HttpResponse> {
    println!("Agent registration received: {}", serde_json::to_string_pretty(&agent_data).unwrap_or_default());
    
    if let Some(agent_id) = agent_data.get("agent_id").and_then(|v| v.as_str()) {
        let mut agents_guard = agents.lock().unwrap();
        
        let empty_obj = serde_json::json!({});
        let system_info = agent_data.get("system_info").unwrap_or(&empty_obj);
        
        let agent_record = serde_json::json!({
            "id": agent_id,
            "hostname": system_info.get("hostname").and_then(|v| v.as_str()).unwrap_or("Unknown Host"),
            "ip": system_info.get("ip_address").and_then(|v| v.as_str()).unwrap_or("N/A"),
            "os": system_info.get("os").and_then(|v| v.as_str()).unwrap_or("Unknown"),
            "os_version": system_info.get("os_version").and_then(|v| v.as_str()).unwrap_or("Unknown"),
            "last_seen": Utc::now().to_rfc3339(),
            "agent_version": system_info.get("agent_version").and_then(|v| v.as_str()).unwrap_or("1.0.0"),
            "status": "online",
            "online": true,
            "cpu_usage": system_info.get("cpu_usage").and_then(|v| v.as_f64()).unwrap_or(0.0),
            "memory_usage": system_info.get("memory_usage").and_then(|v| v.as_f64()).unwrap_or(0.0),
            "disk_usage": system_info.get("disk_usage").and_then(|v| v.as_f64()).unwrap_or(0.0)
        });
        
        agents_guard.insert(agent_id.to_string(), agent_record);
        println!("Agent {} registered successfully", agent_id);
    }
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Agent registered successfully"
    })))
}

async fn agent_heartbeat(
    path: web::Path<String>,
    heartbeat_data: web::Json<serde_json::Value>,
    agents: web::Data<AgentStore>,
) -> ActixResult<HttpResponse> {
    let agent_id = path.into_inner();
    println!("Heartbeat from agent {}", agent_id);
    
    let mut agents_guard = agents.lock().unwrap();
    if let Some(agent_record) = agents_guard.get_mut(&agent_id) {
        agent_record["last_seen"] = serde_json::Value::String(Utc::now().to_rfc3339());
        agent_record["status"] = serde_json::Value::String("online".to_string());
        agent_record["online"] = serde_json::Value::Bool(true);
        
        if let Some(system_info) = heartbeat_data.get("system_info") {
            if let Some(hostname) = system_info.get("hostname") {
                agent_record["hostname"] = hostname.clone();
            }
            if let Some(ip) = system_info.get("ip_address") {
                agent_record["ip"] = ip.clone();
            }
            if let Some(os) = system_info.get("os") {
                agent_record["os"] = os.clone();
            }
            if let Some(cpu_usage) = system_info.get("cpu_usage") {
                agent_record["cpu_usage"] = cpu_usage.clone();
            }
            if let Some(memory_usage) = system_info.get("memory_usage") {
                agent_record["memory_usage"] = memory_usage.clone();
            }
            if let Some(disk_usage) = system_info.get("disk_usage") {
                agent_record["disk_usage"] = disk_usage.clone();
            }
        }
    }
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Heartbeat received"
    })))
}

async fn receive_scan_results(
    scan_data: web::Json<serde_json::Value>,
    vulnerability_store: web::Data<VulnerabilityStore>,
) -> ActixResult<HttpResponse> {
    println!("Scan results received: {}", serde_json::to_string_pretty(&scan_data).unwrap_or_default());
    
    if let Some(findings) = scan_data.get("findings").and_then(|f| f.as_array()) {
        let mut vuln_guard = vulnerability_store.lock().unwrap();
        
        for finding in findings {
            if let Some(id) = finding.get("id").and_then(|i| i.as_str()) {
                let vulnerability = serde_json::json!({
                    "id": id,
                    "agent_id": scan_data.get("agent_id").and_then(|a| a.as_str()).unwrap_or("unknown"),
                    "severity": finding.get("severity").and_then(|s| s.as_str()).unwrap_or("Unknown"),
                    "title": finding.get("title").and_then(|t| t.as_str()).unwrap_or("No title"),
                    "description": finding.get("description").and_then(|d| d.as_str()).unwrap_or("No description"),
                    "category": finding.get("category").and_then(|c| c.as_str()).unwrap_or("General"),
                    "affected_component": finding.get("affected_component").and_then(|a| a.as_str()).unwrap_or("Unknown"),
                    "remediation": finding.get("remediation").and_then(|r| r.as_str()).unwrap_or("No remediation available"),
                    "confidence": finding.get("confidence").and_then(|c| c.as_f64()).unwrap_or(0.0),
                    "timestamp": scan_data.get("timestamp").and_then(|t| t.as_str()).unwrap_or(&Utc::now().to_rfc3339()),
                    "scan_type": scan_data.get("scan_type").and_then(|s| s.as_str()).unwrap_or("unknown"),
                    "cve_id": finding.get("cve_id"),
                    "status": "open"
                });
                
                vuln_guard.insert(format!("{}_{}", scan_data.get("agent_id").and_then(|a| a.as_str()).unwrap_or("unknown"), id), vulnerability);
            }
        }
    }
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Scan results processed and stored",
        "findings_processed": scan_data.get("findings").and_then(|f| f.as_array()).map(|f| f.len()).unwrap_or(0)
    })))
}

async fn get_scan_summary(
    req: HttpRequest,
    sessions: web::Data<SessionStore>,
    vulnerability_store: web::Data<VulnerabilityStore>,
) -> ActixResult<HttpResponse> {
    match require_auth(&req, &sessions).await {
        Ok(_session) => {
            let vuln_guard = vulnerability_store.lock().unwrap();
            let vulnerabilities: Vec<&serde_json::Value> = vuln_guard.values().collect();
            
            let mut critical_count = 0;
            let mut high_count = 0;
            let mut medium_count = 0;
            let mut low_count = 0;
            
            for vuln in &vulnerabilities {
                match vuln.get("severity").and_then(|s| s.as_str()).unwrap_or("Unknown") {
                    "Critical" => critical_count += 1,
                    "High" => high_count += 1,
                    "Medium" => medium_count += 1,
                    "Low" => low_count += 1,
                    _ => {}
                }
            }
            
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "total_vulnerabilities": vulnerabilities.len(),
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "last_scan": Utc::now().to_rfc3339()
            })))
        },
        Err(response) => Ok(response),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    
    let (users, sessions) = auth::init_auth_stores();
    let agents: AgentStore = Arc::new(Mutex::new(HashMap::new()));
    let vulnerabilities: VulnerabilityStore = Arc::new(Mutex::new(HashMap::new()));
    
    println!("Starting Rustaceans Security RMM Server");
    println!("Server will be available at: http://0.0.0.0:5000");
    println!("Login with: admin / admin123");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(users.clone()))
            .app_data(web::Data::new(sessions.clone()))
            .app_data(web::Data::new(agents.clone()))
            .app_data(web::Data::new(vulnerabilities.clone()))
            .wrap(Logger::default())
            .route("/", web::get().to(dashboard))
            .route("/login", web::get().to(login_page))
            .route("/health", web::get().to(health))
            .route("/static/style.css", web::get().to(static_css))
            .route("/static/app.js", web::get().to(static_js))
            .route("/logout", web::post().to(auth::logout))
            .service(
                web::scope("/api")
                    .route("/status", web::get().to(auth::check_auth))
                    .route("/clients", web::get().to(get_clients))
                    .route("/clients", web::post().to(register_agent))
                    .route("/clients/{agent_id}/heartbeat", web::post().to(agent_heartbeat))
                    .route("/vulnerabilities", web::get().to(get_vulnerabilities))
                    .route("/vulnerabilities/summary", web::get().to(get_scan_summary))
                    .route("/scan-results", web::get().to(get_scan_results))
                    .route("/scan-results", web::post().to(receive_scan_results))
                    .service(
                        web::scope("/auth")
                            .route("/login", web::post().to(auth::login))
                            .route("/logout", web::post().to(auth::logout))
                            .route("/check", web::get().to(auth::check_auth))
                    )
            )
    })
    .bind("0.0.0.0:5000")?
    .run()
    .await
}
EOF

echo "Downloading static files..."
# Static files would need to be downloaded from GitHub or created locally
# For now, create minimal versions

# Build the project
echo "Building project..."
cargo build --bin simple-rmm-server

if [ $? -eq 0 ]; then
    echo ""
    echo "=== SUCCESS: Clean RMM Server Ready! ==="
    echo ""
    echo "To start: cargo run --bin simple-rmm-server"
    echo "Available at: http://0.0.0.0:5000"
    echo "Login: admin / admin123"
else
    echo "Build failed. Check errors above."
fi
EOF

chmod +x deployment/clean-simple-rmm-setup.sh