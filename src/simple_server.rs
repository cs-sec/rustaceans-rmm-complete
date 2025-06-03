use actix_web::{web, App, HttpResponse, HttpServer, Result as ActixResult, middleware::Logger, HttpRequest};
use serde_json;
use chrono::Utc;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

mod auth;
use auth::{SessionStore, require_auth};

// Storage for real agent data
type AgentStore = Arc<Mutex<HashMap<String, serde_json::Value>>>;

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

async fn get_clients(
    req: HttpRequest,
    sessions: web::Data<SessionStore>,
    agents: web::Data<AgentStore>,
) -> ActixResult<HttpResponse> {
    match require_auth(&req, &sessions) {
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
) -> ActixResult<HttpResponse> {
    match require_auth(&req, &sessions) {
        Ok(_session) => {
            let vulnerabilities = vec![
                serde_json::json!({
                    "id": "CVE-2024-0001",
                    "title": "Windows Kernel Privilege Escalation",
                    "severity": "Critical",
                    "cvss_score": 9.8,
                    "description": "A privilege escalation vulnerability in Windows kernel",
                    "affected_systems": ["WINDOWS-AGENT-01"],
                    "patch_available": true,
                    "discovery_date": "2024-01-15T10:30:00Z"
                }),
                serde_json::json!({
                    "id": "CVE-2024-0002", 
                    "title": "Chrome Remote Code Execution",
                    "severity": "High",
                    "cvss_score": 8.1,
                    "description": "Remote code execution in Chrome browser",
                    "affected_systems": ["WINDOWS-AGENT-01"],
                    "patch_available": true,
                    "discovery_date": "2024-01-14T14:22:00Z"
                })
            ];
            Ok(HttpResponse::Ok().json(vulnerabilities))
        },
        Err(response) => Ok(response),
    }
}

async fn get_scan_results(
    req: HttpRequest,
    sessions: web::Data<SessionStore>,
) -> ActixResult<HttpResponse> {
    match require_auth(&req, &sessions) {
        Ok(_session) => {
            let scan_results = vec![
                serde_json::json!({
                    "id": "scan-001",
                    "client_hostname": "WINDOWS-AGENT-01",
                    "scan_type": "vulnerability",
                    "timestamp": Utc::now().to_rfc3339(),
                    "status": "completed",
                    "findings_count": 15,
                    "critical_count": 2,
                    "high_count": 5,
                    "medium_count": 8
                })
            ];
            Ok(HttpResponse::Ok().json(scan_results))
        },
        Err(response) => Ok(response),
    }
}

// Agent registration endpoints (no auth required for agent communication)
async fn register_agent(
    agent_data: web::Json<serde_json::Value>,
    agents: web::Data<AgentStore>,
) -> ActixResult<HttpResponse> {
    println!("Agent registration received: {}", serde_json::to_string_pretty(&agent_data).unwrap_or_default());
    
    if let Some(agent_id) = agent_data.get("agent_id").and_then(|v| v.as_str()) {
        let mut agents_guard = agents.lock().unwrap();
        
        // Create agent record
        let mut agent_record = agent_data.clone();
        agent_record["last_seen"] = serde_json::Value::String(Utc::now().to_rfc3339());
        agent_record["status"] = serde_json::Value::String("online".to_string());
        
        agents_guard.insert(agent_id.to_string(), agent_record);
        println!("Agent {} registered and stored", agent_id);
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
    println!("Heartbeat from agent {}: {}", agent_id, serde_json::to_string_pretty(&heartbeat_data).unwrap_or_default());
    
    // Update agent data with heartbeat
    if let mut agents_guard = agents.lock().unwrap() {
        if let Some(agent_record) = agents_guard.get_mut(&agent_id) {
            agent_record["last_seen"] = serde_json::Value::String(Utc::now().to_rfc3339());
            agent_record["status"] = serde_json::Value::String("online".to_string());
            
            // Update system info if provided
            if let Some(system_info) = heartbeat_data.get("system_info") {
                agent_record["system_info"] = system_info.clone();
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
) -> ActixResult<HttpResponse> {
    println!("Scan results received: {}", serde_json::to_string_pretty(&scan_data).unwrap_or_default());
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Scan results received"
    })))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    
    let (users, sessions) = auth::init_auth_stores();
    let agents: AgentStore = Arc::new(Mutex::new(HashMap::new()));
    
    println!("Starting Rustaceans Security RMM Server (Full Console)");
    println!("Server will be available at: http://0.0.0.0:5000");
    println!("Login with: admin / admin123");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(users.clone()))
            .app_data(web::Data::new(sessions.clone()))
            .app_data(web::Data::new(agents.clone()))
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
