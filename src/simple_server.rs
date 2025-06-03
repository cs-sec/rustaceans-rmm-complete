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

async fn get_clients(
    req: HttpRequest,
    sessions: web::Data<SessionStore>,
) -> ActixResult<HttpResponse> {
    match require_auth(&req, &sessions) {
        Ok(_session) => {
            let clients = vec![
                serde_json::json!({
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "hostname": "WINDOWS-AGENT-01",
                    "ip_address": "192.168.1.100",
                    "operating_system": "Windows",
                    "os_version": "Windows 11 Pro 22H2",
                    "last_seen": Utc::now().to_rfc3339(),
                    "agent_version": "1.0.0",
                    "status": "online"
                })
            ];
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    
    let (users, sessions) = auth::init_auth_stores();
    
    println!("Starting Rustaceans Security RMM Server (Full Console)");
    println!("Server will be available at: http://0.0.0.0:5000");
    println!("Login with: admin / admin123");

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
                    .route("/clients", web::get().to(get_clients))
                    .route("/vulnerabilities", web::get().to(get_vulnerabilities))
                    .route("/scan-results", web::get().to(get_scan_results))
            )
    })
    .bind("0.0.0.0:5000")?
    .run()
    .await
}