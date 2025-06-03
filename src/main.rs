use actix_web::{web, App, HttpResponse, HttpServer, Result as ActixResult, middleware::Logger};
use rustaceans_security_rmm::{
    config::Config,
    network::server::RmmServer,
    security::tls::TlsConfig,
    utils::logging::init_logging,
    utils::errors::RmmError,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config.toml")]
    config: String,
    
    /// Server mode (default) or client mode
    #[arg(short, long)]
    mode: Option<String>,
    
    /// Server address for client mode
    #[arg(short, long)]
    server: Option<String>,
    
    /// Port to bind to
    #[arg(short, long, default_value = "8000")]
    port: u16,
}

async fn health() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

async fn dashboard() -> ActixResult<HttpResponse> {
    let html = include_str!("../static/index.html");
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

#[actix_web::main]
async fn main() -> Result<(), RmmError> {
    let args = Args::parse();
    
    init_logging()?;
    info!("Starting Rustaceans Security RMM");

    // Load configuration
    let config = Config::load(&args.config).unwrap_or_else(|_| {
        info!("Using default configuration");
        Config::default()
    });

    // Initialize TLS configuration
    let tls_config = TlsConfig::new(&config.tls.cert_path, &config.tls.key_path)?;
    
    // Create server instance
    let server = Arc::new(RwLock::new(RmmServer::new(config.clone())));

    info!("Starting RMM server on 0.0.0.0:{}", args.port);

    // Start HTTP server for dashboard and API
    HttpServer::new(move || {
        let server_clone = Arc::clone(&server);
        
        App::new()
            .app_data(web::Data::new(server_clone))
            .wrap(Logger::default())
            .route("/", web::get().to(dashboard))
            .route("/health", web::get().to(health))
            .route("/static/style.css", web::get().to(static_css))
            .route("/static/app.js", web::get().to(static_js))
            .service(
                web::scope("/api/v1")
                    .route("/clients", web::get().to(get_clients))
                    .route("/scan-results", web::get().to(get_scan_results))
                    .route("/scan-results", web::post().to(submit_scan_results))
                    .route("/system-info", web::get().to(get_system_info))
            )
    })
    .bind(("0.0.0.0", args.port))?
    .run()
    .await
    .map_err(|e| RmmError::Network(format!("Server error: {}", e)))?;

    Ok(())
}

async fn get_clients(server: web::Data<Arc<RwLock<RmmServer>>>) -> ActixResult<HttpResponse> {
    let server = server.read().await;
    let clients = server.get_connected_clients().await;
    Ok(HttpResponse::Ok().json(clients))
}

async fn get_scan_results(server: web::Data<Arc<RwLock<RmmServer>>>) -> ActixResult<HttpResponse> {
    let server = server.read().await;
    let results = server.get_all_scan_results().await;
    Ok(HttpResponse::Ok().json(results))
}

async fn submit_scan_results(
    server: web::Data<Arc<RwLock<RmmServer>>>,
    payload: web::Json<serde_json::Value>
) -> ActixResult<HttpResponse> {
    let mut server = server.write().await;
    match server.store_scan_results(payload.into_inner()).await {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "message": "Scan results stored successfully"
        }))),
        Err(e) => {
            error!("Failed to store scan results: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to store scan results: {}", e)
            })))
        }
    }
}

async fn get_system_info(server: web::Data<Arc<RwLock<RmmServer>>>) -> ActixResult<HttpResponse> {
    let server = server.read().await;
    let info = server.get_system_info().await;
    Ok(HttpResponse::Ok().json(info))
}
