use actix_web::{web, HttpRequest, HttpResponse, Result as ActixResult, cookie::Cookie, http::header};
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
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub user_id: Uuid,
    pub username: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
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

pub fn create_default_admin() -> User {
    let password_hash = hash("admin123", DEFAULT_COST).expect("Failed to hash password");
    
    User {
        id: Uuid::new_v4(),
        username: "admin".to_string(),
        password_hash,
        role: "administrator".to_string(),
        created_at: Utc::now(),
        last_login: None,
    }
}

pub fn init_auth_stores() -> (UserStore, SessionStore) {
    let users = Arc::new(Mutex::new(HashMap::new()));
    let sessions = Arc::new(Mutex::new(HashMap::new()));
    
    // Add default admin user
    let admin = create_default_admin();
    users.lock().unwrap().insert(admin.username.clone(), admin);
    
    (users, sessions)
}

pub fn create_session(user: &User) -> Session {
    Session {
        id: Uuid::new_v4().to_string(),
        user_id: user.id,
        username: user.username.clone(),
        role: user.role.clone(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(8), // 8-hour session
    }
}

pub fn get_session_from_request(req: &HttpRequest, sessions: &SessionStore) -> Option<Session> {
    // Try to get session ID from cookie
    let session_id = req
        .cookie("rmm_session")
        .map(|cookie| cookie.value().to_string())
        .or_else(|| {
            // Fallback to Authorization header
            req.headers()
                .get("Authorization")
                .and_then(|header| header.to_str().ok())
                .and_then(|auth| auth.strip_prefix("Bearer "))
                .map(|token| token.to_string())
        })?;

    let sessions_guard = sessions.lock().unwrap();
    let session = sessions_guard.get(&session_id)?.clone();
    
    // Check if session is expired
    if session.expires_at < Utc::now() {
        return None;
    }
    
    Some(session)
}

pub async fn login(
    login_req: web::Json<LoginRequest>,
    users: web::Data<UserStore>,
    sessions: web::Data<SessionStore>,
) -> ActixResult<HttpResponse> {
    let users_guard = users.lock().unwrap();
    
    if let Some(user) = users_guard.get(&login_req.username) {
        if verify(&login_req.password, &user.password_hash).unwrap_or(false) {
            // Create new session
            let session = create_session(user);
            let session_id = session.id.clone();
            
            // Store session
            sessions.lock().unwrap().insert(session_id.clone(), session);
            
            // Create secure cookie
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
    if let Some(session) = get_session_from_request(&req, &sessions) {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "authenticated": true,
            "user": {
                "username": session.username,
                "role": session.role
            }
        })))
    } else {
        Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "authenticated": false,
            "message": "Not authenticated"
        })))
    }
}

// Middleware to protect routes
pub fn require_auth(
    req: &HttpRequest,
    sessions: &SessionStore,
) -> Result<Session, HttpResponse> {
    if let Some(session) = get_session_from_request(req, sessions) {
        Ok(session)
    } else {
        Err(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Authentication required",
            "redirect": "/login"
        })))
    }
}