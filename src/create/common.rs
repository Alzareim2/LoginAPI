// common.rs

// actix_web
pub use actix_web::{post, get, web, HttpResponse, ResponseError, HttpMessage};
pub use actix_web::web::{Data, Query};
pub use actix_web::HttpRequest;

// mysql_async
pub use mysql_async::{Pool, Conn, Row, prelude::Queryable};

// serde and serde_json
pub use serde::{Deserialize, Serialize};
pub use serde_json::json;

// chrono
pub use chrono::{Utc, Duration, NaiveDateTime};

// bcrypt
pub use bcrypt::{DEFAULT_COST, hash};

// jsonwebtoken
pub use jsonwebtoken::{encode, EncodingKey, Header, Validation, decode, DecodingKey};

// others
pub use thiserror::Error;
pub use rand::{Rng, distributions::Alphanumeric};
pub use validator::Validate;
pub use lettre::{Message, SmtpTransport, Transport, transport::smtp::authentication::Credentials};
pub use log::{info, error, debug};
pub use std::env;
pub use uuid::Uuid;


impl ResponseError for ServiceError {
    fn error_response(&self) -> HttpResponse {
        match *self {
            ServiceError::InternalServerError => HttpResponse::InternalServerError().json("Internal Server Error"),
            ServiceError::BadRequest(ref message) => HttpResponse::BadRequest().json(message),
            ServiceError::Unauthorized(ref message) => HttpResponse::Unauthorized().json(message),
        }
    }
}

#[derive(Deserialize, Validate)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct Verify2FARequest {
    pub temp_token: String,
    pub code: String,
}

#[derive(Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 3))]
    pub username: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 6))]
    pub password: String,
}

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Internal Server Error")]
    InternalServerError,
    #[error("Bad Request: {0}")]
    BadRequest(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub has_2fa: bool,
}

#[derive(Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct VerifyQuery {
    pub token: String,
}

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub email: String,
    pub token: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct TwoFAVerificationRequest {
    pub username: String,
    pub code: String,
    pub token: String,
}

pub async fn send_2fa_email(
    email_addr: &str,
    subject: &str,
    body: &str,
) -> Result<(), ServiceError> {
    let smtp_email = env::var("SMTP_EMAIL").expect("SMTP_EMAIL is not set in .env");
    let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD is not set in .env");
    let smtp_server = env::var("SMTP_SERVER").expect("SMTP_SERVER is not set in .env");

    let email = Message::builder()
        .to(email_addr.parse().unwrap())
        .from(smtp_email.parse().unwrap())
        .subject(subject)
        .body(body.to_string()) 
        .map_err(|_| ServiceError::InternalServerError)?;

    let credentials = Credentials::new(
        smtp_email,
        smtp_password
    );

    let mailer = SmtpTransport::relay(&smtp_server)
        .unwrap()
        .credentials(credentials)
        .build();

    mailer.send(&email)
        .map_err(|_| ServiceError::InternalServerError)?;
    
    Ok(()) 
}

pub async fn extract_user_email_from_token(
    req: &HttpRequest,
    pool: &Data<Pool>,
) -> Result<(String, String), ServiceError> {
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET is not set in .env");
    let auth_header = req.headers().get(http::header::AUTHORIZATION);

    if auth_header.is_none() {
        return Err(ServiceError::Unauthorized("No authorization header".to_string()));
    }

    let token_str_full = auth_header.unwrap().to_str().unwrap();
    let token_parts: Vec<&str> = token_str_full.split_whitespace().collect();
    if token_parts.len() != 2 || token_parts[0] != "Bearer" {
        return Err(ServiceError::Unauthorized("Invalid authorization header format".to_string()));
    }
    let token_str = token_parts[1];

    let token_data = decode::<Claims>(&token_str, &DecodingKey::from_secret(jwt_secret.as_ref()), &Validation::default())
    .map_err(|e| {
        error!("Error decoding JWT: {:?}", e);
        ServiceError::Unauthorized("Invalid token".to_string())
    })?;

    let user_from_token = token_data.claims.sub;

    let mut conn = pool.get_conn().await.map_err(|e| {
        error!("Error getting DB connection: {:?}", e);
        ServiceError::InternalServerError
    })?;

    let user_email: Option<String> = conn
        .exec_first("SELECT email FROM users WHERE username = ?", (&user_from_token,))
        .await
        .map_err(|e| {
            error!("Error executing DB query: {:?}", e);
            ServiceError::InternalServerError
        })?;

    Ok((user_email.ok_or(ServiceError::BadRequest("User not found".to_string()))?, user_from_token))
}

