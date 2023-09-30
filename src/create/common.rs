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

