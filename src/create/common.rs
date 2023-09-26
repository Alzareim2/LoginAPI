// common.rs

pub use actix_web::{post, get, web, HttpResponse, ResponseError};
pub use actix_web::web::Data;
pub use mysql_async::{Pool, prelude::Queryable};
pub use serde_json::json;
pub use thiserror::Error;
pub use jsonwebtoken::{encode, EncodingKey, Header};
pub use serde::{Deserialize, Serialize};
pub use chrono::{Utc, Duration};
pub use bcrypt::DEFAULT_COST;
pub use rand::{Rng, distributions::Alphanumeric};
pub use validator::Validate;
pub use lettre::{Message, SmtpTransport, Transport, transport::smtp::authentication::Credentials};
pub use bcrypt::hash;
pub use chrono::NaiveDateTime;
pub use actix_web::web::Query;
pub use std::env;



impl ResponseError for ServiceError {
    fn error_response(&self) -> HttpResponse {
        match *self {
            ServiceError::InternalServerError => HttpResponse::InternalServerError().json("Internal Server Error"),
            ServiceError::BadRequest(ref message) => HttpResponse::BadRequest().json(message),
        }
    }
}

#[derive(Deserialize, Validate)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
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
