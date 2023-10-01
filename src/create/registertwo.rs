// register func

use crate::create::common::*;  

// Part 1: Email Verification
pub async fn handle_email_verification(
    info: &web::Json<RegisterRequest>
) -> Result<String, ServiceError> {
    let email_verification_enabled: bool = env::var("EMAIL_VERIFICATION_ENABLED")
        .unwrap_or("false".to_string())
        .to_lowercase() == "true";

    if !email_verification_enabled {
        return Ok(String::new());
    }

    let smtp_email = env::var("SMTP_EMAIL").map_err(|_| {
        error!("SMTP_EMAIL is missing from .env");
        ServiceError::InternalServerError
    })?;

    let smtp_password = env::var("SMTP_PASSWORD").map_err(|_| {
        error!("SMTP_PASSWORD is missing from .env");
        ServiceError::InternalServerError
    })?;

    let smtp_server = env::var("SMTP_SERVER").map_err(|_| {
        error!("SMTP_SERVER is missing from .env");
        ServiceError::InternalServerError
    })?;

    let verification_base_url = env::var("VERIFICATION_BASE_URL").map_err(|_| {
        error!("VERIFICATION_BASE_URL is missing from .env");
        ServiceError::InternalServerError
    })?;

    let verification_token = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    let verification_link = format!("{}/verify?token={}", verification_base_url, verification_token);

    let email = Message::builder()
        .to(info.email.parse().map_err(|_| {
            error!("Failed to parse email");
            ServiceError::InternalServerError
        })?)
        .from(smtp_email.parse().map_err(|_| {
            error!("Failed to parse SMTP email");
            ServiceError::InternalServerError
        })?)
        .subject("Please verify your email")
        .body(format!("Click on the link to verify your email: {}", verification_link))
        .map_err(|_| {
            error!("Failed to create email message");
            ServiceError::InternalServerError
        })?;

    let credentials = Credentials::new(smtp_email, smtp_password);

    let mailer = SmtpTransport::relay(&smtp_server)
        .map_err(|_| {
            error!("Failed to create SMTP transport");
            ServiceError::InternalServerError
        })?
        .credentials(credentials)
        .build();

    mailer.send(&email)
        .map_err(|_| {
            error!("Failed to send email");
            ServiceError::InternalServerError
        })?;

    Ok(verification_token)
}

// Part 2: Database and Token Generation
pub async fn handle_database_and_token_generation(
    pool: Data<Pool>,
    info: &web::Json<RegisterRequest>,
    verification_token: &str
) -> Result<String, ServiceError> {
    let is_verified = verification_token.is_empty();

    let hashed_password = hash(&info.password, DEFAULT_COST).map_err(|e| {
        error!("Hashing error: {:?}", e);
        ServiceError::InternalServerError
    })?;

    let token_expiry = Utc::now()
        .checked_add_signed(Duration::days(1))
        .ok_or_else(|| {
            error!("Failed to calculate token expiry");
            ServiceError::InternalServerError
        })?;
    let token_expiry_naive = token_expiry.naive_utc();
    let token_expiry_string = token_expiry_naive.to_string();

    let mut conn = pool.get_conn().await.map_err(|e| {
        error!("Error getting DB connection: {:?}", e);
        ServiceError::InternalServerError
    })?;
    
    conn.exec_drop(
        r"INSERT INTO users (username, email, password, verification_token, token_expiry, verified) 
           VALUES (?, ?, ?, ?, ?, ?)",
        (&info.username, &info.email, &hashed_password, &verification_token, &token_expiry_string, &is_verified),
    )
    .await.map_err(|e| {
        error!("Error executing DB query: {:?}", e);
        ServiceError::InternalServerError
    })?;

    let expiration = Utc::now()
        .checked_add_signed(Duration::days(1)) 
        .ok_or_else(|| {
            error!("Failed to calculate JWT expiration");
            ServiceError::InternalServerError
        })?
        .timestamp() as usize;

    let has_2fa = false; 
    let jwt_secret = env::var("JWT_SECRET").map_err(|_| {
        error!("JWT_SECRET is missing from .env");
        ServiceError::InternalServerError
    })?;
    let claims = Claims {
        sub: info.username.clone(),
        exp: expiration,
        has_2fa: has_2fa,
    };

    let secret = &jwt_secret;
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
    .map_err(|e| {
        error!("Error encoding JWT: {:?}", e);
        ServiceError::InternalServerError
    })?;

    Ok(token)
}
