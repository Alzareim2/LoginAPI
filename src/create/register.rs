// register.rs

use crate::create::common::*;  

#[post("/create_account")]
async fn create_account(
    pool: Data<Pool>,
    info: web::Json<RegisterRequest>,
) -> Result<HttpResponse, ServiceError> {
    info.validate().map_err(|e| {
        let errors = e.field_errors();
        let err_str = errors
            .into_iter()
            .map(|(k, v)| format!("{}: {:?}", k, v))
            .collect::<Vec<String>>()
            .join(", ");
        ServiceError::BadRequest(err_str)
    })?;

    let smtp_email = env::var("SMTP_EMAIL").expect("SMTP_EMAIL is not set in .env");
    let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD is not set in .env");
    let smtp_server = env::var("SMTP_SERVER").expect("SMTP_SERVER is not set in .env");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET is not set in .env");
    let verification_base_url = env::var("VERIFICATION_BASE_URL").expect("VERIFICATION_BASE_URL is not set in .env");

    let hashed_password = hash(&info.password, DEFAULT_COST).map_err(|_| ServiceError::InternalServerError)?;

    let verification_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    let verification_link = format!("{}/verify?token={}", verification_base_url, verification_token);

    let email = Message::builder()
        .to(info.email.parse().unwrap())
        .from(smtp_email.parse().unwrap())  
        .subject("Please verify your email")
        .body(format!("Click on the link to verify your email: {}", verification_link))
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

        let token_expiry = Utc::now()
        .checked_add_signed(Duration::days(1))
        .expect("Failed to calculate token expiry");
    let token_expiry_naive = token_expiry.naive_utc();
    let token_expiry_string = token_expiry_naive.to_string();

    let mut conn = pool.get_conn().await.map_err(|_| ServiceError::InternalServerError)?;
    conn.exec_drop(
        r"INSERT INTO users (username, email, password, verification_token, token_expiry) 
           VALUES (?, ?, ?, ?, ?)",
        (&info.username, &info.email, &hashed_password, &verification_token, &token_expiry_string),
    )
    .await.map_err(|_| ServiceError::InternalServerError)?;

    let expiration = Utc::now()
        .checked_add_signed(Duration::days(1)) 
        .expect("Failed to calculate JWT expiration")
        .timestamp() as usize;

    let claims = Claims {
        sub: info.username.clone(),
        exp: expiration,
    };

    let secret = &jwt_secret;
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
    .map_err(|_| ServiceError::InternalServerError)?;

    Ok(HttpResponse::Ok().json(json!({"status": "success", "token": token })))
}