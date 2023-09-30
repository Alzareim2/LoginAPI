//activatetwoauth.rs

use crate::create::common::*;
use crate::create::twoauth;

#[post("/activate_2fa")]
async fn activate_2fa(
    pool: Data<Pool>,
    req: HttpRequest,
    
) -> Result<HttpResponse, ServiceError> {
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET is not set in .env");

    let auth_header = req.headers().get(http::header::AUTHORIZATION);

    if auth_header.is_none() {
        return Err(ServiceError::Unauthorized("No authorization header".to_string()));
    }

    let token_str = auth_header.unwrap().to_str().unwrap();
    let token_data = decode::<Claims>(&token_str, &DecodingKey::from_secret(jwt_secret.as_ref()), &Validation::default())
        .map_err(|_| ServiceError::Unauthorized("Invalid token".to_string()))?;

    let user_from_token = token_data.claims.sub;

    // Use `user_from_token` instead of `info.0.username` for the rest of the logic
    debug!("Received 2FA activation request for username: {}", user_from_token);

    let mut conn = pool.get_conn().await.map_err(|e| {
        error!("Error getting DB connection: {:?}", e);
        ServiceError::InternalServerError
    })?;

    let smtp_email = env::var("SMTP_EMAIL").expect("SMTP_EMAIL is not set in .env");
    let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD is not set in .env");
    let smtp_server = env::var("SMTP_SERVER").expect("SMTP_SERVER is not set in .env");

    let user_email: Option<String> = conn
        .exec_first("SELECT email FROM users WHERE username = ?", (&user_from_token,))
        .await
        .map_err(|e| {
            error!("Error executing DB query: {:?}", e);
            ServiceError::InternalServerError
        })?;

    if user_email.is_none() {
        return Err(ServiceError::BadRequest("User not found".to_string()));
    }

    let email_addr = user_email.unwrap();
    info!("Found email for user: {}", user_from_token);

    let code = twoauth::generate_2fa_code();
    let temp_token = Uuid::new_v4().to_string();

    let email = Message::builder()
        .to(email_addr.parse().unwrap())
        .from(smtp_email.parse().unwrap())
        .subject("Your 2FA activation code")
        .body(format!("Here is your 2FA activation code: {}", code))
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

    conn.exec_drop(
        "UPDATE users SET temp_2fa_code = ?, temp_token = ? WHERE username = ?",
        (&code, &temp_token, &user_from_token),
    ).await.map_err(|_| ServiceError::InternalServerError)?;

    Ok(HttpResponse::Ok().json(json!({"status": "success", "message": "2FA activation code sent. Check your email and submit the code to finalize activation.", "token": temp_token })))
}

#[post("/verify_2fa_activation")]
async fn verify_2fa_activation(
    pool: Data<Pool>,
    verification_data: web::Json<TwoFAVerificationRequest>,
) -> Result<HttpResponse, ServiceError> {
    let mut conn = pool.get_conn().await.map_err(|e| {
        error!("Error getting DB connection: {:?}", e);
        ServiceError::InternalServerError
    })?;
    
    let result: Option<(String, String)> = conn
        .exec_first("SELECT temp_2fa_code, temp_token FROM users WHERE username = ?", (&verification_data.0.username,))
        .await
        .map_err(|e| {
            error!("Error executing DB query: {:?}", e);
            ServiceError::InternalServerError
        })?;

    if let Some((stored_code, stored_token)) = result {
        if stored_code == verification_data.0.code && stored_token == verification_data.0.token {
            
            conn.exec_drop(
                "UPDATE users SET has_2fa = 1, temp_2fa_code = NULL, temp_token = NULL WHERE username = ?",
                (&verification_data.0.username,),
            ).await.map_err(|_| ServiceError::InternalServerError)?;

            Ok(HttpResponse::Ok().json(json!({"status": "success", "message": "2FA activated." })))
        } else {
            Err(ServiceError::BadRequest("Invalid code or token".to_string()))
        }
    } else {
        Err(ServiceError::BadRequest("User not found or no pending 2FA activation".to_string()))
    }
}

#[derive(Deserialize)]
struct TwoFAVerificationRequest {
    username: String,
    code: String,
    token: String,
}