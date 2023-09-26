// forgot.rs

use crate::create::common::*; 

#[post("/forgot_password")]
async fn forgot_password(
    pool: Data<Pool>,
    info: web::Json<ForgotPasswordRequest>,
) -> Result<HttpResponse, ServiceError> {

    let smtp_email = env::var("SMTP_EMAIL").expect("SMTP_EMAIL is not set in .env");
    let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD is not set in .env");
    let smtp_server = env::var("SMTP_SERVER").expect("SMTP_SERVER is not set in .env");
    let reset_password_base_url = env::var("RESET_PASSWORD_BASE_URL").expect("RESET_PASSWORD_BASE_URL is not set in .env");

    let reset_password_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    let reset_link = format!("{}/reset_password?token={}", reset_password_base_url, reset_password_token);

    let email = Message::builder()
        .to(info.email.parse().unwrap())
        .from(smtp_email.parse().unwrap()) 
        .subject("Reset Your Password")
        .body(format!("Click on the link to reset your password: {}", reset_link))
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
        r"UPDATE users SET reset_password_token=?, token_expiry=? WHERE email=?",
        (&reset_password_token, &token_expiry_string, &info.email),
    )
    .await.map_err(|_| ServiceError::InternalServerError)?;

    Ok(HttpResponse::Ok().json(json!({"status": "success"})))
}
