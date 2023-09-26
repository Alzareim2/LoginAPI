// sbverification.rs

use crate::create::common::*;

#[post("/resend_verification")]
async fn resend_verification(
    pool: Data<Pool>,
    info: web::Json<ResendVerificationRequest>,
) -> Result<HttpResponse, ServiceError> {

    let smtp_email = env::var("SMTP_EMAIL").expect("SMTP_EMAIL is not set in .env");
    let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD is not set in .env");
    let smtp_server = env::var("SMTP_SERVER").expect("SMTP_SERVER is not set in .env");
    let verification_base_url = env::var("RESET_PASSWORD_BASE_URL").expect("RESET_PASSWORD_BASE_URL is not set in .env");

    let mut conn = pool.get_conn().await.map_err(|_| ServiceError::InternalServerError)?;
    let result: Option<(String, bool)> = conn.exec_first(
        r"SELECT verification_token, verified FROM users WHERE email = ?",
        (&info.email,),
    )
    .await.map_err(|_| ServiceError::InternalServerError)?;

    match result {
        Some((token, verified)) if !verified => {

            let verification_link = format!("{}/verify?token={}", verification_base_url, token);
            
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
            
            Ok(HttpResponse::Ok().json(json!({"status": "success"})))
        },
        _ => Err(ServiceError::BadRequest("Email already verified or not found".to_string())),
    }
}