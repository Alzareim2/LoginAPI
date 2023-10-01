// deactivatetwoauth.rs

use crate::create::common::*;
use crate::create::twoauth;

#[post("/request_deactivate_2fa")]
async fn request_deactivate_2fa(
    pool: Data<Pool>,
    req: HttpRequest,
) -> Result<HttpResponse, ServiceError> {
    let (email_addr, user_from_token) = extract_user_email_from_token(&req, &pool).await?; 
    let code = twoauth::generate_2fa_code();
    let temp_token = Uuid::new_v4().to_string();

    send_2fa_email(&email_addr, "Your 2FA deactivation code", &format!("Here is your 2FA deactivation code: {}", code)).await?;

    let mut conn = pool.get_conn().await.map_err(|e| {
        error!("Error getting DB connection: {:?}", e);
        ServiceError::InternalServerError
    })?;

    conn.exec_drop(
        "UPDATE users SET temp_2fa_code = ?, temp_token = ? WHERE username = ?",
        (&code, &temp_token, &user_from_token),
    ).await.map_err(|_| ServiceError::InternalServerError)?;

    Ok(HttpResponse::Ok().json(json!({"status": "success", "message": "2FA deactivation code sent. Check your email and submit the code to finalize deactivation.", "token": temp_token })))
}

#[post("/verify_2fa_deactivation")]
async fn verify_2fa_deactivation(
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
                "UPDATE users SET has_2fa = false, 2fa_code = NULL, 2fa_expiry = NULL, temp_2fa_code = NULL, temp_token = NULL WHERE username = ?",
                (&verification_data.0.username,),
            ).await.map_err(|_| ServiceError::InternalServerError)?;

            Ok(HttpResponse::Ok().json(json!({"status": "success", "message": "2FA deactivated." })))
        } else {
            Err(ServiceError::BadRequest("Invalid code or token".to_string()))
        }
    } else {
        Err(ServiceError::BadRequest("User not found or no pending 2FA deactivation".to_string()))
    }
}
