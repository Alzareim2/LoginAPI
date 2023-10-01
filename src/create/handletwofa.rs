// handletwofa.rs

use crate::create::common::*;
use crate::create::twoauth;

pub async fn handle_2fa(
    conn: &mut Conn,
    username: &str
) -> Result<HttpResponse, ServiceError> {
    let code = twoauth::generate_2fa_code();

    let email_addr: String = conn
        .exec_first("SELECT email FROM users WHERE username = ?", (username,))
        .await
        .map_err(|e| {
            error!("Error executing DB query: {:?}", e);
            ServiceError::InternalServerError
        })?
        .ok_or(ServiceError::BadRequest("User not found".to_string()))?;

    send_2fa_email(&email_addr, "Your 2FA code", &format!("Here is your 2FA code: {}", code)).await?;

    let expiry = Utc::now()
        .checked_add_signed(Duration::minutes(3))
        .expect("Failed to calculate 2FA code expiry");
    let expiry_naive = expiry.naive_utc();
    let expiry_string = expiry_naive.to_string();

    conn.exec_drop(
        "UPDATE users SET 2fa_code = ?, 2fa_expiry = ? WHERE username = ?",
        (&code, &expiry_string, username),
    ).await.map_err(|_| ServiceError::InternalServerError)?;

    let temp_token = Uuid::new_v4().to_string();

    let token_expiry = Utc::now()
        .checked_add_signed(Duration::minutes(10))
        .expect("Failed to calculate temp token expiry");
    let token_expiry_naive = token_expiry.naive_utc();
    let token_expiry_string = token_expiry_naive.to_string();

    conn.exec_drop(
        "UPDATE users SET temp_token = ?, temp_token_expiry = ? WHERE username = ?",
        (&temp_token, &token_expiry_string, username),
    ).await.map_err(|_| ServiceError::InternalServerError)?;

    Ok(HttpResponse::Ok().json(json!({"status": "2fa_required", "temp_token": temp_token})))
}
