//activatetwoauth.rs

use crate::create::common::*;
use crate::create::twoauth;

#[post("/activate_2fa")]
async fn activate_2fa(
    pool: Data<Pool>,
    req: HttpRequest,
) -> Result<HttpResponse, ServiceError> {
    let (email_addr, user_from_token) = extract_user_email_from_token(&req, &pool).await?;  // <-- Destructure the tuple
    let code = twoauth::generate_2fa_code();
    let temp_token = Uuid::new_v4().to_string();

    send_2fa_email(&email_addr, "Your 2FA activation code", &format!("Here is your 2FA activation code: {}", code)).await?;

    let mut conn = pool.get_conn().await.map_err(|e| {
        error!("Error getting DB connection: {:?}", e);
        ServiceError::InternalServerError
    })?;

    conn.exec_drop(
        "UPDATE users SET temp_2fa_code = ?, temp_token = ? WHERE username = ?",
        (&code, &temp_token, &user_from_token),
    ).await.map_err(|_| ServiceError::InternalServerError)?;

    Ok(HttpResponse::Ok().json(json!({"status": "success", "message": "2FA activation code sent. Check your email and submit the code to finalize activation.", "token": temp_token })))
}