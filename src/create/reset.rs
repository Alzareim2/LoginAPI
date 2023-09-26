// reset.rs

use crate::create::common::*; 

#[post("/reset_password")]
async fn reset_password(
    pool: Data<Pool>,
    info: web::Json<ResetPasswordRequest>,
) -> Result<HttpResponse, ServiceError> {
    let mut conn = pool.get_conn().await.map_err(|_| ServiceError::InternalServerError)?;

    let result: Option<(String, String)> = conn.exec_first(
        r"SELECT reset_password_token, token_expiry FROM users WHERE email = ?",
        (&info.email,)
    )
    .await.map_err(|_| ServiceError::InternalServerError)?;

    match result {
        Some((db_token, token_expiry_string)) => {
            let token_expiry = NaiveDateTime::parse_from_str(&token_expiry_string, "%Y-%m-%d %H:%M:%S")
                .map_err(|_| ServiceError::InternalServerError)?;

            if db_token != info.token {
                return Err(ServiceError::BadRequest("Invalid reset token.".to_string()));
            }

            let current_time = Utc::now().naive_utc();
            if current_time > token_expiry {
                return Err(ServiceError::BadRequest("Reset token has expired.".to_string()));
            }

            let hashed_password = hash(&info.new_password, DEFAULT_COST).map_err(|_| ServiceError::InternalServerError)?;

            conn.exec_drop(
                r"UPDATE users SET password = ?, reset_password_token = NULL, token_expiry = NULL WHERE email = ?",
                (&hashed_password, &info.email),
            )
            .await.map_err(|_| ServiceError::InternalServerError)?;

            Ok(HttpResponse::Ok().json(json!({"status": "success"})))
        },
        None => Err(ServiceError::BadRequest("Email not found.".to_string())),
    }
}
