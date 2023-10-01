use crate::create::common::*;

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