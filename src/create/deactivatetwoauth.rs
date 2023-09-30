// deactivatetwoauth.rs

use crate::create::common::*;

#[post("/deactivate_2fa")]
async fn deactivate_2fa(
    pool: Data<Pool>,
    info: web::Json<LoginRequest>,
) -> Result<HttpResponse, ServiceError> {
    debug!("Received 2FA deactivation request for username: {}", info.0.username);

    let mut conn = pool.get_conn().await.map_err(|e| {
        error!("Error getting DB connection: {:?}", e);
        ServiceError::InternalServerError
    })?;

    conn.exec_drop(
        "UPDATE users SET has_2fa = false, 2fa_code = NULL, 2fa_expiry = NULL WHERE username = ?",
        (&info.username,),
    ).await.map_err(|e| {
        error!("Error executing DB query: {:?}", e);
        ServiceError::InternalServerError
    })?;

    info!("Deactivated 2FA for user: {}", info.0.username);

    Ok(HttpResponse::Ok().json(json!({"status": "success", "message": "2FA deactivated." })))
}