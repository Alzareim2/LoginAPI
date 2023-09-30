// twoauth.rs

use crate::create::common::*;

pub fn generate_2fa_code() -> String {
    let code: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();
    code
}

#[post("/verify_2fa")]
async fn verify_2fa(
    pool: Data<Pool>,
    info: web::Json<Verify2FARequest>,
) -> Result<HttpResponse, ServiceError> {
    let mut conn = pool.get_conn().await.map_err(|e| {
        error!("Error getting DB connection: {:?}", e);
        ServiceError::InternalServerError
    })?;

    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET is not set in .env");

    let row: Option<Row> = conn
        .exec_first(
            "SELECT 2fa_code, DATE_FORMAT(2fa_expiry, '%Y-%m-%d %H:%i:%s') AS 2fa_expiry, username FROM users WHERE temp_token = ?",
            (&info.temp_token,),
        )
        .await.map_err(|e| {
            error!("Error executing DB query: {:?}", e);
            ServiceError::InternalServerError
        })?;

    match row {
        Some(mut row_data) => {
            let db_code: String = row_data.take("2fa_code").unwrap();
            let expiry_string: String = row_data.take("2fa_expiry").unwrap();
            let expiry = NaiveDateTime::parse_from_str(&expiry_string, "%Y-%m-%d %H:%M:%S").map_err(|_| ServiceError::InternalServerError)?;
            let username: String = row_data.take("username").unwrap();
            if db_code != info.code {
                return Err(ServiceError::BadRequest("Invalid 2FA code.".to_string()));
            }
            if Utc::now().naive_utc() > expiry {
                return Err(ServiceError::BadRequest("2FA code has expired.".to_string()));

            }

            let has_2fa: bool = row_data.take("has_2fa").unwrap_or(false);

            let expiration = Utc::now()
                .checked_add_signed(Duration::days(1))
                .expect("Failed to calculate JWT expiration")
                .timestamp() as usize;
            let username_clone = username.clone();
            let claims = Claims {
                sub: username.clone(), 
                exp: expiration,
                has_2fa: has_2fa,
            };
            let secret = &jwt_secret;
            let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
                .map_err(|e| {
                    error!("Error encoding JWT: {:?}", e);
                    ServiceError::InternalServerError
                })?;
            info!("Generated JWT for user: {}", username_clone);
            info!("About to invalidate temp_token for {}", info.temp_token);
            conn.exec_drop(
                "UPDATE users SET temp_token = NULL, temp_token_expiry = NULL WHERE temp_token = ?",
                (&info.temp_token,),
            ).await.map_err(|e| {
                error!("Error invalidating temp_token: {:?}", e);
                ServiceError::InternalServerError
            })?;
            info!("Successfully invalidated temp_token for {}", info.temp_token);
            
            Ok(HttpResponse::Ok().json(json!({"status": "success", "token": token })))
        },
        None => Err(ServiceError::BadRequest("Invalid temporary token.".to_string()))
    }
}