// login.rs

use crate::create::common::*;
use crate::create::handletwofa;

#[post("/login")]
async fn login(
    pool: Data<Pool>,
    info: web::Json<LoginRequest>,
) -> Result<HttpResponse, ServiceError> {
    let mut conn = pool.get_conn().await.map_err(|e| {
        error!("Error getting DB connection: {:?}", e);
        ServiceError::InternalServerError
    })?;

    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET is not set in .env");

    let row: Option<(String, bool, bool)> = conn
        .exec_first(
            "SELECT password, verified, has_2fa FROM users WHERE username = ?",
            (&info.0.username,),
        )
        .await.map_err(|e| {
            error!("Error executing DB query: {:?}", e);
            ServiceError::InternalServerError
        })?;

    match row {
        Some((hashed_password, is_verified, has_2fa)) => {
            if bcrypt::verify(&info.0.password, &hashed_password).is_err() {
                error!("Password verification failed for user: {}", info.0.username);
                return Err(ServiceError::BadRequest("Invalid username or password. If you haven't verified your email, please do so.".to_string()));
            }
            info!("Password verified for user: {}", info.0.username);

            if !is_verified {
                error!("User not verified: {}", info.0.username);
                return Err(ServiceError::BadRequest("Invalid username or password. If you haven't verified your email, please do so.".to_string()));
            }
            info!("User is verified: {}", info.0.username);

            if has_2fa {
                return handletwofa::handle_2fa(&mut conn, &info.0.username).await;
            }

            let expiration = Utc::now()
                .checked_add_signed(Duration::days(1))
                .expect("Failed to calculate JWT expiration")
                .timestamp() as usize;

            let claims = Claims {
                sub: info.0.username.clone(),
                exp: expiration,
                has_2fa: has_2fa,  
            };

            let secret = &jwt_secret;
            let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
                .map_err(|e| {
                    error!("Error encoding JWT: {:?}", e);
                    ServiceError::InternalServerError
                })?;
            info!("Generated JWT for user: {}", info.0.username);

            Ok(HttpResponse::Ok().json(json!({"status": "success", "token": token })))
        },
        None => Err(ServiceError::BadRequest("Invalid username or password. If you haven't verified your email, please do so.".to_string()))
    }
}