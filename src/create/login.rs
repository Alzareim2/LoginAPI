// login.rs

use crate::create::common::*;  

#[post("/login")]
async fn login(
    pool: Data<Pool>,
    info: web::Json<LoginRequest>,
) -> Result<HttpResponse, ServiceError> {
    let mut conn = pool.get_conn().await.map_err(|_| ServiceError::InternalServerError)?;

    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET is not set in .env");

    let row: Option<(String, bool)> = conn
        .exec_first(
            "SELECT password, is_verified FROM users WHERE username = ?",
            (&info.username,),
        )
        .await.map_err(|_| ServiceError::InternalServerError)?;

    match row {
        Some((hashed_password, is_verified)) => {
            if bcrypt::verify(&info.password, &hashed_password).is_err() || !is_verified {
                return Err(ServiceError::BadRequest("Invalid username or password. If you haven't verified your email, please do so.".to_string()));
            }
            
            let expiration = Utc::now()
                .checked_add_signed(Duration::days(1)) 
                .expect("Failed to calculate JWT expiration")
                .timestamp() as usize;

            let claims = Claims {
                sub: info.username.clone(),
                exp: expiration,
            };

            let secret = &jwt_secret;
            let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
                .map_err(|_| ServiceError::InternalServerError)?;

            Ok(HttpResponse::Ok().json(json!({"status": "success", "token": token })))
        },
        None => Err(ServiceError::BadRequest("Invalid username or password. If you haven't verified your email, please do so.".to_string()))
    }
}

