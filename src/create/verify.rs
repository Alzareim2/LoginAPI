// verify.rs

use crate::create::common::*;

#[get("/verify")]
async fn handle_verification_link(
    pool: Data<Pool>,
    query: Query<VerifyQuery>,
) -> Result<HttpResponse, ServiceError> {

    let mut conn = pool.get_conn().await.map_err(|_| ServiceError::InternalServerError)?;

    let result: Option<(String, i32, i32, String)> = conn.exec_first(
        r"SELECT 
            CAST(verification_token AS CHAR),
            verified, 
            verification_attempts, 
            CAST(token_expiry AS CHAR)
           FROM users WHERE verification_token = ?",
        (&query.token,),
    )
    .await.map_err(|_| ServiceError::InternalServerError)?;

    let processed_result = result.map(|(token, ver, attempts, expiry_str)| {
        let verified = ver == 1;
        let expiry_date = NaiveDateTime::parse_from_str(&expiry_str, "%Y-%m-%d %H:%M:%S").unwrap_or_else(|_| Utc::now().naive_utc());
        
        (token, verified, attempts, expiry_date)
    });

    match processed_result {
        Some((db_token, verified, attempts, expiry_date)) if db_token == query.token => {
            if verified {
                return Err(ServiceError::BadRequest("Email already verified".to_string()));
            }
            if attempts >= 5 {
                return Err(ServiceError::BadRequest("Too many verification attempts".to_string()));
            }
            if Utc::now().naive_utc() > expiry_date {
                return Err(ServiceError::BadRequest("Verification token has expired".to_string()));
            }
            conn.exec_drop(
                r"UPDATE users SET verified = true, verification_attempts = verification_attempts + 1 
                   WHERE verification_token = ?",
                (&query.token,),
            )
            .await.map_err(|_| ServiceError::InternalServerError)?;
    
            Ok(HttpResponse::Ok().json(json!({"status": "Email verified successfully"})))
        },
        Some((_, _, attempts, _)) => {
            if attempts >= 5 {
                Err(ServiceError::BadRequest("Too many verification attempts".to_string()))
            } else {
                conn.exec_drop(
                    r"UPDATE users SET verification_attempts = verification_attempts + 1 
                       WHERE verification_token = ?",
                    (&query.token,),
                )
                .await.map_err(|_| ServiceError::InternalServerError)?;
                Err(ServiceError::BadRequest("Invalid verification token".to_string()))
            }
        },
        _ => Err(ServiceError::BadRequest("Invalid request".to_string())),
    }
    
}
