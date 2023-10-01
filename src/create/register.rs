// register.rs

use crate::create::common::*; 
use crate::create::registertwo::handle_email_verification;
use crate::create::registertwo::handle_database_and_token_generation;

#[post("/create_account")]
async fn create_account(
    pool: Data<Pool>,
    info: web::Json<RegisterRequest>,
) -> Result<HttpResponse, ServiceError> {
    info.validate().map_err(|e| {
        error!("Validation error: {:?}", e);
        ServiceError::BadRequest("Invalid input data.".to_string())
    })?;

    let verification_token = handle_email_verification(&info).await?;
    let token = handle_database_and_token_generation(pool, &info, &verification_token).await?;

    Ok(HttpResponse::Ok().json(json!({"status": "success", "token": token })))
}
