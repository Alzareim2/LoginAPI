use mysql_async::{Pool, prelude::Queryable};

pub async fn ensure_database_and_table_exists(pool: &Pool) -> Result<(), mysql_async::Error> {
    let mut conn = pool.get_conn().await?;

    conn.query_drop("CREATE DATABASE IF NOT EXISTS `u515622069_Letsport`").await?;
    conn.query_drop("USE `u515622069_Letsport`").await?;

    let tables: Vec<String> = conn
        .query("SHOW TABLES LIKE 'users'")
        .await?;

        if tables.is_empty() {
            conn.query_drop(
                r"CREATE TABLE users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) NOT NULL UNIQUE,
                    email VARCHAR(255) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL,
                    verification_token VARCHAR(255) NOT NULL,
                    verified BOOLEAN DEFAULT FALSE,
                    verification_attempts INT DEFAULT 0,
                    token_expiry TIMESTAMP NULL,
                    reset_password_token VARCHAR(255),
                    reset_token_expiry TIMESTAMP NULL,
                    has_2fa BOOLEAN DEFAULT FALSE,
                    2fa_code VARCHAR(6),
                    2fa_expiry TIMESTAMP NULL,
                    temp_2fa_code VARCHAR(6),
                    temp_token VARCHAR(36), 
                    temp_token_expiry TIMESTAMP NULL
                )",
            )
            .await?;
            
        
            conn.query_drop(r"CREATE INDEX idx_username ON users(username)").await?;
            conn.query_drop(r"CREATE INDEX idx_email ON users(email)").await?;
            conn.query_drop(r"CREATE INDEX idx_verification_token ON users(verification_token)").await?;
            conn.query_drop(r"CREATE INDEX idx_2fa_code ON users(2fa_code)").await?;
        }

    Ok(())
}
