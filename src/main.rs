// Main.rs with Rustls

use std::{fs::File, io::BufReader};
use actix_web::{App, HttpServer, middleware, web::Data};
use mysql_async::{Pool, Opts};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use env_logger::Builder;
use log::LevelFilter;

mod create;
mod func;

extern crate mysql_async;
#[macro_use]
extern crate validator_derive;

fn load_rustls_config() -> rustls::ServerConfig {
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    let cert_file = &mut BufReader::new(File::open("cert.pem").unwrap());
    let key_file = &mut BufReader::new(File::open("key.pem").unwrap());

    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
        .unwrap()
        .into_iter()
        .map(PrivateKey)
        .collect();

    if keys.is_empty() {
        eprintln!("Could not locate PKCS 8 private keys.");
        std::process::exit(1);
    }

    config.with_single_cert(cert_chain, keys.remove(0)).unwrap()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    std::env::set_var("RUST_LOG", "actix_web=debug");
    
    Builder::new()
        .filter(None, LevelFilter::Info) // Modifiez ceci pour ajuster le niveau de filtrage des logs.
        .init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let opts = Opts::from_url(&database_url).expect("Failed to parse database URL");
    let pool = Pool::new(opts);

    match func::ensure_database_and_table_exists(&pool).await {
        Ok(_) => println!("Database and table ready"),
        Err(e) => eprintln!("Failed to create database or table: {}", e),
    }

    let config = load_rustls_config();

    HttpServer::new(move || {
        let cors = actix_cors::Cors::default()
            .allowed_origin("https://192.168.0.39:8084")
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
            .allowed_header(http::header::CONTENT_TYPE)
            .supports_credentials()
            .max_age(3600);

        App::new()
            
            .wrap(middleware::Logger::new("%s %{User-Agent}i %m %U%q %H  %b %{Referer}i %{X-Forwarded-For}i %D"))
            .wrap(cors)
            .app_data(Data::new(pool.clone()))
            .service(create::register::create_account)
            .service(create::verify::handle_verification_link)
            .service(create::sbverification::resend_verification)
            .service(create::reset::reset_password)
            .service(create::forgot::forgot_password)
            .service(create::login::login)
            .service(create::activatetwoauth::activate_2fa)
            .service(create::deactivatetwoauth::deactivate_2fa)
            .service(create::twoauth::verify_2fa)
            .service(create::activatetwoauth::verify_2fa_activation)
    })
    .bind_rustls_021("0.0.0.0:8084", config)?
    .run()
    .await
}