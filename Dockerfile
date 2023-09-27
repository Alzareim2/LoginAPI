FROM rust:latest

WORKDIR /app

COPY Cargo.lock Cargo.toml ./

COPY src/ ./src/

COPY cert.pem cert.pem
COPY env.txt env.txt
COPY key.pem key.pem
COPY openssl.txt openssl.txt
COPY withoutssl.txt withoutssl.txt

COPY .env .env

RUN cargo build --release

EXPOSE 8084

CMD ["./target/release/opensourceapi"]
