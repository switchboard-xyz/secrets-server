FROM rust:latest

WORKDIR /app

COPY src /app/src
COPY Cargo.toml /app/Cargo.toml

RUN cargo build --release
EXPOSE 8080
CMD ["./target/release/secrets-server"]
