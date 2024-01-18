#![allow(unused_imports)]
pub use kv_log_macro::{debug, error, info, trace};

pub mod args;
pub use args::*;

pub mod quote;

pub mod api;
pub use api::*;

pub mod store;
pub use store::*;

use poem::{
    error::InternalServerError, listener::TcpListener, web::Data, Endpoint, EndpointExt, Error,
    Middleware, Result,
};
use poem_openapi::{payload::Json, ApiResponse, Object, OpenApi, OpenApiService};
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPool, PgPoolOptions, PgSslMode};
use sqlx::types::{chrono::DateTime, chrono::Utc, Uuid};
use sqlx::{ConnectOptions, Connection, FromRow};

pub use std::collections::HashMap;
use std::env;
pub use std::str::FromStr;
pub use std::sync::Arc;
pub use std::sync::Mutex;
pub use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> std::result::Result<(), std::io::Error> {
    dotenvy::dotenv().ok();

    // Init logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::DEBUG.into())
                .with_env_var("RUST_LOG")
                .from_env_lossy(),
        )
        .init();

    // Access the version
    let sbv3_version = env!("SBV3_VERSION");
    info!("Version: {}", sbv3_version);

    // Parse args
    let args: Arc<Args> = Arc::new(Args::parse());
    args.log();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let store = PostgresStore::new(&database_url).await;
    // let store = PostgresStore::new(&args.database_url).await;
    let server_port = env::var("PORT").unwrap_or((8080).to_string());
    // let url: String = format!("http://localhost:{:?}", args.port);
    let url: String = format!("http://0.0.0.0:{:?}", server_port);
    let api_service = OpenApiService::new(Api {}, "Sb Secrets Server", "1.0").server(url);

    let ui = api_service.swagger_ui();
    let spec = api_service.spec();

    let app = poem::Route::new()
        .nest("/", api_service)
        .nest("/ui", ui)
        .at("/spec", poem::endpoint::make_sync(move |_| spec.clone()))
        .with(poem::middleware::Cors::new())
        // TODO: add middleware for opentelemetry metrics
        .data(store);

    let mut addr = format!("0.0.0.0:{}", server_port);
    info!("Server Starting on address ({}) ...", addr);

    poem::Server::new(TcpListener::bind(addr)).run(app).await
}
