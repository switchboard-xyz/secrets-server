use crate::*;
pub use clap::Parser;

/// Secret Server arguments struct
#[derive(Parser, Debug)]
pub struct Args {
    #[clap(env, default_value_t = 3000)]
    pub port: u32,
    #[clap(env)]
    pub database_url: String,
    #[clap(env)]
    pub secrets_json_config: Option<String>,
}

impl Args {
    /// Logs the port number
    pub fn log(&self) {
        info!("PORT: {}", self.port, { id: "env" });
    }
}
