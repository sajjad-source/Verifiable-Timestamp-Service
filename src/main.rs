mod config;
mod server;

use config::load_or_generate_keys;

#[tokio::main]
async fn main() {
    // Initialize logging to stdout
    tracing_subscriber::fmt::init();

    // Load or generate keys
    let (private_key, public_key) = match load_or_generate_keys() {
        Ok(keys) => {
            tracing::info!("Loaded existing key pair");
            keys
        }
        Err(e) => {
            tracing::error!("Failed to load or generate keys: {}", e);
            std::process::exit(1);
        }
    };

    // Start the server and pass in the key pair
    server::run_server(private_key, public_key)
        .await
        .unwrap_or_else(|err| {
            tracing::error!("Server error: {}", err);
        });
}
