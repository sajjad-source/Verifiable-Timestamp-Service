use axum::{
    Router,
    extract::Json,
    http::StatusCode,
    response::{IntoResponse, Json as JsonResponse},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use ecdsa_lib::KeyPair; // your library's KeyPair
use k256::ecdsa::Signature; // the Signature type
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use tracing::{error, info};

/// Body returned by GET /key
#[derive(Serialize)]
struct KeyResponse {
    request: &'static str,
    #[serde(rename = "time-requested")]
    time_requested: DateTime<Utc>,
    #[serde(rename = "public-key")]
    public_key: String,
}

/// Body returned by POST /sign
#[derive(Serialize)]
struct SignResponse {
    request: &'static str,
    message: String,
    #[serde(rename = "time-signed")]
    time_signed: DateTime<Utc>,
    signature: String,
}

/// Body for POST /sign requests
#[derive(Deserialize)]
struct SignRequest {
    message: String,
}

/// Builds and runs the server on port 8008
///
/// We accept the raw private and public key bytes (from `.bin` files)
/// on startup so we can reconstruct a `KeyPair` without reading from disk again.
pub async fn run_server(
    private_key_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], 8008));
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    run_server_with_listener(private_key_bytes, public_key_bytes, listener).await
}

/// Runs the server with a provided listener (useful for tests with ephemeral ports)
pub async fn run_server_with_listener(
    private_key_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
    listener: tokio::net::TcpListener,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = listener.local_addr()?;
    info!("VTS microservice starting on {}", addr);

    // Build the router:
    let app = Router::new()
        .route(
            "/key",
            get({
                let pub_bytes = public_key_bytes.clone();
                move || handle_get_key(pub_bytes.clone())
            }),
        )
        .route(
            "/sign",
            post({
                // We now pass the raw private_key_bytes and public_key_bytes
                let priv_bytes = private_key_bytes.clone();
                let pub_bytes = public_key_bytes.clone();
                move |Json(payload): Json<SignRequest>| {
                    handle_post_sign(payload, priv_bytes.clone(), pub_bytes.clone())
                }
            }),
        )
        .fallback(fallback_handler);

    // Bind and serve
    axum::serve(listener, app).await?;
    Ok(())
}

/// GET /key → returns Base64 of the public key
async fn handle_get_key(public_key: Vec<u8>) -> impl IntoResponse {
    let now = Utc::now();
    let b64_pub = general_purpose::STANDARD.encode(&public_key);

    let resp = KeyResponse {
        request: "GET",
        time_requested: now,
        public_key: b64_pub.clone(),
    };
    info!(
        "{} Request: GET /key → responding with public key {}",
        now.to_rfc3339(),
        b64_pub
    );
    (StatusCode::OK, JsonResponse(resp))
}

/// POST /sign (JSON body `{"message":"..."}`) → returns signature
///
/// Now takes both raw private-key bytes and public-key bytes. We reconstruct
/// `KeyPair` purely from these byte arrays (no need to write `.bin` files).
async fn handle_post_sign(
    payload: SignRequest,
    private_key_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
) -> impl IntoResponse {
    let now = Utc::now();
    let message = payload.message.clone();

    // Reconstruct KeyPair directly from bytes (no file I/O). The library only
    // provides `load_from_files`, but we can load from raw bytes by:
    //
    //  1) Write them to temporary files
    //  2) Add a helper in `ecdsa_lib` to load from raw slices.
    //
    // Here, I will do the temporary-file approach. Can also add a
    // `KeyPair::from_bytes(pub_key_bytes, priv_key_bytes)` method to `ecdsa_lib`.
    //
    // For now, write to a unique path to avoid race conditions, load, then delete.
    let unique_id = std::process::id();
    let priv_file = format!("private_key_{}.bin", unique_id);
    let pub_file = format!("public_key_{}.bin", unique_id);

    let _ = fs::write(&priv_file, &private_key_bytes);
    let _ = fs::write(&pub_file, &public_key_bytes);

    let keypair = match KeyPair::load_from_files(&priv_file, &pub_file) {
        Ok(kp) => {
            // Clean up temp files
            let _ = fs::remove_file(&priv_file);
            let _ = fs::remove_file(&pub_file);
            kp
        }
        Err(e) => {
            // Clean up temp files even on error
            let _ = fs::remove_file(&priv_file);
            let _ = fs::remove_file(&pub_file);
            error!("{} Failed to load KeyPair: {}", now.to_rfc3339(), e);
            let err_body = serde_json::json!({ "error": "Key load error" });
            return (StatusCode::INTERNAL_SERVER_ERROR, JsonResponse(err_body));
        }
    };

    // Sign "message + timestamp":
    // Use the same format that will be serialized to JSON
    let timestamp_str = now.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
    let data_to_sign = format!("{}{}", message, timestamp_str);
    let sig: Signature = keypair.sign(data_to_sign.as_bytes());
    let sig_b64 = general_purpose::STANDARD.encode(sig.to_vec());

    let resp = SignResponse {
        request: "POST",
        message: message.clone(),
        time_signed: now,
        signature: sig_b64.clone(),
    };

    info!(
        "{} Request: POST /sign message='{}' → response sig='{}'",
        now.to_rfc3339(),
        message,
        sig_b64
    );

    // **Return the successful response** (StatusCode::OK + JSON)
    (
        StatusCode::OK,
        JsonResponse(serde_json::to_value(resp).unwrap()),
    )
}

/// Fallback for any unsupported route
async fn fallback_handler() -> impl IntoResponse {
    let now = Utc::now();
    error!("{} Invalid request, returning 400", now.to_rfc3339());
    (StatusCode::BAD_REQUEST, "Invalid request")
}
