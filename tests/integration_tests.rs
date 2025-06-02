//! Integration tests: launches the server on an ephemeral port and uses the client API.

use ecdsa_lib::KeyPair;
use lab4::ecdsa_requests::verify_signature;
use lab4::server;
use reqwest;
use serde_json;
use std::fs;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::task;
use tokio::time::{Duration, sleep};

static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

async fn spawn_server() -> SocketAddr {
    // Generate unique filenames for this test instance
    let test_id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let private_key_file = format!("test_private_key_{}.bin", test_id);
    let public_key_file = format!("test_public_key_{}.bin", test_id);

    // 1) Generate a fresh KeyPair and write to .bin files
    let keypair = KeyPair::generate();
    keypair
        .save_to_files(&private_key_file, &public_key_file)
        .unwrap();

    // 2) Read raw bytes from those files
    let priv_bytes = fs::read(&private_key_file).unwrap();
    let pub_bytes = fs::read(&public_key_file).unwrap();

    // 3) Clean up the test files
    let _ = fs::remove_file(&private_key_file);
    let _ = fs::remove_file(&public_key_file);

    // 4) Bind to an ephemeral port (0)
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // 5) Spawn the server with those raw key bytes and the listener
    task::spawn(async move {
        server::run_server_with_listener(priv_bytes, pub_bytes, listener)
            .await
            .unwrap_or_else(|e| eprintln!("Server error: {}", e));
    });

    // 6) Give the server a moment to start up
    sleep(Duration::from_millis(100)).await;
    addr
}

#[tokio::test]
async fn test_get_key_and_structure() {
    let addr = spawn_server().await;
    let server_url = format!("http://{}", addr);

    // Use async reqwest instead of blocking client
    let client = reqwest::Client::new();
    let resp = client
        .get(&format!("{}/key", server_url))
        .send()
        .await
        .unwrap();
    let key_struct: lab4::EcdsaVerificationKey = resp.json().await.unwrap();

    assert_eq!(key_struct.request, "GET");
    // Ensure the timestamp is parseable
    key_struct
        .time_requested
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();
    assert!(!key_struct.public_key.is_empty());
}

#[tokio::test]
async fn test_post_sign_and_verify() {
    let addr = spawn_server().await;
    let server_url = format!("http://{}", addr);

    // Use async reqwest instead of blocking client
    let client = reqwest::Client::new();

    // Get key
    let resp = client
        .get(&format!("{}/key", server_url))
        .send()
        .await
        .unwrap();
    let key_struct: lab4::EcdsaVerificationKey = resp.json().await.unwrap();

    // Post sign request
    let body = serde_json::json!({ "message": "Integration test!" });
    let resp = client
        .post(&format!("{}/sign", server_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    let signed: lab4::EcdsaSignedTimestamp = resp.json().await.unwrap();

    assert_eq!(signed.request, "POST");
    assert_eq!(signed.message, "Integration test!");
    // Ensure the time_signed is valid ISO8601
    let _ = signed
        .time_signed
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();

    // Check that verify_signature returns true
    let valid = verify_signature(&signed, &key_struct);
    assert!(valid, "Signature should verify correctly");
}

#[tokio::test]
async fn test_invalid_route_returns_bad_request() {
    let addr = spawn_server().await;
    let client = reqwest::Client::new();
    let url = format!("http://{}/nonexistent", addr);
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}
