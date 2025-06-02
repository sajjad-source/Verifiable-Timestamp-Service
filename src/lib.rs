//! Lab4 client library: ecdsa_requests
//!
//! Provides three functions for talking to the VTS service:
//! - `request_key(...)`
//! - `request_timestamp(...)`
//! - `verify_signature(...)`

pub mod config;
pub mod server;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct EcdsaVerificationKey {
    pub request: String,
    #[serde(rename = "time-requested")]
    pub time_requested: String,
    #[serde(rename = "public-key")]
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct EcdsaSignedTimestamp {
    pub request: String,
    pub message: String,
    #[serde(rename = "time-signed")]
    pub time_signed: String,
    pub signature: String,
}

pub mod ecdsa_requests {
    use super::{EcdsaSignedTimestamp, EcdsaVerificationKey};
    use base64::{Engine as _, engine::general_purpose};
    use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    use reqwest::blocking::Client;
    use serde_json::json;
    use std::error::Error;

    /// Fetches the server's public key via HTTP GET.
    ///
    /// # Example
    /// ```no_run
    /// # use lab4::ecdsa_requests::request_key;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let key = request_key("http://127.0.0.1:8008")?;
    /// println!("Got public key: {}", key.public_key);
    /// # Ok(()) }
    /// ```
    pub fn request_key(server_addr: &str) -> Result<EcdsaVerificationKey, Box<dyn Error>> {
        let url = format!("{}/key", server_addr);
        let client = Client::new();
        let resp = client.get(&url).send()?;
        if !resp.status().is_success() {
            return Err(format!("Server returned error: {}", resp.status()).into());
        }
        let key_struct: EcdsaVerificationKey = resp.json()?;
        Ok(key_struct)
    }

    /// Sends a message to be timestamped. Returns the server's full response struct.
    ///
    /// # Example
    /// ```no_run
    /// # use lab4::ecdsa_requests::request_timestamp;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let signed = request_timestamp("http://127.0.0.1:8008", "Hello")?;
    /// println!("Signed at {}: {}", signed.time_signed, signed.signature);
    /// # Ok(()) }
    /// ```
    pub fn request_timestamp(
        server_addr: &str,
        message: &str,
    ) -> Result<EcdsaSignedTimestamp, Box<dyn Error>> {
        let url = format!("{}/sign", server_addr);
        let client = Client::new();
        let body = json!({ "message": message });
        let resp = client.post(&url).json(&body).send()?;
        if !resp.status().is_success() {
            return Err(format!("Server returned error: {}", resp.status()).into());
        }
        let ts_struct: EcdsaSignedTimestamp = resp.json()?;
        Ok(ts_struct)
    }

    /// Verifies that `signed.signature` is a valid ECDSA over the bytes of
    /// `(signed.message + signed.time_signed)`, using only `key.public_key`.
    ///
    /// # Example
    /// ```no_run
    /// # use lab4::ecdsa_requests::{request_key, request_timestamp, verify_signature};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let key = request_key("http://127.0.0.1:8008")?;
    /// let signed = request_timestamp("http://127.0.0.1:8008", "Test")?;
    /// assert!(verify_signature(&signed, &key));
    /// # Ok(()) }
    /// ```
    pub fn verify_signature(signed: &EcdsaSignedTimestamp, key: &EcdsaVerificationKey) -> bool {
        // 1) Recreate data = message + time_signed
        let data = format!("{}{}", signed.message, signed.time_signed);

        // 2) Base64‐decode public key and signature
        let pub_bytes = match general_purpose::STANDARD.decode(&key.public_key) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig_bytes = match general_purpose::STANDARD.decode(&signed.signature) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // 3) Parse into k256 types
        let vk = match VerifyingKey::from_sec1_bytes(&pub_bytes) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig = match Signature::try_from(sig_bytes.as_slice()) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // 4) Verify
        vk.verify(data.as_bytes(), &sig).is_ok()
    }
}
