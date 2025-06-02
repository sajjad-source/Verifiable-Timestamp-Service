use std::fs;
use std::path::Path;

use ecdsa_lib::KeyPair;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CryptoConfig {
    pub private_key: String,
    pub public_key: String,
}

pub const PRIVATE_BIN: &str = "private_key.bin";
pub const PUBLIC_BIN: &str = "public_key.bin";

/// We simply use the library's `.bin` files as our source of truth.
/// On startup, if the `.bin` files don't exist, generate a new KeyPair and save them.
/// Then return the raw key bytes (so server.rs can pass them around if needed).
pub fn load_or_generate_keys() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    // If the private/public bin files don't exist, generate and write them:
    if !Path::new(PRIVATE_BIN).exists() || !Path::new(PUBLIC_BIN).exists() {
        // 1) Generate a new keypair
        let keypair = KeyPair::generate();

        // 2) Save to disk (two .bin files)
        keypair.save_to_files(PRIVATE_BIN, PUBLIC_BIN)?;

        // 3) Read the raw bytes back out of those files:
        let priv_bytes = fs::read(PRIVATE_BIN)?;
        let pub_bytes = fs::read(PUBLIC_BIN)?;

        // Return both raw vectors
        return Ok((priv_bytes, pub_bytes));
    }

    // Otherwise, both files exist → just read their contents:
    let priv_bytes = fs::read(PRIVATE_BIN)?;
    let pub_bytes = fs::read(PUBLIC_BIN)?;
    Ok((priv_bytes, pub_bytes))
}
