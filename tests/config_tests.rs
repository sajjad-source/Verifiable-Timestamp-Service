//! Unit tests for Option A (.bin‐only) loading/generation

use lab4::config::load_or_generate_keys;
use std::fs;
use std::path::Path;

const PRIV: &str = "private_key.bin";
const PUB: &str = "public_key.bin";

#[test]
fn test_generate_and_load_keys_bin() {
    // 1) Remove any existing .bin files
    let _ = fs::remove_file(PRIV);
    let _ = fs::remove_file(PUB);

    // 2) First call: should create the two .bin files and return their bytes
    let (priv_bytes1, pub_bytes1) = load_or_generate_keys().unwrap();
    assert!(Path::new(PRIV).exists());
    assert!(Path::new(PUB).exists());
    assert!(!priv_bytes1.is_empty());
    assert!(!pub_bytes1.is_empty());

    // 3) Second call: should read the same bytes back from disk
    let (priv_bytes2, pub_bytes2) = load_or_generate_keys().unwrap();
    assert_eq!(priv_bytes1, priv_bytes2);
    assert_eq!(pub_bytes1, pub_bytes2);

    // 4) Clean up
    let _ = fs::remove_file(PRIV);
    let _ = fs::remove_file(PUB);
}
