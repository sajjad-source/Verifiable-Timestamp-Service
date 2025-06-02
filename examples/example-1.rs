//! Example 1: fetch public key, request a timestamped signature, and verify it.

use lab4::ecdsa_requests::{request_key, request_timestamp, verify_signature};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = "http://127.0.0.1:8008";

    // 1) Get the public key
    let key_struct = request_key(server)?;
    println!(
        "Public key (received at {}): {}",
        key_struct.time_requested, key_struct.public_key
    );

    // 2) Request a signed timestamp for "Hello, VTS!"
    let signed = request_timestamp(server, "Hello, VTS!")?;
    println!(
        "Signed: request={}, message='{}', time-signed={}, signature={}",
        signed.request, signed.message, signed.time_signed, signed.signature
    );

    // 3) Verify
    let is_valid = verify_signature(&signed, &key_struct);
    println!("Signature valid? {}", is_valid);

    Ok(())
}
