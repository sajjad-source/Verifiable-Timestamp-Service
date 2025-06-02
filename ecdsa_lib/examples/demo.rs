use digsig::KeyPair;

fn main() {
    // Generate a new key pair
    let keypair = KeyPair::generate();

    // Save keys to files
    keypair
        .save_to_files("private_key.bin", "public_key.bin")
        .unwrap();

    // Sign a message
    let message = b"Hello, World!";
    let signature = keypair.sign(message);

    // Verify the signature
    let is_valid = keypair.verify(message, &signature);
    println!("Signature is valid: {}", is_valid);

    // Load keys from files
    let loaded_keypair = KeyPair::load_from_files("private_key.bin", "public_key.bin").unwrap();

    // Verify with loaded keys
    let is_valid = loaded_keypair.verify(message, &signature);
    println!("Signature is valid with loaded keys: {}", is_valid);
}

// use these cargo dependencies
// [dependencies]
// ecdsa_lib = { path = "path/to/ecdsa_lib" }
