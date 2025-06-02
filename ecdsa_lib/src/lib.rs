//! COSC 69.21/169.1 wrapper crate for for
//! Elliptic Curve Digital Signature Algorithm (ECDSA)crate
//!
//! This module provides a simplified API for use in Lab 4 of
//! the Spring 2025 BRASS course @ Dartmouth College.
//!
//!

use k256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

/// A digital signature is 8 bytes long
type SignatureBytes = Vec<u8>;

/// Represents a key pair for ECDSA operations
pub struct KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Save the key pair to files
    /// WARNING: This is not a secure way to save keys!
    /// It is only being done to facilitate this class assignment.
    pub fn save_to_files(
        &self,
        private_key_path: &str,
        public_key_path: &str,
    ) -> std::io::Result<()> {
        // Save the private key
        let private_key_bytes = self.signing_key.to_bytes();
        let mut private_key_file = File::create(private_key_path)?;
        private_key_file.write_all(&private_key_bytes)?;

        // Save the public key
        let public_key_bytes = self
            .verifying_key
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let mut public_key_file = File::create(public_key_path)?;
        public_key_file.write_all(&public_key_bytes)?;

        Ok(())
    }

    /// Load a key pair stored by save_to_files  
    pub fn load_from_files(private_key_path: &str, public_key_path: &str) -> std::io::Result<Self> {
        // Read private key
        let mut private_key_bytes = Vec::new();
        File::open(private_key_path)?.read_to_end(&mut private_key_bytes)?;
        let signing_key = SigningKey::from_bytes(k256::FieldBytes::from_slice(&private_key_bytes))
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid private key")
            })?;

        // Read public key
        let mut public_key_bytes = Vec::new();
        File::open(public_key_path)?.read_to_end(&mut public_key_bytes)?;
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid public key")
        })?;

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Sign a message with the current signing key
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verify the signature with the verifying key
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.verifying_key.verify(message, signature).is_ok()
    }

    /// Get the public (verifying) key
    pub fn public_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Save a digital signature to a file
    pub fn write_signature_to_file(signature: &Signature, path: &str) -> std::io::Result<()> {
        let signature_bytes = signature.to_vec();
        let mut file = File::create(path)?;
        file.write_all(&signature_bytes)?;
        Ok(())
    }

    /// Read a digital signature from a file created by write_signature_to_file
    pub fn read_signature_from_file(path: &str) -> std::io::Result<Signature> {
        let mut signature_bytes = Vec::new();
        File::open(path)?.read_to_end(&mut signature_bytes)?;
        Signature::from_slice(&signature_bytes)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid signature"))
    }

    /// Saves a signature to a file using a more efficient implementation
    pub fn save_signature(signature: &Signature, path: impl AsRef<Path>) -> std::io::Result<()> {
        std::fs::write(path, Self::serialize_signature(signature))
    }

    /// Serializes a signature into its byte representation
    fn serialize_signature(signature: &Signature) -> SignatureBytes {
        signature.to_vec()
    }
}

// ----------------------------------------------
//
// Unit tests
//

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_verification() {
        let keypair = KeyPair::generate();
        let message = b"Hello, World!";
        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature));
    }

    #[test]
    fn test_key_file_operations() {
        let keypair = KeyPair::generate();
        let private_key_path = "test_private_key.bin";
        let public_key_path = "test_public_key.bin";

        // Save keys
        keypair
            .save_to_files(private_key_path, public_key_path)
            .unwrap();

        // Load keys
        let loaded_keypair = KeyPair::load_from_files(private_key_path, public_key_path).unwrap();

        // Test that loaded keys work correctly
        let message = b"Hello, World!";
        let signature = keypair.sign(message);
        assert!(loaded_keypair.verify(message, &signature));

        // Clean up test files
        std::fs::remove_file(private_key_path).unwrap();
        std::fs::remove_file(public_key_path).unwrap();
    }

    #[test]
    fn test_signature_file_operations() {
        let keypair = KeyPair::generate();
        let message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";

        let signature = keypair.sign(message);
        let signature_path = "signature_test_1.bin"; // must be unique to each test!

        // Write signature to a file
        KeyPair::write_signature_to_file(&signature, signature_path).unwrap();

        // Read signature from a file
        let loaded_signature = KeyPair::read_signature_from_file(signature_path).unwrap();

        // Verify the loaded signature
        assert!(keypair.verify(message, &loaded_signature));

        // Clean up the test file
        std::fs::remove_file(signature_path).unwrap();
    }

    #[test]
    fn test_signature_file_operations2() {
        let keypair = KeyPair::generate();
        let message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";

        let signature = keypair.sign(message);
        let signature_path = "signature_test_2.bin"; // must be unique to each test!

        // Write signature to a file
        KeyPair::write_signature_to_file(&signature, signature_path).unwrap();

        // Read signature from a file
        let loaded_signature = KeyPair::read_signature_from_file(signature_path).unwrap();

        // Verify the loaded signature
        assert!(keypair.verify(message, &loaded_signature));

        // Clean up the test file
        std::fs::remove_file(signature_path).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_badsig() {
        // generate a signature
        let keypair = KeyPair::generate();
        let message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
        let mut signature = keypair.sign(message);

        // change the sig so it fails verificstion
        let mut signature_bytes = Signature::to_bytes(&signature);
        signature_bytes[3] = 0x42;

        signature = Signature::from_bytes(&signature_bytes).unwrap();

        // Verify of the loaded signature SHOULD FAIL
        assert!(keypair.verify(message, &signature));
    }
}
