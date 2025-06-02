# lab4: Verifiable Timestamp Service (VTS)

A Rust-based microservice that accepts plain-text messages, appends a cryptographic timestamp, and returns a digitally signed receipt. This project includes:

- **`lab4` crate**:
  - `src/main.rs` → starts the Axum‐based web server
  - `src/server.rs` → implements the `/key` and `/sign` endpoints
  - `src/config.rs` → generates/loads ECDSA keys from `.bin` files
- **Client library** in `src/lib.rs` (`ecdsa_requests` module) with:
  - `request_key(...)`
  - `request_timestamp(...)`
  - `verify_signature(...)`
- **Examples** in `examples/` showing how to use the client library
- **Tests** in `tests/` (unit tests for key loading, integration tests for end‑to‑end flow)
- **GitHub Actions CI** in `.github/workflows/ci.yml` to enforce formatting, linting, tests, and docs

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Prerequisites](#prerequisites)
3. [Key‐Storage Strategy & Design Decisions](#key-storage-strategy--design-decisions)
4. [Directory Layout](#directory-layout)
5. [Building & Running the Server](#building--running-the-server)
6. [Client Library](#client-library)
7. [Examples](#examples)
8. [Testing](#testing)
9. [Documentation](#documentation)
10. [Continuous Integration (CI)](#continuous-integration-ci)
11. [Authors & License](#authors--license)

---

## Project Overview

A **Verifiable Timestamp Service (VTS)** allows clients to obtain a trustworthy, cryptographically signed timestamp for any message. This can prove that a message was known at a specific UTC instant, suitable for:

- Proving you submitted a document before a deadline
- Logging transactions in a tamper-evident way
- Any scenario where a "notarized" timestamp is required

Our Rust implementation:

1. **Generates an ECDSA key pair on first run**, stored in local files (`private_key.bin`, `public_key.bin`).
2. **Listens on port 8008** and provides two HTTP endpoints:
   - `GET /key` → returns `{ request: "GET", time-requested: <ISO 8601 UTC>, public-key: <Base64> }`
   - `POST /sign` (JSON body `{ "message": "…" }`) → returns `{ request: "POST", message: "…", time-signed: <ISO 8601 UTC>, signature: <Base64> }`
3. **Signs "message + UTC timestamp"** using ECDSA (via the provided `ecdsa_lib` crate).
4. **Logs every request/response** (including errors) to stdout with ISO 8601 timestamps.
5. Provides a **client library** (`ecdsa_requests`) so users can fetch the public key, request a timestamp, and verify signatures entirely client-side.

This README covers our design choices, usage, and how to run tests/CI.

---

## Prerequisites

- **Rust toolchain** (stable, ≥ 1.60). Install via [rustup](https://rustup.rs/).
- **Git** (to clone this repository).
- A modern **UNIX‑like OS** (macOS, Linux, WSL, etc.). (All code was tested on macOS and Ubuntu.)
- **Internet access** only if you wish to fetch crates from crates.io. Otherwise, all core logic runs offline once dependencies are cached.

**Note:** This repository includes the `ecdsa_lib` crate as a local dependency to ensure GitHub Actions CI can build and test the project without external dependencies.

---

## Key‐Storage Strategy & Design Decisions

### 1. Choice: `.bin` files only

Although we could store keys in a single `vts.config` TOML file, we opted for the simpler approach of letting the provided `ecdsa_lib` crate manage **two binary files**:

- `private_key.bin` (raw private key bytes)
- `public_key.bin` (raw public key bytes)

#### Why `.bin` only?

- The `ecdsa_lib::KeyPair` API offers:
  - `KeyPair::generate()` → random ECDSA key pair
  - `keypair.save_to_files(private_path, public_path)` → write raw bytes to two `.bin` files
  - `KeyPair::load_from_files(private_path, public_path)` → read from those `.bin` files
- Adding a layer to re-encode into a separate `vts.config` (TOML) would duplicate effort: we'd generate `.bin`, then Base64‐encode, then decode again, then write `.bin` just to reload.
- By sticking to `.bin`, our code is shorter, error‐prone surface is smaller, and we still meet all functional requirements.

#### How it works on startup (`src/config.rs`)

1. **`load_or_generate_keys()`** checks:
   - If `private_key.bin` or `public_key.bin` is missing, call `KeyPair::generate()` → `keypair.save_to_files("private_key.bin", "public_key.bin")`.
   - Then read raw bytes from those files and return `(priv_bytes, pub_bytes)`.
   - If both files exist, just read raw bytes and return them.
2. The server (`src/main.rs`) calls `load_or_generate_keys()` at launch and holds those raw bytes in memory.
3. Each time `POST /sign` is invoked, we reconstruct `KeyPair` from `private_key.bin` and `public_key.bin`, sign `message + timestamp`, and return the Base64‐encoded signature.

Because we never publish `private_key.bin` in version control, your private key remains local. In practice, you'd use a secure vault; here, `.bin` is sufficient for an educational exercise.

---

## Directory Layout

```
lab4/                          # Repository root
├── .github/
│   └── workflows/
│       └── ci.yml             # GitHub Actions CI configuration
├── ecdsa_lib/                 # Local copy of ecdsa_lib crate (for CI)
├── Cargo.toml                 # Crate manifest (lab4)
├── Cargo.lock                 # Cargo lockfile (auto-generated)
├── README.md                  # ← this file
├── .gitignore                 # Excludes /target, *.bin files
├── src/
│   ├── config.rs              # Key‐loading/generation logic (Option A: .bin files)
│   ├── server.rs              # Axum routes and handlers for /key and /sign
│   ├── main.rs                # loads keys + starts the server
│   └── lib.rs                 # client library (ecdsa_requests)
├── examples/
│   └── example-1.rs           # Example client usage of ecdsa_requests
├── tests/
│   ├── config_tests.rs        # Unit tests for load_or_generate_keys()
│   └── integration_tests.rs   # Integration tests: spawn server + client calls
├── private_key.bin            # Created on first server run (not committed)
└── public_key.bin             # Created on first server run (not committed)
```

- **`.github/workflows/ci.yml`**  
  Runs CI checks (formatting, linting, tests, docs, build) on every push/PR.

- **`src/config.rs`**  
  Implements `load_or_generate_keys()` → (priv_bytes, pub_bytes). Key files are `private_key.bin` and `public_key.bin` in the working directory.

- **`src/server.rs`**  
  Defines:

  - `GET /key` → returns JSON with `{ request, time-requested, public-key }`
  - `POST /sign` (body `{ message }`) → returns `{ request, message, time-signed, signature }`  
    Uses `KeyPair::load_from_files` to rebuild keys for signing.

- **`src/main.rs`**  
  Calls `config::load_or_generate_keys()`, then `server::run_server(priv_bytes, pub_bytes).await`.

- **`src/lib.rs`**  
  Module `ecdsa_requests` with:

  - `request_key(server_addr) → EcdsaVerificationKey`
  - `request_timestamp(server_addr, message) → EcdsaSignedTimestamp`
  - `verify_signature(&signed, &key) → bool`

- **`examples/example-1.rs`**  
  Demonstrates step‑by‑step:

  1. `request_key("http://127.0.0.1:8008")`
  2. `request_timestamp("http://127.0.0.1:8008", "Hello, VTS!")`
  3. `verify_signature(&signed, &key)`

- **`tests/config_tests.rs`**  
  Unit test ensures `load_or_generate_keys()` actually creates/loads the same `.bin` files consistently.

- **`tests/integration_tests.rs`**  
  Uses Tokio to spawn a server on a random port and exercises:
  1. `GET /key` shape & contents
  2. `POST /sign` shape & signature verification
  3. `GET /nonexistent` returns `400 Bad Request`

---

## Building & Running the Server

1. **Clone the repository** (if you haven't already):

   ```bash
   git clone https://github.com/sajjad-source/Verifiable-Timestamp-Service.git
   cd lab4
   ```

2. **Ensure you have the Rust toolchain**:

   ```bash
   rustup update stable
   ```

3. **Build in release mode** (optional):

   ```bash
   cargo build --release
   ```

4. **Run the server** (debug mode is fine for development):

   ```bash
   cargo run
   ```

   You should see:

   ```
   VTS microservice starting on 0.0.0.0:8008
   ```

   On first run, `private_key.bin` and `public_key.bin` will be created in the current directory.

5. **Verify endpoints**:

   **Fetch public key:**

   ```bash
   curl http://127.0.0.1:8008/key
   ```

   Sample response:

   ```json
   {
     "request": "GET",
     "time-requested": "2025-06-02T05:05:35.206739Z",
     "public-key": "As5FZ8Z7jX+V/pW+CDwW1EM99tt3VZmMMrcNKokPloeR"
   }
   ```

   **Request a signed timestamp:**

   ```bash
   curl -X POST -H "Content-Type: application/json" \
     -d '{ "message": "Smoke test" }' \
     http://127.0.0.1:8008/sign
   ```

   Sample response:

   ```json
   {
     "request": "POST",
     "message": "Smoke test",
     "time-signed": "2025-06-02T05:05:35.784383Z",
     "signature": "sHE4LJMr2n/0+0YKuqSPV0HCsboBJYY+u8cvk1KzHQw2AAnkBrzpBRlozCuZoqqtCIE+qx93fMR6fWpZGEDjmg=="
   }
   ```

### Logs

All requests (and errors) are logged to stdout with ISO 8601 UTC timestamps. Example:

```
2025-06-02T05:05:35.784383Z INFO lab4::server: 2025-06-02T05:05:35.784383Z Request: POST /sign message='Smoke test' → response sig='…'
```

---

## Client Library

The `ecdsa_requests` module in `src/lib.rs` lets you interact with the VTS server without manually crafting HTTP calls.

### Public API

```rust
// 1) Fetch the server's public key
fn request_key(server_addr: &str) -> Result<EcdsaVerificationKey, Box<dyn Error>>

// 2) Request a signed timestamp for a message
fn request_timestamp(server_addr: &str, message: &str) -> Result<EcdsaSignedTimestamp, Box<dyn Error>>

// 3) Verify a signature produced by the server
fn verify_signature(signed: &EcdsaSignedTimestamp, key: &EcdsaVerificationKey) -> bool
```

### `EcdsaVerificationKey` (returned by `request_key`)

```rust
#[derive(Debug, Deserialize)]
pub struct EcdsaVerificationKey {
    pub request: String,            // "GET"
    #[serde(rename = "time-requested")]
    pub time_requested: String,      // ISO 8601 timestamp
    #[serde(rename = "public-key")]
    pub public_key: String,          // Base64-encoded public key bytes
}
```

### `EcdsaSignedTimestamp` (returned by `request_timestamp`)

```rust
#[derive(Debug, Deserialize)]
pub struct EcdsaSignedTimestamp {
    pub request: String,          // "POST"
    pub message: String,          // original message
    #[serde(rename = "time-signed")]
    pub time_signed: String,      // ISO 8601 timestamp
    pub signature: String,        // Base64-encoded ECDSA signature
}
```

### `verify_signature(...)`

1. Reconstructs the signed data as `data = message + time_signed`
2. Base64‐decodes `public_key` and `signature`
3. Parses them into `VerifyingKey` and `Signature`
4. Returns `true` if the signature is valid over `data`, `false` otherwise

---

## Examples

We provide a simple example in `examples/example-1.rs`. To run it:

1. **Start the server** in one terminal:

   ```bash
   cargo run
   ```

2. **In a separate terminal**, run:

   ```bash
   cargo run --example example-1
   ```

   Sample output:

   ```
   Public key (received at 2025-06-02T05:05:35.206739Z): As5FZ8Z7jX+V/pW+CDwW1EM99tt3VZmMMrcNKokPloeR
   Signed: request=POST, message='Hello, VTS!', time-signed=2025-06-02T05:05:35.784383Z, signature=sHE4LJMr2n/0+0YKuqSPV0HCsboBJYY+u8cvk1KzHQw2AAnkBrzpBRlozCuZoqqtCIE+qx93fMR6fWpZGEDjmg==
   Signature valid? true
   ```

---

## Testing

All tests are located under `tests/`:

- **`tests/config_tests.rs`**  
  Verifies that `load_or_generate_keys()` properly creates and reloads `private_key.bin` and `public_key.bin`.

- **`tests/integration_tests.rs`**  
  Spawns the server on an ephemeral port (using Tokio).  
  Tests:
  - `GET /key` returns well-formed JSON.
  - `POST /sign` returns a valid signature.
  - Invalid route returns `400 Bad Request`.

**Run the full test suite:**

```bash
cargo test -- --nocapture
```

You should see all tests pass.

---

## Documentation

Rustdoc comments are provided throughout `src/lib.rs` and `src/server.rs`. To build and view the documentation locally:

```bash
cargo doc --no-deps --open
```

This opens a browser window showing:

- `lab4` crate docs
- `ecdsa_requests` module
- Data structures and function examples

If you prefer manual browsing:

```bash
cargo doc --no-deps
# Then open target/doc/lab4/index.html in your browser
```

---

## Continuous Integration (CI)

We use GitHub Actions to enforce quality checks on every push and pull request to `main`. The workflow is defined in `.github/workflows/ci.yml`.

**CI steps:**

1. Checkout repository (`actions/checkout@v4`)
2. Install Rust (`actions-rs/toolchain@v1`)
3. Check formatting: `cargo fmt -- --check`
4. Run Clippy: `cargo clippy -- -D warnings`
5. Run all tests: `cargo test --all`
6. Build documentation: `cargo doc --no-deps`
7. Verify README.md exists
8. Build release: `cargo build --release`

To view CI status, go to the **Actions** tab on GitHub. A successful run will show green ✅ for every step. If any step fails, the workflow marks as failed, preventing merges until the issue is resolved.

---

## Authors & License

**Author:**  
Sajjad C Kareem <sajjadck04@gmail.com>

**License:**  
MIT License - this assignment is for educational purposes only.

---

Thank you for reviewing our Verifiable Timestamp Service implementation. If you have any questions or suggestions, feel free to open an issue or send a pull request!
