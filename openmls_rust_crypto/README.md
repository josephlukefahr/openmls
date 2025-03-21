OpenMLS crypto and entropy provider based on RustCrypto but modified for research.

# Overview

This crate includes a custom implementation of the `OpenMlsCrypto` and `OpenMlsRand` traits designed for research purposes. This crate integrates various cryptographic algorithms and primitives to support the MLS (Messaging Layer Security) protocol. It leverages `hpke_rs` for Hybrid Public Key Encryption (HPKE) and includes support for multiple AEAD algorithms, hashing algorithms, signature schemes, key derivation functions, and random number generation.

# Features

- **Supported Ciphersuites**:
  - `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
  - `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
  - `MLS_128_DHKEMP256_AES128GCM_SHA256_P256`
- **HKDF Functions**:
  - SHA-256
  - SHA-384
  - SHA-512
  - AsconHash256
- **Hash Functions**:
  - SHA-256
  - SHA-384
  - SHA-512
  - AsconHash256
- **AEAD Encryption**:
  - AES-128-GCM
  - AES-256-GCM
  - ChaCha20-Poly1305
  - Ascon128
- **Signature Functions**:
  - ECDSA_SECP256R1_SHA256
  - ED25519
- **HPKE Functions**:
  - Sealing
  - Opening
  - Key pair derivation
- **Random Number Generation**:
  - `random_array`: Generates a fixed-size array of random bytes.
  - `random_vec`: Generates a variable-length vector of random bytes.

# Usage

Here's a basic example of how to use the `Provider` struct:

```rust
use openmls_rust_crypto_nps::Provider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::types::HashType;

let provider = Provider;

// Generate a random array
let random_array = provider.random_array::<32>().unwrap();
println!("Random array: {:?}", random_array);

// Generate a random vector
let random_vec = provider.random_vec(16).unwrap();
println!("Random vector: {:?}", random_vec);

// Perform HKDF extract and expand
let salt = b"some_salt";
let ikm = b"some_input_key_material";
let hkdf_output = provider.hkdf_extract(HashType::AsconHash256, salt, ikm).unwrap();
println!("HKDF output: {:?}", hkdf_output);
```

# Contributing

Contributions are welcome! Please open an issue or submit a pull request.

# Acknowledgements

This crate is developed for research purposes and integrates various cryptographic libraries and algorithms to support the MLS protocol.
