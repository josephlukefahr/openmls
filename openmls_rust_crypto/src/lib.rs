#![no_std]
#![doc = include_str!("../README.md")]

extern crate alloc;

use aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use alloc::{vec, vec::Vec};
use ascon_aead::Ascon128;
use ascon_hash::AsconHash;
use chacha20poly1305::ChaCha20Poly1305;
use digest::Digest;
use hkdf::Hkdf;
use hpke_rs::{Hpke, HpkeError};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{
        AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeCiphertext,
        HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair, SignatureScheme,
    },
};
use p256::EncodedPoint;
use rand_core::{OsRng, RngCore};
use sha2::{Sha256, Sha384, Sha512};
use signature::{Signer, Verifier};
use tls_codec::SecretVLBytes;

#[inline(always)]
fn hpke_from_config(config: HpkeConfig) -> Result<Hpke<HpkeRustCrypto>, CryptoError> {
    let kem_alg = match config.0 {
        HpkeKemType::DhKemP256 => Ok(hpke_rs_crypto::types::KemAlgorithm::DhKemP256),
        HpkeKemType::DhKemP384 => Ok(hpke_rs_crypto::types::KemAlgorithm::DhKemP384),
        HpkeKemType::DhKemP521 => Ok(hpke_rs_crypto::types::KemAlgorithm::DhKemP521),
        HpkeKemType::DhKem25519 => Ok(hpke_rs_crypto::types::KemAlgorithm::DhKem25519),
        HpkeKemType::DhKem448 => Ok(hpke_rs_crypto::types::KemAlgorithm::DhKem448),
        _ => Err(CryptoError::UnsupportedKem),
    }?;
    let kdf_alg = match config.1 {
        HpkeKdfType::HkdfSha256 => Ok(hpke_rs_crypto::types::KdfAlgorithm::HkdfSha256),
        HpkeKdfType::HkdfSha384 => Ok(hpke_rs_crypto::types::KdfAlgorithm::HkdfSha384),
        HpkeKdfType::HkdfSha512 => Ok(hpke_rs_crypto::types::KdfAlgorithm::HkdfSha512),
        _ => Err(CryptoError::UnsupportedKdf),
    }?;
    let aead_alg = match config.2 {
        HpkeAeadType::AesGcm128 => Ok(hpke_rs_crypto::types::AeadAlgorithm::Aes128Gcm),
        HpkeAeadType::AesGcm256 => Ok(hpke_rs_crypto::types::AeadAlgorithm::Aes256Gcm),
        HpkeAeadType::ChaCha20Poly1305 => {
            Ok(hpke_rs_crypto::types::AeadAlgorithm::ChaCha20Poly1305)
        }
        HpkeAeadType::Export => Ok(hpke_rs_crypto::types::AeadAlgorithm::HpkeExport),
        _ => Err(CryptoError::UnsupportedAeadAlgorithm),
    }?;
    Ok(Hpke::<HpkeRustCrypto>::new(
        hpke_rs::Mode::Base,
        kem_alg,
        kdf_alg,
        aead_alg,
    ))
}

/// Custom `OpenMlsCrypto` and `OpenMlsRand` provider for use in research.
///
/// # Overview
///
/// `Provider` is a custom implementation of the `OpenMlsCrypto` trait designed for research purposes.
/// This struct integrates various cryptographic algorithms and primitives to support the MLS protocol.
/// It leverages `hpke_rs` for Hybrid Public Key Encryption (HPKE) and includes support for multiple AEAD
/// algorithms such as AES-GCM, ChaCha20-Poly1305, and Ascon128. Additionally, it incorporates hashing
/// algorithms like SHA-256, SHA-384, SHA-512, and AsconHash, along with signature schemes and key derivation
/// functions. The `Provider` struct aims to offer a flexible and extensible cryptographic backend for
/// experimenting with and advancing MLS-related research.
///
/// # Supported Ciphersuites
///
/// The `Provider` supports the following ciphersuites:
/// - `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
/// - `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
/// - `MLS_128_DHKEMP256_AES128GCM_SHA256_P256`
///
/// # HKDF Functions
///
/// The `Provider` implements HKDF extract and expand functions for various hash algorithms, including:
/// - SHA-256
/// - SHA-384
/// - SHA-512
/// - AsconHash256
///
/// # Hash Functions
///
/// The `Provider` supports hashing with the following algorithms:
/// - SHA-256
/// - SHA-384
/// - SHA-512
/// - AsconHash256
///
/// # AEAD Encryption
///
/// The `Provider` supports AEAD encryption with the following algorithms:
/// - AES-128-GCM
/// - AES-256-GCM
/// - ChaCha20-Poly1305
/// - Ascon128
///
/// # Signature Functions
///
/// The `Provider` supports key generation, signing, and signature verification for the following schemes:
/// - ECDSA_SECP256R1_SHA256
/// - ED25519
///
/// # HPKE Functions
///
/// The `Provider` supports HPKE operations including sealing, opening, and key pair derivation with various configurations.
///
/// # Random Number Generation
///
/// The `Provider` implements random number generation functions using the `OsRng` cryptographic random number generator:
/// - `random_array`: Generates a fixed-size array of random bytes.
/// - `random_vec`: Generates a variable-length vector of random bytes.
#[derive(Clone, Debug)]
pub struct Provider;

impl Default for Provider {
    fn default() -> Self {
        Self
    }
}

#[allow(unreachable_patterns)]
impl OpenMlsCrypto for Provider {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }
    }
    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        ]
    }
    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        match hash_type {
            HashType::Sha2_256 => Ok(Hkdf::<Sha256>::extract(Some(salt), ikm).0.as_slice().into()),
            HashType::Sha2_384 => Ok(Hkdf::<Sha384>::extract(Some(salt), ikm).0.as_slice().into()),
            HashType::Sha2_512 => Ok(Hkdf::<Sha512>::extract(Some(salt), ikm).0.as_slice().into()),
            HashType::AsconHash256 => Ok(Hkdf::<AsconHash>::extract(Some(salt), ikm)
                .0
                .as_slice()
                .into()),
            _ => Err(CryptoError::UnsupportedHashAlgorithm),
        }
    }
    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        match hash_type {
            HashType::Sha2_256 => match Hkdf::<Sha256>::from_prk(prk) {
                Ok(hkdf) => {
                    let mut okm = vec![0u8; okm_len];
                    match hkdf.expand(info, &mut okm) {
                        Ok(_) => Ok(okm.into()),
                        Err(_) => Err(CryptoError::HkdfOutputLengthInvalid),
                    }
                }
                Err(_) => Err(CryptoError::HkdfOutputLengthInvalid),
            },
            HashType::Sha2_512 => match Hkdf::<Sha512>::from_prk(prk) {
                Ok(hkdf) => {
                    let mut okm = vec![0u8; okm_len];
                    match hkdf.expand(info, &mut okm) {
                        Ok(_) => Ok(okm.into()),
                        Err(_) => Err(CryptoError::HkdfOutputLengthInvalid),
                    }
                }
                Err(_) => Err(CryptoError::HkdfOutputLengthInvalid),
            },
            HashType::Sha2_384 => match Hkdf::<Sha384>::from_prk(prk) {
                Ok(hkdf) => {
                    let mut okm = vec![0u8; okm_len];
                    match hkdf.expand(info, &mut okm) {
                        Ok(_) => Ok(okm.into()),
                        Err(_) => Err(CryptoError::HkdfOutputLengthInvalid),
                    }
                }
                Err(_) => Err(CryptoError::HkdfOutputLengthInvalid),
            },
            HashType::AsconHash256 => match Hkdf::<AsconHash>::from_prk(prk) {
                Ok(hkdf) => {
                    let mut okm = vec![0u8; okm_len];
                    match hkdf.expand(info, &mut okm) {
                        Ok(_) => Ok(okm.into()),
                        Err(_) => Err(CryptoError::HkdfOutputLengthInvalid),
                    }
                }
                Err(_) => Err(CryptoError::HkdfOutputLengthInvalid),
            },
            _ => Err(CryptoError::UnsupportedHashAlgorithm),
        }
    }
    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match hash_type {
            HashType::Sha2_256 => Ok(Sha256::digest(data).as_slice().into()),
            HashType::Sha2_384 => Ok(Sha384::digest(data).as_slice().into()),
            HashType::Sha2_512 => Ok(Sha512::digest(data).as_slice().into()),
            HashType::AsconHash256 => Ok(AsconHash::digest(data).as_slice().into()),
            _ => Err(CryptoError::UnsupportedHashAlgorithm),
        }
    }
    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match alg {
            AeadType::Aes128Gcm => match Aes128Gcm::new_from_slice(key) {
                Ok(aead) => match aead.encrypt(nonce.into(), Payload { msg: data, aad }) {
                    Ok(ct_tag) => Ok(ct_tag),
                    Err(_) => Err(CryptoError::CryptoLibraryError),
                },
                Err(_) => Err(CryptoError::CryptoLibraryError),
            },
            AeadType::Aes256Gcm => match Aes256Gcm::new_from_slice(key) {
                Ok(aead) => match aead.encrypt(nonce.into(), Payload { msg: data, aad }) {
                    Ok(ct_tag) => Ok(ct_tag),
                    Err(_) => Err(CryptoError::CryptoLibraryError),
                },
                Err(_) => Err(CryptoError::CryptoLibraryError),
            },
            AeadType::ChaCha20Poly1305 => match ChaCha20Poly1305::new_from_slice(key) {
                Ok(aead) => match aead.encrypt(nonce.into(), Payload { msg: data, aad }) {
                    Ok(ct_tag) => Ok(ct_tag),
                    Err(_) => Err(CryptoError::CryptoLibraryError),
                },
                Err(_) => Err(CryptoError::CryptoLibraryError),
            },
            AeadType::AsconAead128 => match Ascon128::new_from_slice(key) {
                Ok(aead) => match aead.encrypt(nonce.into(), Payload { msg: data, aad }) {
                    Ok(ct_tag) => Ok(ct_tag),
                    Err(_) => Err(CryptoError::CryptoLibraryError),
                },
                Err(_) => Err(CryptoError::CryptoLibraryError),
            },
            _ => Err(CryptoError::UnsupportedAeadAlgorithm),
        }
    }
    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match alg {
            AeadType::Aes128Gcm => match Aes128Gcm::new_from_slice(key) {
                Ok(aead) => match aead.decrypt(nonce.into(), Payload { msg: ct_tag, aad }) {
                    Ok(ct_tag) => Ok(ct_tag),
                    Err(_) => Err(CryptoError::AeadDecryptionError),
                },
                Err(_) => Err(CryptoError::CryptoLibraryError),
            },
            AeadType::Aes256Gcm => match Aes256Gcm::new_from_slice(key) {
                Ok(aead) => match aead.decrypt(nonce.into(), Payload { msg: ct_tag, aad }) {
                    Ok(ct_tag) => Ok(ct_tag),
                    Err(_) => Err(CryptoError::AeadDecryptionError),
                },
                Err(_) => Err(CryptoError::CryptoLibraryError),
            },
            AeadType::ChaCha20Poly1305 => match ChaCha20Poly1305::new_from_slice(key) {
                Ok(aead) => match aead.decrypt(nonce.into(), Payload { msg: ct_tag, aad }) {
                    Ok(ct_tag) => Ok(ct_tag),
                    Err(_) => Err(CryptoError::AeadDecryptionError),
                },
                Err(_) => Err(CryptoError::CryptoLibraryError),
            },
            AeadType::AsconAead128 => match Ascon128::new_from_slice(key) {
                Ok(aead) => match aead.decrypt(nonce.into(), Payload { msg: ct_tag, aad }) {
                    Ok(ct_tag) => Ok(ct_tag),
                    Err(_) => Err(CryptoError::AeadDecryptionError),
                },
                Err(_) => Err(CryptoError::CryptoLibraryError),
            },
            _ => Err(CryptoError::UnsupportedAeadAlgorithm),
        }
    }
    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        match alg {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
                Ok((
                    sk.to_bytes().as_slice().into(),
                    sk.verifying_key().to_encoded_point(false).as_bytes().into(),
                ))
            }
            SignatureScheme::ED25519 => {
                let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
                Ok((sk.to_bytes().into(), sk.verifying_key().to_bytes().into()))
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }
    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        match alg {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => match EncodedPoint::from_bytes(pk) {
                Ok(pt) => match p256::ecdsa::VerifyingKey::from_encoded_point(&pt) {
                    Ok(sk) => match p256::ecdsa::Signature::from_der(signature) {
                        Ok(sig_obj) => match sk.verify(data, &sig_obj) {
                            Ok(_) => Ok(()),
                            Err(_) => Err(CryptoError::InvalidSignature),
                        },
                        Err(_) => Err(CryptoError::InvalidSignature),
                    },
                    Err(_) => Err(CryptoError::CryptoLibraryError),
                },
                Err(_) => Err(CryptoError::CryptoLibraryError),
            },
            SignatureScheme::ED25519 => match ed25519_dalek::VerifyingKey::try_from(pk) {
                Ok(sk) => {
                    if signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
                        Err(CryptoError::InvalidSignature)
                    } else {
                        let mut sig = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
                        sig.clone_from_slice(signature);
                        match sk.verify_strict(data, &ed25519_dalek::Signature::from(sig)) {
                            Ok(_) => Ok(()),
                            Err(_) => Err(CryptoError::InvalidSignature),
                        }
                    }
                }
                Err(_) => Err(CryptoError::CryptoLibraryError),
            },
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }
    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match alg {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                match p256::ecdsa::SigningKey::from_bytes(key.into()) {
                    Ok(sk) => {
                        let signature: p256::ecdsa::Signature = sk.sign(data);
                        Ok(signature.to_der().to_bytes().into())
                    }
                    Err(_) => Err(CryptoError::CryptoLibraryError),
                }
            }
            SignatureScheme::ED25519 => match ed25519_dalek::SigningKey::try_from(key) {
                Ok(sk) => Ok(sk.sign(data).to_bytes().into()),
                Err(_) => Err(CryptoError::CryptoLibraryError),
            },
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }
    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        match hpke_from_config(config)?.seal(&pk_r.into(), info, aad, ptxt, None, None, None) {
            Ok((kem_output, ciphertext)) => Ok(HpkeCiphertext {
                kem_output: kem_output.into(),
                ciphertext: ciphertext.into(),
            }),
            Err(e) => match e {
                HpkeError::InvalidInput => Err(CryptoError::InvalidLength),
                _ => Err(CryptoError::CryptoLibraryError),
            },
        }
    }
    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match hpke_from_config(config)?.open(
            input.kem_output.as_slice(),
            &sk_r.into(),
            info,
            aad,
            input.ciphertext.as_slice(),
            None,
            None,
            None,
        ) {
            Ok(vec) => Ok(vec),
            Err(_) => Err(CryptoError::HpkeDecryptionError),
        }
    }
    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(Vec<u8>, ExporterSecret), CryptoError> {
        match hpke_from_config(config)?.setup_sender(&pk_r.into(), info, None, None, None) {
            Ok((kem_output, context)) => match context.export(exporter_context, exporter_length) {
                Ok(exported_secret) => Ok((kem_output, exported_secret.into())),
                Err(_) => Err(CryptoError::ExporterError),
            },
            Err(_) => Err(CryptoError::SenderSetupError),
        }
    }
    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        match hpke_from_config(config)?.setup_receiver(enc, &sk_r.into(), info, None, None, None) {
            Ok(context) => match context.export(exporter_context, exporter_length) {
                Ok(exported_secret) => Ok(exported_secret.into()),
                Err(_) => Err(CryptoError::ExporterError),
            },
            Err(_) => Err(CryptoError::ReceiverSetupError),
        }
    }
    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        match hpke_from_config(config)?.derive_key_pair(ikm) {
            Ok(kp) => Ok(HpkeKeyPair {
                private: kp.private_key().as_slice().into(),
                public: kp.public_key().as_slice().into(),
            }),
            Err(e) => match e {
                HpkeError::InvalidInput => Err(CryptoError::InvalidLength),
                _ => Err(CryptoError::CryptoLibraryError),
            },
        }
    }
}

impl OpenMlsRand for Provider {
    type Error = CryptoError;
    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut out = [0u8; N];
        OsRng.fill_bytes(&mut out);
        Ok(out)
    }
    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut out = vec![0u8; len];
        OsRng.fill_bytes(&mut out);
        Ok(out)
    }
}
