use crate::*;

use ed25519_dalek::Verifier;
use hex::ToHex;
use regex::Regex;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

/// A trait required for a struct to be able to be authenticated.
pub trait AuthPayloadTrait {
    fn user_pubkey(&self) -> &str;
    fn ciphersuite(&self) -> &str;
    fn timestamp(&self) -> u64;
}

// Generic function to parse a configurable type from a payload
pub fn authenticate_request<T>(req: &poem::Request, payload_vec: Vec<u8>) -> Result<T, String>
where
    T: DeserializeOwned + AuthPayloadTrait + std::fmt::Debug,
{
    // Parse the signature from the request headers.
    let payload_signature = match req
        .headers()
        .get("X-Signed-Header")
        .and_then(|value| value.to_str().ok())
    {
        Some(signature) => signature,
        None => return Err(format!("X-Signed-Header is required")),
    };

    // Attempt to deserialize the payload as the specified type
    let parsed: T = match serde_json::from_slice(&payload_vec) {
        Ok(data) => data,
        Err(err) => return Err(format!("Failed to parse payload: {}", err)),
    };

    // Validate that the timestamp in this payload is not expired.
    if parsed.timestamp() < unix_timestamp_sec() {
        return Err(format!("Payload timestamp expired."));
    }

    // Produce a hash of the payload to validate with.
    let message = hex::encode(Sha256::digest(payload_vec).as_slice());
    info!(
        "verifying signature {:?} for pubkey {:?} with message {:?}",
        payload_signature,
        parsed.user_pubkey(),
        message
    );

    // Parse the signature bytes from the header value.
    let signature_bytes = match parse_string(payload_signature) {
        Ok(bytes) => bytes,
        Err(msg) => return Err(msg),
    };
    // Parse the pubkey bytes from the parsed payload value.
    let pubkey_bytes = match parse_string(parsed.user_pubkey()) {
        Ok(bytes) => bytes,
        Err(msg) => return Err(msg),
    };
    // Verification libraries expect that the message bytes are produced from a utf8 encoded string,
    // so we first encode the hash as a hex string, before serializing it to bytes.
    let message_bytes = message.as_bytes();

    // NOTE: will return error on both invalid AND incorrect signatures
    match parsed.ciphersuite() {
        "ed25519" => {
            match verify_ed25519_signature(&pubkey_bytes, message_bytes, &signature_bytes) {
                Ok(_) => Ok(parsed),
                Err(err) => Err(format!("Verification failed [ed25519]")),
            }
        }
        "ethers" => match verify_ethers_signature(&pubkey_bytes, message_bytes, &signature_bytes) {
            Ok(_) => Ok(parsed),
            Err(err) => Err(format!("Verification failed [ethers]")),
        },
        ciphersuite => Err(format!("Unsupported ciphersuite: {:?}", ciphersuite)),
    }
}

fn verify_ed25519_signature(
    pubkey_bytes: &[u8],
    message_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<(), String> {
    let error_message = format!("Failed to verify using ed25519");
    let signature = match ed25519_dalek::Signature::from_bytes(signature_bytes) {
        Ok(value) => value,
        Err(error) => {
            error!("Failed to parse Signature [ed25519] {:#?}", error);
            return Err(error_message);
        }
    };
    let public_key = match ed25519_dalek::PublicKey::from_bytes(pubkey_bytes) {
        Ok(value) => value,
        Err(error) => {
            error!("Failed to parse PublicKey [ed25519] {:#?}", error);
            return Err(error_message);
        }
    };
    match public_key.verify(message_bytes, &signature) {
        Ok(()) => Ok(()),
        Err(error) => {
            error!("Failed to verify [ed25519] {:#?}", error);
            Err(error_message)
        }
    }
}

fn verify_ethers_signature(
    pubkey_bytes: &[u8],
    message_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<(), String> {
    let error_message = format!("Failed to verify using ethers");
    let message_hash = message_bytes;
    let address = ethers::types::Address::from_slice(pubkey_bytes);
    let signature = match ethers::types::Signature::try_from(signature_bytes) {
        Ok(value) => value,
        Err(error) => {
            error!("Failed to parse Signature [ethers] {:#?}", error);
            return Err(error_message);
        }
    };
    // Using the signature and message hash, recover the signer - which can be compared to pubkey.
    match signature.verify(message_hash, address) {
        Ok(_) => Ok(()),
        Err(error) => {
            error!("Failed to verify [ethers] {:#?}", error);
            Err(error_message)
        }
    }
}

pub fn unix_timestamp_sec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn parse_string(input: &str) -> Result<Vec<u8>, String> {
    if input.is_empty() {
        return Err(format!("Unable to parse empty string"));
    }

    let hex_regex = Regex::new(r"^(0x)?[a-fA-F0-9]+$").unwrap();
    let base58_regex = Regex::new(r"^[1-9A-HJ-NP-Za-km-z]+$").unwrap();
    let base64_regex =
        Regex::new(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$").unwrap();

    if hex_regex.is_match(input) {
        let hex_str = if input.starts_with("0x") {
            &input[2..]
        } else {
            input
        };
        hex::decode(hex_str).map_err(|e| e.to_string())
    } else if base58_regex.is_match(input) {
        bs58::decode(input).into_vec().map_err(|e| e.to_string())
    } else if base64_regex.is_match(input) {
        base64::decode(input).map_err(|e| e.to_string())
    } else {
        Err(format!("Unable to parse string: {:?}", input))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::prelude::*;
    use bs58::decode;
    use std::result::Result;

    #[test]
    fn test_ed25519_signature_auth() -> Result<(), String> {
        let signed_message_str: &str =
            "8eb4e6749cbb7afb53f095a51627cfe892d101af367daf0d7a15ca9e4a361f00";
        let signature_str = "xq/7d7QmyWHuLo1UyLxxyApatGY4oNmG39e9nL1348itsJfbo0SV2QyUJTLhomm55AYtdOLjzBWW6HJRhqyCBg==";
        let pubkey_str = "BNiGJpc6zkmkk7Jir1ggRfyxFy2fwjMmt2BUDUEg4eCG";

        verify_ed25519_signature(
            &parse_string(pubkey_str).unwrap(),
            signed_message_str.as_bytes(),
            &parse_string(signature_str).unwrap(),
        )
    }

    #[test]
    fn test_ethers_signature_auth() -> Result<(), String> {
        let signed_message_str: &str =
            "6fa011e7ea3326625af6086c996a998f1b0c3e8be7b563e5d2937b69fd8e26d2";
        let signature_str = "Cq4zE56NSHhsKRu+8qnsJShN+L4RfOAF2MjqmK+dcEsKeI/54UoAOsqQDUCsSJaPbsCyWFPzrdjj94mh6089IBs=";
        let pubkey_str = "0xFec0F7f810371CF2c9E53d9D048B4Dc1C3392183";

        verify_ethers_signature(
            &parse_string(pubkey_str).unwrap(),
            signed_message_str.as_bytes(),
            &parse_string(signature_str).unwrap(),
        )
    }

    #[test]
    fn test_hex_with_0x_prefix() {
        assert_eq!(parse_string("0x68656c6c6f").unwrap(), b"hello".to_vec());
    }

    #[test]
    fn test_hex_without_prefix() {
        assert_eq!(parse_string("68656c6c6f").unwrap(), b"hello".to_vec());
    }

    #[test]
    fn test_invalid_hex() {
        assert!(parse_string("0xzzzz").is_err());
    }

    #[test]
    fn test_base58() {
        assert_eq!(
            parse_string("BNiGJpc6zkmkk7Jir1ggRfyxFy2fwjMmt2BUDUEg4eCG").unwrap(),
            [
                154, 36, 185, 56, 73, 196, 75, 11, 71, 82, 206, 141, 25, 137, 140, 172, 197, 21,
                105, 146, 234, 182, 56, 5, 151, 116, 202, 28, 54, 18, 15, 137
            ]
        );
    }

    #[test]
    fn test_invalid_base58() {
        assert!(parse_string("I0O").is_err());
    }

    #[test]
    fn test_base64() {
        assert_eq!(parse_string("aGVsbG8=").unwrap(), b"hello".to_vec());
    }

    #[test]
    fn test_invalid_base64() {
        assert!(parse_string("****").is_err());
    }

    #[test]
    fn test_empty_string() {
        assert!(parse_string("").is_err());
    }

    #[test]
    fn test_non_encoded_string() {
        assert!(parse_string("not_encoded").is_err());
    }
}
