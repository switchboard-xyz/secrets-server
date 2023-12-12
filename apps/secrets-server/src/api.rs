use crate::*;

// https://github.com/poem-web/poem/blob/master/examples/openapi/users-crud/src/main.rs
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use poem::{http::StatusCode, Request};
use poem_openapi::param::Path;
use poem_openapi::payload::PlainText;
use rand::rngs::OsRng;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};

use sha2::{Digest, Sha256};

// Knock off JWT
// Ciphersuite - bytes payload + sha256 hash + signature (client)
// user includes signature in header (verify the signature)

#[derive(Debug, Object, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct FetchSecretPayload {
    user_pubkey: String,
    ciphersuite: String,
    secret_name: String,
    encryption_key: String,
    quote: Vec<u8>,
}

#[derive(Debug, Object, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct FetchSecretsPayload {
    /// The requesting user's pubkey.
    user_pubkey: String,
    /// The signing system used for the user's pubkey auth.
    ciphersuite: String,
    /// The quote being run (used to verify which `mr_enclave` is being run).
    quote: Vec<u8>,
    /// The signing system used for the user's pubkey auth.
    encryption_key: String,
}

#[derive(Debug, Object, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct UpdateUserPayload {
    user_pubkey: String,
    ciphersuite: String,
    contact_info: Option<String>,
    timestamp: u64,
}

#[derive(Debug, Object, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct DeleteSecretPayload {
    user_pubkey: String,
    ciphersuite: String,
    secret_name: String,
    timestamp: u64,
}

#[derive(Debug, Object, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct PutMrenclaveWhitelistPayload {
    user_pubkey: String,
    ciphersuite: String,
    mr_enclave: String,
    secret_name: String,
    timestamp: u64,
}

#[derive(Debug, Object, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct PutMrenclavePayload {
    user_pubkey: String,
    ciphersuite: String,
    mr_enclave: String,
    timestamp: u64,
}

#[derive(Debug, Object, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct PutUserSecretPayload {
    user_pubkey: String,
    ciphersuite: String,
    secret: String,
    secret_name: String,
    timestamp: u64,
}

#[derive(Debug, Object, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct EncryptedData {
    // A key that has been encrypted using the client's provided PublicKey and, once decrypted, can
    // be used to decrypt the rest of the data.
    key: String,
    // The nonce is a random value used to prevent attackers from reusing intercepted ciphertexts to
    // decrypt other messages.
    nonce: String,
    // The encrypted payload.
    data: String,
}

#[derive(ApiResponse)]
enum HttpResponse {
    #[oai(status = 200)]
    OkString(Json<String>),
    #[oai(status = 200)]
    OkUser(Json<UserPg>),
    #[oai(status = 200)]
    OkSecrets(Json<Vec<SecretInfoPg>>),
    #[oai(status = 200)]
    OkEncryptedData(Json<EncryptedData>),
    #[oai(status = 401)]
    Unauthorized(poem_openapi::payload::PlainText<String>),
    #[oai(status = 404)]
    NotFound(poem_openapi::payload::PlainText<String>),
    #[oai(status = 500)]
    InternalError(poem_openapi::payload::PlainText<String>),
}

#[derive(Default)]
pub struct Api;

#[OpenApi]
impl Api {
    /// Get a user's config based on a `user_pubkey` and `ciphersuite`.
    ///
    ///  Usage:
    ///  ```bash
    ///  curl -X GET \
    ///    -H 'Content-Type: application/json' \
    ///    -H 'X-Signed-Header: test-sig' \
    ///    https://api.secrets.switchboard.xyz/user/test-pubkey/ciphersuite/ed25519
    ///  ```
    #[oai(path = "/user/:user_pubkey/ciphersuite/:ciphersuite", method = "get")]
    async fn get_user<'a>(
        &self,
        db: Data<&'a PostgresStore>,
        user_pubkey: Path<String>,
        ciphersuite: Path<String>,
    ) -> Result<HttpResponse> {
        info!("GetUser: {}", *user_pubkey);
        match db.0.get_user(&*user_pubkey, &ciphersuite).await {
            Ok(user) => Ok(HttpResponse::OkUser(Json(user))),
            Err(e) => {
                log_error(&e);
                let msg = "UserNotFound".to_string();
                Ok(HttpResponse::NotFound(PlainText(msg)))
            }
        }
    }

    ///  Save / update a user's contact info.
    ///
    ///  Authenticated Route: User must sign the payload and provide a valid signature in the
    /// `X-Signed-Header` header.
    ///
    ///  Usage:
    ///  ```bash
    ///  curl -X PUT \
    ///    -H 'Content-Type: application/json' \
    ///    -H 'X-Signed-Header: test-sig' \
    ///    -d '{
    ///      "user_pubkey": "test-pubkey",
    ///      "ciphersuite": "ed25519",
    ///      "contact_info": "new_contact_info"
    ///    }' \
    ///    https://api.secrets.switchboard.xyz/user
    ///  ```
    #[oai(path = "/user", method = "put")]
    async fn put_user<'a>(
        &self,
        req: &'a Request,
        db: Data<&'a PostgresStore>,
        payload: Json<UpdateUserPayload>,
    ) -> Result<HttpResponse> {
        info!("PutUser: {}", payload.user_pubkey);
        let contact_info = payload
            .contact_info
            .clone()
            .unwrap_or_else(|| String::from(""));
        match db
            .0
            .create_user(&*payload.user_pubkey, &payload.ciphersuite, &contact_info)
            .await
        {
            Ok(_) => Ok(HttpResponse::OkString(Json("Ok".to_string()))),
            Err(e) => {
                log_error(&e);
                Ok(HttpResponse::InternalError(PlainText(e.to_string())))
            }
        }
    }

    ///  Return a user's secrets (hashed) based on the provided `user_pubkey` and `ciphersuite`.
    ///
    ///  Usage:
    ///  ```bash
    ///  curl -X GET \
    ///    -H 'Content-Type: application/json' \
    ///    -H 'X-Signed-Header: test-sig' \
    ///    https://api.secrets.switchboard.xyz/user/test-pubkey/ciphersuite/ed25519/secrets
    ///  ```
    #[oai(
        path = "/user/:user_pubkey/ciphersuite/:ciphersuite/secrets",
        method = "get"
    )]
    async fn get_user_secrets<'a>(
        &self,
        db: Data<&'a PostgresStore>,
        user_pubkey: Path<String>,
        ciphersuite: Path<String>,
    ) -> Result<HttpResponse> {
        info!("GetUserSecrets: {}", *user_pubkey);
        match db.0.get_secrets(&*user_pubkey, &*ciphersuite).await {
            Ok(mut secrets) => {
                for secret in &mut secrets {
                    secret.secret = hash_secret(&secret.secret);
                }
                Ok(HttpResponse::OkSecrets(Json(secrets)))
            }
            Err(e) => {
                log_error(&e);
                Ok(HttpResponse::InternalError(PlainText(e.to_string())))
            }
        }
    }

    ///  Save / update a secret.
    ///
    ///  Authenticated Route: User must sign the payload and provide a valid signature in the
    /// `X-Signed-Header` header.
    ///
    ///  Usage:
    ///  ```bash
    ///  curl -X PUT \
    ///    -H 'Content-Type: application/json' \
    ///    -H 'X-Signed-Header: test-sig' \
    ///    -d '{
    ///      "user_pubkey": "test-pubkey",
    ///      "ciphersuite": "ed25519",
    ///      "secret_name": "test-secret-name",
    ///      "secret": "test-secret-value"
    ///    }' \
    ///    https://api.secrets.switchboard.xyz/secret
    ///  ```
    #[oai(path = "/secret", method = "put")]
    async fn put_user_secret<'a>(
        &self,
        req: &'a Request,
        db: Data<&'a PostgresStore>,
        payload: Json<PutUserSecretPayload>,
    ) -> Result<HttpResponse> {
        info!(
            "PutUserSecret: {} {}",
            payload.user_pubkey, payload.secret_name
        );
        match db
            .0
            .create_secret(
                &*payload.user_pubkey,
                &payload.ciphersuite,
                &payload.secret_name,
                &payload.secret,
            )
            .await
        {
            Ok(_) => Ok(HttpResponse::OkString(Json("Ok".to_string()))),
            Err(e) => {
                log_error(&e);
                Ok(HttpResponse::InternalError(PlainText(e.to_string())))
            }
        }
    }

    ///  Delete a secret.
    ///
    ///  Authenticated Route: User must sign the payload and provide a valid signature in the
    /// `X-Signed-Header` header.
    ///
    ///  Usage:
    ///  ```bash
    ///  curl -X DELETE \
    ///    -H 'Content-Type: application/json' \
    ///    -H 'X-Signed-Header: test-sig' \
    ///    -d '{
    ///      "user_pubkey": "test-pubkey",
    ///      "ciphersuite": "ed25519",
    ///      "secret_name": "test-secret-name"
    ///    }' \
    ///    https://api.secrets.switchboard.xyz/secret
    ///  ```
    #[oai(path = "/secret", method = "delete")]
    async fn delete_secret<'a>(
        &self,
        req: &'a Request,
        db: Data<&'a PostgresStore>,
        payload: Json<DeleteSecretPayload>,
    ) -> Result<HttpResponse> {
        info!(
            "DeleteUserSecret: {} {}",
            payload.user_pubkey, payload.secret_name
        );
        match db
            .0
            .delete_secret(&payload.user_pubkey, &payload.secret_name)
            .await
        {
            Ok(_) => Ok(HttpResponse::OkString(Json("Ok".to_string()))),
            Err(e) => {
                log_error(&e);
                Ok(HttpResponse::InternalError(PlainText(e.to_string())))
            }
        }
    }

    ///  Fetch secrets from the database for a provided `user_pubkey` and whitelisted for use by the
    /// `quote`'s mr_enclave and return an encrypted map.
    ///
    ///  Usage:
    ///  ```bash
    ///  curl -X POST \
    ///    -H 'Content-Type: application/json' \
    ///    -H 'X-Signed-Header: test-sig' \
    ///    -d '{
    ///      "user_pubkey": "test-pubkey",
    ///      "ciphersuite": "ed25519",
    ///      "encryption_key": "encryption-pubkey",
    ///      "quote": [0,0,0,0]
    ///    }' \
    ///    https://api.secrets.switchboard.xyz/
    ///  ```
    #[oai(path = "/", method = "post")]
    async fn fetch_secrets<'a>(
        &self,
        db: Data<&'a PostgresStore>,
        payload: Json<FetchSecretsPayload>,
    ) -> Result<HttpResponse> {
        info!("FetchSecrets: {}", payload.user_pubkey);
        // Parse the quote and get the MrEnclave
        let (quote, quote_mr_enclave) = match verify_quote(&payload.quote) {
            Ok(value) => value,
            Err(e) => {
                log_error(&e);
                return Ok(HttpResponse::Unauthorized(PlainText(e.to_string())));
            }
        };
        // Get the secrets for this user.
        let hashmap = match db
            .0
            .get_secrets_map(
                &payload.user_pubkey,
                &payload.ciphersuite,
                &quote_mr_enclave,
            )
            .await
        {
            Ok(value) => value,
            Err(e) => {
                log_error(&e);
                return Ok(HttpResponse::InternalError(PlainText(e.to_string())));
            }
        };
        let json_map = serde_json::to_value(&hashmap).unwrap();
        // Serialize the secrets map to be encrypted.
        let mut unencrypted = Vec::<u8>::new();
        serde_json::to_writer(&mut unencrypted, &json_map).unwrap();
        // Encrypt the response and return it.
        let quote_hash = &quote.isv_report.report_data[..32];
        match encrypt_bytes(&payload.encryption_key, quote_hash, &unencrypted) {
            Ok(value) => Ok(HttpResponse::OkEncryptedData(Json(value))),
            Err(e) => {
                log_error(&e);
                return Ok(HttpResponse::Unauthorized(PlainText(e.to_string())));
            }
        }
    }

    ///  Creates an `mr_enclave` value in the database.
    ///  NOTE: The measurement value must already be known in the database.
    ///
    ///  Authenticated Route: User must sign the payload and provide a valid signature in the
    /// `X-Signed-Header` header.
    ///
    ///  Usage:
    ///  ```bash
    ///  curl -X PUT \
    ///    -H 'Content-Type: application/json' \
    ///    -H 'X-Signed-Header: test-sig' \
    ///    -d '{
    ///      "user_pubkey": "test-pubkey",
    ///      "ciphersuite": "ed25519",
    ///      "mr_enclave": "test-mr-enclave"
    ///    }' \
    ///    https://api.secrets.switchboard.xyz/mrenclave
    ///  ```
    #[oai(path = "/mrenclave", method = "put")]
    async fn put_mrenclave<'a>(
        &self,
        db: Data<&'a PostgresStore>,
        payload: Json<PutMrenclavePayload>,
    ) -> Result<HttpResponse> {
        info!(
            "PutMrEnclave: {} {}",
            payload.user_pubkey, payload.mr_enclave
        );
        match db
            .0
            .create_mrenclave(
                &payload.user_pubkey,
                &payload.ciphersuite,
                &payload.mr_enclave,
            )
            .await
        {
            Ok(_) => Ok(HttpResponse::OkString(Json("Ok".to_string()))),
            Err(e) => {
                log_error(&e);
                Ok(HttpResponse::InternalError(PlainText(e.to_string())))
            }
        }
    }

    ///  Deletes an `mr_enclave` value from the database if it exists.
    ///
    ///  Authenticated Route: User must sign the payload and provide a valid signature in the
    /// `X-Signed-Header` header.
    ///
    ///  Usage:
    ///  ```bash
    ///  curl -X DELETE \
    ///    -H 'Content-Type: application/json' \
    ///    -H 'X-Signed-Header: test-sig' \
    ///    -d '{
    ///      "user_pubkey": "test-pubkey",
    ///      "ciphersuite": "ed25519",
    ///      "mr_enclave": "test-mr-enclave"
    ///    }' \
    ///    https://api.secrets.switchboard.xyz/mrenclave
    ///  ```
    #[oai(path = "/mrenclave", method = "delete")]
    async fn delete_mrenclave<'a>(
        &self,
        req: &'a Request,
        db: Data<&'a PostgresStore>,
        payload: Json<PutMrenclavePayload>,
    ) -> Result<HttpResponse> {
        info!(
            "DeleteMrEnclave: {} {}",
            payload.user_pubkey, payload.mr_enclave
        );
        match db
            .0
            .delete_mrenclave(
                &payload.user_pubkey,
                &payload.ciphersuite,
                &payload.mr_enclave,
            )
            .await
        {
            Ok(_) => Ok(HttpResponse::OkString(Json("Ok".to_string()))),
            Err(e) => {
                log_error(&e);
                Ok(HttpResponse::InternalError(PlainText(e.to_string())))
            }
        }
    }

    ///  Creates an a `mr_enclave` object (if not already existing) and adds it to a whitelist for
    ///  the specified `user_pubkey` and `secret_name`.
    ///
    ///  Authenticated Route: User must sign the payload and provide a valid signature in the
    /// `X-Signed-Header` header.
    ///
    ///  Usage:
    ///  ```bash
    ///  curl -X PUT \
    ///    -H 'Content-Type: application/json' \
    ///    -H 'X-Signed-Header: test-sig' \
    ///    -d '{
    ///      "user_pubkey": "test-pubkey",
    ///      "ciphersuite": "ed25519",
    ///      "mr_enclave": "test-mr-enclave",
    ///      "secret_name": "test-secret-name"
    ///    }' \
    ///    https://api.secrets.switchboard.xyz/add_mrenclave
    ///  ```
    #[oai(path = "/add_mrenclave", method = "put")]
    async fn add_mrenclave_to_whitelist<'a>(
        &self,
        req: &'a Request,
        db: Data<&'a PostgresStore>,
        payload: Json<PutMrenclaveWhitelistPayload>,
    ) -> Result<HttpResponse> {
        info!(
            "AddMrEnclaveToWhitelist: {} {} {}",
            payload.user_pubkey, payload.secret_name, payload.mr_enclave
        );
        // Create / update an MrEnclave for this mr_enclave.
        if let Err(e) =
            db.0.create_mrenclave(
                &payload.user_pubkey,
                &payload.ciphersuite,
                &payload.mr_enclave,
            )
            .await
        {
            log_error(&e);
            return Ok(HttpResponse::InternalError(PlainText(e.to_string())));
        }
        // Add the new mr_enclave value to the whitelist for (`user_pubkey`, `secret_name`).
        if let Err(e) =
            db.0.create_mrenclave_whitelist(
                &payload.user_pubkey,
                &payload.ciphersuite,
                &payload.secret_name,
                &payload.mr_enclave,
            )
            .await
        {
            log_error(&e);
            return Ok(HttpResponse::InternalError(PlainText(e.to_string())));
        }
        Ok(HttpResponse::OkString(Json("Ok".to_string())))
    }

    ///  Deletes a `mr_enclave` value from a whitelist for the specified `user_pubkey` and
    ///  `secret_name`.
    ///
    ///  Authenticated Route: User must sign the payload and provide a valid signature in the
    /// `X-Signed-Header` header.
    ///
    ///  Usage:
    ///  ```bash
    ///  curl -X DELETE \
    ///    -H 'Content-Type: application/json' \
    ///    -H 'X-Signed-Header: test-sig' \
    ///    -d '{
    ///      "user_pubkey": "test-pubkey",
    ///      "ciphersuite": "ed25519",
    ///      "mr_enclave": "test-mr-enclave",
    ///      "secret_name": "test-secret-name"
    ///    }' \
    ///    https://api.secrets.switchboard.xyz/mrenclave/whitelist
    ///  ```
    #[oai(path = "/mrenclave/whitelist", method = "delete")]
    async fn delete_mrenclave_from_whitelist<'a>(
        &self,
        req: &'a Request,
        db: Data<&'a PostgresStore>,
        payload: Json<PutMrenclaveWhitelistPayload>,
    ) -> Result<HttpResponse> {
        info!(
            "DeleteMrEnclaveWhitelist: {} {} {}",
            payload.user_pubkey, payload.secret_name, payload.mr_enclave
        );
        match db
            .0
            .delete_mrenclave_whitelist(
                &payload.user_pubkey,
                &payload.ciphersuite,
                &payload.secret_name,
                &payload.mr_enclave,
            )
            .await
        {
            Ok(_) => Ok(HttpResponse::OkString(Json("Ok".to_string()))),
            Err(e) => {
                log_error(&e);
                Ok(HttpResponse::InternalError(PlainText(e.to_string())))
            }
        }
    }
}

/// Verifies that bytes can be decoded into a Quote
fn verify_quote(bytes: &Vec<u8>) -> Result<(sgx_quote::Quote, String)> {
    let quote = match sgx_quote::Quote::parse(bytes) {
        Ok(value) => value,
        Err(e) => {
            let msg = "QuoteParseError".to_string();
            return Err(Error::from_string(msg, StatusCode::UNAUTHORIZED));
        }
    };
    let quote_mr_enclave = hex::encode(quote.isv_report.mrenclave);
    info!("Quote parse successful. mr_enclave={:?}", quote_mr_enclave);
    // Verify that the ECDSA quote is valid
    if !quote::ecdsa_quote_verification(bytes) {
        let msg = format!("Quote is invalid. mr_enclave={:?}", quote_mr_enclave);
        return Err(Error::from_string(msg, StatusCode::UNAUTHORIZED));
    }
    Ok((quote, quote_mr_enclave))
}

/// Verify that the quote hash matches the encryption key and, if so, encrypt and return a
/// serialized object.
fn encrypt_bytes(
    encryption_key: &str,
    quote_hash: &[u8],
    unencrypted: &[u8],
) -> Result<EncryptedData> {
    // Produce the public key from the payload that will be used to encrypt the response data.
    let public_key = match RsaPublicKey::from_public_key_pem(encryption_key) {
        Ok(val) => val,
        Err(e) => {
            let msg = format!("Failed to parse encryption key: {}", e.to_string());
            return Err(Error::from_string(msg, StatusCode::UNAUTHORIZED));
        }
    };
    // Validate that the encryption key in the payload matches the generated quote.
    let document = public_key.to_public_key_der().unwrap();
    if quote_hash != Sha256::digest(document.as_bytes()).as_slice() {
        let msg = "Quote does not match encryption key.".to_string();
        return Err(Error::from_string(msg, StatusCode::UNAUTHORIZED));
    }

    // Generate the key, cipher, and nonce that will be used to encrypt the data.
    let key = Aes256Gcm::generate_key(OsRng);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);

    println!("nonce: {:?}", nonce);
    println!("key: {:?}", key);

    let encrypted_data = match cipher.encrypt(&nonce, unencrypted) {
        Ok(value) => value,
        Err(e) => {
            let msg = format!("Failed to encrypt data: {}", e.to_string());
            return Err(Error::from_string(msg, StatusCode::UNAUTHORIZED));
        }
    };
    let encrypted_key = match public_key.encrypt(&mut OsRng {}, Pkcs1v15Encrypt, &key) {
        Ok(value) => value,
        Err(e) => {
            let msg = format!("Failed to encrypt key: {}", e.to_string());
            return Err(Error::from_string(msg, StatusCode::UNAUTHORIZED));
        }
    };
    return Ok(EncryptedData {
        key: base64::encode(encrypted_key),
        nonce: base64::encode(nonce),
        data: base64::encode(encrypted_data),
    });
}
/// Consistent logging for [Error](poem::Error) type.
fn log_error(error: &Error) {
    error!("An error occurred: {:#?}", error);
}
/// Return a Sha256 hash a string.
fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    let result = hasher.finalize();
    format!("{:x}", result)
}
