use actix_web::{
    web::{self, Bytes},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use chrono::{DateTime, Utc};
use ring::{digest, signature};
use serde::Deserialize;
use std::io;
use untrusted;

use crate::db;

//todo format can either be "sha256" or "mrenclave:$ENCLAVE_VALUE". if the latter, then it's checked in the whitelist before getting encrypted and sent
pub async fn get_secrets(path: web::Path<(String, String)>) -> impl Responder {
    let (user_pubkey, format) = path.into_inner();
    match format.as_str() {
        "json" => HttpResponse::Ok().body("You requested JSON!"),
        "xml" => HttpResponse::Ok().body("You requested XML!"),
        _ => HttpResponse::BadRequest().body("Invalid format!"),
    }
}

pub async fn get_functions(path: web::Path<String>) -> impl Responder {
    let (user_pubkey) = path.into_inner();
    HttpResponse::Ok().body(format!("Getting functions for user: {}", user_pubkey))
}

#[derive(Deserialize, Debug)]
struct PutUserPayload {
    ciphersuite: String,
    pubkey: String,
    #[serde(with = "ts_milliseconds")]
    timestamp: DateTime<Utc>,
    contact_info: Option<String>,
}
pub async fn put_user(payload_bytes: web::Bytes, req: HttpRequest) -> impl Responder {
    let mut payload_sig: &str;
    match req.headers().get("payload-signature") {
        Some(header) => {
            payload_sig = header.to_str().unwrap_or("");
            // HttpResponse::Ok().body(format!("The value of payload-signature is: {}", header_value))
        }
        None => HttpResponse::BadRequest().body("No payload-signature header found"),
    }
    let body_str = str::from_utf8(&payload_bytes).unwrap_or("");
    let payload: PutUserPayload = from_slice(body_str.as_bytes()).unwrap();
    let payload_is_valid: Result<bool, Box<_>> = verify_payload_sig(
        payload_bytes,
        payload_sig,
        &payload.pubkey,
        &payload.ciphersuite,
    );
    let contact_info = payload.contact_info.unwrap_or("".to_string());
    match payload_is_valid {
        Ok(is_valid) => {
            if is_valid {
                //endpoint-specific logic
                match db::insert_user(&payload.pubkey, &payload.ciphersuite, &contact_info).await {
                    Ok(_) => HttpResponse::Ok().body("User inserted successfully"),
                    Err(e) => {
                        HttpResponse::InternalServerError().body(format!("Database error: {}", e))
                    }
                }
            } else {
                HttpResponse::BadRequest().body("unable to verify signature")
            }
        }
        Err(e) => HttpResponse::BadRequest().body("invalid ciphersuite"),
    }
}

#[derive(Deserialize, Debug)]
struct PutSecretPayload {
    ciphersuite: String,
    pubkey: String,
    #[serde(with = "ts_milliseconds")]
    timestamp: DateTime<Utc>,
    secret_value: String,
}

pub async fn put_secrets(payload_bytes: web::Bytes, req: HttpRequest) -> impl Responder {
    let mut payload_sig: &str;
    match req.headers().get("payload-signature") {
        Some(header) => {
            payload_sig = header.to_str().unwrap_or("");
            // HttpResponse::Ok().body(format!("The value of payload-signature is: {}", header_value))
        }
        None => HttpResponse::BadRequest().body("No payload-signature header found"),
    }
    let body_str = str::from_utf8(&payload_bytes).unwrap_or("");
    let payload: PutSecretPayload = from_slice(body_str.as_bytes()).unwrap();
    let payload_is_valid: Result<bool, Box<_>> = verify_payload_sig(
        payload_bytes,
        payload_sig,
        &payload.pubkey,
        &payload.ciphersuite,
    );
    let contact_info = payload.contact_info.unwrap_or("".to_string());
    match payload_is_valid {
        Ok(is_valid) => {
            if is_valid {
                //endpoint-specific logic
                match db::insert_secret(&payload.pubkey, &payload.ciphersuite, &secret_value).await
                {
                    Ok(_) => HttpResponse::Ok().body("Secret inserted successfully"),
                    Err(e) => {
                        HttpResponse::InternalServerError().body(format!("Database error: {}", e))
                    }
                }
            } else {
                HttpResponse::BadRequest().body("unable to verify signature")
            }
        }
        Err(e) => HttpResponse::BadRequest().body("invalid ciphersuite"),
    }
}

#[derive(Deserialize, Debug)]
struct PutFunctionPayload {
    ciphersuite: String,
    pubkey: String,
    #[serde(with = "ts_milliseconds")]
    timestamp: DateTime<Utc>,
    mrenclave_quote: String,
}

pub async fn put_functions(payload_bytes: web::Bytes, req: HttpRequest) -> impl Responder {
    let mut payload_sig: &str;
    match req.headers().get("payload-signature") {
        Some(header) => {
            payload_sig = header.to_str().unwrap_or("");
            // HttpResponse::Ok().body(format!("The value of payload-signature is: {}", header_value))
        }
        None => HttpResponse::BadRequest().body("No payload-signature header found"),
    }
    let body_str = str::from_utf8(&payload_bytes).unwrap_or("");
    let payload: PutFunctionPayload = from_slice(body_str.as_bytes()).unwrap();
    let payload_is_valid: Result<bool, Box<_>> = verify_payload_sig(
        payload_bytes,
        payload_sig,
        &payload.pubkey,
        &payload.ciphersuite,
    );
    let contact_info = payload.contact_info.unwrap_or("".to_string());
    match payload_is_valid {
        Ok(is_valid) => {
            if is_valid {
                //endpoint-specific logic
                match db::insert_mrenclave(&payload.pubkey, &payload.ciphersuite, &mrenclave_quote)
                    .await
                {
                    Ok(_) => HttpResponse::Ok().body("Function inserted successfully"),
                    Err(e) => {
                        HttpResponse::InternalServerError().body(format!("Database error: {}", e))
                    }
                }
            } else {
                HttpResponse::BadRequest().body("unable to verify signature")
            }
        }
        Err(e) => HttpResponse::BadRequest().body("invalid ciphersuite"),
    }
}

#[derive(Deserialize, Debug)]
struct PutWhitelistPayload {
    mrenclave_quote: String,
    secret: String,
    pubkey: String,
    ciphersuite: String,
    #[serde(with = "ts_milliseconds")]
    timestamp: DateTime<Utc>,
}

pub async fn put_whitelist(payload_bytes: web::Bytes, req: HttpRequest) -> impl Responder {
    let mut payload_sig: &str;
    match req.headers().get("payload-signature") {
        Some(header) => {
            payload_sig = header.to_str().unwrap_or("");
            // HttpResponse::Ok().body(format!("The value of payload-signature is: {}", header_value))
        }
        None => HttpResponse::BadRequest().body("No payload-signature header found"),
    }
    let body_str = str::from_utf8(&payload_bytes).unwrap_or("");
    let payload: PutWhitelistPayload = from_slice(body_str.as_bytes()).unwrap();
    let payload_is_valid: Result<bool, Box<_>> = verify_payload_sig(
        payload_bytes,
        payload_sig,
        &payload.pubkey,
        &payload.ciphersuite,
    );
    let contact_info = payload.contact_info.unwrap_or("".to_string());
    match payload_is_valid {
        Ok(is_valid) => {
            if is_valid {
                //endpoint-specific logic
                match db::insert_mrenclave_whitelist(&payload.mrenclave_quote, &payload.secret)
                    .await
                {
                    Ok(_) => HttpResponse::Ok().body("Whitelist inserted successfully"),
                    Err(e) => {
                        HttpResponse::InternalServerError().body(format!("Database error: {}", e))
                    }
                }
            } else {
                HttpResponse::BadRequest().body("unable to verify signature")
            }
        }
        Err(e) => HttpResponse::BadRequest().body("invalid ciphersuite"),
    }
}

fn verify_payload_sig(
    payload: Bytes,
    signature: &str,
    pubkey: &str,
    ciphersuite: &str,
) -> Result<bool, Box<dyn Error>> {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let result = hasher.finalize();

    let signature_bytes = base64::decode(signature)?;
    let pubkey_bytes = base64::decode(pubkey)?;

    //note: will return error on both invalid AND incorrect signatures
    match ciphersuite {
        "secp256k1" => {
            let public_key = untrusted::Input::from(&pubkey_bytes);
            let msg = untrusted::Input::from(&result);
            let sig = untrusted::Input::from(&signature_bytes);
            signature::verify(&signature::ECDSA_P256_SHA256_FIXED, public_key, msg, sig)
                .map_err(|_| false)?;
        }
        "ed25519" => {
            let public_key = untrusted::Input::from(&pubkey_bytes);
            let msg = untrusted::Input::from(&result);
            let sig = untrusted::Input::from(&signature_bytes);
            signature::verify(&signature::ED25519, public_key, msg, sig).map_err(|_| false)?;
        }
        _ => return Err("Unsupported ciphersuite".into()),
    }

    Ok(true)
}
