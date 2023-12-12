#![allow(unused_assignments)]
#![allow(clippy::wildcard_in_or_patterns)]
use sgx_dcap_quoteverify_rs::*;

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use hex;
use rand::rngs::OsRng;
use rsa::pkcs8::DecodePublicKey;
use rsa::Pkcs1v15Encrypt;
use rsa::RsaPublicKey;
use serde::Deserialize;
use serde_json;
use sgx_quote;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::mem;
use std::time::{SystemTime, UNIX_EPOCH};


#[derive(Deserialize, Debug)]
struct VerifyPayload {
    quote: Vec<u8>,
    pubkey: Vec<u8>,
}

#[allow(dead_code)]
#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct Configs {
    mrEnclaves: Vec<String>,
    permittedAdvisories: Vec<String>,
    keys: HashMap<String, String>,
}

async fn verify(payload: web::Json<VerifyPayload>) -> impl Responder {
    let configs_str = std::env::var("CONFIGS").unwrap();
    let configs = serde_json::from_str(&configs_str);
    if configs.is_err() {
        return HttpResponse::Unauthorized().body("ConfigParseError");
    }
    let configs: Configs = configs.unwrap();
    println!("Received request: {:#?}", payload);
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64;
    let (is_success, advisories) = ecdsa_quote_verification(&payload.quote, current_time);
    if !is_success {
        return HttpResponse::Unauthorized().body("QuoteVerifyFailure");
    }
    for advisory in advisories {
        if !configs.permittedAdvisories.contains(&advisory) {
            return HttpResponse::Unauthorized().body("IllegalAdvisoryPresent");
        }
    }
    let quote = sgx_quote::Quote::parse(&payload.quote);
    if quote.is_err() {
        return HttpResponse::Unauthorized().body("QuoteParseError");
    }
    let quote = quote.unwrap();
    let mut mr_enclave_found = false;
    for mr_enclave in configs.mrEnclaves {
        let mr_enclave = hex::decode(mr_enclave);
        if mr_enclave.is_err() {
            return HttpResponse::Unauthorized().body("MrEnclaveParseError");
        }
        if quote.isv_report.mrenclave == mr_enclave.unwrap() {
            mr_enclave_found = true;
            break;          
        }
    }
    if !mr_enclave_found {
        return HttpResponse::Unauthorized().body("MrEnclaveNotFound");
    }
    let keyhash = &quote.isv_report.report_data[..32];
    if keyhash != Sha256::digest(&payload.pubkey).as_slice() {
        return HttpResponse::Unauthorized().body("Keymismatch");
    }
    let public_key = RsaPublicKey::from_public_key_der(&payload.pubkey);
    if public_key.is_err() {
        return HttpResponse::Unauthorized().body("PubkeyParseError");
    }
    let public_key = public_key.unwrap();
    let mut rng = OsRng {};
    let ciphertext = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, configs_str.as_bytes())
        .unwrap();

    HttpResponse::Ok().body(ciphertext)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Access the version
    let sbv3_version = env!("SBV3_VERSION");
    println!("Version: {}", sbv3_version);

    println!("Server Starting ...");
    HttpServer::new(|| {
        println!("Started.");
        App::new().route("/", web::post().to(verify))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
