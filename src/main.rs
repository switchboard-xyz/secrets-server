#![allow(unused_assignments)]
#![allow(clippy::wildcard_in_or_patterns)]
use sgx_dcap_quoteverify_rs::*;

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use hex;
use rand::rngs::OsRng;
use rsa::Pkcs1v15Encrypt;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use serde::Deserialize;
use serde_json;
use sgx_quote;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::mem;
use std::time::{SystemTime, UNIX_EPOCH};

/// Quote verification with QVL
///
/// # Param
/// - **quote**\
/// ECDSA quote buffer.
pub fn ecdsa_quote_verification(quote: &[u8], current_time: i64) -> (bool, Vec<String>) {
    let mut collateral_expiration_status = 1u32;
    let mut quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;

    let mut supp_data: sgx_ql_qv_supplemental_t = Default::default();
    let mut supp_data_desc = tee_supp_data_descriptor_t {
        major_version: 0,
        data_size: 0,
        p_data: &mut supp_data as *mut sgx_ql_qv_supplemental_t as *mut u8,
    };

    // Untrusted quote verification

    // call DCAP quote verify library to get supplemental latest version and data size
    // version is a combination of major_version and minor version
    // you can set the major version in 'supp_data.major_version' to get old version supplemental data
    // only support major_version 3 right now
    //
    match tee_get_supplemental_data_version_and_size(quote) {
        Ok((_supp_ver, supp_size)) => {
            if supp_size == mem::size_of::<sgx_ql_qv_supplemental_t>() as u32 {
                // println!("\tInfo: tee_get_quote_supplemental_data_version_and_size successfully returned.");
                // println!("\tInfo: latest supplemental data major version: {}, minor version: {}, size: {}",
                // u16::from_be_bytes(supp_ver.to_be_bytes()[..2].try_into().unwrap()),
                // u16::from_be_bytes(supp_ver.to_be_bytes()[2..].try_into().unwrap()),
                // supp_size,
                // );
                supp_data_desc.data_size = supp_size;
            } else {
                println!("\tWarning: Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.")
            }
        }
        Err(e) => {
            println!(
                "\tError: tee_get_quote_supplemental_data_size failed: {:#04x}",
                e as u32
            );
            return (false, vec![]);
        }
    }

    let p_supplemental_data = match supp_data_desc.data_size {
        0 => None,
        _ => Some(&mut supp_data_desc),
    };

    // call DCAP quote verify library for quote verification
    // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
    // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
    // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    match tee_verify_quote(quote, None, current_time, None, p_supplemental_data) {
        Ok((colla_exp_stat, qv_result)) => {
            collateral_expiration_status = colla_exp_stat;
            quote_verification_result = qv_result;
            // println!("\tInfo: App: tee_verify_quote successfully returned.");
        }
        Err(e) => {
            println!("\tError: App: tee_verify_quote failed: {:#04x}", e as u32);
            return (false, vec![]);
        }
    }

    // check verification result
    //
    match quote_verification_result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            // check verification collateral expiration status
            // this value should be considered in your own attestation/verification policy
            //
            if collateral_expiration_status == 0 {
                // println!("\tInfo: App: Verification completed successfully.");
            } else {
                println!("\tWarning: App: Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
                return (false, vec![]);
            }
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            println!(
                "\tWarning: App: Verification completed with Non-terminal result: {:x}",
                quote_verification_result as u32
            );
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_INVALID_SIGNATURE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_REVOKED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED
        | _ => {
            println!(
                "\tError: App: Verification completed with Terminal result: {:x}",
                quote_verification_result as u32
            );
        }
    }

    // check supplemental data if necessary
    //
    if supp_data_desc.data_size > 0 {
        // you can check supplemental data based on your own attestation/verification policy
        // here we only print supplemental data version for demo usage
        //
        let _version_s = unsafe { supp_data.__bindgen_anon_1.__bindgen_anon_1 };
        // println!(
        // "\tInfo: Supplemental data Major Version: {}",
        // version_s.major_version
        // );
        // println!(
        // "\tInfo: Supplemental data Minor Version: {}",
        // version_s.minor_version
        // );

        // print SA list if it is a valid UTF-8 string

        let sa_list = unsafe {
            std::slice::from_raw_parts(
                supp_data.sa_list.as_ptr() as *const u8,
                mem::size_of_val(&supp_data.sa_list),
            )
        };
        if let Ok(s) = std::str::from_utf8(sa_list) {
            println!("\tInfo: Advisory ID: {}", s);
            return (true, s.split(',').map(|s| s.to_string()).collect());
        }
    }
    (true, vec![])
}

#[derive(Deserialize)]
struct VerifyPayload {
    quote: Vec<u8>,
    pubkey: Vec<u8>,
}

async fn verify(payload: web::Json<VerifyPayload>) -> impl Responder {
    let configs_str = std::env::var("CONFIGS").unwrap();
    let configs: Configs = serde_json::from_str(&configs_str).unwrap();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64;
    let (is_success, advisories) = ecdsa_quote_verification(&payload.quote, current_time);
    if !is_success {
        return HttpResponse::Unauthorized().finish();
    }
    for advisory in advisories {
        if !configs.permittedAdvisories.contains(&advisory) {
            return HttpResponse::Unauthorized().finish();
        }
    }
    let quote = sgx_quote::Quote::parse(&payload.quote).unwrap();
    let mut mr_enclave_found = false;
    for mr_enclave in configs.mrEnclaves {
        if quote.isv_report.mrenclave == hex::decode(mr_enclave).unwrap() {
            mr_enclave_found = true;
            break;
        }
    }
    if !mr_enclave_found {
        return HttpResponse::Unauthorized().finish();
    }
    let keyhash = &quote.isv_report.report_data[..32];
    if keyhash != Sha256::digest(&payload.pubkey).as_slice() {
        return HttpResponse::Unauthorized().finish();
    }
    let public_key = RsaPublicKey::from_public_key_der(&payload.pubkey).unwrap();
    let mut rng = OsRng {};
    let _ciphertext = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, configs_str.as_bytes())
        .unwrap();

    // TODO: encrypt with pubkey
    HttpResponse::Ok().body(configs_str)
}

#[allow(dead_code)]
#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct Configs {
    mrEnclaves: Vec<String>,
    permittedAdvisories: Vec<String>,
    keys: HashMap<String, String>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(web::resource("/verify").route(web::post().to(verify))))
        .bind("0.0.0.0:8080")?
        .run()
        .await
}
