#![allow(unused)]

use crate::*;

use std::mem;
use std::ptr;
use std::time::{Duration, SystemTime};

use intel_tee_quote_verification_rs::*;

#[cfg(debug_assertions)]
const SGX_DEBUG_FLAG: i32 = 1;
#[cfg(not(debug_assertions))]
const SGX_DEBUG_FLAG: i32 = 0;

const _COMMON_ADVISORIES: [&str; 1] = ["INTEL-SA-00334"];
const PERMITTED_ADVISORIES: [&str; 1] = ["INTEL-SA-00615"];

/// Quote verification with QvE/QVL
pub fn ecdsa_quote_verification(quote: &[u8]) -> bool {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(0);

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
        Ok((supp_ver, supp_size)) => {
            if supp_size == mem::size_of::<sgx_ql_qv_supplemental_t>() as u32 {
                info!("\tInfo: tee_get_quote_supplemental_data_version_and_size successfully returned.");
                info!("\tInfo: latest supplemental data major version: {}, minor version: {}, size: {}",
                    u16::from_be_bytes(supp_ver.to_be_bytes()[..2].try_into().unwrap()),
                    u16::from_be_bytes(supp_ver.to_be_bytes()[2..].try_into().unwrap()),
                    supp_size,
                );
                supp_data_desc.data_size = supp_size;
            } else {
                info!("\tWarning: Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.");
                // return false;
            }
        }
        Err(e) => {
            info!(
                "\tError: tee_get_quote_supplemental_data_size failed: {:#04x}",
                e as u32
            );
            return false;
        }
    }

    // get collateral
    let collateral = match tee_qv_get_collateral(quote) {
        Ok(c) => {
            info!("\tInfo: tee_qv_get_collateral successfully returned.");
            Some(c)
        }
        Err(e) => {
            info!("\tError: tee_qv_get_collateral failed: {:#04x}", e as u32);
            None
        }
    };

    let p_collateral: Option<&QuoteCollateral> = None;
    // TODO should I add
    // uncomment the next 2 lines, if you want to use the collateral provided by the caller in the verification
    // let collateral = collateral.unwrap();
    // let p_collateral = Some(&collateral[..]);

    let p_supplemental_data = match supp_data_desc.data_size {
        0 => None,
        _ => Some(&mut supp_data_desc),
    };

    // call DCAP quote verify library for quote verification
    // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
    // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
    // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    match tee_verify_quote(quote, p_collateral, current_time, None, p_supplemental_data) {
        Ok((colla_exp_stat, qv_result)) => {
            collateral_expiration_status = colla_exp_stat;
            quote_verification_result = qv_result;
            info!("\tInfo: App: tee_verify_quote successfully returned.");
        }
        Err(e) => info!("\tError: App: tee_verify_quote failed: {:#04x}", e as u32),
    }

    // check verification result
    //
    match quote_verification_result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            // check verification collateral expiration status
            // this value should be considered in your own attestation/verification policy
            //
            if collateral_expiration_status == 0 {
                info!("\tInfo: App: Verification completed successfully.");
            } else {
                info!("\tWarning: App: Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
                // TODO: Re-enable this check.
                // return false;
            }
        }
        // TODO: check QL/QV outdated satus as well.
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            info!(
                "\tWarning: App: Verification completed with Non-terminal result: {:x}",
                quote_verification_result as u32
            );
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_INVALID_SIGNATURE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_REVOKED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED
        | _ => {
            info!(
                "\tError: App: Verification completed with Terminal result: {:x}",
                quote_verification_result as u32
            );
            return false;
        }
    }

    // check supplemental data if necessary
    //
    if supp_data_desc.data_size > 0 {
        // you can check supplemental data based on your own attestation/verification policy
        // here we only print supplemental data version for demo usage
        //
        let version_s = unsafe { supp_data.__bindgen_anon_1.__bindgen_anon_1 };
        // info!("\tInfo: Supplemental data Major Version: {}", version_s.major_version);
        // info!("\tInfo: Supplemental data Minor Version: {}", version_s.minor_version);

        // print SA list if it is a valid UTF-8 string

        let sa_list = unsafe {
            std::slice::from_raw_parts(
                supp_data.sa_list.as_ptr() as *const u8,
                mem::size_of_val(&supp_data.sa_list),
            )
        };
        if let Ok(s) = std::str::from_utf8(sa_list) {
            let advisories = s.replace("\0", "");
            let advisories = advisories.replace(",", " ");
            let advisories: Vec<&str> = advisories
                .split_whitespace()
                .filter(|x| !x.is_empty())
                .collect();
            info!("{:#?}", advisories);
            info!("\tInfo: Advisory ID: {}", s);
            let mut disallowed_advisories = advisories.clone();
            disallowed_advisories.retain(|item| !PERMITTED_ADVISORIES.contains(item));
            if !disallowed_advisories.is_empty() {
                info!(
                    "Disallowed advisory list non-empty {:?}",
                    disallowed_advisories
                );
                return false;
            }
        }
    }
    true
}
