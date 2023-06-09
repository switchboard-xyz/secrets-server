fn main() {
    let sgx_sdk_path = "/opt/intel/sgxsdk";
    println!("cargo:rustc-env=CFLAGS=-Wl,--allow-multiple-definition");
    println!(r"cargo:rustc-link-search=.");
    println!("cargo:rustc-link-search=native={}/lib64", sgx_sdk_path);
    println!("cargo:include={}/include", sgx_sdk_path);
    println!("cargo:include=/usr/include");
    println!("cargo:rustc-link-search=/usr/lib/x86_64-linux-gnu");
    println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu/");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
}
