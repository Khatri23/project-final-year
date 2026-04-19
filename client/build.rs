fn main() {
    cxx_build::bridge("src/utility.rs")
    .include("client/include/RLWE.h")
    .file("src/RLWE.cc")
    .compile("rlwe");

    println!("cargo:rerun-if-changed=src/RLWE.cc");
    println!("cargo:rerun-if-changed=client/include/RLWE.h");
}