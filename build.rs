fn main() {
    println!("cargo:rustc-link-lib=static=ssl");
    println!("cargo:rustc-link-lib=static=crypto");

    println!("cargo:rustc-cfg=release");
    println!("cargo:rustc-env=RUSTFLAGS=-C optimization=3 -C lto");
    println!("cargo:rustc-cfg=static");
}
