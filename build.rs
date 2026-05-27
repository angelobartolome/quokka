fn main() {
    // Prints during `cargo build` / `cargo test` compilation.
    // `cargo:warning=` is the most reliable way to surface output in CI logs.
    println!("cargo:warning=hello world");
}

