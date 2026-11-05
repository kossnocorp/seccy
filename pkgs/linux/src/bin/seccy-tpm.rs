fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = seccy_linux::broker::serve() {
        eprintln!("seccy-tpm: {error:#}");
        std::process::exit(1);
    }
}
