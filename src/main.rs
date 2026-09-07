//! Entrypoint: environment-driven configuration, then serve forever.

#[tokio::main]
async fn main() {
    let config = unidpp_archive::Config::from_env();
    if let Err(e) = unidpp_archive::run(config).await {
        eprintln!("unidpp-archive: {e}");
        std::process::exit(1);
    }
}
