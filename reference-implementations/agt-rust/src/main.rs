use acs_agt_guardian::{serve, GuardianConfig};
use std::{env, net::SocketAddr, path::PathBuf};

#[tokio::main]
async fn main() -> Result<(), String> {
    let mut config = GuardianConfig::from_repo();
    if let Some(value) = env::var_os("ACS_MANIFEST_PATH") {
        config.manifest = PathBuf::from(value);
    }
    if let Some(value) = env::var_os("ACS_ENVELOPE_LOG") {
        config.envelope_log = Some(PathBuf::from(value));
    }
    if let Some(value) = env::var_os("ACS_SESSION_CONTEXT_LOG") {
        config.session_log = Some(PathBuf::from(value));
    }
    config.on_decision_failure =
        env::var("ACS_ON_DECISION_FAILURE").unwrap_or_else(|_| "proceed".into());
    let host = env::var("ACS_GUARDIAN_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = env::var("ACS_GUARDIAN_PORT").unwrap_or_else(|_| "8787".into());
    let address: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|error| format!("invalid Guardian address: {error}"))?;
    eprintln!("Rust Guardian listening at http://{address}/acs");
    serve(config, address).await
}
