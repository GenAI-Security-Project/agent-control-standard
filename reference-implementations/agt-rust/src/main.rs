use acs_agt_guardian::{serve, GuardianConfig, HmacKeyring};
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
    if let Some(value) = env::var_os("ACS_LOG_MAX_BYTES") {
        config.log_max_bytes = value
            .to_str()
            .ok_or("ACS_LOG_MAX_BYTES is not UTF-8")?
            .parse()
            .map_err(|_| "ACS_LOG_MAX_BYTES must be a positive integer")?;
    }
    if let Some(value) = env::var_os("ACS_LOG_MAX_FILES") {
        config.log_max_files = value
            .to_str()
            .ok_or("ACS_LOG_MAX_FILES is not UTF-8")?
            .parse()
            .map_err(|_| "ACS_LOG_MAX_FILES must be a positive integer")?;
    }
    config.on_decision_failure =
        env::var("ACS_ON_DECISION_FAILURE").unwrap_or_else(|_| "proceed".into());
    config.hmac_keys = hmac_keys_from_env()?;
    if config.hmac_keys.is_empty() {
        eprintln!(
            "warning: no HMAC key is configured, so requests are not verified and responses are not signed (not ACS-Core)"
        );
    }
    if let Some(value) = env::var_os("ACS_SKEW_WINDOW_MS") {
        config.skew_window_ms = value
            .to_str()
            .ok_or("ACS_SKEW_WINDOW_MS is not UTF-8")?
            .parse()
            .map_err(|_| "ACS_SKEW_WINDOW_MS must be a non-negative integer")?;
    }
    let host = env::var("ACS_GUARDIAN_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = env::var("ACS_GUARDIAN_PORT").unwrap_or_else(|_| "8787".into());
    let address: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|error| format!("invalid Guardian address: {error}"))?;
    eprintln!("Rust Guardian listening at http://{address}/acs");
    serve(config, address).await
}

/// §10 secrets from `ACS_HMAC_KEYS_FILE`, a JSON object mapping each `key_id`
/// to a base64 secret, and from the `ACS_HMAC_KEY_ID` and `ACS_HMAC_SECRET`
/// pair the TypeScript host adapter also reads. A label has no default, so one
/// of that pair without the other is a configuration error.
fn hmac_keys_from_env() -> Result<HmacKeyring, String> {
    let mut keyring = HmacKeyring::default();
    if let Some(path) = env::var_os("ACS_HMAC_KEYS_FILE") {
        keyring.insert_file(&PathBuf::from(path))?;
    }
    match (env::var("ACS_HMAC_KEY_ID"), env::var("ACS_HMAC_SECRET")) {
        (Ok(key_id), Ok(secret)) => keyring.insert_base64(&key_id, &secret)?,
        (Err(_), Err(_)) => {}
        _ => {
            return Err(
                "ACS_HMAC_KEY_ID and ACS_HMAC_SECRET must be set together: key_id names the configured secret (§10)"
                    .into(),
            )
        }
    }
    Ok(keyring)
}
