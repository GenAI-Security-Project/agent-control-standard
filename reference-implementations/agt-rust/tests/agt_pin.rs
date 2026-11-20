//! The Rust SDK pin must name the AGT release `../agt/agt.lock` names.
//!
//! The published 0.3.1-beta.0 crates record AGT commit 9de8cc1 in their
//! `.cargo_vcs_info.json`, while `agt.lock` pins `agt_ref` 81955d4, so the
//! commits cannot be compared for equality until AGT publishes crates from
//! that ref. This checks the release version both Guardians run.

#[test]
fn rust_sdk_pin_matches_the_agt_lock_sdk_version() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let lock: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("../agt/agt.lock")).unwrap())
            .unwrap();
    let sdk_version = lock["sdk_version"].as_str().expect("agt.lock sdk_version");
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let pin = manifest
        .lines()
        .find_map(|line| line.strip_prefix("agent_control_specification = "))
        .expect("agent_control_specification dependency");
    assert_eq!(pin.trim().trim_matches('"'), format!("={sdk_version}"));
}
