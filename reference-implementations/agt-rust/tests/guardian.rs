use acs_agt_guardian::{Guardian, GuardianConfig, HmacKeyring};
use serde_json::{json, Value};

/// The repository configuration with the explicit unsigned opt-in that the
/// tests not about signing use.
fn unsigned_config() -> GuardianConfig {
    let mut config = GuardianConfig::from_repo();
    config.allow_unsigned = true;
    config
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn request(method: &str, payload: Value, request_id: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": method,
        "id": request_id,
        "params": {
            "acs_version": "0.1.0",
            "request_id": request_id,
            "timestamp": now(),
            "metadata": {
                "agent_id": "claude-code",
                "session_id": "6ccc72b8-a167-5573-b3ea-a310262ea93f"
            },
            "payload": payload
        }
    })
}

#[test]
fn refuses_to_start_when_an_audit_log_cannot_be_opened() {
    let directory = tempfile::tempdir().expect("temporary log directory");
    let mut config = unsigned_config();
    config.envelope_log = Some(directory.path().to_owned());
    let Err(error) = Guardian::new(config) else {
        panic!("an unavailable audit log must stop startup");
    };
    assert_eq!(error, "audit log path is a directory");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn audit_write_failure_returns_an_honored_deny_over_http() {
    for fail_session_log in [false, true] {
        let directory = tempfile::tempdir().expect("temporary log directory");
        let failing_log = directory.path().join("failing.jsonl");
        std::os::unix::fs::symlink("/dev/full", &failing_log).unwrap();
        let mut config = unsigned_config();
        config.envelope_log = Some(if fail_session_log {
            directory.path().join("envelopes.jsonl")
        } else {
            failing_log.clone()
        });
        config.session_log = Some(if fail_session_log {
            failing_log
        } else {
            directory.path().join("sessions.jsonl")
        });
        let guardian = Guardian::new(config).expect("pinned AGT manifest should load");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, guardian.router()).await });
        let client = reqwest::Client::new();
        for _ in 0..2 {
            let response: Value = client
                .post(format!("http://{address}/acs"))
                .json(&request(
                    "steps/toolCallRequest",
                    json!({
                        "tool": {"name": "Bash"},
                        "arguments": {"command": {"value": "ls -la"}},
                        "raw_command": "ls -la"
                    }),
                    "ff1c17fa-48e1-49dd-88c6-50796a504c14",
                ))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(response["result"]["decision"], "deny", "{response}");
            assert!(
                response.get("error").is_none(),
                "logging failure must not trigger fail-open"
            );
        }
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn a_response_log_failure_replaces_an_allow_with_an_honored_deny() {
    let directory = tempfile::tempdir().unwrap();
    let raw = request(
        "steps/toolCallRequest",
        json!({
            "tool": {"name": "Bash"},
            "arguments": {"command": {"value": "ls -la"}},
            "raw_command": "ls -la"
        }),
        "ff1c17fa-48e1-49dd-88c6-50796a504c14",
    );
    let request_record = json!({
        "seq": 1, "recorded_at": "2000-01-01T00:00:00.000Z",
        "direction": "request", "method": "steps/toolCallRequest",
        "rpc_id": raw["id"], "envelope": raw,
    });
    for audit_full in [false, true] {
        let mut config = unsigned_config();
        let envelopes = directory
            .path()
            .join(format!("envelopes-{audit_full}.jsonl"));
        let sessions = directory
            .path()
            .join(format!("sessions-{audit_full}.jsonl"));
        config.envelope_log = Some(envelopes.clone());
        config.session_log = Some(sessions.clone());
        if audit_full {
            config.log_max_bytes = serde_json::to_vec(&request_record).unwrap().len() as u64 + 1;
            config.log_max_files = 1;
        }
        let guardian = Guardian::new(config).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, guardian.router()).await });
        let response: Value = reqwest::Client::new()
            .post(format!("http://{address}/acs"))
            .json(&raw)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            response["result"]["decision"],
            if audit_full { "deny" } else { "allow" },
            "{response}"
        );
        if audit_full {
            assert_eq!(
                response["result"]["reason_codes"],
                json!(["audit_unavailable"])
            );
        }
        assert!(response.get("error").is_none());
        // Both requests reached policy evaluation; only the capped response cannot fit.
        assert_eq!(
            std::fs::read_to_string(envelopes).unwrap().lines().count(),
            if audit_full { 1 } else { 2 }
        );
        assert_eq!(
            std::fs::read_to_string(sessions).unwrap().lines().count(),
            1
        );
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn guardian_matches_the_two_tool_gates_and_refuses_invalid_steps() {
    let mut config = unsigned_config();
    let logs = tempfile::tempdir().expect("temporary log directory");
    let envelope_path = logs.path().join("envelopes.jsonl");
    let session_path = logs.path().join("session-context.jsonl");
    config.envelope_log = Some(envelope_path.clone());
    config.session_log = Some(session_path.clone());
    let guardian = Guardian::new(config).expect("pinned AGT manifest should load");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move { axum::serve(listener, guardian.router()).await });
    let url = format!("http://{address}/acs");
    let client = reqwest::Client::new();
    let send = |value: Value| {
        let client = client.clone();
        let url = url.clone();
        async move {
            client
                .post(url)
                .json(&value)
                .send()
                .await
                .expect("HTTP request")
                .json::<Value>()
                .await
                .expect("JSON response")
        }
    };

    let hello = send(request(
        "handshake/hello",
        json!({}),
        "816407fa-7cf0-41d9-978e-398039d28dbe",
    ))
    .await;
    assert_eq!(
        hello["result"]["methods_evaluated"],
        json!(["steps/toolCallRequest", "steps/toolCallResult"])
    );
    assert_eq!(hello["result"]["on_decision_failure"], "proceed");
    let opa_timeout = agent_control_specification::OpaRegoRunner::from_environment()
        .eval_timeout()
        .as_millis();
    assert_eq!(
        hello["result"]["timeout_config"]["default_ms"],
        json!(opa_timeout + 1000 + 1000),
        "evaluator deadline, delivery margin and the default queue timeout"
    );

    let denied = send(request(
        "steps/toolCallRequest",
        json!({
            "tool": {"name": "Bash"},
            "arguments": {"command": {"value": "echo rm -rf /"}},
            "raw_command": "echo rm -rf /"
        }),
        "6a22a0f7-5547-448a-add7-3327aed144df",
    ))
    .await;
    assert_eq!(denied["result"]["decision"], "deny", "{denied}");
    assert_eq!(
        denied["result"]["reason_codes"],
        json!(["destructive_shell_command_blocked"])
    );

    let allowed = send(request(
        "steps/toolCallRequest",
        json!({
            "tool": {"name": "Bash"},
            "arguments": {"command": {"value": "ls -la"}},
            "raw_command": "ls -la"
        }),
        "ff1c17fa-48e1-49dd-88c6-50796a504c14",
    ))
    .await;
    assert_eq!(allowed["result"]["decision"], "allow", "{allowed}");

    let fetch_allowed = send(request(
        "steps/toolCallRequest",
        json!({
            "tool": {"name": "WebFetch"},
            "arguments": {"url": {"value": "https://docs.anthropic.com/en/docs"}}
        }),
        "ccac4743-e2ef-4d31-95cf-0f55e417a790",
    ))
    .await;
    assert_eq!(
        fetch_allowed["result"]["decision"], "allow",
        "{fetch_allowed}"
    );

    let request_redacted = send(request(
        "steps/toolCallRequest",
        json!({
            "tool": {"name": "Bash"},
            "arguments": {"command": {"value": "echo ghp_ABCDEF123456"}},
            "raw_command": "echo ghp_ABCDEF123456"
        }),
        "b361a722-7c7a-449f-930d-a52c1c8022ab",
    ))
    .await;
    assert_eq!(
        request_redacted["result"]["decision"], "modify",
        "{request_redacted}"
    );
    assert_eq!(
        request_redacted["result"]["modifications"]["parameter_overrides"]["command"],
        "echo [REDACTED]"
    );

    let egress_denied = send(request(
        "steps/toolCallRequest",
        json!({
            "tool": {"name": "Bash"},
            "arguments": {"command": {"value": "git clone https://github.com/openai/whisper"}},
            "raw_command": "git clone https://github.com/openai/whisper"
        }),
        "e30572e0-c599-407c-b369-af41345872c4",
    ))
    .await;
    assert_eq!(
        egress_denied["result"]["decision"], "deny",
        "{egress_denied}"
    );
    assert_eq!(
        egress_denied["result"]["reason_codes"],
        json!(["egress_destination_not_allowed"])
    );

    let redacted = send(request(
        "steps/toolCallResult",
        json!({
            "tool": {"name": "Bash"},
            "exit_status": "success",
            "outputs": [{"value": "TOKEN=ghp_ABCDEF123456"}]
        }),
        "928d63c8-453e-4a8f-b637-b6181632e69a",
    ))
    .await;
    assert_eq!(redacted["result"]["decision"], "modify", "{redacted}");
    assert_eq!(
        redacted["result"]["modifications"]["redactions"][0]["path"],
        "/outputs/0/value"
    );
    assert_eq!(
        redacted["result"]["modifications"]["redactions"][0]["replacement"],
        "TOKEN=[REDACTED]"
    );

    let invalid = send(request(
        "steps/toolCallRequest",
        json!({"tool": {"name": "Bash"}}),
        "abc22c1b-6e7e-4212-9e90-acfded36f356",
    ))
    .await;
    assert_eq!(invalid["result"]["decision"], "deny", "{invalid}");
    assert_eq!(
        invalid["result"]["reason_codes"],
        json!(["envelope_invalid"])
    );
    assert_eq!(
        invalid["result"]["reasoning"],
        "ACS envelope failed schema validation at /params/payload/arguments: must have required property 'arguments'"
    );

    let unknown = send(request(
        "steps/sessionStart",
        json!({}),
        "278934b6-c5cd-45d7-81b5-5dc93b037e0d",
    ))
    .await;
    assert_eq!(unknown["error"]["code"], -32011, "{unknown}");

    let malformed: Value = client
        .post(&url)
        .body("{")
        .send()
        .await
        .expect("HTTP request")
        .json()
        .await
        .expect("JSON response");
    assert_eq!(malformed["error"]["code"], -32700);

    let oversized: Value = client
        .post(&url)
        .body("x".repeat(1_048_577))
        .send()
        .await
        .expect("HTTP request")
        .json()
        .await
        .expect("JSON response");
    assert_eq!(oversized["error"]["code"], -32010);

    let envelopes = std::fs::read_to_string(envelope_path).expect("envelope log");
    assert!(envelopes.contains("echo rm -rf /"));
    assert!(envelopes.contains("envelope_invalid"));
    let chain = std::fs::read_to_string(session_path).expect("session log");
    assert!(chain.contains("steps/toolCallRequest"));
    assert!(chain.contains("steps/toolCallResult"));

    server.abort();
    let _ = server.await;
}

const SESSION: &str = "6ccc72b8-a167-5573-b3ea-a310262ea93f";

/// Two secrets at once, as during a rotation from "2026-10" to "2026-11".
fn keyring() -> HmacKeyring {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let mut keyring = HmacKeyring::default();
    keyring
        .insert_base64("2026-10", &STANDARD.encode([0x11u8; 32]))
        .unwrap();
    keyring
        .insert_base64("2026-11", &STANDARD.encode([0x22u8; 32]))
        .unwrap();
    keyring
}

#[tokio::test]
async fn signed_requests_are_verified_answered_signed_and_not_replayed() {
    let mut config = GuardianConfig::from_repo();
    let logs = tempfile::tempdir().expect("temporary log directory");
    config.envelope_log = Some(logs.path().join("envelopes.jsonl"));
    config.session_log = Some(logs.path().join("session-context.jsonl"));
    config.hmac_keys = keyring();
    let guardian = Guardian::new(config).expect("pinned AGT manifest should load");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move { axum::serve(listener, guardian.router()).await });
    let url = format!("http://{address}/acs");
    let client = reqwest::Client::new();
    let send = |value: Value| {
        let client = client.clone();
        let url = url.clone();
        async move {
            client
                .post(url)
                .json(&value)
                .send()
                .await
                .expect("HTTP request")
                .json::<Value>()
                .await
                .expect("JSON response")
        }
    };
    let keys = keyring();
    let signed = |mut value: Value, key_id: &str| {
        keys.sign_request(key_id, &mut value).expect("sign request");
        value
    };
    let allowed_step = |request_id: &str| {
        request(
            "steps/toolCallRequest",
            json!({
                "tool": {"name": "Bash"},
                "arguments": {"command": {"value": "ls -la"}},
                "raw_command": "ls -la"
            }),
            request_id,
        )
    };

    // The newer of the two configured secrets: a response names the request's key_id.
    let hello = send(signed(
        request(
            "handshake/hello",
            json!({}),
            "0e5f5c39-8f39-4c46-9d2a-3c1f6f0a7b11",
        ),
        "2026-11",
    ))
    .await;
    assert_eq!(
        hello["result"]["signature_algorithms_supported"],
        json!(["HMAC-SHA256"])
    );
    assert_eq!(hello["result"]["skew_window_ms"], 300_000);
    assert_eq!(hello["result"]["signature"]["key_id"], "2026-11");
    keys.verify_response(SESSION, &hello)
        .expect("hello response signature");

    let step = signed(
        allowed_step("5a3c0d9e-3b8f-4d3e-9a43-7d5e2c1b0f21"),
        "2026-10",
    );
    let allowed = send(step.clone()).await;
    assert_eq!(allowed["result"]["decision"], "allow", "{allowed}");
    assert_eq!(allowed["result"]["signature"]["key_id"], "2026-10");
    keys.verify_response(SESSION, &allowed)
        .expect("decision signature");

    // The same signed request again is a replay, and its refusal is signed.
    let replayed = send(step).await;
    assert_eq!(replayed["error"]["code"], -32005, "{replayed}");
    keys.verify_response(SESSION, &replayed)
        .expect("replay refusal signature");

    let mut stale = allowed_step("9d7b6a5c-4e3f-4a2b-8c1d-0e9f8a7b6c5d");
    stale["params"]["timestamp"] = json!("2026-01-01T00:00:00.000Z");
    let stale = send(signed(stale, "2026-10")).await;
    assert_eq!(stale["error"]["code"], -32006, "{stale}");
    assert_eq!(stale["error"]["data"]["skew_window_ms"], 300_000);

    let mut tampered = signed(
        allowed_step("1f2e3d4c-5b6a-4798-8a7b-6c5d4e3f2a1b"),
        "2026-10",
    );
    tampered["params"]["payload"]["raw_command"] = json!("rm -rf /");
    let tampered = send(tampered).await;
    assert_eq!(tampered["error"]["code"], -32004, "{tampered}");

    let mut retired = keyring();
    retired
        .insert_base64(
            "2026-09",
            &base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0x33u8; 32]),
        )
        .unwrap();
    let mut unknown = allowed_step("2b3c4d5e-6f70-4182-9a3b-4c5d6e7f8091");
    retired.sign_request("2026-09", &mut unknown).unwrap();
    let unknown = send(unknown).await;
    assert_eq!(unknown["error"]["code"], -32004, "{unknown}");
    assert_eq!(
        unknown["error"]["data"]["reason"],
        "signature key_id names no configured secret"
    );
    assert!(
        unknown["error"].get("signature").is_none(),
        "an unknown key_id is answered unsigned"
    );

    let unsigned = send(allowed_step("3c4d5e6f-7081-4293-8a4b-5c6d7e8f90a1")).await;
    assert_eq!(unsigned["error"]["code"], -32004, "{unsigned}");
    assert!(unsigned["error"].get("signature").is_none());

    // system/ping is never signature-checked or signed: an unsigned probe is allowed.
    let ping = send(request(
        "system/ping",
        json!({"echo": "probe-1"}),
        "4d5e6f70-8192-43a4-9b5c-6d7e8f90a1b2",
    ))
    .await;
    assert_eq!(ping["result"]["decision"], "allow", "{ping}");
    assert_eq!(ping["result"]["payload"]["status"], "ok");
    assert_eq!(ping["result"]["payload"]["echo"], "probe-1");
    assert!(ping["result"].get("signature").is_none());

    server.abort();
    let _ = server.await;
}

async fn serve_guardian(config: GuardianConfig) -> (String, tokio::task::JoinHandle<()>) {
    let guardian = Guardian::new(config).expect("pinned AGT manifest should load");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, guardian.router()).await;
    });
    (format!("http://{address}/acs"), server)
}

async fn post(url: &str, value: &Value) -> Value {
    reqwest::Client::new()
        .post(url)
        .json(value)
        .send()
        .await
        .expect("HTTP request")
        .json()
        .await
        .expect("JSON response")
}

fn ls_step(request_id: &str) -> Value {
    request(
        "steps/toolCallRequest",
        json!({
            "tool": {"name": "Bash"},
            "arguments": {"command": {"value": "ls -la"}},
            "raw_command": "ls -la"
        }),
        request_id,
    )
}

#[test]
fn refuses_to_start_unsigned_without_the_explicit_opt_in() {
    let logs = tempfile::tempdir().unwrap();
    let mut config = GuardianConfig::from_repo();
    config.envelope_log = Some(logs.path().join("envelopes.jsonl"));
    config.session_log = Some(logs.path().join("sessions.jsonl"));
    let Err(error) = Guardian::new(config) else {
        panic!("a Guardian with no HMAC key must not start by default");
    };
    assert!(error.contains("ACS_ALLOW_UNSIGNED=1"), "{error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_with_no_free_slot_gets_an_honored_denial() {
    let logs = tempfile::tempdir().unwrap();
    let mut config = unsigned_config();
    config.envelope_log = Some(logs.path().join("envelopes.jsonl"));
    config.session_log = Some(logs.path().join("sessions.jsonl"));
    config.max_concurrent_requests = 1;
    config.queue_timeout_ms = 1;
    let (url, server) = serve_guardian(config).await;
    let ids = [
        "a1b2c3d4-0001-4000-8000-000000000001",
        "a1b2c3d4-0002-4000-8000-000000000002",
        "a1b2c3d4-0003-4000-8000-000000000003",
        "a1b2c3d4-0004-4000-8000-000000000004",
        "a1b2c3d4-0005-4000-8000-000000000005",
        "a1b2c3d4-0006-4000-8000-000000000006",
        "a1b2c3d4-0007-4000-8000-000000000007",
        "a1b2c3d4-0008-4000-8000-000000000008",
    ];
    let responses = futures_join(ids.iter().map(|id| {
        let url = url.clone();
        let step = ls_step(id);
        async move { post(&url, &step).await }
    }))
    .await;
    let mut busy = 0;
    for response in &responses {
        let decision = response["result"]["decision"].as_str();
        assert!(matches!(decision, Some("allow" | "deny")), "{response}");
        if response["result"]["reason_codes"] == json!(["guardian_busy"]) {
            busy += 1;
        }
    }
    assert!(
        busy > 0,
        "one slot and a 1 ms queue must turn some requests away"
    );
    assert!(
        busy < ids.len(),
        "the request holding the slot is evaluated"
    );
    // The busy denials were recorded too.
    let envelopes = std::fs::read_to_string(logs.path().join("envelopes.jsonl")).unwrap();
    assert_eq!(envelopes.lines().count(), ids.len() * 2);
    server.abort();
}

async fn futures_join<F: std::future::Future<Output = Value> + Send + 'static>(
    futures: impl Iterator<Item = F>,
) -> Vec<Value> {
    let handles: Vec<_> = futures.map(tokio::spawn).collect();
    let mut out = Vec::new();
    for handle in handles {
        out.push(handle.await.expect("request task"));
    }
    out
}

#[tokio::test]
async fn an_oversized_envelope_is_recorded_as_a_digest_without_closing_the_log() {
    let logs = tempfile::tempdir().unwrap();
    let envelopes = logs.path().join("envelopes.jsonl");
    let mut config = unsigned_config();
    config.envelope_log = Some(envelopes.clone());
    config.session_log = Some(logs.path().join("sessions.jsonl"));
    config.log_max_bytes = 2_048;
    config.log_max_files = 8;
    let (url, server) = serve_guardian(config).await;
    let mut large = ls_step("b1c2d3e4-0001-4000-8000-000000000001");
    large["params"]["payload"]["raw_command"] = json!(format!("ls {}", "x".repeat(4_096)));
    let first = post(&url, &large).await;
    assert!(first["result"]["decision"].is_string(), "{first}");
    assert_ne!(
        first["result"]["reason_codes"],
        json!(["audit_unavailable"])
    );
    let second = post(&url, &ls_step("b1c2d3e4-0002-4000-8000-000000000002")).await;
    assert_eq!(second["result"]["decision"], "allow", "{second}");
    let log = std::fs::read_to_string(&envelopes).unwrap();
    assert!(log.contains("envelope exceeds the audit segment limit"));
    assert!(log.contains("b1c2d3e4-0001-4000-8000-000000000001"));
    server.abort();
}

#[tokio::test]
async fn a_rejected_signature_is_recorded_as_a_summary() {
    let logs = tempfile::tempdir().unwrap();
    let envelopes = logs.path().join("envelopes.jsonl");
    let mut config = GuardianConfig::from_repo();
    config.envelope_log = Some(envelopes.clone());
    config.session_log = Some(logs.path().join("sessions.jsonl"));
    config.hmac_keys = keyring();
    let (url, server) = serve_guardian(config).await;
    let mut unsigned = ls_step("c1d2e3f4-0001-4000-8000-000000000001");
    unsigned["params"]["payload"]["raw_command"] = json!("ls secret-looking-body");
    let rejected = post(&url, &unsigned).await;
    assert_eq!(rejected["error"]["code"], -32004, "{rejected}");
    let log = std::fs::read_to_string(&envelopes).unwrap();
    assert!(log.contains("request failed signature verification"));
    assert!(log.contains("c1d2e3f4-0001-4000-8000-000000000001"));
    assert!(!log.contains("secret-looking-body"));
    server.abort();
}

#[tokio::test]
async fn non_step_methods_are_never_answered_with_a_step_decision() {
    let logs = tempfile::tempdir().unwrap();
    let mut config = unsigned_config();
    config.envelope_log = Some(logs.path().join("envelopes.jsonl"));
    config.session_log = Some(logs.path().join("sessions.jsonl"));
    // One segment that the first request record fills: every later record is refused.
    config.log_max_bytes = 600;
    config.log_max_files = 1;
    let (url, server) = serve_guardian(config).await;
    let mut hello = request(
        "handshake/hello",
        json!({}),
        "d1e2f3a4-0001-4000-8000-000000000001",
    );
    hello["params"]["payload"] = json!({"padding": "p".repeat(300)});
    let response = post(&url, &hello).await;
    assert!(response.get("result").is_none(), "{response}");
    assert_eq!(response["error"]["code"], -32020, "{response}");
    server.abort();
}
