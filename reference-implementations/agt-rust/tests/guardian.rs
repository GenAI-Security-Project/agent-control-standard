use acs_agt_guardian::{Guardian, GuardianConfig};
use serde_json::{json, Value};

fn request(method: &str, payload: Value, request_id: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": method,
        "id": request_id,
        "params": {
            "acs_version": "0.1.0",
            "request_id": request_id,
            "timestamp": "2026-09-07T16:00:37.962Z",
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
    let mut config = GuardianConfig::from_repo();
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
        let mut config = GuardianConfig::from_repo();
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
        let mut config = GuardianConfig::from_repo();
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
    let mut config = GuardianConfig::from_repo();
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
        json!(opa_timeout + 1000)
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
