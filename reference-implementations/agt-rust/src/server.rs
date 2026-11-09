use crate::{
    audit::AuditLog,
    mapping::Mapping,
    policy::Policy,
    replay::{Freshness, ReplayStore},
    schema::Schemas,
    session::{SessionLocks, SessionStore},
    signing::{sign_response, verify_request, HmacKeyring, Verification, HMAC_SHA256},
};
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::Request,
    routing::post,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::sync::Semaphore;

/// §10.3 RECOMMENDED default for `skew_window_ms`.
pub const DEFAULT_SKEW_WINDOW_MS: u64 = 300_000;

/// Paths and the negotiated failure posture for the Rust Guardian.
pub struct GuardianConfig {
    pub manifest: PathBuf,
    pub mapping: PathBuf,
    pub schemas: PathBuf,
    pub envelope_log: Option<PathBuf>,
    pub session_log: Option<PathBuf>,
    /// Maximum bytes in each audit log segment, including line separators.
    pub log_max_bytes: u64,
    /// Maximum retained files per sink, including its active segment.
    pub log_max_files: usize,
    pub on_decision_failure: String,
    /// §10 HMAC secrets by `key_id`. Empty means requests are neither verified
    /// nor signed, which is not ACS-Core.
    pub hmac_keys: HmacKeyring,
    /// §10.3 maximum clock skew, in milliseconds, for a request `timestamp`.
    pub skew_window_ms: u64,
    /// Accept unsigned traffic when no HMAC key is configured. For local tests
    /// and the side-by-side comparison only: it is not ACS-Core.
    pub allow_unsigned: bool,
    /// Requests evaluated at once. Further requests wait in a queue.
    pub max_concurrent_requests: usize,
    /// How long a request may wait for an evaluation slot before it is
    /// answered with a denial. Added to the handshake's advertised deadline.
    pub queue_timeout_ms: u64,
    /// Largest accepted request body, in bytes.
    pub max_request_bytes: usize,
}

impl GuardianConfig {
    /// Use the policy, mapping, and schemas beside this repository's TypeScript reference.
    pub fn from_repo() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        Self {
            manifest: root.join("../agt/policy/manifest.yaml"),
            mapping: root.join("../agt/mapping.yaml"),
            schemas: root.join("../../specification/v0.1.0"),
            envelope_log: Some(root.join("../agt/.acs/envelopes-rust.jsonl")),
            session_log: Some(root.join("../agt/.acs/session-context-rust.jsonl")),
            log_max_bytes: 8 * 1024 * 1024,
            log_max_files: 5,
            on_decision_failure: "proceed".into(),
            hmac_keys: HmacKeyring::default(),
            skew_window_ms: DEFAULT_SKEW_WINDOW_MS,
            allow_unsigned: false,
            max_concurrent_requests: 64,
            queue_timeout_ms: 1000,
            max_request_bytes: 1_048_576,
        }
    }
}

/// A configured Guardian. Construct once and share its router across requests.
pub struct Guardian {
    policy: Policy,
    mapping: Mapping,
    schemas: Schemas,
    sessions: SessionStore,
    envelope_log: AuditLog,
    session_log: AuditLog,
    posture: String,
    hmac_keys: HmacKeyring,
    replay: ReplayStore,
    skew_window_ms: u64,
    session_locks: SessionLocks,
    slots: Arc<Semaphore>,
    queue_timeout: Duration,
    max_request_bytes: usize,
    advertised_timeout_ms: u64,
}

impl Guardian {
    /// Validate configuration and initialize AGT before accepting requests.
    pub fn new(config: GuardianConfig) -> Result<Arc<Self>, String> {
        if config.on_decision_failure != "proceed" && config.on_decision_failure != "deny" {
            return Err("ACS_ON_DECISION_FAILURE must be proceed or deny".into());
        }
        if i64::try_from(config.skew_window_ms).is_err() {
            return Err("the skew window is too large to represent".into());
        }
        if config.hmac_keys.is_empty() && !config.allow_unsigned {
            return Err("no HMAC key is configured: set ACS_HMAC_KEYS_FILE, or ACS_HMAC_KEY_ID with ACS_HMAC_SECRET (§10). ACS_ALLOW_UNSIGNED=1 runs unsigned for local testing only".into());
        }
        if config.max_concurrent_requests == 0 || config.max_request_bytes == 0 {
            return Err("request concurrency and body limits must be positive".into());
        }
        let policy = Policy::load(&config.manifest)?;
        // The host waits for queueing as well as evaluation and delivery.
        let advertised_timeout_ms = policy
            .decision_timeout_ms()
            .checked_add(config.queue_timeout_ms)
            .ok_or("the queue timeout is too large to advertise a host deadline")?;
        let mapping = Mapping::load(&config.mapping)?;
        let schemas = Schemas::load(&config.schemas)?;
        let envelope_log = AuditLog::open(
            config
                .envelope_log
                .ok_or("the envelope audit log is required")?,
            config.log_max_bytes,
            config.log_max_files,
        )?;
        let session_log = AuditLog::open(
            config
                .session_log
                .ok_or("the session audit log is required")?,
            config.log_max_bytes,
            config.log_max_files,
        )?;
        Ok(Arc::new(Self {
            policy,
            mapping,
            schemas,
            sessions: SessionStore::default(),
            envelope_log,
            session_log,
            posture: config.on_decision_failure,
            hmac_keys: config.hmac_keys,
            replay: ReplayStore::default(),
            skew_window_ms: config.skew_window_ms,
            session_locks: SessionLocks::default(),
            slots: Arc::new(Semaphore::new(config.max_concurrent_requests)),
            queue_timeout: Duration::from_millis(config.queue_timeout_ms),
            max_request_bytes: config.max_request_bytes,
            advertised_timeout_ms,
        }))
    }

    /// Build the same `POST /acs` route the TypeScript Guardian serves.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new().route("/acs", post(handle)).with_state(self)
    }

    /// Answer one parsed request. `busy` means no evaluation slot freed up in
    /// time: the request is still authenticated, recorded and answered, but
    /// with a denial instead of an evaluation.
    fn respond(&self, raw: Value, busy: bool) -> Value {
        let method = raw.get("method").and_then(Value::as_str).map(str::to_owned);
        // §10: verify every request except system/ping when keys are configured.
        // Ping stays outside the authenticated channel, so a liveness probe
        // works during a key-resolution failure and its answer is never signed.
        let verification = (!self.hmac_keys.is_empty() && method.as_deref() != Some("system/ping"))
            .then(|| verify_request(&self.hmac_keys, &raw));
        // A response is signed with the key and key_id of the request it
        // answers. A request that did not verify gets an unsigned answer.
        let sign = |mut response: Value| {
            if let Some(Verification::Verified(key)) = &verification {
                sign_response(key, &mut response);
            }
            response
        };
        // A request that failed verification is recorded in a bounded summary,
        // so unauthenticated traffic cannot spend the audit budget on bodies.
        let unverified = matches!(verification, Some(Verification::Rejected(_)));
        if !self.session_log.available()
            || self
                .write_envelope("request", &raw, method.as_deref(), unverified)
                .is_err()
        {
            return sign(audit_failure(&raw));
        }
        let mut response = if busy {
            busy_response(&raw)
        } else {
            self.dispatch(&raw, verification.as_ref())
        };
        if !self.session_log.available() {
            response = audit_failure(&raw);
        }
        let response = sign(response);
        if let Err(error) = self.schemas.validate_response(&response) {
            let _ = writeln!(
                io::stderr().lock(),
                "guardian sent a response that fails response-envelope.json: {error}"
            );
        }
        if self
            .write_envelope("response", &response, method.as_deref(), false)
            .is_err()
        {
            return sign(audit_failure(&raw));
        }
        response
    }

    fn dispatch(&self, raw: &Value, verification: Option<&Verification>) -> Value {
        let id = rpc_id(raw);
        if let Err(message) = self.schemas.validate_request(raw) {
            if raw
                .get("method")
                .and_then(Value::as_str)
                .is_some_and(|method| method.starts_with("steps/"))
            {
                if let Some(decision) = deny_on_failure(raw, &message, "envelope_invalid") {
                    return success(id, decision);
                }
            }
            return failure(id, -32010, &message, None);
        }
        let method = raw["method"].as_str().unwrap_or_default();
        if method == "system/ping" {
            // §13: always allow, never sign, never touch the session chain or
            // replay state, so liveness works whatever the key state.
            let mut payload = json!({"status": "ok", "server_timestamp": timestamp()});
            if let Some(echo) = raw.pointer("/params/payload/echo") {
                payload["echo"] = echo.clone();
            }
            return success(
                id,
                json!({
                    "type": "final",
                    "acs_version": raw["params"]["acs_version"],
                    "request_id": raw["params"]["request_id"],
                    "decision": "allow",
                    "payload": payload,
                }),
            );
        }
        if let Some(rejection) = self.reject_unauthenticated_or_stale(raw, verification) {
            return rejection;
        }
        if method == "handshake/hello" {
            let algorithms: &[&str] = if self.hmac_keys.is_empty() {
                &[]
            } else {
                &[HMAC_SHA256]
            };
            return success(
                id,
                json!({
                    "negotiated_version": "0.1.0",
                    "methods_evaluated": ["steps/toolCallRequest", "steps/toolCallResult"],
                    "selected_transport": "http",
                    "signature_algorithms_supported": algorithms,
                    "timeout_config": {"default_ms": self.advertised_timeout_ms},
                    "skew_window_ms": self.skew_window_ms,
                    "on_decision_failure": self.posture,
                }),
            );
        }
        if method != "steps/toolCallRequest" && method != "steps/toolCallResult" {
            return failure(
                id,
                -32011,
                &format!("method not dispatched by this Guardian: {method}"),
                Some(json!({"method": method})),
            );
        }
        match self.evaluate(raw) {
            Ok(decision) => success(id, decision),
            Err(message) => {
                let message = sanitize(&message);
                if let Some(decision) = deny_on_failure(raw, &message, "evaluation_failed") {
                    success(id, decision)
                } else {
                    failure(id, -32020, &format!("evaluation failed: {message}"), None)
                }
            }
        }
    }

    /// §10 signature and §10.3 freshness checks, in that order. A request is
    /// remembered for replay protection only once its signature and timestamp
    /// pass, so a rejected request can be corrected and resent.
    fn reject_unauthenticated_or_stale(
        &self,
        raw: &Value,
        verification: Option<&Verification>,
    ) -> Option<Value> {
        let id = rpc_id(raw);
        if let Some(Verification::Rejected(reason)) = verification {
            return Some(failure(
                id,
                -32004,
                "SIGNATURE_INVALID",
                Some(json!({"reason": reason})),
            ));
        }
        let window = i64::try_from(self.skew_window_ms).unwrap_or(i64::MAX);
        let now_ms = Utc::now().timestamp_millis();
        let timestamp_ms = raw
            .pointer("/params/timestamp")
            .and_then(Value::as_str)
            .and_then(|timestamp| DateTime::parse_from_rfc3339(timestamp).ok())
            .map(|timestamp| timestamp.timestamp_millis());
        let Some(timestamp_ms) =
            timestamp_ms.filter(|timestamp| now_ms.abs_diff(*timestamp) <= window.unsigned_abs())
        else {
            return Some(failure(
                id,
                -32006,
                "TIMESTAMP_OUT_OF_WINDOW",
                Some(json!({"skew_window_ms": self.skew_window_ms})),
            ));
        };
        let session_id = raw.pointer("/params/metadata/session_id")?.as_str()?;
        let request_id = raw.pointer("/params/request_id")?.as_str()?;
        // A future-dated request stays valid until its timestamp plus the
        // window, so its id is kept for that long, not for a fixed time.
        match self.replay.check_and_remember(
            session_id,
            request_id,
            now_ms,
            timestamp_ms.saturating_add(window),
        ) {
            Ok(Freshness::Fresh) => None,
            Ok(Freshness::Replay) => Some(failure(id, -32005, "REPLAY_DETECTED", None)),
            // A full store is not a replay: regenerating request_id, the -32005
            // recovery, cannot succeed here.
            Ok(Freshness::Capacity) => Some(failure(
                id,
                -32000,
                "SESSION_REFUSED",
                Some(json!({"reason": "replay_protection_capacity"})),
            )),
            Err(message) => Some(failure(id, -32020, &message, None)),
        }
    }

    /// Evaluate one step while holding its session's lock, so the labels it
    /// reads and the labels it writes back are not interleaved with another
    /// step of the same session.
    fn evaluate(&self, raw: &Value) -> Result<Value, String> {
        let session_id = raw["params"]["metadata"]["session_id"]
            .as_str()
            .ok_or("missing session_id")?;
        self.session_locks
            .run(session_id, || self.evaluate_step(raw))?
    }

    fn evaluate_step(&self, raw: &Value) -> Result<Value, String> {
        let method = raw["method"].as_str().ok_or("missing method")?;
        let params = &raw["params"];
        let payload = &params["payload"];
        let request_id = params["request_id"].as_str().ok_or("missing request_id")?;
        let session_id = params["metadata"]["session_id"]
            .as_str()
            .ok_or("missing session_id")?;
        let tool_name = payload["tool"]["name"]
            .as_str()
            .ok_or("missing tool name")?;
        let (entry, labels) = self
            .sessions
            .append(session_id, method, request_id, tool_name)?;
        self.write_session(&entry)?;

        let point = self.mapping.point(method)?;
        let target_argument = self.mapping.target_argument(point, tool_name);
        let budgets =
            json!({"tool_call_count": 0, "token_count": 0, "elapsed_seconds": 0, "cost_usd": 0});
        let snapshot = if method == "steps/toolCallRequest" {
            let target = target_argument.ok_or("mapping has no policy_target_argument")?;
            let wrappers = payload["arguments"]
                .as_object()
                .ok_or("arguments is not an object")?;
            let mut args = Map::new();
            for (name, wrapper) in wrappers {
                args.insert(name.clone(), wrapper["value"].clone());
            }
            if args.contains_key("acs_policy_target") {
                return Err(
                    "tool argument acs_policy_target conflicts with Guardian policy target".into(),
                );
            }
            let value = args
                .get(target)
                .cloned()
                .ok_or_else(|| format!("tool {tool_name} has no {target} argument"))?;
            args.insert("acs_policy_target".into(), value);
            json!({
                "envelope": {"budgets": budgets},
                "tool_call": {
                    "name": tool_name,
                    "args": args,
                    "id": request_id,
                    "raw_command": payload["raw_command"].as_str().unwrap_or("")
                },
                "input": {"ifc": {"source_labels": labels}}
            })
        } else {
            let outputs = payload["outputs"]
                .as_array()
                .ok_or("outputs is not an array")?
                .iter()
                .map(|item| json!({"value": item["value"]}))
                .collect::<Vec<_>>();
            json!({
                "envelope": {"budgets": budgets},
                "tool_call": {"name": tool_name},
                "tool_result": {"outputs": outputs},
                "input": {"ifc": {"source_labels": labels}}
            })
        };
        let verdict = self.policy.evaluate(point, snapshot)?;
        let mut decision = self.mapping.map_verdict(&verdict, point, target_argument)?;
        if !verdict.result_labels.is_empty() {
            self.sessions
                .replace_labels(session_id, &verdict.result_labels)?;
        }
        decision.insert("type".into(), json!("final"));
        decision.insert("acs_version".into(), params["acs_version"].clone());
        decision.insert("request_id".into(), json!(request_id));
        Ok(Value::Object(decision))
    }

    /// Record an envelope. A `summary` record, or any record too large for a
    /// log segment, keeps the identifiers and a SHA-256 digest of the envelope
    /// instead of its body, so the exchange is still on record.
    fn write_envelope(
        &self,
        direction: &str,
        envelope: &Value,
        method: Option<&str>,
        summary: bool,
    ) -> Result<(), String> {
        let limit = self.envelope_log.max_record_bytes();
        self.envelope_log.append(|seq| {
            let mut record = json!({
                "seq": seq,
                "recorded_at": timestamp(),
                "direction": direction,
                "method": method,
                "rpc_id": rpc_id(envelope),
                "envelope": envelope,
            });
            let full = serde_json::to_vec(&record).map_err(|error| error.to_string())?;
            let oversized = u64::try_from(full.len()).map_or(true, |bytes| bytes > limit);
            if !summary && !oversized {
                return Ok(full);
            }
            let body = serde_json::to_vec(envelope).map_err(|error| error.to_string())?;
            let object = record.as_object_mut().ok_or("audit record is not an object")?;
            object.remove("envelope");
            object.insert(
                "envelope_summary".into(),
                json!({
                    "reason": if summary { "request failed signature verification" } else { "envelope exceeds the audit segment limit" },
                    "bytes": body.len(),
                    "sha256": format!("{:x}", Sha256::digest(&body)),
                    "request_id": envelope.pointer("/params/request_id"),
                    "session_id": envelope.pointer("/params/metadata/session_id"),
                    "key_id": envelope.pointer("/params/signature/key_id"),
                }),
            );
            serde_json::to_vec(&record).map_err(|error| error.to_string())
        })
    }

    fn write_session(&self, entry: &crate::session::ChainEntry) -> Result<(), String> {
        self.session_log
            .append(|_| serde_json::to_vec(entry).map_err(|error| error.to_string()))
    }
}

/// Serve the Guardian until the process is stopped.
pub async fn serve(config: GuardianConfig, addr: SocketAddr) -> Result<(), String> {
    let guardian = Guardian::new(config)?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|error| error.to_string())?;
    axum::serve(listener, guardian.router())
        .await
        .map_err(|error| error.to_string())
}

async fn handle(State(guardian): State<Arc<Guardian>>, request: Request<Body>) -> Json<Value> {
    let limit = guardian.max_request_bytes;
    let body = match to_bytes(request.into_body(), limit).await {
        Ok(bytes) => bytes,
        Err(_) => {
            let response = failure(
                Value::Null,
                -32010,
                &format!("request body exceeds the {limit}-byte limit"),
                None,
            );
            let _ = guardian.write_envelope("response", &response, None, false);
            return Json(response);
        }
    };
    let raw: Value = match serde_json::from_slice(&body) {
        Ok(raw) => raw,
        Err(_) => {
            let response = failure(Value::Null, -32700, "Parse error", None);
            let _ = guardian.write_envelope("response", &response, None, false);
            return Json(response);
        }
    };
    let id = rpc_id(&raw);
    let method = raw.get("method").and_then(Value::as_str).map(str::to_owned);
    let on_failure = Arc::clone(&guardian);
    // Wait at most queue_timeout for an evaluation slot. A request that does
    // not get one is still recorded and answered, with a denial.
    let slot = tokio::time::timeout(
        guardian.queue_timeout,
        Arc::clone(&guardian.slots).acquire_owned(),
    )
    .await
    .ok()
    .and_then(Result::ok);
    let busy = slot.is_none();
    match tokio::task::spawn_blocking(move || {
        let _slot = slot;
        guardian.respond(raw, busy)
    })
    .await
    {
        Ok(response) => Json(response),
        Err(error) => {
            let response = failure(
                id,
                -32020,
                &format!("guardian failed to handle the request: {error}"),
                None,
            );
            let _ = on_failure.write_envelope("response", &response, method.as_deref(), false);
            Json(response)
        }
    }
}

fn rpc_id(raw: &Value) -> Value {
    match raw.get("id") {
        Some(Value::String(id)) => json!(id),
        Some(Value::Number(id)) => json!(id),
        _ => Value::Null,
    }
}

fn success(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn failure(id: Value, code: i64, message: &str, data: Option<Value>) -> Value {
    if let Some(data) = data {
        json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message, "data": data}})
    } else {
        json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
    }
}

fn deny_on_failure(raw: &Value, message: &str, reason: &str) -> Option<Value> {
    if rpc_id(raw).is_null() {
        return None;
    }
    let request_id = raw
        .pointer("/params/request_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .or_else(|| match rpc_id(raw) {
            Value::String(id) => Some(id),
            Value::Number(id) => Some(id.to_string()),
            _ => None,
        })?;
    Some(json!({
        "type": "final", "acs_version": raw.pointer("/params/acs_version").and_then(Value::as_str).filter(|value| !value.is_empty()).unwrap_or("0.1.0"),
        "request_id": request_id,
        "decision": "deny", "reasoning": message,
        "reason_codes": [reason], "policy_references": []
    }))
}

/// Only a step is answered with a decision; any other method gets an error,
/// so a client expecting a ServerHello never receives a step result.
fn deny_step_or_fail(raw: &Value, message: &str, reason: &str) -> Value {
    let is_step = raw
        .get("method")
        .and_then(Value::as_str)
        .is_some_and(|method| method.starts_with("steps/"));
    match deny_on_failure(raw, message, reason).filter(|_| is_step) {
        Some(decision) => success(rpc_id(raw), decision),
        None => failure(rpc_id(raw), -32020, message, None),
    }
}

fn audit_failure(raw: &Value) -> Value {
    deny_step_or_fail(
        raw,
        "the required audit record could not be kept",
        "audit_unavailable",
    )
}

fn busy_response(raw: &Value) -> Value {
    deny_step_or_fail(
        raw,
        "the Guardian has no free evaluation slot within its queue timeout",
        "guardian_busy",
    )
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn sanitize(message: &str) -> String {
    message.replace(env!("CARGO_MANIFEST_DIR"), "")
}
