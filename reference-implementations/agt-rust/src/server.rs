use crate::{mapping::Mapping, policy::Policy, schema::Schemas, session::SessionStore};
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::Request,
    routing::post,
    Json, Router,
};
use chrono::Utc;
use serde_json::{json, Map, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

const MAX_REQUEST_BYTES: usize = 1_048_576;

/// Paths and the negotiated failure posture for the Rust Guardian.
pub struct GuardianConfig {
    pub manifest: PathBuf,
    pub mapping: PathBuf,
    pub schemas: PathBuf,
    pub envelope_log: Option<PathBuf>,
    pub session_log: Option<PathBuf>,
    pub on_decision_failure: String,
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
            on_decision_failure: "proceed".into(),
        }
    }
}

/// A configured Guardian. Construct once and share its router across requests.
pub struct Guardian {
    policy: Policy,
    mapping: Mapping,
    schemas: Schemas,
    sessions: SessionStore,
    envelope_log: Option<Mutex<EnvelopeLog>>,
    session_log: Option<Mutex<Option<File>>>,
    posture: String,
}

struct EnvelopeLog {
    file: Option<File>,
    seq: u64,
}

impl Guardian {
    /// Validate configuration and initialize AGT before accepting requests.
    pub fn new(config: GuardianConfig) -> Result<Arc<Self>, String> {
        if config.on_decision_failure != "proceed" && config.on_decision_failure != "deny" {
            return Err("ACS_ON_DECISION_FAILURE must be proceed or deny".into());
        }
        let policy = Policy::load(&config.manifest)?;
        let mapping = Mapping::load(&config.mapping)?;
        let schemas = Schemas::load(&config.schemas)?;
        let envelope_log = config.envelope_log.map(|path| {
            Mutex::new(EnvelopeLog {
                file: open_log_best_effort(&path),
                seq: 0,
            })
        });
        let session_log = config
            .session_log
            .map(|path| Mutex::new(open_log_best_effort(&path)));
        Ok(Arc::new(Self {
            policy,
            mapping,
            schemas,
            sessions: SessionStore::default(),
            envelope_log,
            session_log,
            posture: config.on_decision_failure,
        }))
    }

    /// Build the same `POST /acs` route the TypeScript Guardian serves.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new().route("/acs", post(handle)).with_state(self)
    }

    fn respond(&self, raw: Value) -> Value {
        let method = raw.get("method").and_then(Value::as_str).map(str::to_owned);
        self.write_envelope("request", &raw, method.as_deref());
        let response = self.dispatch(&raw);
        if let Err(error) = self.schemas.validate_response(&response) {
            eprintln!("guardian sent a response that fails response-envelope.json: {error}");
        }
        self.write_envelope("response", &response, method.as_deref());
        response
    }

    fn dispatch(&self, raw: &Value) -> Value {
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
        if method == "handshake/hello" {
            return success(
                id,
                json!({
                    "negotiated_version": "0.1.0",
                    "methods_evaluated": ["steps/toolCallRequest", "steps/toolCallResult"],
                    "selected_transport": "http",
                    "timeout_config": {"default_ms": 5000},
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

    fn evaluate(&self, raw: &Value) -> Result<Value, String> {
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
        self.write_session(&entry);

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

    fn write_envelope(&self, direction: &str, envelope: &Value, method: Option<&str>) {
        let Some(log) = &self.envelope_log else {
            return;
        };
        let Ok(mut log) = log.lock() else { return };
        let entry = json!({
            "seq": log.seq + 1,
            "recorded_at": timestamp(),
            "direction": direction,
            "method": method,
            "rpc_id": rpc_id(envelope),
            "envelope": envelope,
        });
        let Some(file) = log.file.as_mut() else {
            return;
        };
        if let Err(error) = write_line(file, &entry) {
            eprintln!("envelope log write failed: {error}");
            log.file = None;
        } else {
            log.seq += 1;
        }
    }

    fn write_session(&self, entry: &crate::session::ChainEntry) {
        let Some(log) = &self.session_log else { return };
        let Ok(mut guard) = log.lock() else { return };
        let Some(file) = guard.as_mut() else { return };
        if let Err(error) = write_line(file, entry) {
            eprintln!("session context log write failed: {error}");
            *guard = None;
        }
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
    let body = match to_bytes(request.into_body(), MAX_REQUEST_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            let response = failure(
                Value::Null,
                -32010,
                "request body exceeds the 1048576-byte limit",
                None,
            );
            guardian.write_envelope("response", &response, None);
            return Json(response);
        }
    };
    let raw: Value = match serde_json::from_slice(&body) {
        Ok(raw) => raw,
        Err(_) => {
            let response = failure(Value::Null, -32700, "Parse error", None);
            guardian.write_envelope("response", &response, None);
            return Json(response);
        }
    };
    let id = rpc_id(&raw);
    let method = raw.get("method").and_then(Value::as_str).map(str::to_owned);
    let on_failure = Arc::clone(&guardian);
    match tokio::task::spawn_blocking(move || guardian.respond(raw)).await {
        Ok(response) => Json(response),
        Err(error) => {
            let response = failure(
                id,
                -32020,
                &format!("guardian failed to handle the request: {error}"),
                None,
            );
            on_failure.write_envelope("response", &response, method.as_deref());
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

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn sanitize(message: &str) -> String {
    message.replace(env!("CARGO_MANIFEST_DIR"), "")
}

fn open_log(path: &PathBuf) -> Result<File, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn open_log_best_effort(path: &PathBuf) -> Option<File> {
    match open_log(path) {
        Ok(file) => Some(file),
        Err(error) => {
            eprintln!("log sink disabled after open failure: {error}");
            None
        }
    }
}

fn write_line(file: &mut File, value: &impl serde::Serialize) -> Result<(), String> {
    serde_json::to_writer(&mut *file, value).map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())
}
