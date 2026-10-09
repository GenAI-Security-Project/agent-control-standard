use agent_control_specification::{
    AgentControl, AnnotatorDispatcher, AnnotatorInvocation, EnforcementMode, InterventionPoint,
    JsonValue, RuntimeError, Verdict,
};
use regex::Regex;
use serde_json::json;
use std::{path::Path, process::Command, sync::Arc};
use url::Url;

pub(crate) struct Policy {
    runtime: AgentControl,
}

impl Policy {
    pub(crate) fn load(manifest: &Path) -> Result<Self, String> {
        // The pinned AGT runtime invokes OPA as a subprocess. Check this at boot,
        // so a missing evaluator cannot silently turn every decision into a deny.
        let opa = std::env::var_os("ACS_OPA_PATH").unwrap_or_else(|| "opa".into());
        let output = Command::new(&opa)
            .arg("version")
            .output()
            .map_err(|error| {
                format!(
                    "cannot execute OPA at {}: {error}",
                    Path::new(&opa).display()
                )
            })?;
        if !output.status.success() {
            return Err(format!(
                "OPA at {} failed its version check",
                Path::new(&opa).display()
            ));
        }
        let runtime = AgentControl::from_path_with_dispatchers(
            manifest,
            Some(Arc::new(EgressAnnotator)),
            None,
        )
        .map_err(|error| format!("AGT runtime: {error}"))?;
        Ok(Self { runtime })
    }

    pub(crate) fn evaluate(&self, point: &str, snapshot: JsonValue) -> Result<Verdict, String> {
        let point: InterventionPoint = point.parse().map_err(|error: String| error)?;
        Ok(self
            .runtime
            .evaluate_intervention_point(point, snapshot, EnforcementMode::Enforce)
            .verdict)
    }
}

struct EgressAnnotator;

impl AnnotatorDispatcher for EgressAnnotator {
    fn dispatch(
        &self,
        _name: &str,
        _config: &AnnotatorInvocation,
        preliminary: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        let Some(tool) = preliminary.pointer("/snapshot/tool_call") else {
            return Ok(json!({}));
        };
        let args = &tool["args"];
        if ["url", "endpoint", "host", "domain"]
            .iter()
            .any(|key| args.get(key).is_some_and(JsonValue::is_string))
        {
            return Ok(json!({}));
        }
        let Some(command) = tool["raw_command"].as_str() else {
            return Ok(json!({}));
        };
        let pattern = Regex::new(r##"\bhttps?://[^\s'"`;|&()<>]+"##)
            .map_err(|error| RuntimeError::AnnotationFailed(error.to_string()))?;
        let Some(hit) = pattern.find(command) else {
            return Ok(json!({}));
        };
        let candidate = hit.as_str();
        let authority = Regex::new(r"^https?://[A-Za-z0-9.\-]+(?::\d+)?(?:[/?#]|$)")
            .map_err(|error| RuntimeError::AnnotationFailed(error.to_string()))?;
        if !authority.is_match(candidate) {
            return Ok(json!({"destination": "https://unresolved.invalid"}));
        }
        match Url::parse(candidate) {
            Ok(url) => Ok(json!({"destination": url.origin().ascii_serialization()})),
            Err(_) => Ok(json!({"destination": "https://unresolved.invalid"})),
        }
    }
}
