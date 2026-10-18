use agent_control_specification::{
    AgentControl, AnnotatorDispatcher, AnnotatorInvocation, EnforcementMode, InterventionPoint,
    JsonValue, OpaRegoRunner, RuntimeError, Verdict,
};
use regex::Regex;
use serde_json::json;
use std::{path::Path, process::Command, sync::Arc, time::Duration};
use url::Url;

pub(crate) struct Policy {
    runtime: AgentControl,
    decision_timeout_ms: u64,
}

const REQUIRED_OPA_VERSION: &str = "0.70.0";

fn check_opa_version(stdout: &[u8]) -> Result<(), String> {
    let output = std::str::from_utf8(stdout).map_err(|_| "OPA version output is not UTF-8")?;
    let version = output
        .lines()
        .find_map(|line| line.strip_prefix("Version:").map(str::trim));
    if version != Some(REQUIRED_OPA_VERSION) {
        return Err(format!(
            "OPA {REQUIRED_OPA_VERSION} is required by the pinned AGT bundle; found {}",
            version.unwrap_or("no Version field")
        ));
    }
    Ok(())
}

fn decision_timeout_ms(opa_timeout: Duration) -> Result<u64, String> {
    u64::try_from(opa_timeout.as_millis())
        .ok()
        .and_then(|millis| millis.checked_add(1000))
        .ok_or_else(|| "OPA timeout is too large to advertise a host deadline".into())
}

impl Policy {
    pub(crate) fn load(manifest: &Path) -> Result<Self, String> {
        // Use the SDK's path and timeout resolution, including its default timeout.
        let runner = OpaRegoRunner::from_environment();
        let opa = runner.executable();
        let decision_timeout_ms = decision_timeout_ms(runner.eval_timeout())?;
        let output = Command::new(opa)
            .arg("version")
            .output()
            .map_err(|error| format!("cannot execute OPA at {}: {error}", opa.display()))?;
        if !output.status.success() {
            return Err(format!("OPA at {} failed its version check", opa.display()));
        }
        check_opa_version(&output.stdout)?;
        let runtime = AgentControl::from_path_with_dispatchers(
            manifest,
            Some(Arc::new(EgressAnnotator)),
            None,
        )
        .map_err(|error| format!("AGT runtime: {error}"))?;
        Ok(Self {
            runtime,
            decision_timeout_ms,
        })
    }

    pub(crate) fn decision_timeout_ms(&self) -> u64 {
        self.decision_timeout_ms
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

#[cfg(test)]
mod tests {
    use super::{check_opa_version, decision_timeout_ms};
    use std::time::Duration;

    #[test]
    fn requires_the_exact_pinned_opa_version() {
        assert!(check_opa_version(b"Version: 0.70.0\r\nBuild Commit: abc\r\n").is_ok());
        for output in [
            b"Version: 1.0.0\n".as_slice(),
            b"Version: 0.70.0-dev\n".as_slice(),
            b"Build Commit: 0.70.0\n".as_slice(),
            b"Version: 0.70.0\n\xff".as_slice(),
            b"".as_slice(),
        ] {
            assert!(check_opa_version(output).is_err(), "{output:?}");
        }
    }

    #[test]
    fn host_deadline_leaves_a_second_for_delivery_after_opa() {
        assert_eq!(decision_timeout_ms(Duration::from_secs(5)), Ok(6000));
        assert_eq!(decision_timeout_ms(Duration::from_secs(30)), Ok(31000));
        assert!(decision_timeout_ms(Duration::from_millis(u64::MAX)).is_err());
    }
}
