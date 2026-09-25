use agent_control_specification::Verdict;
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Deserialize)]
pub(crate) struct Mapping {
    acs_version: String,
    intervention_points: BTreeMap<String, Point>,
    verdicts: BTreeMap<String, VerdictRule>,
    field_synthesis: Synthesis,
}

#[derive(Debug, Deserialize)]
struct Point {
    acs_method: Option<String>,
    policy_target_argument: Option<TargetArgument>,
    modifications: Option<ModificationRule>,
}

#[derive(Debug, Deserialize)]
struct TargetArgument {
    default: String,
    #[serde(default)]
    by_tool: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct ModificationRule {
    from: String,
    when_path: String,
    into: String,
    into_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VerdictRule {
    decision: String,
    #[serde(default)]
    require_policy_references: bool,
}

#[derive(Debug, Deserialize)]
struct Synthesis {
    reasoning: Reasoning,
    reason_codes: Source,
    policy_references: PolicyReferences,
}

#[derive(Debug, Deserialize)]
struct PolicyReferences {
    rule_id: Source,
    policy_id: Literal,
}

#[derive(Debug, Deserialize)]
struct Source {
    source: String,
    wrap: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Literal {
    literal: String,
}

#[derive(Debug, Deserialize)]
struct Reasoning {
    source: String,
    template: String,
    summaries: BTreeMap<String, serde_yaml::Value>,
    detail: Detail,
}

#[derive(Debug, Deserialize)]
struct Detail {
    when_matches: String,
    render: String,
    otherwise: String,
}

impl Mapping {
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let content =
            fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
        let mapping: Self = serde_yaml::from_str(&content).map_err(|error| error.to_string())?;
        if mapping.acs_version != "0.1.0"
            || mapping.field_synthesis.reasoning.source != "verdict.message"
            || mapping.field_synthesis.reason_codes.source != "verdict.reason"
            || mapping.field_synthesis.reason_codes.wrap.as_deref() != Some("array")
            || mapping.field_synthesis.policy_references.rule_id.source != "verdict.reason"
        {
            return Err(
                "mapping.yaml field synthesis differs from the supported AGT mapping".into(),
            );
        }
        for row in mapping.intervention_points.values() {
            if row
                .modifications
                .as_ref()
                .is_some_and(|rule| rule.from != "verdict.transform")
            {
                return Err("mapping.yaml names an unsupported transform source".into());
            }
        }
        for method in ["steps/toolCallRequest", "steps/toolCallResult"] {
            mapping.point(method)?;
        }
        for decision in ["allow", "deny", "warn", "escalate", "transform"] {
            if !mapping.verdicts.contains_key(decision) {
                return Err(format!("mapping.yaml has no verdict rule for {decision}"));
            }
        }
        Ok(mapping)
    }

    pub(crate) fn point(&self, method: &str) -> Result<&str, String> {
        let mut matches = self
            .intervention_points
            .iter()
            .filter(|(_, row)| row.acs_method.as_deref() == Some(method));
        let first = matches
            .next()
            .ok_or_else(|| format!("mapping.yaml maps no AGT point to ACS method {method}"))?;
        if matches.next().is_some() {
            return Err(format!(
                "mapping.yaml maps ACS method {method} more than once"
            ));
        }
        Ok(first.0)
    }

    pub(crate) fn target_argument(&self, point: &str, tool: &str) -> Option<&str> {
        let row = self.intervention_points.get(point)?;
        let table = row.policy_target_argument.as_ref()?;
        Some(table.by_tool.get(tool).unwrap_or(&table.default))
    }

    pub(crate) fn map_verdict(
        &self,
        verdict: &Verdict,
        point: &str,
        target_argument: Option<&str>,
    ) -> Result<Map<String, Value>, String> {
        let key = verdict.decision.as_str();
        let rule = self
            .verdicts
            .get(key)
            .ok_or_else(|| format!("mapping.yaml has no verdict rule for {key}"))?;
        let mut result = Map::new();
        result.insert("decision".into(), json!(rule.decision));

        if let Some(reason) = verdict.reason.as_deref() {
            let policy_id = &self.field_synthesis.policy_references.policy_id.literal;
            result.insert("reason_codes".into(), json!([reason]));
            result.insert(
                "policy_references".into(),
                json!([{"policy_id": policy_id, "rule_id": reason}]),
            );
            result.insert(
                "reasoning".into(),
                json!(self.reasoning(reason, verdict.message.as_deref(), point)?),
            );
        } else if rule.require_policy_references {
            return Err(format!(
                "AGT {key} verdict has no reason for required policy reference"
            ));
        }

        if rule.decision == "modify" {
            let row = self
                .intervention_points
                .get(point)
                .ok_or_else(|| format!("mapping.yaml has no point {point}"))?;
            let modification = row
                .modifications
                .as_ref()
                .ok_or_else(|| format!("mapping.yaml has no modifications rule for {point}"))?;
            let transform = verdict
                .transform
                .as_ref()
                .ok_or("AGT transform verdict has no transform")?;
            if transform.path != modification.when_path {
                return Err(format!(
                    "AGT transform path {} differs from mapping {}",
                    transform.path, modification.when_path
                ));
            }
            let changes = match modification.into.as_str() {
                "parameter_overrides" => {
                    let argument = target_argument.ok_or("mapping has no target argument")?;
                    let mut overrides = Map::new();
                    overrides.insert(argument.to_owned(), transform.value.clone());
                    json!({"parameter_overrides": overrides})
                }
                "redactions" => {
                    let path = modification
                        .into_path
                        .as_deref()
                        .ok_or("mapping has no redaction path")?;
                    let value = transform
                        .value
                        .as_str()
                        .ok_or("AGT redaction value is not a string")?;
                    json!({"redactions": [{"path": path, "replacement": value}]})
                }
                other => return Err(format!("unsupported mapping destination {other}")),
            };
            result.insert("modifications".into(), changes);
        }
        Ok(result)
    }

    fn reasoning(
        &self,
        reason: &str,
        message: Option<&str>,
        point: &str,
    ) -> Result<String, String> {
        let config = &self.field_synthesis.reasoning;
        let summary = config
            .summaries
            .get(reason)
            .and_then(|value| {
                value
                    .as_str()
                    .or_else(|| value.get(point).and_then(serde_yaml::Value::as_str))
            })
            .or_else(|| {
                config
                    .summaries
                    .get("default")
                    .and_then(serde_yaml::Value::as_str)
            })
            .unwrap_or("");
        let detail = if let Some(message) = message.filter(|text| !text.is_empty()) {
            let regex =
                Regex::new(&config.detail.when_matches).map_err(|error| error.to_string())?;
            if let Some(captures) = regex.captures(message) {
                config
                    .detail
                    .render
                    .replace("{1}", captures.get(1).map_or("", |hit| hit.as_str()))
            } else {
                config.detail.otherwise.replace("{message}", message)
            }
        } else {
            String::new()
        };
        Ok(config
            .template
            .replace("{summary}", summary)
            .replace("{rule_id}", reason)
            .replace(
                "{policy_id}",
                &self.field_synthesis.policy_references.policy_id.literal,
            )
            .replace("{detail}", &detail))
    }
}

#[cfg(test)]
mod tests {
    use super::Mapping;
    use agent_control_specification::{Decision, Transform, Verdict};
    use serde_json::json;
    use std::path::PathBuf;

    fn mapping() -> Mapping {
        Mapping::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../agt/mapping.yaml"))
            .expect("shared mapping")
    }

    fn verdict(decision: Decision) -> Verdict {
        Verdict {
            decision,
            reason: Some("redaction_applied".into()),
            message: None,
            transform: None,
            evidence: None,
            result_labels: Vec::new(),
        }
    }

    #[test]
    fn maps_warning_and_both_transform_destinations() {
        let mapping = mapping();
        let warn = mapping
            .map_verdict(&verdict(Decision::Warn), "pre_tool_call", Some("command"))
            .expect("warn mapping");
        assert_eq!(warn["decision"], "allow");
        assert_eq!(warn["policy_references"][0]["rule_id"], "redaction_applied");

        let escalate = mapping
            .map_verdict(
                &verdict(Decision::Escalate),
                "pre_tool_call",
                Some("command"),
            )
            .expect("escalate mapping");
        assert_eq!(escalate["decision"], "ask");

        let mut transformed = verdict(Decision::Transform);
        transformed.transform = Some(Transform {
            path: "$policy_target".into(),
            value: json!("echo [REDACTED]"),
        });
        let pre = mapping
            .map_verdict(&transformed, "pre_tool_call", Some("command"))
            .expect("request transform");
        assert_eq!(
            pre["modifications"]["parameter_overrides"]["command"],
            "echo [REDACTED]"
        );
        let post = mapping
            .map_verdict(&transformed, "post_tool_call", None)
            .expect("result transform");
        assert_eq!(
            post["modifications"]["redactions"][0]["path"],
            "/outputs/0/value"
        );
        assert_eq!(
            post["modifications"]["redactions"][0]["replacement"],
            "echo [REDACTED]"
        );
    }

    #[test]
    fn refuses_a_transform_that_mapping_cannot_apply() {
        let mapping = mapping();
        let mut transformed = verdict(Decision::Transform);
        transformed.transform = Some(Transform {
            path: "$policy_target.other".into(),
            value: json!("changed"),
        });
        assert!(mapping
            .map_verdict(&transformed, "pre_tool_call", Some("command"))
            .is_err());
    }
}
