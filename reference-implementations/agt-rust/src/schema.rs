use jsonschema::{error::ValidationErrorKind, Draft, Resource, Validator};
use serde_json::Value;
use std::{fs, path::Path};

pub(crate) struct Schemas {
    request: Validator,
    response: Validator,
    tool_request: Validator,
    tool_result: Validator,
}

impl Schemas {
    pub(crate) fn load(root: &Path) -> Result<Self, String> {
        let mut resources = Vec::new();
        collect(root, &mut resources)?;
        let build = |name: &str| -> Result<Validator, String> {
            let path = root.join(name);
            let schema = read_json(&path)?;
            let registered = resources
                .iter()
                .map(|(uri, value)| {
                    Resource::from_contents(value.clone())
                        .map(|resource| (uri.clone(), resource))
                        .map_err(|error| error.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            jsonschema::options()
                .with_draft(Draft::Draft202012)
                .should_validate_formats(true)
                .with_resources(registered.into_iter())
                .build(&schema)
                .map_err(|error| format!("{}: {error}", path.display()))
        };
        Ok(Self {
            request: build("request-envelope.json")?,
            response: build("response-envelope.json")?,
            tool_request: build("hooks/tool-call-request.json")?,
            tool_result: build("hooks/tool-call-result.json")?,
        })
    }

    pub(crate) fn validate_request(&self, value: &Value) -> Result<(), String> {
        check(&self.request, value, "")?;
        match value.get("method").and_then(Value::as_str) {
            Some("steps/toolCallRequest") => check(
                &self.tool_request,
                &value["params"]["payload"],
                "/params/payload",
            ),
            Some("steps/toolCallResult") => check(
                &self.tool_result,
                &value["params"]["payload"],
                "/params/payload",
            ),
            _ => Ok(()),
        }
    }

    pub(crate) fn validate_response(&self, value: &Value) -> Result<(), String> {
        check(&self.response, value, "")
    }
}

fn check(validator: &Validator, value: &Value, prefix: &str) -> Result<(), String> {
    if let Err(error) = validator.validate(value) {
        let path = error.instance_path.to_string();
        let (pointer, detail) = match &error.kind {
            ValidationErrorKind::Required { property } => {
                let property = property.as_str().unwrap_or_default();
                (
                    format!("{prefix}{path}/{property}"),
                    format!("must have required property '{property}'"),
                )
            }
            _ => (
                if path.is_empty() {
                    format!("{prefix}/")
                } else {
                    format!("{prefix}{path}")
                },
                error.to_string(),
            ),
        };
        Err(format!(
            "ACS envelope failed schema validation at {pointer}: {detail}"
        ))
    } else {
        Ok(())
    }
}

fn read_json(path: &Path) -> Result<Value, String> {
    let content =
        fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_str(&content).map_err(|error| format!("{}: {error}", path.display()))
}

fn collect(dir: &Path, out: &mut Vec<(String, Value)>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let value = read_json(&path)?;
            if let Some(uri) = value.get("$id").and_then(Value::as_str) {
                out.push((uri.to_owned(), value));
            }
        }
    }
    Ok(())
}
