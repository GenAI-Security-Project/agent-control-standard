//! §10 HMAC-SHA256 signing and verification of ACS envelopes.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde_json::{Map, Number, Value};
use sha2::Sha256;
use std::{collections::BTreeMap, fmt, fs, path::Path};

/// The only algorithm this Guardian signs and verifies.
pub(crate) const HMAC_SHA256: &str = "HMAC-SHA256";

/// §10 requires at least 32 bytes from a cryptographically secure source.
const MIN_SECRET_BYTES: usize = 32;

/// Configured HMAC secrets, each named by the `key_id` a deployment chose for it.
///
/// More than one secret can be configured at once, so a secret is replaced
/// without an outage: add the new secret under a new `key_id`, move signers
/// to it, then remove the old one. The secrets never leave this type. Its
/// `Debug` output lists only the labels.
#[derive(Clone, Default)]
pub struct HmacKeyring {
    secrets: BTreeMap<String, Vec<u8>>,
}

impl fmt::Debug for HmacKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HmacKeyring")
            .field("key_ids", &self.secrets.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl HmacKeyring {
    /// Add the secret that `key_id` names.
    ///
    /// The secret is standard base64 (RFC 4648 §4) with padding. Surrounding
    /// whitespace is ignored. The decoded bytes are the §10 secret and must be
    /// at least 32 bytes long. Error messages name the `key_id`, never the secret.
    pub fn insert_base64(&mut self, key_id: &str, secret: &str) -> Result<(), String> {
        if key_id.trim().is_empty() {
            return Err("an HMAC key_id must not be empty".into());
        }
        if self.secrets.contains_key(key_id) {
            return Err(format!("HMAC key_id {key_id:?} is configured twice"));
        }
        let secret = STANDARD
            .decode(secret.trim())
            .map_err(|_| format!("the secret for HMAC key_id {key_id:?} is not standard base64"))?;
        if secret.len() < MIN_SECRET_BYTES {
            return Err(format!(
                "the secret for HMAC key_id {key_id:?} decodes to {} bytes; §10 requires at least {MIN_SECRET_BYTES}",
                secret.len()
            ));
        }
        self.secrets.insert(key_id.to_owned(), secret);
        Ok(())
    }

    /// Add every secret in a JSON object file that maps each `key_id` to its
    /// base64 secret, for example `{"2026-10": "...", "2026-11": "..."}`.
    pub fn insert_file(&mut self, path: &Path) -> Result<(), String> {
        let text = fs::read_to_string(path)
            .map_err(|error| format!("cannot read HMAC key file {}: {error}", path.display()))?;
        let Ok(Value::Object(entries)) = serde_json::from_str::<Value>(&text) else {
            return Err(format!(
                "HMAC key file {} must be a JSON object mapping each key_id to a base64 secret",
                path.display()
            ));
        };
        for (key_id, secret) in entries {
            let Value::String(secret) = secret else {
                return Err(format!(
                    "the secret for HMAC key_id {key_id:?} in {} is not a string",
                    path.display()
                ));
            };
            self.insert_base64(&key_id, &secret)?;
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Sign a request envelope in place as an Observed Agent does: HMAC-SHA256
    /// with the per-session key for `metadata.session_id`, over the canonical
    /// envelope without `params.signature`, recorded under `key_id`.
    pub fn sign_request(&self, key_id: &str, request: &mut Value) -> Result<(), String> {
        let secret = self
            .secret(key_id)
            .ok_or_else(|| format!("HMAC key_id {key_id:?} is not configured"))?;
        let session_id = request
            .pointer("/params/metadata/session_id")
            .and_then(Value::as_str)
            .ok_or("the request has no metadata.session_id")?;
        let key = derive_session_key(secret, session_id)?;
        let params = request
            .get_mut("params")
            .and_then(Value::as_object_mut)
            .ok_or("the request has no params object")?;
        params.remove("signature");
        let mut mac = mac(&key);
        mac.update(canonicalize(request).as_bytes());
        let value = STANDARD.encode(mac.finalize().into_bytes());
        if let Some(params) = request.get_mut("params").and_then(Value::as_object_mut) {
            params.insert(
                "signature".into(),
                serde_json::json!({"algorithm": HMAC_SHA256, "value": value, "key_id": key_id}),
            );
        }
        Ok(())
    }

    /// Check the signature a Guardian put on its response to a request in
    /// `session_id`, as an Observed Agent does before honoring the decision.
    pub fn verify_response(&self, session_id: &str, response: &Value) -> Result<(), String> {
        let carrier = if response.get("result").is_some() {
            "result"
        } else {
            "error"
        };
        let signature = response
            .get(carrier)
            .and_then(|carrier| carrier.get("signature"))
            .ok_or("the response is not signed")?;
        let field = |name: &str| signature.get(name).and_then(Value::as_str);
        if field("algorithm") != Some(HMAC_SHA256) {
            return Err("the response is not signed with HMAC-SHA256".into());
        }
        let key_id = field("key_id").ok_or("the response signature has no key_id")?;
        let secret = self
            .secret(key_id)
            .ok_or("the response key_id names no configured secret")?;
        let expected = field("value")
            .and_then(|value| STANDARD.decode(value).ok())
            .ok_or("the response signature value is not standard base64")?;
        let mut unsigned = response.clone();
        if let Some(carrier) = unsigned.get_mut(carrier).and_then(Value::as_object_mut) {
            carrier.remove("signature");
        }
        let mut mac = mac(&derive_session_key(secret, session_id)?);
        mac.update(canonicalize(&unsigned).as_bytes());
        mac.verify_slice(&expected)
            .map_err(|_| "the response signature does not verify".to_string())
    }

    fn secret(&self, key_id: &str) -> Option<&[u8]> {
        self.secrets.get(key_id).map(Vec::as_slice)
    }
}

/// A per-session key and the `key_id` of the secret it came from.
pub(crate) struct SessionKey {
    pub(crate) key_id: String,
    key: [u8; 32],
}

/// The outcome of checking a request's §10 signature.
pub(crate) enum Verification {
    /// The request named a configured secret and its signature verified.
    /// A response to it is signed with the same key and `key_id`.
    Verified(SessionKey),
    /// The signature is missing, unknown, or does not verify.
    Rejected(String),
}

/// Derive the §10 per-session key: HKDF-SHA256 with no salt, the UTF-8 bytes
/// of `session_id` exactly as received as `info`, and a 32-byte output.
fn derive_session_key(secret: &[u8], session_id: &str) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, secret)
        .expand(session_id.as_bytes(), &mut key)
        .map_err(|_| "HKDF could not derive a session key".to_string())?;
    Ok(key)
}

fn mac(key: &[u8; 32]) -> Hmac<Sha256> {
    Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts a key of any length")
}

/// Check the `params.signature` of a request envelope against the keyring.
///
/// The signed input is the RFC 8785 canonical form of the whole envelope with
/// `params.signature` removed. An unknown `key_id` is rejected and never
/// checked against another secret.
pub(crate) fn verify_request(keyring: &HmacKeyring, request: &Value) -> Verification {
    let Some(params) = request.get("params").and_then(Value::as_object) else {
        return Verification::Rejected("request has no params".into());
    };
    let Some(signature) = params.get("signature") else {
        return Verification::Rejected("signature required but not present".into());
    };
    let field = |name: &str| signature.get(name).and_then(Value::as_str);
    let (Some(algorithm), Some(value), Some(key_id)) =
        (field("algorithm"), field("value"), field("key_id"))
    else {
        return Verification::Rejected(
            "signature must carry string algorithm, value and key_id".into(),
        );
    };
    if algorithm != HMAC_SHA256 {
        return Verification::Rejected(format!("unsupported algorithm: {algorithm}"));
    }
    let Some(secret) = keyring.secret(key_id) else {
        return Verification::Rejected("signature key_id names no configured secret".into());
    };
    let Some(session_id) = params
        .get("metadata")
        .and_then(|metadata| metadata.get("session_id"))
        .and_then(Value::as_str)
    else {
        return Verification::Rejected("metadata.session_id is required to derive the key".into());
    };
    let Ok(expected) = STANDARD.decode(value) else {
        return Verification::Rejected("signature value is not standard base64".into());
    };
    let key = match derive_session_key(secret, session_id) {
        Ok(key) => key,
        Err(reason) => return Verification::Rejected(reason),
    };
    let mut unsigned = request.clone();
    if let Some(params) = unsigned.get_mut("params").and_then(Value::as_object_mut) {
        params.remove("signature");
    }
    let mut mac = mac(&key);
    mac.update(canonicalize(&unsigned).as_bytes());
    if mac.verify_slice(&expected).is_err() {
        return Verification::Rejected("signature does not match the canonical envelope".into());
    }
    Verification::Verified(SessionKey {
        key_id: key_id.to_owned(),
        key,
    })
}

/// Sign a response envelope in place with the key of the request it answers.
///
/// The signature goes on `result` or, for an error response, on `error`. The
/// signed input is the canonical response with that `signature` removed.
pub(crate) fn sign_response(key: &SessionKey, response: &mut Value) {
    let carrier = if response.get("result").is_some() {
        "result"
    } else if response.get("error").is_some() {
        "error"
    } else {
        return;
    };
    let Some(object) = response.get_mut(carrier).and_then(Value::as_object_mut) else {
        return;
    };
    object.remove("signature");
    let mut mac = mac(&key.key);
    mac.update(canonicalize(response).as_bytes());
    let value = STANDARD.encode(mac.finalize().into_bytes());
    if let Some(object) = response.get_mut(carrier).and_then(Value::as_object_mut) {
        object.insert(
            "signature".into(),
            serde_json::json!({"algorithm": HMAC_SHA256, "value": value, "key_id": key.key_id}),
        );
    }
}

/// RFC 8785 JSON Canonicalization Scheme for a parsed JSON value.
///
/// Object members are sorted by the UTF-16 code units of their names, strings
/// use ECMAScript `JSON.stringify` escaping, and numbers use ECMAScript
/// `Number.prototype.toString`.
pub(crate) fn canonicalize(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Value::Number(number) => write_number(number, out),
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(members) => write_object(members, out),
    }
}

fn write_object(members: &Map<String, Value>, out: &mut String) {
    let mut entries: Vec<(&String, &Value)> = members.iter().collect();
    entries.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
    out.push('{');
    for (index, (name, value)) in entries.into_iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_string(name, out);
        out.push(':');
        write_canonical(value, out);
    }
    out.push('}');
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

fn write_number(number: &Number, out: &mut String) {
    // ECMAScript holds every number as a double, so an integer beyond 2^53 is
    // rounded exactly as a JavaScript signer would round it.
    const MAX_SAFE: u64 = (1 << 53) - 1;
    if let Some(value) = number.as_u64().filter(|value| *value <= MAX_SAFE) {
        out.push_str(&value.to_string());
    } else if let Some(value) = number
        .as_i64()
        .filter(|value| value.unsigned_abs() <= MAX_SAFE)
    {
        out.push_str(&value.to_string());
    } else {
        let value = number.as_f64().unwrap_or(0.0);
        if value == 0.0 {
            // ECMAScript prints negative zero as "0".
            out.push('0');
        } else {
            out.push_str(ryu_js::Buffer::new().format_finite(value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn keyring() -> HmacKeyring {
        let mut keyring = HmacKeyring::default();
        keyring
            .insert_base64("2026-10", &STANDARD.encode((0u8..32).collect::<Vec<_>>()))
            .unwrap();
        keyring
    }

    fn signed_request(keyring: &HmacKeyring, key_id: &str) -> Value {
        let mut request = json!({
            "jsonrpc": "2.0", "method": "steps/toolCallRequest", "id": "1",
            "params": {
                "acs_version": "0.1.0",
                "request_id": "7a0f4f3e-1d2c-4b5a-9e8f-0a1b2c3d4e5f",
                "timestamp": "2026-11-08T10:00:00Z",
                "metadata": {"agent_id": "a", "session_id": "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36"},
                "payload": {"tool": {"name": "Bash"}}
            }
        });
        let key = derive_session_key(
            keyring.secret("2026-10").unwrap(),
            "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36",
        )
        .unwrap();
        let mut mac = mac(&key);
        mac.update(canonicalize(&request).as_bytes());
        let value = STANDARD.encode(mac.finalize().into_bytes());
        request["params"]["signature"] =
            json!({"algorithm": HMAC_SHA256, "value": value, "key_id": key_id});
        request
    }

    #[test]
    fn derives_the_specification_example_key() {
        let key = derive_session_key(
            &(0u8..32).collect::<Vec<_>>(),
            "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36",
        )
        .unwrap();
        let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "80f0dc8c611279bfc2af2d5f374c5cb685888192ce1af5c3e0673d8fa748e8a4"
        );
    }

    #[test]
    fn canonicalizes_like_rfc_8785() {
        let value: Value = serde_json::from_str(
            r#"{"b":[1e30,4.5,0.002,1E-7,-0,9007199254740993],"a":"€\u001f\n\"","€":1,"😀":2,"דּ":3}"#,
        )
        .unwrap();
        assert_eq!(
            canonicalize(&value),
            "{\"a\":\"€\\u001f\\n\\\"\",\"b\":[1e+30,4.5,0.002,1e-7,0,9007199254740992],\"€\":1,\"😀\":2,\"\u{fb33}\":3}"
        );
    }

    #[test]
    fn verifies_a_signed_request_and_signs_the_response_with_its_key_id() {
        let keyring = keyring();
        let Verification::Verified(key) =
            verify_request(&keyring, &signed_request(&keyring, "2026-10"))
        else {
            panic!("a correctly signed request should verify");
        };
        assert_eq!(key.key_id, "2026-10");
        let mut response = json!({"jsonrpc": "2.0", "id": "1", "result": {"decision": "allow"}});
        sign_response(&key, &mut response);
        assert_eq!(response["result"]["signature"]["key_id"], "2026-10");
        let signature = response["result"]
            .as_object_mut()
            .unwrap()
            .remove("signature")
            .unwrap();
        let mut mac = mac(&key.key);
        mac.update(canonicalize(&response).as_bytes());
        assert_eq!(
            signature["value"],
            STANDARD.encode(mac.finalize().into_bytes())
        );
    }

    #[test]
    fn rejects_tampering_unknown_key_ids_and_missing_signatures() {
        let keyring = keyring();
        let mut tampered = signed_request(&keyring, "2026-10");
        tampered["params"]["metadata"]["session_id"] =
            json!("00000000-0000-4000-8000-000000000000");
        let mut unsigned = signed_request(&keyring, "2026-10");
        unsigned["params"]
            .as_object_mut()
            .unwrap()
            .remove("signature");
        for (request, reason) in [
            (tampered, "signature does not match the canonical envelope"),
            (
                signed_request(&keyring, "2026-11"),
                "signature key_id names no configured secret",
            ),
            (unsigned, "signature required but not present"),
        ] {
            match verify_request(&keyring, &request) {
                Verification::Rejected(actual) => assert_eq!(actual, reason),
                Verification::Verified(_) => panic!("{reason}: should not verify"),
            }
        }
    }

    #[test]
    fn keyring_rejects_short_invalid_and_duplicate_secrets_without_echoing_them() {
        let mut keyring = HmacKeyring::default();
        let short = STANDARD.encode([7u8; 16]);
        let error = keyring.insert_base64("k", &short).unwrap_err();
        assert!(error.contains("16 bytes") && !error.contains(&short));
        assert!(keyring.insert_base64("k", "not base64!").is_err());
        assert!(keyring
            .insert_base64("", &STANDARD.encode([7u8; 32]))
            .is_err());
        let padded = format!("  {}\n", STANDARD.encode([7u8; 32]));
        keyring.insert_base64("k", &padded).unwrap();
        assert!(keyring.insert_base64("k", &padded).is_err());
        assert_eq!(format!("{keyring:?}"), "HmacKeyring { key_ids: [\"k\"] }");
    }
}
