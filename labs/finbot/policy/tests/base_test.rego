# Tests for base.rego and egress.rego: the verdict, its precedence, the registry, and the egress warmup.
#
# Every input carries the pinned digest of its tool, so these tests pass with any mix of module starters and
# solutions in the pack.
package finbot_test.base

import data.finbot

tools := {
	"finmail__send_email": {"digests": ["sha256:aa"]},
	"systemutils__network_request": {"digests": ["sha256:bb"]},
}

versions := {"finmail__send_email": "sha256:aa", "systemutils__network_request": "sha256:bb"}

call(name, args) := {
	"method": "steps/toolCallRequest",
	"payload": {
		"tool": {"name": name, "version": object.get(versions, name, "sha256:00")},
		"arguments": {k: {"value": v} | some k, v in args},
	},
	"metadata": {},
}

result(name, value) := {
	"method": "steps/toolCallResult",
	"payload": {
		"tool": {"name": name, "version": object.get(versions, name, "sha256:00")},
		"exit_status": "success",
		"outputs": [{"value": value}],
	},
	"metadata": {},
}

fetch(url) := call("systemutils__network_request", {"url": url})

test_unregistered_tool_denies if {
	v := finbot.verdict with input as call("made_up__tool", {}) with data.finbot_lab.tools as tools
	v.decision == "deny"
	v.reason_codes == ["tool_unregistered"]
	is_string(v.reasoning)
}

test_missing_tool_name_denies if {
	v := finbot.verdict with input as {"method": "steps/toolCallRequest", "payload": {"arguments": {}}, "metadata": {}}
		with data.finbot_lab.tools as tools
	v.reason_codes == ["tool_unregistered"]
}

test_unregistered_wins_over_other_denies if {
	v := finbot.verdict with input as call("made_up__tool", {"to": ["collector@exfil.example"]})
		with data.finbot_lab.tools as tools
		with finbot.deny_codes as {"external_recipient"}
	v.reason_codes == ["tool_unregistered"]
}

test_registered_call_allows if {
	v := finbot.verdict with input as call("finmail__send_email", {"to": ["admin@ns_user_abc.finbot"]})
		with data.finbot_lab.tools as tools
	v == {"decision": "allow"}
}

test_result_always_defined if {
	v := finbot.verdict with input as result("finmail__send_email", "sent") with data.finbot_lab.tools as tools
	v.decision == "allow"
}

test_deny_beats_ask_beats_modify if {
	inp := result("finmail__send_email", {"a": 1})
	ask := {{"amount": 9000, "question": "Approve a transfer of 9000?"}}
	deny := finbot.verdict with input as inp with data.finbot_lab.tools as tools
		with finbot.deny_codes as {"egress_blocked"}
		with finbot.ask_requests as ask
		with finbot.redaction_paths as {"/outputs/0/value/a"}
	deny.decision == "deny"
	deny.reason_codes == ["egress_blocked"]
	asked := finbot.verdict with input as inp with data.finbot_lab.tools as tools
		with finbot.deny_codes as set()
		with finbot.ask_requests as ask
		with finbot.redaction_paths as {"/outputs/0/value/a"}
	asked.decision == "ask"
	asked.ask_details.approver == {"type": "human", "id": "lab-approver"}
	asked.ask_details.timeout_seconds == 240
	not "timeout_disposition" in object.keys(asked.ask_details)
	modified := finbot.verdict with input as inp with data.finbot_lab.tools as tools
		with finbot.deny_codes as set()
		with finbot.ask_requests as set()
		with finbot.redaction_paths as {"/outputs/0/value/a"}
	modified.decision == "modify"
	modified.modifications == {"redactions": [{"path": "/outputs/0/value/a"}]}
}

test_egress_outside_allow_denies if {
	v := finbot.verdict with input as fetch("https://collector.example/x") with data.finbot_lab.tools as tools
		with data.finbot_lab.egress_allow as ["status.example"]
	v.decision == "deny"
	v.reason_codes == ["egress_blocked"]
}

test_egress_allowed_host_allows if {
	v := finbot.verdict with input as fetch("https://status.example/health") with data.finbot_lab.tools as tools
		with data.finbot_lab.egress_allow as ["status.example"]
	v == {"decision": "allow"}
}

test_userinfo_host_blocked if {
	v := finbot.verdict with input as fetch("http://status.example@evil.example/") with data.finbot_lab.tools as tools
		with data.finbot_lab.egress_allow as ["status.example"]
	v.reason_codes == ["egress_blocked"]
}

# A WHATWG parser reads a backslash as a path separator, so this URL goes to evil.example.
test_backslash_host_blocked if {
	v := finbot.verdict with input as fetch(`http://evil.example\@status.example/`) with data.finbot_lab.tools as tools
		with data.finbot_lab.egress_allow as ["status.example"]
	v.reason_codes == ["egress_blocked"]
}

# Only http and https reach a host the allow list names. file and gopher never go through, whatever the host.
test_non_http_scheme_blocked if {
	every url in ["gopher://status.example/", "file://status.example/etc/passwd", "ftp://status.example/"] {
		egress_blocked_for(url)
	}
}

egress_blocked_for(url) if {
	v := finbot.verdict with input as fetch(url) with data.finbot_lab.tools as tools
		with data.finbot_lab.egress_allow as ["status.example"]
	v.reason_codes == ["egress_blocked"]
}

# Node's URL and Python's urlsplit take the host after the last @ before the path, so the host here is evil.example.
test_host_after_last_at_blocked if {
	egress_blocked_for("https://u@status.example:1@evil.example/")
}

test_host_after_last_at_allowed if {
	v := finbot.verdict with input as fetch("https://a@b@status.example/health") with data.finbot_lab.tools as tools
		with data.finbot_lab.egress_allow as ["status.example"]
	v == {"decision": "allow"}
}

# RE2 case folding matches U+017F (long s) to s, so a case-insensitive scheme would read this as https.
test_unicode_scheme_blocked if {
	egress_blocked_for("http\u017f://status.example/")
}

# Node reads a backslash as a slash and Python's urlsplit doesn't, so the two send these URLs to different hosts.
# Any backslash denies rather than picking a parser.
test_backslash_anywhere_blocked if {
	every url in [`https://status.example\@evil.example/`, `https://status.example/health\check`] {
		egress_blocked_for(url)
	}
}

test_uppercase_allowed_host if {
	v := finbot.verdict with input as fetch("HTTPS://STATUS.EXAMPLE:443/health") with data.finbot_lab.tools as tools
		with data.finbot_lab.egress_allow as ["status.example"]
	v == {"decision": "allow"}
}

test_unparseable_url_denies if {
	v := finbot.verdict with input as fetch("not a url") with data.finbot_lab.tools as tools
		with data.finbot_lab.egress_allow as ["status.example"]
	v.reason_codes == ["egress_blocked"]
}

test_non_string_url_denies if {
	v := finbot.verdict with input as fetch(7) with data.finbot_lab.tools as tools
		with data.finbot_lab.egress_allow as ["status.example"]
	v.reason_codes == ["egress_blocked"]
}
