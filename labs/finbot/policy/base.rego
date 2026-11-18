# The FinBot lab policy pack's entry point: data.finbot.verdict, with its precedence and the tool registry.
#
# Lab conventions, each off unless the Guardian runs with ACS_POLICY_BACKEND=opa:
# - The input document {"method", "payload", "metadata"} and the verdict shape are the example Guardian's OPA
#   binding, a lab convention until issue #531 settles how ACS binds to OPA.
# - The approver's answer arrives in the resent step at payload.x_acs_lab_ask_answer, a lab convention until
#   issue #175 defines how an answer reaches the Guardian.
#
# Attendees edit the module files (outbound_email.rego, payment_threshold.rego, redact_bank.rego,
# tool_pins.rego). Each adds to one of the partial sets below, and this file turns them into one verdict, so a
# module never decides the order on its own.
package finbot

tool_methods := {"steps/toolCallRequest", "steps/toolCallResult"}

tool_name := input.payload.tool.name

# FinBot's arguments arrive wrapped, one {"value": ...} per argument name.
arg(name) := input.payload.arguments[name].value

# A rule that reads arg(...) judges the call only, so its body starts with tool_call. The result step carries the
# tool's output and no arguments, so without the guard the rule would read the missing argument as unreadable and
# deny or ask on the result of a call the pack allowed. A result is judged only by rules that read its output.
tool_call if input.method == "steps/toolCallRequest"

# The registry holds every tool FinBot declares, filled by tools/pins.py from a real run. A name it doesn't hold
# denies before any module runs, so a tool nobody reviewed never reaches a module that would let it through.
registered if data.finbot_lab.tools[tool_name]

# Negate a named rule, never an expression over a value that may be missing. OPA binds a missing value before the
# not, so `not data.finbot_lab.tools[tool_name]` with no tool name fails the body and the step would allow.
tool_unregistered if not registered

# One fixed sentence per A.10 reason code. The reasoning never repeats text from the step, which the model wrote.
reasons := {
	"tool_unregistered": "This tool is not in the lab's tool registry, so the step is denied.",
	"tool_content_hash_mismatch": "This tool's declaration does not match its pinned digest, so the step is denied.",
	"external_recipient": "The email names a recipient outside the company and its known vendors, so it is denied.",
	"payment_over_threshold": "This transfer is above the approval threshold, so a person must approve it.",
	"sensitive_field_redacted": "A bank account number in the tool output was redacted.",
	"egress_blocked": "The request goes to a host outside the egress allow list, so it is denied.",
}

# A code with no sentence still denies, with a generic one, so a typo in a module never turns a deny into an allow.
reasoning_for(code) := object.get(reasons, code, "The lab policy denied this step.")

# The partial sets the module files add to. Each is empty until a module adds to it.
deny_codes contains code if {
	some code in set()
}

ask_requests contains request if {
	some request in set()
}

redaction_paths contains pointer if {
	some pointer in set()
}

# An approval the gateway resent for this call. Only an approval is ever resent, but the check reads the answer
# rather than trusting that, and a second ASK on the resend would deny.
ask_approved if {
	input.method == "steps/toolCallRequest"
	answer := input.payload.x_acs_lab_ask_answer
	answer.answer == "approve"
	answer.approver == {"type": "human", "id": "lab-approver"}
}

# WP6 order: an unregistered tool, then any other deny, then an ask, then a modify, then allow.
verdict := {
	"decision": "deny",
	"reasoning": reasons.tool_unregistered,
	"reason_codes": ["tool_unregistered"],
} if {
	input.method in tool_methods
	tool_unregistered
} else := deny_verdict if {
	input.method in tool_methods
	count(deny_codes) > 0
} else := ask_verdict if {
	input.method in tool_methods
	count(ask_requests) > 0
	not ask_approved
} else := modify_verdict if {
	input.method in tool_methods
	count(redaction_paths) > 0
} else := {"decision": "allow"} if {
	input.method in tool_methods
}

deny_verdict := {"decision": "deny", "reasoning": reasoning_for(codes[0]), "reason_codes": codes} if {
	codes := sort(deny_codes)
}

ask_verdict := {
	"decision": "ask",
	"reasoning": reasons.payment_over_threshold,
	"reason_codes": ["payment_over_threshold"],
	"ask_details": {
		"approver": {"type": "human", "id": "lab-approver"},
		"question": sort(ask_requests)[0].question,
		"timeout_seconds": 240,
	},
}

# Paths into a call's arguments would fail the Guardian's check that a call is modified only through
# parameter_overrides, which denies the step. That is the safe failure for a module that redacts a call.
modify_verdict := {
	"decision": "modify",
	"reasoning": reasons.sensitive_field_redacted,
	"reason_codes": ["sensitive_field_redacted"],
	"modifications": {"redactions": [{"path": p} | some p in sort(redaction_paths)]},
}
