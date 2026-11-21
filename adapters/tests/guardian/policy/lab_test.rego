# Minimal Rego v1 policy for the example Guardian's OPA backend tests. Entry point: data.lab.verdict.
# The input document and verdict shape are a lab convention until issue #531 settles the OPA binding.
# The lab policy pack (LAB-12) replaces this. It only shows one deny, one modify, and the allow fallback.
package lab

verdict := {
	"decision": "deny",
	"reasoning": "Recipient outside the company",
	"reason_codes": ["external_recipient"],
} if {
	input.method == "steps/toolCallRequest"
	input.payload.tool.name == "finmail__send_email"
	external_recipient
} else := {
	"decision": "modify",
	"reasoning": "Bank account numbers are withheld",
	"reason_codes": ["sensitive_field_redacted"],
	"modifications": {"redactions": redactions},
} if {
	input.method == "steps/toolCallResult"
	count(redactions) > 0
} else := {"decision": "allow"} if {
	input.method in {"steps/toolCallRequest", "steps/toolCallResult"}
}

# A recipient list that is missing or not a list counts as external, so a malformed call never reads as allowed.
external_recipient if {
	some recipient in input.payload.arguments.to.value
	not endswith(recipient, ".finbot")
}

external_recipient if not is_array(input.payload.arguments.to.value)

# One redaction per output that carries the field, so no output after the first slips through (issue #469).
redactions := [{"path": sprintf("/outputs/%d/value/bank_account_number", [i])} |
	some i, output in input.payload.outputs
	output.value.bank_account_number
]
