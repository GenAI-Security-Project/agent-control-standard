package no_arg_tool

import rego.v1

default allow_verdict := {"decision": "deny", "reason": "tool_name_denied"}

allow_verdict := {"decision": "allow", "reason": "tool_name_allowed"} if {
	input.tool.name == "list_reservations"
}

default transform_verdict := {"decision": "deny", "reason": "tool_name_denied"}

transform_verdict := {
	"decision": "transform",
	"reason": "rewrite_requested",
	"transform": {"path": "$policy_target", "value": "replacement"},
} if {
	input.tool.name == "list_reservations"
}
