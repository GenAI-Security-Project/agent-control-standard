# Module 6: pin each tool's declaration, so a changed description or schema denies.
#
# The gateway hashes the declaration the model read for each function (name, description, parameters, strict) and
# sends it as payload.tool.version, a lab convention until issue #38 settles how a call binds to its declaration.
# data.finbot_lab.tools.<name>.digests lists the digests tools/pins.py recorded from a trusted run. A tool can have
# several, since FinBot's agents declare get_vendor_details more than once. base.rego already denies a tool the
# registry doesn't hold. The input and verdict shape are a lab convention until issue #531.
#
#   {"tool": {"name": "finmail__send_email", "version": "sha256:3f1c..."}, "arguments": {...}}
#
# Deny with tool_content_hash_mismatch on calls and results alike. Think about a step that carries no version, and
# a registry entry with no digests list. Negate a named rule, never an expression over a value that may be
# missing: OPA binds the value before the not, so `not is_string(input.payload.tool.version)` with no version fails
# the body and the step goes through.
package finbot

# The starter's body never matches, so a poisoned declaration goes through. Replace false with the rule.
deny_codes contains "tool_content_hash_mismatch" if {
	input.payload.tool.version
	false
}
