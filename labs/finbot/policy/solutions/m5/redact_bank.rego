# Module 5: redact bank account numbers from tool output before the model reads it.
#
# Every bank_account_number key in a toolCallResult's outputs, at any depth and in every list item, becomes one
# RFC 6901 pointer from /outputs down. The paths come from walk(), so each one resolves, and the Guardian's coverage
# check (issue #469) finds no occurrence left out. The input and verdict shape are a lab convention until issue #531.
#
# Only the exact key is redacted. get_invoice_for_payment's vendor_bank_account_number stays, since the payments
# agent passes it to create_transfer. A number inside a plain string output has no path to point at, so it passes.
package finbot

sensitive_key := "bank_account_number"

# RFC 6901 escapes ~ before /, so a key holding ~1 doesn't decode back to a slash.
pointer_token(token) := replace(replace(token, "~", "~0"), "/", "~1") if is_string(token)

pointer_token(token) := format_int(token, 10) if is_number(token)

redaction_paths contains pointer if {
	input.method == "steps/toolCallResult"
	walk(input.payload.outputs, [path, _])
	count(path) > 0
	path[count(path) - 1] == sensitive_key

	# A field inside another redacted field is already gone, and a second path would overlap it.
	not sensitive_key in array.slice(path, 0, count(path) - 1)
	pointer := concat("/", array.concat(["", "outputs"], [pointer_token(t) | some t in path]))
}
