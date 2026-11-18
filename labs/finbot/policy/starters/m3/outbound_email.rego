# Module 3: outbound email. finmail__send_email may write only to the company and the vendors it pays.
#
# The starter allows company mailboxes only, any address @<namespace>.finbot. The policy can't see the visitor's
# namespace, so every .finbot mailbox counts as internal. Run scenario s3 and watch what this rule also blocks.
# The input and verdict shape are a lab convention until issue #531, as base.rego says.
package finbot

recipient_fields := ["to", "cc", "bcc"]

# FinBot's send_email takes each field as a list of addresses, or null for cc and bcc.
internal_address(address) if regex.match(`^[^@\s]+@[a-z0-9_-]+\.finbot$`, lower(address))

recipient_allowed(address) if internal_address(address)

# A field that isn't a list of strings can't be checked, so the email denies rather than going out unread.
recipients_malformed if {
	some field in recipient_fields
	value := arg(field)
	value != null
	not is_array(value)
}

recipients_malformed if {
	some field in recipient_fields
	some address in arg(field)
	not is_string(address)
}

deny_codes contains "external_recipient" if {
	tool_name == "finmail__send_email"
	recipients_malformed
}

deny_codes contains "external_recipient" if {
	tool_name == "finmail__send_email"
	some field in recipient_fields
	some address in arg(field)
	is_string(address)
	not recipient_allowed(address)
}
