# Module 5: redact bank account numbers from tool output before the model reads it.
#
# get_vendor_details returns the vendor record, bank_account_number included. Add a redaction path for every
# bank_account_number key in a toolCallResult's outputs, at any depth and in every list item, as an RFC 6901 pointer
# from /outputs down. The Guardian denies the whole result when a path doesn't resolve, two paths overlap, or one
# occurrence of the field is left out (issue #469). The input and verdict shape are a lab convention until
# issue #531.
#
# A result arrives as:
#   {"tool": {"name": "get_vendor_details", "version": "sha256:..."}, "exit_status": "success",
#    "outputs": [{"value": {"company_name": "...", "bank_account_number": "..."}}]}
# so the flat case is the pointer /outputs/0/value/bank_account_number. walk() visits every node with its path.
package finbot

# The starter's body never matches, so the number reaches the model. Replace false with the rule.
redaction_paths contains "/outputs/0/value/bank_account_number" if {
	input.method == "steps/toolCallResult"
	false
}
