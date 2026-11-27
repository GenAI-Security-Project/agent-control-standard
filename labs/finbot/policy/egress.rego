# The egress warmup: systemutils__network_request reaches only hosts in data.finbot_lab.egress_allow.
#
# This rule ships complete, so attendees read a working module before they write one. The input and verdict
# shape are a lab convention until issue #531, as base.rego says.
package finbot

# http or https, spelled in ASCII because RE2's case folding matches U+017F to s. Then optional userinfo up to the
# last @ before the path, then the host: a bracketed IPv6 literal or everything up to the next separator.
# http://status.example@evil.example/ therefore reads as host evil.example, as a client would send it. Parsers
# disagree on a backslash (Node's URL reads it as a slash, Python's urlsplit doesn't), so egress_host refuses any URL
# that holds one rather than picking a parser.
url_pattern := `^[Hh][Tt][Tt][Pp][Ss]?://(?:[^/?#\\]*@)?(\[[^\]]*\]|[^/?#:\\@]*)`

egress_host := lower(match[0][1]) if {
	url := arg("url")
	is_string(url)
	not contains(url, `\`)
	match := regex.find_all_string_submatch_n(url_pattern, url, 1)
}

egress_allowed if {
	egress_host != ""
	some allowed in data.finbot_lab.egress_allow
	lower(allowed) == egress_host
}

# No url, one that isn't a string, one with a backslash, a scheme other than http or https, one the pattern can't
# read, and an empty host all deny. The call is judged, not its result, which carries no url.
deny_codes contains "egress_blocked" if {
	tool_call
	tool_name == "systemutils__network_request"
	not egress_allowed
}
