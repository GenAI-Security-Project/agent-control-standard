package agtbridge

import (
	"math"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// egressAnnotator is the one annotator the checked-in manifest declares, and the
// only one this bridge dispatches, as the TypeScript reference's Guardian
// does (packages/guardian/src/annotate-egress.ts).
const egressAnnotator = "egress"

// argumentsAGTAlreadyReads are the tool arguments egress.rego reads a
// destination from itself; when one holds a string, the annotator stands
// down so it cannot contradict AGT's own reading.
var argumentsAGTAlreadyReads = []string{"url", "endpoint", "host", "domain"}

// jsWhitespace is ECMAScript's \s: RE2's \s is ASCII only and leaves out the
// vertical tab and every Unicode space.
const jsWhitespace = `\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`

var (
	destinationInCommand = regexp.MustCompile(`\bhttps?://[^` + jsWhitespace + "'\"`;|&()<>]+")
	unambiguousAuthority = regexp.MustCompile(`^https?://[A-Za-z0-9.\-]+(?::[0-9]+)?(?:[/?#]|$)`)
)

// ambiguousDestination is the destination the annotator reports when it
// found a URL it cannot read unambiguously; no allowlist covers it, so AGT
// denies.
const ambiguousDestination = "https://unresolved.invalid"

// annotateEgress returns the destination a shell command reaches, as
// {destination: origin}, or {} when the command names none or AGT reads
// the destination from an argument itself. It reads the command out of the
// preliminary policy input, as AGT hands a dispatcher the whole document.
func annotateEgress(preliminary map[string]any) map[string]any {
	snapshot, _ := preliminary["snapshot"].(map[string]any)
	toolCall, _ := snapshot["tool_call"].(map[string]any)
	if toolCall == nil {
		return map[string]any{}
	}
	args, _ := toolCall["args"].(map[string]any)
	for _, name := range argumentsAGTAlreadyReads {
		if _, ok := args[name].(string); ok {
			return map[string]any{}
		}
	}
	command, ok := toolCall["raw_command"].(string)
	if !ok {
		return map[string]any{}
	}
	found := destinationInCommand.FindString(command)
	if found == "" {
		return map[string]any{}
	}
	if !unambiguousAuthority.MatchString(found) {
		return map[string]any{"destination": ambiguousDestination}
	}
	origin, ok := whatwgOrigin(found)
	if !ok {
		return map[string]any{"destination": ambiguousDestination}
	}
	return map[string]any{"destination": origin}
}

// whatwgOrigin is new URL(u).origin from the WHATWG URL Standard, for the
// URLs unambiguousAuthority admits: an http or https scheme and a host of
// ASCII letters, digits, dots and hyphens with an optional port. It reports
// false where the URL parser throws.
func whatwgOrigin(u string) (string, bool) {
	scheme, rest, _ := strings.Cut(u, "://")
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority := rest[:end]
	host, port, hasPort := strings.Cut(authority, ":")
	h, ok := whatwgHost(host)
	if !ok {
		return "", false
	}
	origin := scheme + "://" + h
	if hasPort && port != "" {
		n, err := strconv.ParseUint(port, 10, 64)
		if err != nil || n > 65535 {
			return "", false
		}
		if !(scheme == "http" && n == 80) && !(scheme == "https" && n == 443) {
			origin += ":" + strconv.FormatUint(n, 10)
		}
	}
	return origin, true
}

// whatwgProfile is the URL Standard's "domain to ASCII" with beStrict false:
// UTS #46 non-transitional processing without the DNS length and hyphen
// checks.
var whatwgProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.StrictDomainName(false),
	idna.VerifyDNSLength(false),
	idna.CheckHyphens(false),
	idna.BidiRule(),
	idna.CheckJoiners(true),
)

// whatwgHost parses a host as the URL Standard's host parser does for a
// special scheme: domain to ASCII, then IPv4 when the host ends in a number.
func whatwgHost(host string) (string, bool) {
	if host == "" {
		return "", false
	}
	ascii, err := whatwgProfile.ToASCII(host)
	if err != nil || ascii == "" {
		return "", false
	}
	if !endsInANumber(ascii) {
		return ascii, true
	}
	return parseIPv4(ascii)
}

func endsInANumber(host string) bool {
	parts := strings.Split(host, ".")
	if parts[len(parts)-1] == "" {
		if len(parts) == 1 {
			return false
		}
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	if last != "" && strings.Trim(last, "0123456789") == "" {
		return true
	}
	_, ok := parseIPv4Number(last)
	return ok
}

// parseIPv4 is the URL Standard's IPv4 parser.
func parseIPv4(host string) (string, bool) {
	parts := strings.Split(host, ".")
	if parts[len(parts)-1] == "" && len(parts) > 1 {
		parts = parts[:len(parts)-1]
	}
	if len(parts) > 4 {
		return "", false
	}
	numbers := make([]uint64, len(parts))
	for i, p := range parts {
		n, ok := parseIPv4Number(p)
		if !ok {
			return "", false
		}
		numbers[i] = n
	}
	for _, n := range numbers[:len(numbers)-1] {
		if n > 255 {
			return "", false
		}
	}
	last := numbers[len(numbers)-1]
	if last >= uint64(math.Pow(256, float64(5-len(numbers)))) {
		return "", false
	}
	ipv4 := last
	for i, n := range numbers[:len(numbers)-1] {
		ipv4 += n << (8 * (3 - i))
	}
	return strconv.FormatUint(ipv4>>24, 10) + "." + strconv.FormatUint(ipv4>>16&255, 10) + "." +
		strconv.FormatUint(ipv4>>8&255, 10) + "." + strconv.FormatUint(ipv4&255, 10), true
}

// parseIPv4Number parses one part: 0x hexadecimal, a leading 0 octal,
// otherwise decimal.
func parseIPv4Number(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	base := 10
	switch {
	case len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X"):
		s, base = s[2:], 16
	case len(s) >= 2 && s[0] == '0':
		s, base = s[1:], 8
	}
	if s == "" {
		return 0, true
	}
	n, err := strconv.ParseUint(s, base, 64)
	return n, err == nil
}
