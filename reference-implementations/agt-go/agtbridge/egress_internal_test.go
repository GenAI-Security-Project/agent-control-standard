package agtbridge

import "testing"

func TestWhatwgOrigin(t *testing.T) {
	tests := map[string]string{
		"https://docs.example.com/x":     "https://docs.example.com",
		"http://DOCS.example.com:80/":    "http://docs.example.com",
		"https://docs.example.com:443":   "https://docs.example.com",
		"https://docs.example.com:0443/": "https://docs.example.com",
		"https://docs.example.com:8443/": "https://docs.example.com:8443",
		"http://0x7f.1/":                 "http://127.0.0.1",
		"http://0177.0.0.1/":             "http://127.0.0.1",
		"http://2130706433/":             "http://127.0.0.1",
		"http://1.2.3/":                  "http://1.2.0.3",
		"https://docs.example.com./":     "https://docs.example.com.",
	}
	for in, want := range tests {
		if got, ok := whatwgOrigin(in); !ok || got != want {
			t.Errorf("%s: got %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"https://docs.example.com:70000/", "http://256.1.1.1.1/", "http://1.2.3.4.5/", "https://xn--zz.example.net/", "http://999.1.1.1/"} {
		if got, ok := whatwgOrigin(in); ok {
			t.Errorf("%s: parsed as %q, want a failure", in, got)
		}
	}
}

func TestAnnotateEgressReadsOnlyASCIIWhitespaceAsURLEnd(t *testing.T) {
	annotate := func(command string) string {
		preliminary := map[string]any{"snapshot": map[string]any{"tool_call": map[string]any{"raw_command": command, "args": map[string]any{}}}}
		return AnnotateEgress(preliminary)["destination"].(string)
	}
	tests := map[string]string{
		"curl https://docs.example.com/x":                    "https://docs.example.com",
		"curl https://docs.example.com\tx":                   "https://docs.example.com",
		"curl https://docs.example.com\u00a0@evil.invalid/x": ambiguousDestination,
		"curl https://docs.example.com\ufeff@evil.invalid/x": ambiguousDestination,
	}
	for command, want := range tests {
		if got := annotate(command); got != want {
			t.Errorf("%q: destination %q, want %q", command, got, want)
		}
	}
}
