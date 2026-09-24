// Package tscases holds the parity corpus: sessions of steps sent to the
// TypeScript reference Guardian, whose answers are recorded once and replayed
// against the Go implementation. The corpus exercises the two hooks the TypeScript
// Guardian evaluates, through the reproduced AGT runtime's branches: the
// destructive-command patterns, the egress annotator and its URL parsing,
// the tool registry, the policy target argument, the result redaction, and
// the session's information-flow labels across steps.
package tscases

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
)

// Recording is the file the recorder writes and the replay reads.
type Recording struct {
	// TSCommit is the commit of the TypeScript tree the answers came from,
	// and SpecVersion the repository's version.txt beside it.
	TSCommit    string `json:"ts_commit"`
	SpecVersion string `json:"spec_version"`
	Cases       []Case `json:"cases"`
}

// Case is one session: its steps run in order.
type Case struct {
	Name  string `json:"name"`
	Steps []Step `json:"steps"`
}

// Step is one request and the TypeScript Guardian's answer to it.
type Step struct {
	Method  string          `json:"method"`
	Payload json.RawMessage `json:"payload"`
	// Result is the decision the TypeScript Guardian answered, nil when it
	// answered Error.
	Result *acs.Decision `json:"result,omitempty"`
	Error  *acs.Error    `json:"error,omitempty"`
}

func shell(command string) json.RawMessage {
	return mustJSON(map[string]any{
		"tool":        map[string]any{"name": "Bash"},
		"arguments":   map[string]any{"command": map[string]any{"value": command}},
		"raw_command": command,
	})
}

func toolCall(tool string, args map[string]any, raw *string) json.RawMessage {
	wrapped := map[string]any{}
	for k, v := range args {
		wrapped[k] = map[string]any{"value": v}
	}
	p := map[string]any{"tool": map[string]any{"name": tool}, "arguments": wrapped}
	if raw != nil {
		p["raw_command"] = *raw
	}
	return mustJSON(p)
}

func result(tool string, outputs ...any) json.RawMessage {
	out := make([]any, len(outputs))
	for i, o := range outputs {
		out[i] = map[string]any{"value": o}
	}
	return mustJSON(map[string]any{"tool": map[string]any{"name": tool}, "exit_status": "success", "outputs": out})
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func request(p json.RawMessage) Step { return Step{Method: acs.StepToolCallRequest, Payload: p} }
func answer(p json.RawMessage) Step  { return Step{Method: acs.StepToolCallResult, Payload: p} }

func one(name string, s Step) Case { return Case{Name: name, Steps: []Step{s}} }

// Corpus is every case, unrecorded.
func Corpus() []Case {
	str := func(s string) *string { return &s }
	cases := []Case{}
	for name, command := range map[string]string{
		"destructive_root":              "rm -rf /",
		"destructive_echoed":            "echo rm -rf /",
		"destructive_flags_reversed":    "rm -fr /",
		"destructive_upper_case":        "RM -RF /",
		"destructive_current_directory": "rm -rf ./",
		"destructive_parent_directory":  "rm -rf ..",
		"destructive_with_sudo":         "sudo rm -rf / --no-preserve-root",
		"split_flags_not_matched":       "rm -r -f /",
		"benign_listing":                "ls -la",
		"benign_install":                "npm install",
		"benign_empty":                  "",
		"secret_in_command":             "echo ghp_abcdefgh1234",
		"aws_key_in_command":            "export K=AKIAABCDEFGHIJKLMNOP",
		"egress_off_allowlist":          "curl https://evil.example.net/x",
		"egress_on_allowlist":           "curl https://docs.example.com/a",
		"egress_clone":                  "git clone https://example.org/r",
		"egress_default_port":           "curl https://docs.example.com:443/",
		"egress_other_port":             "curl https://docs.example.com:8443/",
		"egress_upper_case_host":        "curl http://DOCS.EXAMPLE.COM/",
		"egress_upper_case_scheme":      "curl HTTPS://evil.example.net/",
		"egress_hex_ipv4":               "wget http://0x7f.1/",
		"egress_dotted_ipv4":            "curl http://127.0.0.1/",
		"egress_userinfo":               "curl https://user@evil.example.net/",
		"egress_invalid_punycode":       "curl https://xn--zz.example.net/",
		"egress_suffix_confusion":       "curl https://docs.example.com.evil.example.net/",
		"egress_quoted":                 "echo 'https://docs.example.com/q'",
		"egress_first_url_counts":       "curl https://docs.example.com/?next=https://evil.example.net",
		"egress_ftp_ignored":            "curl ftp://evil.example.net/",
		"egress_trailing_dot":           "curl https://docs.example.com./",
		"egress_port_out_of_range":      "curl https://docs.example.com:70000/",
	} {
		cases = append(cases, one(name, request(shell(command))))
	}
	cases = append(cases,
		one("fetch_on_allowlist", request(toolCall("WebFetch", map[string]any{"url": "https://docs.example.com/en"}, nil))),
		one("fetch_off_allowlist", request(toolCall("WebFetch", map[string]any{"url": "https://evil.example.net/"}, nil))),
		one("fetch_lower_case_tool", request(toolCall("webfetch", map[string]any{"url": "https://evil.example.net/"}, nil))),
		one("fetch_userinfo_soft_spot", request(toolCall("WebFetch", map[string]any{"url": "https://docs.example.com@evil.example.net/"}, nil))),
		one("fetch_url_not_a_string", request(toolCall("WebFetch", map[string]any{"url": 42}, nil))),
		one("unregistered_tool", request(toolCall("Write", map[string]any{"command": "x"}, nil))),
		one("policy_target_argument_missing", request(toolCall("Bash", map[string]any{"cmd": "ls"}, str("ls")))),
		one("argument_named_like_the_leaf", request(toolCall("Bash", map[string]any{"command": "ls", "acs_policy_target": "x"}, str("ls")))),
		one("raw_command_absent", request(toolCall("Bash", map[string]any{"command": "curl https://evil.example.net/"}, nil))),
		one("command_not_a_string", request(toolCall("Bash", map[string]any{"command": 5}, str("5")))),
		one("url_argument_on_shell", request(toolCall("bash", map[string]any{"command": "ls", "url": "https://evil.example.net/"}, str("ls")))),
		one("result_secret_redacted", answer(result("Bash", "TOKEN=ghp_ABCDEF123456"))),
		one("result_aws_key_redacted", answer(result("Bash", "key AKIAABCDEFGHIJKLMNOP end"))),
		one("result_clean", answer(result("Bash", "total 0"))),
		one("result_no_outputs", answer(result("Bash"))),
		one("result_secret_in_second_output", answer(result("Bash", "clean", "ghp_ABCDEF123456"))),
		one("result_output_is_an_object", answer(result("Bash", map[string]any{"stdout": "ghp_ABCDEF123456"}))),
		one("result_unregistered_tool", answer(result("Write", "ok"))),
		Case{Name: "labels_across_steps", Steps: []Step{
			request(shell("ls")),
			answer(result("Bash", "file")),
			request(shell("cat file")),
			answer(result("Bash", "TOKEN=ghp_ABCDEF123456")),
			request(shell("rm -rf /")),
		}},
	)
	slices.SortFunc(cases, func(a, b Case) int { return strings.Compare(a.Name, b.Name) })
	return cases
}
