//go:build agteval

package main_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/handshake"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/observedagent"
)

const secret = "0123456789abcdef0123456789abcdef"

// build compiles the command with the build tags of the test binary.
func build(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("ACS_TEST_GUARDIAN_BINARY"); bin != "" {
		info, err := os.Stat(bin)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("ACS_TEST_GUARDIAN_BINARY is not a file: %q (%v)", bin, err)
		}
		return bin
	}
	bin := filepath.Join(t.TempDir(), "guardian")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	out, err := exec.Command("go", append(append([]string{"build"}, buildFlags...), "-o", bin, ".")...).CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

type process struct {
	cmd  *exec.Cmd
	url  string
	logs string
	done chan error
}

func referenceConfig(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs("../../guardian.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// start runs the binary from dir and waits for its banner. The configuration
// comes from the module, while every mutable test value is an ACS__ override.
func start(t *testing.T, bin, dir string, env ...string) *process {
	t.Helper()
	return startWith(t, bin, dir, referenceConfig(t), env...)
}

func startWith(t *testing.T, bin, dir, config string, env ...string) *process {
	t.Helper()
	logs := t.TempDir()
	secretFile := filepath.Join(logs, "hmac-secret")
	if err := os.WriteFile(secretFile, []byte(base64.StdEncoding.EncodeToString([]byte(secret))), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--config", config)
	prepareProcess(cmd)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"ACS__SERVER__PORT=0",
		"ACS__SECURITY__HMAC_SECRET_FILE="+secretFile,
		"ACS__AUDIT__ENVELOPE_LOG="+filepath.Join(logs, "envelopes.jsonl"),
		"ACS__AUDIT__EVENT_LOG="+filepath.Join(logs, "events.jsonl"),
	)
	cmd.Env = append(cmd.Env, evaluatorEnv...)
	cmd.Env = append(cmd.Env, env...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &process{cmd: cmd, logs: logs, done: make(chan error, 1)}
	banner := regexp.MustCompile(`^Guardian listening at (http://\S+)/acs$`)
	lines := bufio.NewScanner(stdout)
	for lines.Scan() {
		if m := banner.FindStringSubmatch(lines.Text()); m != nil {
			p.url = m[1]
			break
		}
	}
	go func() {
		_, _ = io.Copy(io.Discard, stdout)
		p.done <- cmd.Wait()
	}()
	if p.url == "" {
		t.Fatal("the Guardian printed no banner")
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return p
}

func (p *process) client(t *testing.T) *observedagent.Client {
	t.Helper()
	return p.clientWith(t, guardian.HMACKey{ID: "2026-10", Secret: []byte(secret)})
}

func (p *process) clientWith(t *testing.T, key guardian.HMACKey) *observedagent.Client {
	t.Helper()
	signer, err := guardian.NewHMACSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return &observedagent.Client{
		Signer: signer, AgentID: "agent", SessionID: observedagent.NewUUID(),
		Transport: func(ctx context.Context, body []byte) ([]byte, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url+"/acs", strings.NewReader(string(body)))
			if err != nil {
				return nil, err
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			return io.ReadAll(resp.Body)
		},
	}
}

func shell(command string) acs.ToolCallRequestPayload {
	return acs.ToolCallRequestPayload{
		Tool:       acs.Tool{Name: "Bash"},
		Arguments:  map[string]acs.ToolArgument{"command": {Value: []byte(`"` + command + `"`)}},
		RawCommand: &command,
	}
}

// TestServesDecisions runs the command from the module directory and an
// unrelated directory, and asks for the reference policy's two decisions.
func TestServesDecisions(t *testing.T) {
	bin := build(t)
	for _, dir := range []string{".", t.TempDir()} {
		t.Run(filepath.Base(mustAbs(t, dir)), func(t *testing.T) {
			p := start(t, bin, dir)
			for path, want := range map[string]int{"/healthz": 200, "/readyz": 200, "/nothing": 404} {
				resp, err := http.Get(p.url + path)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != want {
					t.Fatalf("%s answered %d, want %d", path, resp.StatusCode, want)
				}
			}
			c := p.client(t)
			ctx := context.Background()
			if o, err := c.Handshake(ctx, observedagent.DefaultHello(handshake.CoreMethods()...)); err != nil || o.Hello == nil || !o.Verified {
				t.Fatalf("handshake: %v %s", err, o.Raw)
			}
			for command, want := range map[string]acs.Disposition{"echo rm -rf /": acs.Deny, "ls -la": acs.Allow} {
				o, err := c.Send(ctx, observedagent.Request{Method: acs.StepToolCallRequest, Payload: shell(command)})
				if err != nil {
					t.Fatal(err)
				}
				if o.Result == nil || !o.Verified || o.Result.Disposition != want || o.Result.ChainHash == "" {
					t.Fatalf("%s: got %s", command, o.Raw)
				}
			}
		})
	}
}

// TestServesThePreviousHMACKey: an agent on a key in
// security.hmac_previous_keys and an agent on the current key are both
// answered, each under its own key.
func TestServesThePreviousHMACKey(t *testing.T) {
	bin := build(t)
	const previousSecret = "fedcba9876543210fedcba9876543210"
	p := startWith(t, bin, ".", configWithPreviousKeys(t, "2026-09", secretFile(t, previousSecret)))
	for name, key := range map[string]guardian.HMACKey{
		"current":  {ID: "2026-10", Secret: []byte(secret)},
		"previous": {ID: "2026-09", Secret: []byte(previousSecret)},
	} {
		t.Run(name, func(t *testing.T) {
			c := p.clientWith(t, key)
			ctx := context.Background()
			if o, err := c.Handshake(ctx, observedagent.DefaultHello(handshake.CoreMethods()...)); err != nil || o.Hello == nil || !o.Verified {
				t.Fatalf("handshake: %v %s", err, o.Raw)
			}
			o, err := c.Send(ctx, observedagent.Request{Method: acs.StepToolCallRequest, Payload: shell("ls -la")})
			if err != nil {
				t.Fatal(err)
			}
			if o.Result == nil || !o.Verified || o.Result.Disposition != acs.Allow {
				t.Fatalf("got %s", o.Raw)
			}
		})
	}
	c := p.clientWith(t, guardian.HMACKey{ID: "2026-08", Secret: []byte(previousSecret)})
	if o, err := c.Handshake(context.Background(), observedagent.DefaultHello(handshake.CoreMethods()...)); err != nil || o.Hello != nil || o.Error == nil || o.Error.Code != acs.SignatureInvalid {
		t.Fatalf("a key_id the Guardian does not hold got %v %s, want SIGNATURE_INVALID", err, o.Raw)
	}
}

// configWithPreviousKeys writes guardian.yaml, with absolute paths and one
// entry in security.hmac_previous_keys, to a temporary file.
func configWithPreviousKeys(t *testing.T, keyID, secretFile string) string {
	t.Helper()
	module := mustAbs(t, "../..")
	raw, err := os.ReadFile(referenceConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for from, to := range map[string]string{
		"deployment_dir: ../agt":               "deployment_dir: " + filepath.Join(module, "../agt"),
		"opa_path: .acs/agt/bin":               "opa_path: " + filepath.Join(module, ".acs/agt/bin"),
		"hmac_secret_file: .acs/hmac-secret\n": "hmac_secret_file: .acs/hmac-secret\n  hmac_previous_keys:\n    - key_id: " + yamlString(keyID) + "\n      secret_file: " + yamlString(secretFile) + "\n",
	} {
		if !strings.Contains(text, from) {
			t.Fatalf("guardian.yaml no longer has %q", from)
		}
		text = strings.Replace(text, from, to, 1)
	}
	path := filepath.Join(t.TempDir(), "guardian.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// yamlString single-quotes s, so a Windows path keeps its backslashes.
func yamlString(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func secretFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hmac-secret")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString([]byte(value))), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustAbs(t *testing.T, dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func TestRefusesToStart(t *testing.T) {
	bin := build(t)
	tests := []struct {
		name, secret, want string
		args               []string
		env                []string
	}{
		{"configuration_required", "", "--config is required", nil, nil},
		{"short_secret", base64.StdEncoding.EncodeToString([]byte("short")), "decodes to 5 bytes, fewer than 32", []string{"--config", referenceConfig(t)}, nil},
		{"secret_not_base64", "not base64!", "is not standard base64", []string{"--config", referenceConfig(t)}, nil},
		{"write_timeout_within_decision", base64.StdEncoding.EncodeToString([]byte(secret)), "server.write_timeout must exceed protocol.decision_timeout", []string{"--config", referenceConfig(t)}, []string{"ACS__SERVER__WRITE_TIMEOUT=5s"}},
		{"non_positive_deferral_limit", base64.StdEncoding.EncodeToString([]byte(secret)), "limits.max_deferrals must be positive", []string{"--config", referenceConfig(t)}, []string{"ACS__LIMITS__MAX_DEFERRALS=0"}},
		{"unknown_ask_substitution", base64.StdEncoding.EncodeToString([]byte(secret)), "policy.ask_substitution must be none, deny or defer", []string{"--config", referenceConfig(t)}, []string{"ACS__POLICY__ASK_SUBSTITUTION=ask"}},
		{"unknown_override", base64.StdEncoding.EncodeToString([]byte(secret)), "invalid keys", []string{"--config", referenceConfig(t)}, []string{"ACS__NO__SUCH__SETTING=value"}},
		{"unknown_storage_provider", base64.StdEncoding.EncodeToString([]byte(secret)), `storage.provider must be "memory"`, []string{"--config", referenceConfig(t)}, []string{"ACS__STORAGE__PROVIDER=redis"}},
		{"negative_audit_rotation", base64.StdEncoding.EncodeToString([]byte(secret)), "audit: max_file_bytes and max_files cannot be negative", []string{"--config", referenceConfig(t)}, []string{"ACS__AUDIT__MAX_FILES=-1"}},
		{"audit_files_without_a_size", base64.StdEncoding.EncodeToString([]byte(secret)), "audit: max_files needs max_file_bytes", []string{"--config", referenceConfig(t)}, []string{"ACS__AUDIT__MAX_FILE_BYTES=0"}},
		{"audit_size_without_files", base64.StdEncoding.EncodeToString([]byte(secret)), "audit: max_file_bytes needs max_files", []string{"--config", referenceConfig(t)}, []string{"ACS__AUDIT__MAX_FILES=0"}},
		{"non_positive_audit_queue_records", base64.StdEncoding.EncodeToString([]byte(secret)), "audit.max_queue_records must be positive", []string{"--config", referenceConfig(t)}, []string{"ACS__AUDIT__MAX_QUEUE_RECORDS=0"}},
		{"previous_key_without_a_key_id", base64.StdEncoding.EncodeToString([]byte(secret)), "security.hmac_previous_keys[0].key_id must not be empty", []string{"--config", configWithPreviousKeys(t, "", secretFile(t, secret))}, nil},
		{"previous_key_id_equal_to_the_current", base64.StdEncoding.EncodeToString([]byte(secret)), `security.hmac_previous_keys[0].key_id "2026-10" is already used by another key`, []string{"--config", configWithPreviousKeys(t, "2026-10", secretFile(t, secret))}, nil},
		{"previous_key_without_a_secret_file", base64.StdEncoding.EncodeToString([]byte(secret)), "security.hmac_previous_keys[0].secret_file", []string{"--config", configWithPreviousKeys(t, "2026-09", "")}, nil},
		{"audit_queue_smaller_than_a_request", base64.StdEncoding.EncodeToString([]byte(secret)), "audit.max_queue_bytes must be at least 2097408 to hold one request of limits.max_body_bytes", []string{"--config", referenceConfig(t)}, []string{"ACS__AUDIT__MAX_QUEUE_BYTES=2097407"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(bin, tt.args...)
			cmd.Env = append(os.Environ(), tt.env...)
			if tt.secret != "" {
				secretFile := filepath.Join(t.TempDir(), "hmac-secret")
				if err := os.WriteFile(secretFile, []byte(tt.secret), 0o600); err != nil {
					t.Fatal(err)
				}
				cmd.Env = append(cmd.Env, "ACS__SECURITY__HMAC_SECRET_FILE="+secretFile)
			}
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tt.want) {
				t.Fatalf("exit %v, output %q", err, out)
			}
		})
	}
}

// TestLifecycle sends a termination signal while a request is still
// arriving, and expects the request to be answered and the process to exit
// zero.
func TestLifecycle(t *testing.T) {
	bin := build(t)
	p := start(t, bin, ".")
	c := p.client(t)
	ctx := context.Background()
	if o, err := c.Handshake(ctx, observedagent.DefaultHello(handshake.CoreMethods()...)); err != nil || o.Hello == nil {
		t.Fatalf("handshake: %v", err)
	}
	body, err := c.Envelope(ctx, observedagent.Request{Method: acs.StepToolCallRequest, Payload: shell("ls")})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", strings.TrimPrefix(p.url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	head := "POST /acs HTTP/1.1\r\nHost: guardian\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	half := len(body) / 2
	if _, err := conn.Write([]byte(head + string(body[:half]))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := stopProcess(p.cmd); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := conn.Write(body[half:]); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("the in-flight request got no answer: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	o, err := c.Read(ctx, raw)
	if err != nil || o.Result == nil || o.Result.Disposition != acs.Allow {
		t.Fatalf("the in-flight request got %s (%v)", raw, err)
	}
	select {
	case err := <-p.done:
		if err != nil {
			t.Fatalf("exit: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the Guardian did not exit after the signal")
	}
	body, readErr := os.ReadFile(filepath.Join(p.logs, "envelopes.jsonl"))
	if readErr != nil {
		t.Fatalf("read envelope log: %v", readErr)
	}
	if records := strings.Count(string(body), "\n"); records != 4 {
		t.Fatalf("shutdown flushed %d envelope records, want all 4: %q", records, body)
	}
	if _, err := os.Stat(filepath.Join(p.logs, "events.jsonl")); err != nil {
		t.Fatalf("shutdown did not close the event log: %v", err)
	}
}

// A request whose body never finishes arriving cannot hold the process: at
// the grace the server closes the connection and the Guardian exits.
func TestShutdownClosesAStalledRequest(t *testing.T) {
	bin := build(t)
	p := start(t, bin, ".", "ACS__SERVER__SHUTDOWN_GRACE=300ms")
	conn, err := net.Dial("tcp", strings.TrimPrefix(p.url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("POST /acs HTTP/1.1\r\nHost: guardian\r\nContent-Length: 1000\r\n\r\n{")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	signalled := time.Now()
	if err := stopProcess(p.cmd); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.done:
		// Exiting before the grace would mean the request was never in
		// flight, and the test would prove nothing.
		if waited := time.Since(signalled); waited < 250*time.Millisecond || waited > 3*time.Second {
			t.Fatalf("exited %s after the signal, want the 300ms grace", waited)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled request body held the Guardian past its grace")
	}
}
