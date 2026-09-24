package main_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/handshake"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/internal/observedagent"
)

const secret = "0123456789abcdef0123456789abcdef"

// build compiles the command once per test binary.
func build(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "guardian")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
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
	logs := t.TempDir()
	secretFile := filepath.Join(logs, "hmac-secret")
	if err := os.WriteFile(secretFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--config", referenceConfig(t))
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"ACS__SERVER__PORT=0",
		"ACS__SECURITY__HMAC_SECRET_FILE="+secretFile,
		"ACS__AUDIT__ENVELOPE_LOG="+filepath.Join(logs, "envelopes.jsonl"),
		"ACS__AUDIT__EVENT_LOG="+filepath.Join(logs, "events.jsonl"),
	)
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
	signer, err := guardian.NewHMACSigner(guardian.HMACKey{ID: "default", Secret: []byte(secret)})
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
		{"short_secret", "short", "security.hmac_secret_file must hold at least 32 bytes", []string{"--config", referenceConfig(t)}, nil},
		{"write_timeout_within_decision", secret, "server.write_timeout must exceed protocol.decision_timeout", []string{"--config", referenceConfig(t)}, []string{"ACS__SERVER__WRITE_TIMEOUT=5s"}},
		{"non_positive_deferral_limit", secret, "limits.max_deferrals must be positive", []string{"--config", referenceConfig(t)}, []string{"ACS__LIMITS__MAX_DEFERRALS=0"}},
		{"unknown_ask_substitution", secret, "policy.ask_substitution must be none, deny or defer", []string{"--config", referenceConfig(t)}, []string{"ACS__POLICY__ASK_SUBSTITUTION=ask"}},
		{"unknown_override", secret, "invalid keys", []string{"--config", referenceConfig(t)}, []string{"ACS__NO__SUCH__SETTING=value"}},
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
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
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
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
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
